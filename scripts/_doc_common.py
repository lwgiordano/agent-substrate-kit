"""Internal helpers for the meta-system scripts. Pure stdlib.

Surface (substrate internal helpers):
  parse_front_matter(path)         -> (dict, body_str)
  iter_code_modules(root, excl)    -> Iterator[Path]
  read_last_history_entries(p, n)  -> list[dict]
  git_short_sha(cwd=None)          -> str
  git_file_last_modified(p, cwd)   -> date | None
  repo_root(start=None)            -> Path
  utc_now_iso()                    -> str
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

# ----- YAML front-matter (a small, fixed subset) -----

_FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
_KEY_VALUE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$")
_LIST_ITEM_RE = re.compile(r"^\s+-\s+(.+)$")


def parse_front_matter(path: Path) -> tuple[dict, str]:
    """Parse a markdown file with optional YAML front-matter.

    Supported YAML: top-level scalars (`key: value`) and top-level lists
    (`key:` followed by indented `- item` lines). Comments (`#`) ignored.
    Returns ({}, full_text) when no front-matter is present.
    """
    text = Path(path).read_text(encoding="utf-8")
    m = _FRONT_MATTER_RE.match(text)
    if not m:
        return {}, text

    fm_text, body = m.group(1), m.group(2)
    fm: dict = {}
    current_list_key: str | None = None

    def _strip_inline_comment(s: str) -> str:
        """Strip ` # comment` (whitespace + #) from end. Don't strip
        `#` inside quotes or at the very start (full-line comments
        are filtered separately). Naive but matches YAML's basic
        comment rule for unquoted scalars + list items."""
        # Find ` #` not inside quotes.
        in_quote = None
        for i, ch in enumerate(s):
            if in_quote:
                if ch == in_quote:
                    in_quote = None
            elif ch in ('"', "'"):
                in_quote = ch
            elif ch == "#" and i > 0 and s[i - 1] in (" ", "\t"):
                return s[:i].rstrip()
        return s

    for raw in fm_text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            li = _LIST_ITEM_RE.match(line)
            if li and current_list_key is not None:
                value = _strip_inline_comment(li.group(1))
                fm.setdefault(current_list_key, []).append(_strip_quotes(value))
            continue
        kv = _KEY_VALUE_RE.match(line)
        if not kv:
            continue
        key, value = kv.group(1), _strip_inline_comment(kv.group(2)).strip()
        if value == "":
            current_list_key = key
            fm.setdefault(key, [])
        elif value == "[]":
            # Inline empty list: `key: []`
            current_list_key = None
            fm[key] = []
        elif value.startswith("[") and value.endswith("]"):
            # Inline list: `key: [a, b, c]` — naive split on commas.
            current_list_key = None
            inner = value[1:-1].strip()
            fm[key] = (
                [_strip_quotes(x.strip()) for x in inner.split(",") if x.strip()]
                if inner else []
            )
        else:
            current_list_key = None
            fm[key] = _strip_quotes(value)
    return fm, body


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s


# ----- Code module discovery -----

def _code_suffixes() -> tuple[str, ...]:
    """Doc-drift code suffixes, language-aware.

    Base set covers the common multi-language cases so drift detection
    works in node/go repos, not just python. The substrate language
    (.substrate/config SUBSTRATE_LANG) and an optional
    SUBSTRATE_CODE_SUFFIXES override extend it. Override format:
    comma-separated, e.g. "SUBSTRATE_CODE_SUFFIXES=.rs,.kt".
    """
    import os
    base = {
        ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
        ".go", ".rs", ".rb", ".java", ".kt", ".sql",
    }
    override = os.environ.get("SUBSTRATE_CODE_SUFFIXES", "")
    if not override:
        cfg = Path.cwd() / ".substrate" / "config"
        if cfg.exists():
            try:
                for line in cfg.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("SUBSTRATE_CODE_SUFFIXES="):
                        override = line.split("=", 1)[1].strip().strip("\"'")
                        break
            except Exception:
                override = ""
    for s in override.split(","):
        s = s.strip()
        if s:
            base.add(s if s.startswith(".") else "." + s)
    return tuple(sorted(base))


CODE_SUFFIXES = _code_suffixes()
# Project-agnostic excludes. Add project-specific paths (e.g.,
# generated UI components, vendored libs, fixture trees) by passing
# a custom tuple to `iter_code_modules(..., exclude_dirs=...)`. Most
# callers should leave this default and rely on the universal set.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "node_modules",
    "dist",
    "build",
    "data",
    "seeds",
    ".venv",
    "venv",
    "__pycache__",
    "exports",
    ".git",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    # The kit's own source. Excluded REGARDLESS of position so consumers
    # can extract the zip anywhere — at repo root, in docs/, in /tmp/.
    # `bare_excludes` matches any directory holding the kit's own source.
    "agent_substrate_kit_v3",
    "docs/agent_substrate_kit_v3",  # path-form, if extracted under docs/
    # Substrate runtime/staging state (locks, memory, dormant templates —
    # including the staged strict extras *.py, v3.8.2). Never project source;
    # activated copies land in scripts/, which IS covered.
    ".substrate",
    # Tests are validation artifacts, not subsystem code that needs a
    # knowledge doc covering them. The drift detector ensures every
    # production module is documented; tests document themselves via
    # docstrings + assertions.
    "tests",
    # The substrate-init installer is a SEPARATE distributable package (its own
    # pyproject/version), not a knowledge-covered governance module of this repo. Its
    # integrity is guarded by drift tests (embedded pubkey/_minisign == kit), not by a
    # 00_substrate covers: entry. (v3.7.15)
    "installer",
)


def iter_code_modules(
    root: Path,
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDES,
) -> Iterator[Path]:
    """Yield repo-relative Paths for every source module under `root`.

    Excludes generated, vendored, and runtime directories per spec §2.4.
    """
    root = Path(root).resolve()
    bare_excludes = {d for d in exclude_dirs if "/" not in d}
    path_excludes = [d.strip("/") for d in exclude_dirs if "/" in d]

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in CODE_SUFFIXES:
            continue
        rel = path.relative_to(root)
        if any(part in bare_excludes for part in rel.parts):
            continue
        rel_str = rel.as_posix()
        if any(rel_str == ex or rel_str.startswith(ex + "/") for ex in path_excludes):
            continue
        yield rel


# ----- HISTORY tail reader -----

_HISTORY_HEADER_RE = re.compile(
    r"^## (?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) — (?P<token>\S+) — (?P<sha>\S+)\s*$"
)
_FIELD_RE = re.compile(r"^\*\*(?P<field>Summary|Files|Intent|Knowledge):\*\*\s*(?P<value>.+)$")
_FIELDS = ("summary", "files", "intent", "knowledge")


def read_last_history_entries(path: Path, n: int) -> list[dict]:
    """Return the last `n` entries in HISTORY.md, newest first.

    Each entry: {timestamp, session_token, commit_sha, summary, files,
    intent, knowledge}. Missing fields default to empty strings. Returns
    [] if the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        return []
    entries: list[dict] = []
    current: dict | None = None
    for raw in p.read_text(encoding="utf-8").splitlines():
        m = _HISTORY_HEADER_RE.match(raw)
        if m:
            if current is not None:
                entries.append(current)
            current = {
                "timestamp": m.group("ts"),
                "session_token": m.group("token"),
                "commit_sha": m.group("sha"),
                **dict.fromkeys(_FIELDS, ""),
            }
            continue
        if current is None:
            continue
        fm = _FIELD_RE.match(raw)
        if fm:
            current[fm.group("field").lower()] = fm.group("value").strip()
    if current is not None:
        entries.append(current)
    return list(reversed(entries))[:n]


# ----- Git helpers -----


def _git(args: list[str], cwd: Path | None = None) -> str | None:
    # timeout=30 per blind-spot-checklists/commit-msg-hooks.md #14
    # (slow-FS protection).
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return None


def git_short_sha(cwd: Path | None = None) -> str:
    """Return short SHA of HEAD; 'WORKING' if no commit yet."""
    sha = _git(["rev-parse", "--short", "HEAD"], cwd=cwd)
    return sha if sha else "WORKING"


def git_file_last_modified(path: Path, cwd: Path | None = None) -> date | None:
    """Last-commit date of `path`, or None if not yet committed."""
    iso = _git(["log", "-1", "--format=%aI", "--", str(path)], cwd=cwd)
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).date()
    except ValueError:
        return None


def repo_root(start: Path | None = None) -> Path:
    """Git repo root (resolved). Falls back to `start` (or cwd) when outside a repo."""
    base = (start or Path.cwd()).resolve()
    out = _git(["rev-parse", "--show-toplevel"], cwd=base)
    return Path(out).resolve() if out else base


def utc_now_iso() -> str:
    """ISO-8601 UTC, second precision, with `Z` suffix."""
    return (
        datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
