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

import errno
import fcntl
import os
import re
import subprocess
import time
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
        # v3.8.43 (round-26 P2, root cause): this raw read_text ran at MODULE
        # IMPORT (see `CODE_SUFFIXES = _code_suffixes()` below), so a FIFO
        # .substrate/config blocked forever the moment ANY consumer imported
        # _doc_common — the exfil guard, the config gate and the doctor all hung
        # here, upstream of every guard they were about to run. The reported
        # symptom was command_policy.profile(); this is where it actually wedged.
        # safe_read_text is defined later in the module and cannot be used yet,
        # so the minimum is inlined: O_NOFOLLOW (never follow a symlinked config),
        # O_NONBLOCK (a FIFO fails fast), regular-file-only, bounded. Any refusal
        # leaves `override` empty, which is the existing benign default.
        import stat as _st_early
        _fd = -1
        try:
            _fd = os.open(str(cfg), os.O_RDONLY
                          | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            if _st_early.S_ISREG(os.fstat(_fd).st_mode):
                _raw = os.read(_fd, 1 << 20)
                for line in _raw.decode("utf-8", errors="replace").splitlines():
                    if line.strip().startswith("SUBSTRATE_CODE_SUFFIXES="):
                        override = line.split("=", 1)[1].strip().strip("\"'")
                        break
        except (OSError, ValueError):
            override = ""
        finally:
            if _fd >= 0:
                os.close(_fd)
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


import stat as _stat

# A required_* lock holds a tiny token ("0"/"1"/"starter"/"standard"/"strict")
# plus at most trailing whitespace. Anything longer is malformed/padded and
# must be rejected before it can be truncated into a lowering value (v3.8.37).
LOCK_MAX_BYTES = 64

# Default whole-file cap for `safe_read_text`. Callers that must not truncate
# (the memory chain) pass max_bytes=None; tail readers pass tail_bytes.
SAFE_READ_MAX_BYTES = 1 << 20

# Modes an INHERITED permission set may keep when a guarded write replaces an
# existing file (v3.8.44, in-release auditor BLOCK). Carrying the predecessor's
# mode verbatim meant a target an attacker could chmod kept those bits through
# every later "safe" rewrite: 0o4777 stayed 0o4777. setuid/setgid/sticky and
# world-write are dropped; owner/group rwx and the read bits that make 0644 and
# 0755 work survive. An EXPLICIT `mode=` argument is a deliberate choice by the
# caller and is not masked.
INHERIT_MODE_MASK = 0o775


def within_root(target, root) -> bool:
    """True iff `target`'s PARENT resolves to its EXACT lexical location under
    `root` — no aliasing symlink anywhere below root (v3.8.40 — round-23).

    v3.8.39 checked only NO-ESCAPE (realpath(parent) somewhere inside root). But
    a symlinked ancestor that resolves to a DIFFERENT in-repo directory
    (`.substrate -> docs`) still redirects the trust anchor to agent-writable
    content without leaving the tree — an escape of TRUST, not of the filesystem.
    The correct invariant is stricter: the parent must resolve to exactly where
    its lexical path says it should be under the REAL root. Computed by taking
    the parent's path RELATIVE to root (lexically, so a symlinked `root` itself
    is fine — the repo may sit under /tmp on macOS) and requiring
    realpath(parent) == realpath(root)/<that-relative-path>. Any symlink below
    root — escaping OR in-repo-aliasing — makes the two diverge. The leaf is
    still handled by its own O_NOFOLLOW; this isolates the ancestor gap. Returns
    False (fail closed) on any resolution error or a parent above root."""
    try:
        root_real = os.path.realpath(str(root))
        parent = Path(target).parent
        rel = os.path.relpath(str(parent), str(root))
        if rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
            return False  # parent is above / outside root lexically
        expected = os.path.normpath(os.path.join(root_real, rel))
        actual = os.path.realpath(str(parent))
    except (OSError, ValueError):
        return False
    return actual == expected


def refuse_linked_leaf(path) -> str | None:
    """Return a reason string if `path` exists and is an UNSAFE LEAF — a
    symlink OR a hard link (`st_nlink > 1`) — that a read/write must not go
    through to a shared or outside inode; else None (absent, or a private
    regular file). Path-based via `lstat` (never follows), so it is the
    single guard every path-based leaf reader/writer routes through.

    v3.8.41 (round-24): round-23 refused a symlinked leaf with `is_symlink()`
    /`O_NOFOLLOW`, but a HARD LINK is a regular file — it passes `is_symlink()`
    AND the fd-based `O_NOFOLLOW`+`S_ISREG` checks — so `docs/HISTORY.md`,
    `.substrate/required_*`, or `.substrate/memory/events.jsonl` hard-linked to
    an outside inode still read/wrote the shared bytes. `st_nlink > 1` is the
    forgotten half of the class (postmortem carry-forward part 2). fd-based
    readers (`read_lock`, the `command_policy` inline reader) apply the same
    `st_nlink > 1` rule on their TOCTOU-free `fstat` result inline; this helper
    is for the path-based callers that read/replace by name.

    v3.8.42 (round-25): also refuse a NON-REGULAR leaf. v3.8.41 checked only
    "is it linked?" and treated a FIFO/socket/device as safe — so a FIFO in
    place of an append log or a lock did not fail closed, it HUNG the caller on
    open() (a denial of service against the gate, and the third instance of the
    same partial-class-fix pattern). S_ISREG is checked before st_nlink so a
    directory reports its real type rather than a confusing hard-link message."""
    try:
        st = os.lstat(str(path))
    except (OSError, ValueError):
        return None  # absent or unstat-able: nothing to refuse here
    if _stat.S_ISLNK(st.st_mode):
        return "is a symlink"
    if not _stat.S_ISREG(st.st_mode):
        return "is not a regular file (fifo/socket/device/directory)"
    if st.st_nlink > 1:
        return "is a hard link (shared inode)"
    return None


def _read_fd_bytes(fd: int, limit: int | None = None) -> bytes:
    """Read up to `limit` bytes (to EOF when None) from an already-open fd.
    os.read may return short reads, so loop until EOF or the cap."""
    chunks: list[bytes] = []
    got = 0
    while True:
        want = 65536 if limit is None else min(65536, limit - got)
        if want <= 0:
            break
        b = os.read(fd, want)
        if not b:
            break
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def safe_read_bytes(path, root=None, max_bytes: int | None = SAFE_READ_MAX_BYTES,
                    tail_bytes: int | None = None) -> bytes | None:
    """The guarded read, returning RAW BYTES; `safe_read_text` decodes on top.

    v3.8.44: hashing callers (`substrate_profile._sha256`,
    `substrate_upgrade._sha256`, `write_install_json`) need bytes, and each had
    re-derived its own `p.read_bytes()` — the third independent re-derivation of
    a primitive, which is how this class kept coming back. One implementation,
    two return types.

    See `safe_read_text` for the guarantees; they are made here.
    """
    _dir_fd = None
    try:
        if root is not None:
            _dir_fd = open_dir_chain(root, Path(path).parent, create=False)
            fd = os.open(Path(path).name,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                         dir_fd=_dir_fd)
        else:
            fd = os.open(str(path),
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        if _dir_fd is not None:
            os.close(_dir_fd)
        return None  # absent, symlinked (ELOOP), escaping, or unreadable
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            return None
        if tail_bytes is not None:
            if st.st_size > tail_bytes:
                os.lseek(fd, st.st_size - tail_bytes, os.SEEK_SET)
            raw = _read_fd_bytes(fd, tail_bytes)
        elif max_bytes is None:
            raw = _read_fd_bytes(fd, None)
        else:
            raw = _read_fd_bytes(fd, max_bytes + 1)
            if len(raw) > max_bytes:
                return None
        # v3.8.45 (round-28 P1): the pinned parent may have been RENAMED after
        # open_dir_chain returned, in which case these bytes came from a
        # detached directory and the live target now holds something else.
        # Reproduced: this returned INSIDE-OLD while the live path held
        # LIVE-NEW. Stale bytes presented as current are the read-side twin of
        # a write that reports success without landing.
        if _dir_fd is not None and not dir_fd_still_live(root, Path(path).parent, _dir_fd):
            return None
        return raw
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)
        if _dir_fd is not None:
            os.close(_dir_fd)


def safe_read_text(path, root=None, max_bytes: int | None = SAFE_READ_MAX_BYTES,
                   tail_bytes: int | None = None) -> str | None:
    """Containment- and leaf-type-checked text read. Returns the decoded text,
    or None when the file is absent OR unsafe to read.

    v3.8.42 (round-25): rounds 21-24 hardened every WRITER of an agent-writable
    file and never swept the READERS, so `memory_log._read_events`, the
    session-handoff HISTORY/REJECTED tails, `completion_gate`'s event scan, and
    `append_history`'s session-token read all used a bare `open()`. Each one
    would follow a symlinked or hard-linked leaf to OUTSIDE bytes (the handoff
    pair puts those bytes into MODEL CONTEXT; a forged completion-gate event
    suppresses the Stop nudge) and each would HANG on a FIFO. This is the one
    read-side counterpart to `refuse_linked_leaf`, and every reader routes
    through it.

    Guarantees, in order: STRICT ancestor containment when `root` is given;
    `O_NOFOLLOW` (a symlinked leaf is never followed) + `O_NONBLOCK` (a FIFO
    fails fast instead of hanging); `S_ISREG` and `st_nlink == 1` on the
    TOCTOU-free fstat; and a bounded read.

    Size handling is per-caller because truncation is not always safe:
      tail_bytes=N  — read at most the LAST N bytes (append-only logs whose
                      consumers only want the tail).
      max_bytes=N   — whole-file read; LONGER THAN N returns None (a small
                      bounded file that is oversized is malformed, not valid).
      max_bytes=None— unbounded whole-file read. Required where silently
                      returning "no content" would FAIL OPEN (the memory chain:
                      an empty read would verify as a clean empty chain).

    Decoding is `errors="replace"`: undecodable bytes must degrade to
    non-matching text, never to a traceback out of a hook (round-25 finding 3).
    """
    # v3.8.44 (round-27 P1): the read side had the same post-guard window as the
    # write side — within_root() then a MULTI-COMPONENT os.open(str(path)), so a
    # swapped intermediate ancestor returned OUTSIDE bytes while the leaf fstat
    # checks all passed. Descend to the parent one component at a time, then open
    # the leaf by BASENAME relative to that pinned fd. When no root is supplied
    # the caller has opted out of containment and only the leaf guards apply.
    # (That descent now lives in safe_read_bytes; this is the decoding wrapper.)
    raw = safe_read_bytes(path, root, max_bytes=max_bytes, tail_bytes=tail_bytes)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def read_lock(path: Path, allowed: set, root=None) -> tuple:
    """Canonical fail-closed read of a frozen `.substrate/required_*` lock
    (v3.8.36 — the complete class fix after v3.8.33's partial sweep).

    Returns (state, value, reason):
      ("absent", None, None)  — nothing exists at the path (no lock was pinned);
      ("ok", value, None)     — regular file, valid UTF-8, value in `allowed`;
      ("bad", None, reason)   — PRESENT but wrong: symlink, directory/special
                                file, unreadable, undecodable, or out-of-domain
                                value. Callers MUST fail closed on "bad".

    Properties every reader must share (Codex round-19 + round-20 findings):
    - O_NOFOLLOW | O_NONBLOCK open + fstat S_ISREG: a SYMLINKED lock is "bad",
      never read through; a DIRECTORY lock is "bad", never "absent"; and a
      FIFO/special lock is "bad" WITHOUT HANGING (O_NONBLOCK — a plain
      O_NOFOLLOW open of a FIFO blocks until a writer appears, round-20 P2).
    - WHOLE-CONTENT read, bounded to LOCK_MAX_BYTES: a lock longer than a
      handful of bytes is "bad". The old 4096-byte read let `b"0" + 4095
      spaces + b"1"` strip down to "0" (a valid lowering value) while the
      trailing "1" fell off the end (round-20 P1). Reading past the tiny cap
      and rejecting on overflow closes that, and the strip+membership check
      rejects any internal non-whitespace (`"0   1"` is not in {"0","1"}).
    - bytes + explicit UTF-8 decode: undecodable content is "bad".
    - ANCESTOR containment (v3.8.39): a symlinked parent directory
      (`.substrate -> /outside`) routes the lock outside the repo before
      O_NOFOLLOW sees the leaf. realpath(parent) must stay within the repo.
    """
    if root is None:
        root = repo_root()
    # v3.8.44 (round-27 P1): same component-walk descent as the other readers —
    # a lock is the highest-value target in the tree, so it must not be the one
    # place still resolving a multi-component path after its containment check.
    _lock_dir_fd = None
    try:
        _lock_dir_fd = open_dir_chain(root, Path(path).parent, create=False)
    except FileNotFoundError:
        # A component that simply DOES NOT EXIST means there is no lock — the
        # same answer the leaf open used to give. Collapsing this into "bad"
        # made an unconfigured repo look tampered with, and a tier whose lock
        # is absent then reads as REQUIRED (two security-scanner tests caught
        # it). Only FileNotFoundError: an existing-but-unsafe ancestor raises
        # ELOOP/ENOTDIR (O_DIRECTORY|O_NOFOLLOW on a symlink reports ENOTDIR on
        # Linux, not ELOOP — errno alone cannot separate the two cases), and an
        # escaping path raises a plain OSError. Both stay "bad".
        return ("absent", None, None)
    except OSError:
        return ("bad", None, "lock parent escapes the repo, or an ancestor is a "
                             "symlink/non-directory — refusing to resolve it")
    try:
        fd = os.open(Path(path).name,
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=_lock_dir_fd)
    except OSError as e:
        os.close(_lock_dir_fd)
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return ("absent", None, None)
        if e.errno == errno.ELOOP:
            return ("bad", None, "lock is a symlink — refusing to follow it")
        # ENXIO: a write-only FIFO with no reader; still not a real lock.
        return ("bad", None, f"unreadable ({e.__class__.__name__})")
    # Both fds are now owned by the single finally below. v3.8.45 in-release
    # (security-auditor BLOCK): the first cut put the liveness check between the
    # leaf open and the try/finally that closes it, so EVERY time the new
    # detection fired the lock fd leaked — 20 refusals leaked 20 fds. A guard
    # that turns a race into a resource-exhaustion vector is not a guard.
    try:
        # v3.8.45 (round-28 P1): a lock read out of a parent renamed after the
        # descent captured it is a STALE value presented as current — and a lock
        # is the highest-value thing in the tree to read stale. Round 28 reported
        # this on the generic readers; a lock must not be the one place left
        # trusting a detached parent.
        if not dir_fd_still_live(root, Path(path).parent, _lock_dir_fd):
            return ("bad", None, "lock parent was renamed during the read — "
                                 "refusing a value from a detached directory")
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            return ("bad", None, "lock is not a regular file (directory/fifo/special)")
        # v3.8.41 (round-24 P1): a HARD LINK is a regular file — O_NOFOLLOW and
        # S_ISREG both pass it — so a lock hard-linked to an outside inode reads
        # attacker-controlled bytes. fstat on the already-open fd is TOCTOU-free.
        if st.st_nlink > 1:
            return ("bad", None, "lock is a hard link (shared inode) — refusing a shared-inode value")
        try:
            raw = os.read(fd, LOCK_MAX_BYTES + 1)
        except (OSError, BlockingIOError) as e:
            return ("bad", None, f"unreadable ({e.__class__.__name__})")
    finally:
        os.close(fd)
        os.close(_lock_dir_fd)
    if len(raw) > LOCK_MAX_BYTES:
        return ("bad", None, f"lock exceeds {LOCK_MAX_BYTES} bytes — refusing to parse a padded value")
    try:
        val = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return ("bad", None, "lock is not valid UTF-8")
    if val not in allowed:
        return ("bad", None, f"invalid value {val[:40]!r} (allowed: {sorted(allowed)})")
    return ("ok", val, None)


# Canonical secret-shaped-text patterns. v3.8.43 (round-26 P2): todo content is
# model-authored and is persisted verbatim to a tracked file, so it needs the
# same redaction memory_log and session_handoff already apply. Those two each
# carry their own copy (identical patterns, different traversal); rather than
# add a THIRD copy for the new caller, the list gets a canonical home here and a
# parity test pins all copies byte-identical so they cannot drift apart.
SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9._\-/+]{8,}['\"]?"
    ),
]


def redact_secrets(obj):
    """Recursively replace secret-shaped substrings in str/list/dict content."""
    if isinstance(obj, str):
        out = obj
        for rx in SECRET_PATTERNS:
            out = rx.sub("[REDACTED-SECRET]", out)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_secrets(v) for k, v in obj.items()}
    return obj


class GuardRefusal(OSError):
    """A guarded operation REFUSED — containment, or an unsafe leaf/ancestor.

    v3.8.46 (in-release, security-auditor WARN): callers were left string-
    matching or treating every OSError alike, so a read-only checkout and a
    symlink pointing out of the repo produced the same reaction. They are not
    the same event: one is an environment, the other is tampering. Subclassing
    OSError keeps every existing `except OSError` contract intact.
    """


def open_dir_chain(root, parent, create: bool = False) -> int:
    """Open `parent` as a directory fd WITHOUT ever resolving a multi-component
    path. Caller owns the returned fd and must close it.

    v3.8.44 (round-27 P1) — the deepest instance of this series' defect, and it
    was in the primitive every other fix now depends on. `safe_atomic_write` was
    described as "fd-anchored", but it anchored to the parent while still doing
    `os.open(str(parent))` — a MULTI-COMPONENT path. `O_NOFOLLOW` constrains only
    the FINAL component, so swapping any INTERMEDIATE ancestor between the
    containment check and that open rerouted the whole descent, and the dev/ino
    re-validation that was supposed to catch it compared the already-rerouted
    directory against itself and approved it. Reproduced: a write landed outside
    the repo with the in-repo parent untouched.

    A dev/ino comparison cannot close that window, because by the time it runs
    the kernel has already followed the swapped ancestor. The only fix is to
    never hand the kernel a path it can re-resolve: open the ROOT once, then
    descend ONE component at a time with `O_NOFOLLOW | O_DIRECTORY` and
    `dir_fd=`. Each step is a single-component lookup relative to a fd that is
    already pinned to an inode, so there is no multi-component resolution left
    to race. This subsumes `within_root` for callers that use it — containment
    stops being a check performed before the work and becomes a property of how
    the work is done.

    `root` itself IS resolved by path: it may legitimately be reached through a
    symlink (a repo under /tmp on macOS), and it is the trust anchor the caller
    supplied rather than something an attacker introduces mid-call.

    `create=True` makes missing components with `os.mkdir(..., dir_fd=)`, which
    is likewise single-component and cannot create a directory through a
    swapped ancestor.
    """
    root = Path(root)
    rel = os.path.relpath(str(Path(parent)), str(root))
    if rel == os.curdir:
        parts: list[str] = []
    elif rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
        raise GuardRefusal(f"path escapes the root: {parent}")
    else:
        parts = [c for c in rel.split(os.sep) if c and c != os.curdir]
    if any(c == os.pardir for c in parts):
        raise GuardRefusal(f"parent traversal is not allowed in a guarded path: {parent}")
    fd = os.open(str(root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for comp in parts:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                nfd = os.open(comp, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(comp, 0o755, dir_fd=fd)
                nfd = os.open(comp, flags, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def safe_mkdir(path, root=None, mode: int = 0o755) -> None:
    """Create `path` (and missing parents) WITHOUT ever resolving a
    multi-component path — the mkdir counterpart to `safe_atomic_write`.

    v3.8.46 (round-29 P2 x3) — the class this round is really about. Three call
    sites created a directory with a raw `mkdir(parents=True)` and THEN wrote
    into it with a guarded writer. The guard did its job and refused; the
    directory had already been created, outside the repo, through a symlinked
    ancestor. The allowlist reasons I wrote for those three exemptions said
    "creates X immediately before a safe_atomic_write into it" — which states
    the wrong order in my own words, three times. A guard that runs after the
    mutation is a report, not a control.

    `open_dir_chain(create=True)` already descends one component at a time from
    the root with `O_NOFOLLOW|O_DIRECTORY`, so every component is created inside
    the tree or not at all; this just exposes it as a mkdir and owns the fd.
    Raises OSError on refusal — callers map that to their existing contract.
    """
    if root is None:
        root = repo_root()
    try:
        fd = open_dir_chain(root, Path(path), create=True)
    except OSError as e:
        raise GuardRefusal(f"refusing to create a directory outside the repo or "
                           f"through an unsafe ancestor: {path} ({e})") from e
    try:
        if mode != 0o755:
            os.fchmod(fd, mode & INHERIT_MODE_MASK)
    finally:
        os.close(fd)


def dir_fd_still_live(root, parent, dir_fd: int) -> bool:
    """True when `dir_fd` is STILL the directory that `parent` names right now.

    v3.8.45 (round-28 P1 x2) — the honest limit of `open_dir_chain`, and the
    reason it needs a companion. Anchoring to a parent fd stops the kernel from
    following a hostile NEW path, which is exactly what round 27 needed. It says
    nothing about whether that inode is still REACHABLE at the path the caller
    asked for. A concurrent `rename(repo/state, repo/stash)` after the fd is
    captured leaves every subsequent `dir_fd=` operation working correctly on a
    DETACHED directory: the read returns the moved directory's bytes while the
    live target holds something else, and the write lands in the moved directory
    and RETURNS SUCCESS while the live target is absent. Reproduced both ways.
    Move the pinned parent outside the repo instead of alongside it and the same
    mechanism puts the bytes outside — the fd cannot prevent that, because by
    then the rename has already happened.

    So this is detection, not prevention, and it is deliberately placed AFTER
    the operation: re-descend from the root and compare identities. Callers turn
    a False into a refusal. That converts the one shape this series exists to
    remove — a silent false success — into a loud failure. It cannot un-write
    bytes already placed in the detached directory; it can stop the caller
    believing they landed where they were asked to.
    """
    try:
        probe = open_dir_chain(root, parent, create=False)
    except OSError:
        return False
    try:
        a, b = os.fstat(dir_fd), os.fstat(probe)
    except OSError:
        return False
    finally:
        os.close(probe)
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def safe_atomic_write(target, text, root=None, tmp_prefix: str = ".saw-",
                      make_parents: bool = False, mode: int | None = None) -> None:
    """Atomically write `text` to `target`, anchored to the parent DIRECTORY FD.

    v3.8.43 (round-26 P1 x3): the write-side counterpart to `safe_read_text`, and
    the single fix for a defect that appeared in THREE separate writers because
    each re-derived it — `session_handoff._atomic_write_text`, `todo_state_hook`,
    and the evals BENCHMARK/trace writers. Every one of them validated
    containment and then performed PATH-BASED `mkdir`/`mkstemp`/`os.replace`, so
    a parent swapped after the guard still redirected the write outside the repo.
    A guard proves something about the path only at the instant it runs; the work
    must be anchored to a HANDLE captured at that instant, not re-resolved by
    name afterwards.

    Order: containment check -> optional parent mkdir -> open the parent
    `O_DIRECTORY|O_NOFOLLOW` -> re-validate that the path still names the opened
    inode -> create the temp file with `O_CREAT|O_EXCL` under `dir_fd` -> write ->
    `os.replace` with `src_dir_fd`/`dst_dir_fd` and basenames. `os.replace`
    swaps the directory entry, so it breaks a hard link and never writes through
    a symlinked leaf; the temp file is a fresh inode and is unlinked under the
    same fd on any failure. Raises OSError on refusal — callers map that to their
    existing nonzero contract.
    """
    target = Path(target)
    if root is None:
        root = repo_root()
    parent = target.parent
    name = target.name
    # v3.8.44 (round-27 P1): descend to the parent one component at a time from
    # the root instead of resolving `parent` as a path and then re-validating.
    # The old order (check containment -> open the multi-component path -> compare
    # dev/ino) could not work: the comparison ran AFTER the kernel had already
    # followed a swapped intermediate ancestor, so it compared the rerouted
    # directory to itself. `make_parents` creates missing components through the
    # same single-component descent, so a refused path still creates nothing
    # outside (the round-23 lesson, now structural rather than ordered).
    try:
        dir_fd = open_dir_chain(root, parent, create=make_parents)
    except OSError as e:
        raise GuardRefusal(f"write target parent escapes the repo or is unusable: {target} ({e})") from e
    try:
        tmp_name = None
        tfd = None
        for _ in range(16):
            cand = f"{tmp_prefix}{os.getpid()}-{os.urandom(6).hex()}.tmp"
            try:
                tfd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
                tmp_name = cand
                break
            except FileExistsError:
                continue
        if tfd is None:
            raise OSError(f"could not create a temporary file for the write in {parent}")
        try:
            # `text` may be str or bytes: a binary copy (installing a staged
            # script) needs the same anchoring, and a second bytes-only writer
            # would be one more thing to re-derive and get wrong.
            _binary = isinstance(text, (bytes, bytearray))
            _mode = "wb" if _binary else "w"
            _kw = {} if _binary else {"encoding": "utf-8"}
            # v3.8.44 (round-27 P3): carry the EXISTING target mode onto the
            # replacement. The temp file is created 0600 so it is never briefly
            # world-readable, but replacing without restoring the mode silently
            # destroyed permissions on every guarded rewrite — scripts/tool.sh
            # went 0755 -> 0600 (executable bit gone) and docs/HISTORY.md
            # 0644 -> 0600. A safety fix must not break the file it protects.
            # An explicit `mode` wins; otherwise inherit the existing target's
            # mode. Setting it on the TEMP FD before the replace means the final
            # file never exists with the wrong permissions, and callers no longer
            # need a follow-up path-based chmod — which was itself a link-followable
            # operation on a governed path (round-27 P2).
            # Inherit only from a REGULAR existing target: lstat on a symlinked
            # leaf reports 0777, which would widen the replacement's mode from
            # the safe default. `os.replace` breaks the link either way, so a
            # non-regular predecessor simply gets the 0600 default.
            _want_mode = mode
            if _want_mode is None:
                try:
                    _st_prev = os.lstat(name, dir_fd=dir_fd)
                    if _stat.S_ISREG(_st_prev.st_mode):
                        _want_mode = _stat.S_IMODE(_st_prev.st_mode) & INHERIT_MODE_MASK
                except (OSError, ValueError):
                    _want_mode = None
            if _want_mode is not None:
                os.fchmod(tfd, _want_mode)
            with os.fdopen(tfd, _mode, **_kw) as fh:
                tfd = None  # the file object owns the fd now
                fh.write(text)
            os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            tmp_name = None
            # v3.8.45 (round-28 P1): the fd keeps the write inside the directory
            # we validated, but a concurrent rename of that directory AFTER
            # capture means the bytes landed in a DETACHED copy while the live
            # target is untouched — and this used to return success. Reproduced:
            # repo/state renamed to repo/stash mid-write; out.txt absent at the
            # live path, content in the detached one. Raise instead: every
            # caller maps OSError to its existing nonzero contract, and a write
            # reported as done but absent from the requested path is exactly the
            # silent false success this series exists to remove.
            if not dir_fd_still_live(root, parent, dir_fd):
                raise GuardRefusal(
                    f"write parent was renamed during the write — the bytes landed in a "
                    f"detached directory and {target} was NOT updated")
        finally:
            if tfd is not None:
                os.close(tfd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    finally:
        os.close(dir_fd)


def locked_atomic_append(target: Path, entry: str, header: str, tmp_prefix: str,
                         root=None) -> None:
    """Append `entry` to `target`, SERIALIZED against concurrent appenders.

    mkstemp + os.replace alone is atomic for READERS and never writes through a
    hard-linked or symlinked leaf (the v3.8.25 lesson), but it does NOT
    serialize WRITERS: two concurrent appenders both read the same base text
    and the second replace silently discards the first entry (Codex finding,
    AGENT_BUS 2026-07-30 — reproduced with two `./manage.sh reject` calls).
    Both append-only logs (HISTORY.md, REJECTED.md) shared that defect because
    one appender was mirrored from the other; this helper is the single fix
    for the class.

    Serialization is an exclusive flock on the parent DIRECTORY fd:
    - no sidecar lockfile (nothing new to gitignore, nothing an aliased path
      could create somewhere unexpected);
    - no stale-lock recovery needed — the kernel drops the lock when the fd
      closes, including on crash;
    - locking the TARGET inode would not work: os.replace swaps the directory
      entry, so a second writer could lock the old inode after the swap and
      race anyway.
    The replace step is kept inside the lock so the no-write-through-links
    property is unchanged. O_APPEND on the target was rejected instead: it
    writes through a hard-linked leaf (see docs/REJECTED.md).

    The wait is BOUNDED (security-audit finding on the first cut): a blocking
    LOCK_EX would let one stuck or hostile holder hang every future append
    forever, where the house rule is fail closed FAST. A healthy append holds
    the lock for milliseconds, so a deadline measured in seconds only ever
    trips on a genuinely wedged holder; the TimeoutError is an OSError, so
    both CLIs surface it through their existing rc-2 path. Operational caveat:
    flock is advisory and a no-op on some network filesystems — the logs are
    repo files, expected on a local checkout.

    v3.8.39 (round-22): a symlinked PARENT directory (`docs -> /outside`) would
    route the append outside the repo before the lock/replace ran. within_root
    (now strict — no aliasing ancestor) is checked BEFORE mkdir so a refused
    target creates no outside directory.

    v3.8.40 (round-23): the LEAF itself must not be a symlink either. os.replace
    breaks the link on WRITE, but the read of existing content
    (`target.read_text()`) FOLLOWS a symlinked leaf and would import an outside
    file's bytes into the new in-repo log. An append-only log leaf is never a
    symlink; refuse one.
    """
    if root is None:
        root = repo_root()
    if not within_root(target, root):
        raise OSError(f"append target parent escapes the repo (symlinked ancestor): {target}")
    # v3.8.41 (round-24 P1): symlink OR hard link. os.replace breaks the link on
    # WRITE, but the read of existing content below FOLLOWS a symlinked leaf and
    # a hard-linked leaf shares the outside inode's bytes — either imports an
    # outside file's content into the new in-repo log. An append-only log leaf is
    # never a link; refuse both (round-23 caught only the symlink half).
    _leaf_reason = refuse_linked_leaf(target)
    if _leaf_reason is not None:
        raise OSError(f"append target {_leaf_reason} — refusing to read/replace through it: {target}")
    parent = target.parent
    name = target.name
    # v3.8.42 (round-25 P1): O_DIRECTORY|O_NOFOLLOW — the parent must be a real
    # directory, not a symlink swapped in after within_root ran.
    # v3.8.44 (round-27 P1, the same window safe_atomic_write had): O_NOFOLLOW
    # protects only the FINAL component, so resolving `str(parent)` as a
    # multi-component path left every INTERMEDIATE ancestor swappable after
    # within_root ran. Round-27 reported this on safe_atomic_write only; it is
    # one defect in two writers, so both descend component-by-component from the
    # root. `create=True` replaces the path-based parents mkdir above, which had
    # the same flaw and ran BEFORE the fd existed.
    try:
        dir_fd = open_dir_chain(root, parent, create=True)
    except OSError as e:
        raise GuardRefusal(f"append target parent escapes the repo or has an unsafe "
                           f"ancestor: {target} ({e})") from e
    try:
        try:
            timeout_s = float(os.environ.get("SUBSTRATE_APPEND_LOCK_TIMEOUT") or 10.0)
        except ValueError:
            timeout_s = 10.0  # garbage override must not escape the rc-2 contract
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(dir_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                # EINTR is retryable (signal delivery), not a real failure.
                if e.errno not in (errno.EAGAIN, errno.EACCES, errno.EINTR):
                    raise  # real failure (EBADF, ...), not contention
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"append lock on {parent} not acquired within "
                        f"{timeout_s:g}s — another appender is wedged") from e
                time.sleep(0.02)
        # v3.8.42 (round-25 P1): every check above RACED the lock. A concurrent
        # rename can swap `parent` while we block in the loop, and the old code
        # then re-resolved the target BY PATH for read_text/mkstemp/os.replace —
        # so an appender that waited on the lock wrote wherever the path pointed
        # when it woke, which a hostile swap makes an outside directory. Two-part
        # fix: RE-VALIDATE under the lock that the path still names the inode we
        # locked, then anchor EVERY remaining operation to that dir fd (dir_fd=
        # plus basenames) so the bytes land in the locked inode or nowhere.
        try:
            path_st = os.lstat(str(parent))
        except OSError as e:
            raise OSError(f"append parent vanished while locking: {parent}") from e
        fd_st = os.fstat(dir_fd)
        if (path_st.st_dev, path_st.st_ino) != (fd_st.st_dev, fd_st.st_ino):
            raise OSError(
                f"append parent was swapped while waiting for the lock — refusing: {parent}")
        if not within_root(target, root):
            raise OSError(f"append target parent escapes the repo (re-checked post-lock): {target}")
        existing = header
        keep_mode = None
        try:
            leaf_st = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            leaf_st = None
        if leaf_st is not None:
            if (_stat.S_ISLNK(leaf_st.st_mode) or not _stat.S_ISREG(leaf_st.st_mode)
                    or leaf_st.st_nlink > 1):
                raise OSError(f"append target is an unsafe leaf — refusing: {target}")
            # v3.8.44 (round-27 P3): the replacement inherited the temp file's
            # 0600 instead of the log's own mode, so appending to docs/HISTORY.md
            # silently took it from 0644 to 0600 on every entry.
            keep_mode = _stat.S_IMODE(leaf_st.st_mode) & INHERIT_MODE_MASK
            rfd = os.open(name,
                          os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                          dir_fd=dir_fd)
            try:
                # v3.8.43 (round-26 P1): the lstat above and this open are TWO
                # lookups of the same name, and the window between them is
                # attacker-usable. O_NOFOLLOW rejects a SYMLINK swapped in, but a
                # HARD LINK created in that window passes both O_NOFOLLOW and
                # S_ISREG — so the guarded stat proved nothing about the fd we
                # actually read. Re-verify the OPENED fd and require it to be the
                # very inode we approved: same dev/ino as the lstat, still a
                # single-link regular file. Statting a path and then opening it is
                # check-then-use no matter how well the stat is guarded.
                open_st = os.fstat(rfd)
                if (not _stat.S_ISREG(open_st.st_mode) or open_st.st_nlink > 1
                        or (open_st.st_dev, open_st.st_ino)
                        != (leaf_st.st_dev, leaf_st.st_ino)):
                    raise OSError(
                        f"append target was swapped between the guard and the open "
                        f"— refusing: {target}")
                # STRICT decode: an append-only log holding undecodable bytes must
                # surface through each CLI's existing nonzero contract, never be
                # silently rewritten with replacement characters.
                existing = _read_fd_bytes(rfd, None).decode("utf-8")
            finally:
                os.close(rfd)
        tmp_name = None
        tfd = None
        for _ in range(16):
            cand = f"{tmp_prefix}{os.getpid()}-{os.urandom(6).hex()}.tmp"
            try:
                tfd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
                tmp_name = cand
                break
            except FileExistsError:
                continue
        if tfd is None:
            raise OSError(f"could not create a temporary file for the append in {parent}")
        try:
            if keep_mode is not None:
                os.fchmod(tfd, keep_mode)
            with os.fdopen(tfd, "w", encoding="utf-8") as fh:
                tfd = None  # the file object owns the fd now
                fh.write(existing + entry)
            os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            tmp_name = None
            # v3.8.45 (round-28 P1): same detached-parent false success as
            # safe_atomic_write. An append that lands in a moved docs/ while the
            # live HISTORY.md is absent must not report success — the log's whole
            # value is that an entry recorded as written is there to be read.
            if not dir_fd_still_live(root, parent, dir_fd):
                raise OSError(
                    f"append parent was renamed during the append — the entry landed in a "
                    f"detached directory and {target} was NOT updated")
        finally:
            if tfd is not None:
                os.close(tfd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    finally:
        os.close(dir_fd)  # releases the flock


def utc_now_iso() -> str:
    """ISO-8601 UTC, second precision, with `Z` suffix."""
    return (
        datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
