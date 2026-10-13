#!/usr/bin/env python3
"""PostToolUse hook on Edit/Write/MultiEdit: lint the touched file now.

Evidence-backed replacement for "always run the linter" as an advisory
CLAUDE.md instruction: instructions degrade as context fills; a hook
fires identically on session 1 and session 200. Errors are returned on
exit code 2, which Claude Code feeds back to the agent as context so it
fixes the problem in its next action — at write time, not commit time.

Wired in .claude/settings.json:

  PostToolUse (matcher: Edit|Write|MultiEdit) -> lint_on_write.py

Linter resolution per extension, first available wins; a missing linter
is a silent pass (this hook must work in polyglot repos and never block
on environment gaps):

  .py                  ruff check  (uv run ruff if uv present, else ruff)
  .js .jsx .ts .tsx    npx eslint  (only if an eslint config exists)
  .go                  gofmt -l

Skips files outside the project root and gitignored paths are not
special-cased — if the agent writes it, it gets linted.

Exit codes: 0 clean/skip | 2 lint errors (stderr fed back to agent).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
TIMEOUT = 45


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT
        )
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 0, ""  # linter not installed -> silent pass
    except Exception as e:
        print(f"lint-on-write: {cmd[0]} failed to run: {e}", file=sys.stderr)
        return 0, ""


def _eslint_config_exists() -> bool:
    candidates = [
        "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
        ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json",
        ".eslintrc.yaml", ".eslintrc.yml",
    ]
    if any((ROOT / c).exists() for c in candidates):
        return True
    pkg = ROOT / "package.json"
    if pkg.is_file():
        try:
            return "eslintConfig" in json.loads(_safe_read_text(pkg, ROOT, max_bytes=8 << 20) or "{}")
        except Exception:
            return False
    return False


def lint(path: Path) -> tuple[int, str]:
    suffix = path.suffix.lower()
    rel = str(path)
    if suffix == ".py":
        # SUBSTRATE_LINT_DIRECT=1 forces direct ruff (no `uv run`, which
        # would create/sync a venv). Used by hermetic tests to stay fast
        # and offline; also honored when a substrate venv ruff exists.
        # --force-exclude honors [tool.ruff] extend-exclude for explicitly
        # passed paths (same rationale as run_python_gate.sh) — substrate-owned
        # dirs are governed by their own chain, not this hook.
        direct = os.environ.get("SUBSTRATE_LINT_DIRECT", "") in ("1", "true", "yes")
        subruff = ROOT / ".substrate" / "venv" / "bin" / "ruff"
        if not direct and shutil.which("uv") and (ROOT / "pyproject.toml").exists():
            return _run(["uv", "run", "ruff", "check", "--quiet", "--force-exclude", rel])
        if subruff.exists():
            return _run([str(subruff), "check", "--quiet", "--force-exclude", rel])
        if shutil.which("ruff"):
            return _run(["ruff", "check", "--quiet", "--force-exclude", rel])
        return 0, ""
    if suffix in (".js", ".jsx", ".ts", ".tsx"):
        if shutil.which("npx") and _eslint_config_exists():
            return _run(["npx", "--no-install", "eslint", rel])
        return 0, ""
    if suffix == ".go":
        if shutil.which("gofmt"):
            rc, out = _run(["gofmt", "-l", rel])
            if rc == 0 and out:
                return 1, f"gofmt: needs formatting: {out}"
            return rc, out if rc else ""
        return 0, ""
    return 0, ""


def main() -> int:
    try:
        raw = sys.stdin.read()
        hook = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0
    tool_input = hook.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return 0
    path = Path(str(file_path))
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return 0  # outside project root -> not ours to lint
    if not path.is_file():
        return 0
    rc, out = lint(path)
    if rc != 0 and out:
        print(
            f"lint-on-write: {path} has lint errors — fix before moving on:\n{out}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
