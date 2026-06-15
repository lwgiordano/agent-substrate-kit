#!/usr/bin/env python3
"""Compile-check every governed Python script and test.

A syntactically broken security hook is worse than a missing one: the
generated Claude/Codex/Copilot hooks invoke scripts/check_exfil_guard.py
(and friends) as BLOCKING controls, where exit 2 is the deny path. A
`SyntaxError` makes the interpreter exit 1 — which is NOT the blocking
code — so a broken hook silently degrades a security control into a
generic failing command. The command-policy fail-closed path only fires
when .substrate/config actually carries a command value; with empty
commands a broken check_exfil_guard.py passes `check`/pre-commit
untouched.

This validator closes that gap: it py_compiles all of scripts/ and
tests/ so a broken governed script is caught at `check`/pre-commit/CI
time, before the hook can fail-open at runtime. Run it FIRST — other
validators import these files.

Exit codes: 0 ok | 1 a governed Python file failed to compile.
Stdlib only.
"""
from __future__ import annotations

import py_compile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

PY_GLOBS = ["scripts/**/*.py", "tests/**/*.py"]
# Generated runtime/toolchain state, never governance source.
SKIP_PARTS = {"__pycache__", ".substrate", "venv", ".venv",
              "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _iter_py_files():
    seen = set()
    for glob in PY_GLOBS:
        for p in ROOT.glob(glob):
            if not p.is_file():
                continue
            if any(part in SKIP_PARTS for part in p.parts):
                continue
            if p in seen:
                continue
            seen.add(p)
            yield p


def main() -> int:
    failures = []
    for p in sorted(_iter_py_files()):
        try:
            py_compile.compile(str(p), doraise=True)
        except py_compile.PyCompileError as e:
            msg = (e.msg or str(e)).splitlines()[-1]
            failures.append((p.relative_to(ROOT).as_posix(), msg))
        except Exception as e:  # OSError, encoding, etc. — treat as a failure
            failures.append((p.relative_to(ROOT).as_posix(), str(e)))
    if failures:
        print("check-python-syntax: BLOCK", file=sys.stderr)
        for rel, msg in failures:
            print(f"  - {rel}: {msg}", file=sys.stderr)
        return 1
    print("check-python-syntax: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
