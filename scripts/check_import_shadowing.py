#!/usr/bin/env python3
"""Block repo-local files that SHADOW a stdlib module for the validators.

The policy validators run as `python scripts/check_*.py`, which puts the
repo's `scripts/` directory on `sys.path`. A PR can drop `scripts/hashlib.py`
(or `re.py`, `json.py`, `ast.py`, …) to shadow the standard library for the
validators — e.g. a fake `hashlib.sha256` that returns the pinned hash for a
weakened pattern, defeating every hash-based integrity check (the v3.2.19
finding). The substrate also runs validators with `python -I` (the script
dir is not auto-prepended), but an import that happens AFTER a script's own
`sys.path.insert` could still be hijacked — so this gate removes the shadow
FILE entirely, the complete fix.

It flags any `scripts/**/*.py` whose stem is a stdlib module name
(`sys.stdlib_module_names` — the full set, not a partial denylist) and any
`scripts/<stdlibname>/__init__.py` package shadow. Run it FIRST, before any
other Python validator.

This validator hardens ITSELF against the same attack: it imports only `sys`
(a builtin, unshadowable) until it has scrubbed the script dir and cwd from
sys.path, so `scripts/pathlib.py` etc cannot hijack it either.

--root DIR scans DIR/scripts instead of ./scripts (trusted-base use).
Exit: 0 ok | 1 a stdlib-shadowing file exists. Stdlib only.
"""
import sys

# Drop the script dir (sys.path[0] when run directly) and '' (cwd) BEFORE
# importing any non-builtin stdlib module, so a repo-local shadow can't hijack
# this validator. `sys` is a builtin module and cannot be shadowed.
_BAD = {sys.path[0] if sys.path else "", ""}
sys.path = [p for p in sys.path if p not in _BAD]

import os  # noqa: E402  (resolves to stdlib now)
from pathlib import Path  # noqa: E402

_STDLIB = set(sys.stdlib_module_names)
# Kit modules legitimately living in scripts/ never collide with stdlib names;
# if a future kit module ever did, allowlist it here explicitly.
_ALLOW: set[str] = set()


def _target_scripts(argv):
    if "--root" in argv:
        return Path(argv[argv.index("--root") + 1]).resolve() / "scripts"
    return Path(os.getcwd()) / "scripts"


def main(argv) -> int:
    scripts = _target_scripts(argv)
    if not scripts.is_dir():
        print("check-import-shadowing: ok (no scripts/ dir)")
        return 0
    offenders = []
    for p in scripts.rglob("*.py"):
        if p.stem in _STDLIB and p.stem not in _ALLOW:
            offenders.append(f"{p.relative_to(scripts.parent).as_posix()} shadows stdlib '{p.stem}'")
    for p in scripts.rglob("__init__.py"):
        if p.parent.name in _STDLIB and p.parent.name not in _ALLOW:
            offenders.append(f"{p.parent.relative_to(scripts.parent).as_posix()}/ shadows stdlib package '{p.parent.name}'")
    if offenders:
        print("check-import-shadowing: BLOCK (stdlib shadowing can subvert the hash validators)", file=sys.stderr)
        for o in sorted(set(offenders)):
            print(f"  - {o}", file=sys.stderr)
        return 1
    print("check-import-shadowing: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
