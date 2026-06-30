#!/usr/bin/env python3
"""Verify a release artifact against the repo's trusted minisign public key.

Thin release-aware wrapper over scripts/_minisign.py. FAIL-CLOSED: exit 2 if the
signature is missing/invalid, the trusted key is absent, or verification cannot run.
A consumer can also verify with the reference tool: `minisign -Vm <file> -p <pub>`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _minisign import VerifyError, verify_file  # noqa: E402

DEFAULT_PUB = ".substrate/trust/minisign.pub"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify a release artifact's minisign signature (fail-closed).")
    ap.add_argument("file", help="path to the signed artifact (e.g. dist/<name>-<ver>.zip)")
    ap.add_argument("--pub", default=DEFAULT_PUB,
                    help=f"trusted public key (default: {DEFAULT_PUB})")
    ap.add_argument("--sig", help="signature path (default: <file>.minisig)")
    a = ap.parse_args(argv)
    if not Path(a.pub).is_file():
        print(f"verify_release: trusted public key not found: {a.pub} (fail-closed)",
              file=sys.stderr)
        return 2
    try:
        tc = verify_file(a.pub, a.file, a.sig)
    except VerifyError as e:
        print(f"verify_release: FAILED — {e}", file=sys.stderr)
        return 2
    print(f"verify_release: OK — {a.file}\n  trusted comment: {tc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
