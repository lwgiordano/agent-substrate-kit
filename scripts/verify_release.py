#!/usr/bin/env python3
"""Verify a release artifact against the repo's trust root — thin CLI over the shared
multi-backend verifier (scripts/_verify_backends.py), so verify_release / substrate_upgrade /
substrate-init all apply the SAME policy. (v3.7.19)

Backends (auto-detected, or forced by an explicit --sig's suffix):
  <artifact>.minisig   → minisign (Ed25519), pure Python
  <artifact>.sigstore  → Sigstore/cosign keyless (needs cosign + a trusted identity)

FAIL-CLOSED. Exit: 0 verified | 2 signature present but INVALID / required verifier missing |
3 unsigned (or 2 under --require).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _verify_backends import verify  # noqa: E402

DEFAULT_PUB = ".substrate/trust/minisign.pub"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify a release artifact (multi-backend, fail-closed).")
    ap.add_argument("file", help="path to the signed artifact")
    ap.add_argument("--pub", default=DEFAULT_PUB, help=f"minisign trusted key (default: {DEFAULT_PUB})")
    ap.add_argument("--sig", help="explicit signature path (dispatched by .minisig/.sigstore suffix)")
    ap.add_argument("--sigstore-identity", help="path to sigstore_identity.json (else auto-searched)")
    ap.add_argument("--require", action="store_true", help="an unsigned artifact is a failure (exit 2)")
    a = ap.parse_args(argv)
    r = verify(a.file, minisign_pub=Path(a.pub), sig=a.sig,
               sigstore_identity=a.sigstore_identity, root=Path.cwd(), require=a.require)
    if r.rc == 0:
        print(f"verify_release: OK ({r.backend}) — {a.file}\n  {r.detail}")
    else:
        print(f"verify_release: {'UNSIGNED' if r.rc == 3 else 'FAILED'} — {r.detail}", file=sys.stderr)
    return r.rc


if __name__ == "__main__":
    sys.exit(main())
