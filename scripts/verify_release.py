#!/usr/bin/env python3
"""Verify a release artifact against the repo's trust root — MULTI-BACKEND (v3.7.18).

The verifier recognises HOW an artifact was signed and checks it accordingly, so a consumer
verifies ANY release tier out of the box and the signing backend can scale (local minisign →
CI minisign → keyless Sigstore) without a downstream change:

  <artifact>.minisig    → minisign (Ed25519), verified in pure Python (scripts/_minisign.py)
  <artifact>.sigstore   → Sigstore/cosign keyless bundle, verified by shelling to `cosign
                          verify-blob` against the trusted identity in
                          .substrate/trust/sigstore_identity.json {identity_regexp, issuer}

FAIL-CLOSED: a bad signature, an absent trust anchor, or a required backend whose verifier
(cosign) is not installed → non-zero exit. SKIP-HONEST: when NO signature file is present and
--require is not set, it reports unsigned (exit 3) rather than pretending it verified.

CLI: verify_release.py <artifact> [--pub P] [--sig S] [--require]
Exit: 0 verified | 2 signature present but INVALID / required-verifier missing | 3 unsigned.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _minisign import VerifyError, verify_file  # noqa: E402

DEFAULT_PUB = ".substrate/trust/minisign.pub"
SIGSTORE_IDENTITY = ".substrate/trust/sigstore_identity.json"


def _verify_minisign(artifact: Path, pub: Path, sig: Path | None) -> int:
    if not pub.is_file():
        print(f"verify_release: trusted public key not found: {pub} (fail-closed)", file=sys.stderr)
        return 2
    try:
        tc = verify_file(pub, artifact, sig)
    except VerifyError as e:
        print(f"verify_release: minisign FAILED — {e}", file=sys.stderr)
        return 2
    print(f"verify_release: OK (minisign) — {artifact}\n  trusted comment: {tc}")
    return 0


def _verify_sigstore(artifact: Path, bundle: Path, root: Path) -> int:
    ident = root / SIGSTORE_IDENTITY
    if not ident.is_file():
        print(f"verify_release: {bundle.name} present but no {SIGSTORE_IDENTITY} to verify against "
              "(fail-closed) — configure the trusted keyless identity.", file=sys.stderr)
        return 2
    if shutil.which("cosign") is None:
        print("verify_release: keyless (Sigstore) signature present but `cosign` is not installed "
              "— cannot verify (fail-closed). Install cosign or use a minisign release.", file=sys.stderr)
        return 2
    try:
        cfg = json.loads(ident.read_text(encoding="utf-8"))
        regexp, issuer = cfg["identity_regexp"], cfg["issuer"]
    except Exception as e:
        print(f"verify_release: malformed {SIGSTORE_IDENTITY} — {e} (fail-closed)", file=sys.stderr)
        return 2
    r = subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle),
                        "--certificate-identity-regexp", regexp,
                        "--certificate-oidc-issuer", issuer, str(artifact)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"verify_release: Sigstore FAILED — {r.stderr.strip()}", file=sys.stderr)
        return 2
    print(f"verify_release: OK (Sigstore keyless) — {artifact}\n  identity: {regexp} @ {issuer}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify a release artifact (multi-backend, fail-closed).")
    ap.add_argument("file", help="path to the signed artifact")
    ap.add_argument("--pub", default=DEFAULT_PUB, help=f"minisign trusted key (default: {DEFAULT_PUB})")
    ap.add_argument("--sig", help="explicit signature path (default: auto-detect <file>.minisig / .sigstore)")
    ap.add_argument("--require", action="store_true", help="an unsigned artifact is a failure (exit 2)")
    a = ap.parse_args(argv)
    artifact = Path(a.file)
    root = Path.cwd()
    # explicit --sig wins; else auto-detect the backend by which sidecar exists.
    minisig = Path(a.sig) if a.sig else Path(str(artifact) + ".minisig")
    sigstore = Path(str(artifact) + ".sigstore")
    if minisig.is_file():
        return _verify_minisign(artifact, Path(a.pub), minisig)
    if sigstore.is_file():
        return _verify_sigstore(artifact, sigstore, root)
    msg = f"verify_release: no signature found ({minisig.name} / {sigstore.name}) — artifact is UNSIGNED"
    if a.require:
        print(msg + " (fail-closed: --require)", file=sys.stderr)
        return 2
    print(msg, file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())
