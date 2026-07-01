#!/usr/bin/env python3
"""Shared multi-backend release verifier (v3.7.19).

ONE verification policy used by every trust boundary — scripts/verify_release.py,
scripts/substrate_upgrade.py, and (vendored) the substrate-init installer — so a consumer
verifies the SAME way no matter which entry point it comes through. Backends:

  <artifact>.minisig   → minisign / Ed25519, verified in pure Python (_minisign)
  <artifact>.sigstore  → Sigstore/cosign keyless bundle, verified by `cosign verify-blob`
                         against a trusted identity (identity_regexp + issuer)

FAIL-CLOSED: bad signature / absent trust anchor / required verifier (cosign) missing → rc 2.
An artifact with NO signature is unsigned → rc 3 (or rc 2 under require). Explicit `sig` is
dispatched by SUFFIX (.minisig vs .sigstore), never assumed to be minisign. The Sigstore
identity is searched: explicit → .substrate/trust/sigstore_identity.json → ./sigstore_identity.json
(so a flat release asset works too).

Stdlib + _minisign only (importable at hook/venv/installer time).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _minisign import VerifyError, commit_from_trusted_comment, verify_file  # noqa: E402


class Result:
    """rc: 0 verified | 2 present-but-invalid / required-verifier-missing | 3 unsigned."""
    def __init__(self, rc: int, backend: str, detail: str, commit: str | None = None):
        self.rc, self.backend, self.detail, self.commit = rc, backend, detail, commit


def _find_identity(root: Path, explicit) -> Path | None:
    cands = ([Path(explicit)] if explicit else []) + [
        root / ".substrate" / "trust" / "sigstore_identity.json",
        Path("sigstore_identity.json"),
    ]
    return next((c for c in cands if c.is_file()), None)


def _verify_minisign(artifact: Path, pub, sig: Path) -> Result:
    pub = Path(pub) if pub else None
    if not pub or not pub.is_file():
        return Result(2, "minisign", f"trusted public key not found: {pub} (fail-closed)")
    try:
        tc = verify_file(pub, artifact, sig)
    except VerifyError as e:
        return Result(2, "minisign", f"minisign signature invalid — {e}")
    return Result(0, "minisign", f"trusted comment: {tc}", commit_from_trusted_comment(tc))


def _verify_sigstore(artifact: Path, bundle: Path, root: Path, identity) -> Result:
    ident = _find_identity(root, identity)
    if ident is None:
        return Result(2, "sigstore", "no sigstore_identity.json trust anchor found (fail-closed)")
    if shutil.which("cosign") is None:
        return Result(2, "sigstore", "cosign not installed — cannot verify keyless signature (fail-closed)")
    try:
        cfg = json.loads(ident.read_text(encoding="utf-8"))
        regexp, issuer = cfg["identity_regexp"], cfg["issuer"]
    except Exception as e:
        return Result(2, "sigstore", f"malformed {ident} — {e}")
    r = subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle),
                        "--certificate-identity-regexp", regexp,
                        "--certificate-oidc-issuer", issuer, str(artifact)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return Result(2, "sigstore", f"Sigstore verification failed — {r.stderr.strip()}")
    return Result(0, "sigstore", f"identity {regexp} @ {issuer}")


def verify(artifact, *, minisign_pub=None, sig=None, sigstore_identity=None,
           root=None, require: bool = False) -> Result:
    artifact = Path(artifact)
    root = Path(root) if root else Path.cwd()
    if sig:  # explicit — dispatch by suffix, never assume minisign
        s = Path(sig)
        if s.suffix == ".minisig":
            return _verify_minisign(artifact, minisign_pub, s)
        if s.suffix == ".sigstore":
            return _verify_sigstore(artifact, s, root, sigstore_identity)
        return Result(2, "?", f"unsupported signature type: {s.suffix} (want .minisig or .sigstore)")
    ms = Path(str(artifact) + ".minisig")
    ss = Path(str(artifact) + ".sigstore")
    if ms.is_file():
        return _verify_minisign(artifact, minisign_pub, ms)
    if ss.is_file():
        return _verify_sigstore(artifact, ss, root, sigstore_identity)
    return Result(2 if require else 3, "none",
                  f"no signature found ({ms.name} / {ss.name}) — artifact is UNSIGNED")
