#!/usr/bin/env python3
"""Pure-Python verifier for minisign (Ed25519) signatures.

The maintainer SIGNS releases with the reference `minisign` binary; a consumer
VERIFIES them here with no dependency on the minisign binary — only `cryptography`
(Ed25519). This keeps the trust check available wherever Python + cryptography are,
and lets a paranoid operator independently re-verify with the reference `minisign -V`.

FAIL-CLOSED: every parse/algorithm/key-id/signature mismatch raises VerifyError; a
missing `cryptography` dependency raises too (a verification that cannot run must
NEVER be reported as a pass).

minisign format (https://jedisct1.github.io/minisign/):
  public key  line2 b64 -> sig_alg(2) | key_id(8) | ed25519_pubkey(32)
  signature   line2 b64 -> sig_alg(2) | key_id(8) | ed25519_sig(64)
              line4 b64 -> global_ed25519_sig(64) over (ed25519_sig(64) || trusted_comment)
  sig_alg "ED" = signature over blake2b-512(content) (prehashed, the modern default)
  sig_alg "Ed" = signature over the raw content (legacy)
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path


class VerifyError(Exception):
    """Raised on any verification failure — always treated as fail-closed."""


def _load_ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:  # pragma: no cover - environment-dependent
        raise VerifyError(
            "cryptography is required to verify release signatures and is not "
            "available — refusing to proceed (fail-closed)."
        ) from e
    return Ed25519PublicKey, InvalidSignature


def _b64_payload_line(text: str) -> bytes:
    """Return the decoded bytes of the first non-comment line in a minisign block."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("untrusted comment:") or s.startswith("trusted comment:"):
            continue
        return base64.b64decode(s)
    raise VerifyError("no base64 payload line found")


def parse_pubkey(text: str) -> tuple[bytes, bytes]:
    """(key_id, ed25519_public_key_bytes) from a minisign .pub file's contents."""
    raw = _b64_payload_line(text)
    if len(raw) != 42 or raw[0:2] != b"Ed":
        raise VerifyError("malformed minisign public key")
    return raw[2:10], raw[10:42]


def _parse_sig(text: str) -> tuple[bytes, bytes, bytes, str, bytes]:
    """(sig_alg, key_id, signature, trusted_comment, global_sig) from a .minisig file."""
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    payloads = [ln.strip() for ln in lines if ln.strip()
                and not ln.startswith("untrusted comment:")
                and not ln.startswith("trusted comment:")]
    if len(payloads) < 2:
        raise VerifyError("malformed minisign signature (need signature + global signature)")
    sig_raw = base64.b64decode(payloads[0])
    global_sig = base64.b64decode(payloads[1])
    if len(sig_raw) != 74:
        raise VerifyError("malformed minisign signature block")
    if len(global_sig) != 64:
        raise VerifyError("malformed minisign global signature")
    sig_alg, key_id, signature = sig_raw[0:2], sig_raw[2:10], sig_raw[10:74]
    trusted_comment = ""
    for ln in lines:
        if ln.startswith("trusted comment:"):
            trusted_comment = ln[len("trusted comment:"):].lstrip()
            break
    return sig_alg, key_id, signature, trusted_comment, global_sig


def verify_bytes(pubkey_text: str, content: bytes, sig_text: str) -> str:
    """Verify `content` against a minisign signature. Returns the trusted comment on
    success; raises VerifyError otherwise (fail-closed)."""
    Ed25519PublicKey, InvalidSignature = _load_ed25519()
    key_id, pk_bytes = parse_pubkey(pubkey_text)
    sig_alg, sig_key_id, signature, trusted_comment, global_sig = _parse_sig(sig_text)

    if sig_key_id != key_id:
        raise VerifyError("signature key id does not match the trusted public key")

    if sig_alg == b"ED":
        signed = hashlib.blake2b(content, digest_size=64).digest()
    elif sig_alg == b"Ed":
        signed = content
    else:
        raise VerifyError(f"unsupported signature algorithm {sig_alg!r}")

    pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    try:
        pk.verify(signature, signed)
    except InvalidSignature as e:
        raise VerifyError("content signature is invalid") from e
    # The trusted comment is only trustworthy if the global signature over
    # (signature || trusted_comment) checks out — this is what makes an embedded
    # version/timestamp tamper-evident.
    try:
        pk.verify(global_sig, signature + trusted_comment.encode("utf-8"))
    except InvalidSignature as e:
        raise VerifyError("global signature (trusted comment) is invalid") from e
    return trusted_comment


def commit_from_trusted_comment(tc: str) -> str | None:
    """Extract the git commit from a release trusted comment.

    package_release.sh signs with the trusted comment shape:
        agent_substrate_kit <version> <commit> sha256:<hash>
    The global signature makes this tamper-evident, so a commit parsed from a VERIFIED
    signature is trustworthy provenance even for a .zip install with no .git tree. Returns
    None if the comment does not match (never guesses)."""
    parts = tc.split()
    if len(parts) >= 4 and parts[0] == "agent_substrate_kit" and parts[3].startswith("sha256:"):
        return parts[2]
    return None


def verify_file(pubkey_path: Path | str, file_path: Path | str,
                sig_path: Path | str | None = None) -> str:
    pub = Path(pubkey_path).read_text(encoding="utf-8")
    fp = Path(file_path)
    sp = Path(sig_path) if sig_path else fp.with_suffix(fp.suffix + ".minisig")
    if not sp.is_file():
        raise VerifyError(f"signature file not found: {sp}")
    return verify_bytes(pub, fp.read_bytes(), sp.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Verify a minisign signature (fail-closed).")
    ap.add_argument("--pub", required=True, help="path to the trusted minisign public key")
    ap.add_argument("--file", required=True, help="path to the signed file")
    ap.add_argument("--sig", help="path to the .minisig (default: <file>.minisig)")
    a = ap.parse_args()
    try:
        tc = verify_file(a.pub, a.file, a.sig)
    except VerifyError as e:
        print(f"verify_release: FAILED — {e}", file=sys.stderr)
        sys.exit(2)
    print(f"verify_release: OK — trusted comment: {tc}")
    sys.exit(0)
