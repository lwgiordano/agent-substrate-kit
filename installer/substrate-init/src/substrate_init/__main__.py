#!/usr/bin/env python3
"""substrate-init CLI: obtain a signed Agent Substrate Kit release, VERIFY it against the
public key embedded in THIS package (fork-proof), then run its bootstrap.sh into the target.

  uvx substrate-init --url https://…/agent_substrate_kit_v3-X.Y.Z.zip --target .
  uvx substrate-init --from ./agent_substrate_kit_v3-X.Y.Z.zip --target . -- --profile strict

FAIL-CLOSED: a .zip whose minisign signature does not verify against the embedded key is
never extracted or run. `--allow-unverified` (a local directory / deliberately unsigned
build, dev only) is the sole escape and warns loudly.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from . import __version__
from ._verify_backends import verify

PKG = Path(__file__).resolve().parent
EMBEDDED_PUB = PKG / "trust" / "minisign.pub"
EMBEDDED_IDENTITY = PKG / "trust" / "sigstore_identity.json"  # present only when the kit signs keyless


def _download(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:  # noqa: S310
        shutil.copyfileobj(r, f)


def _find_bootstrap(root: Path) -> Path:
    for d in root.rglob("bootstrap.sh"):
        return d
    raise SystemExit("substrate-init: no bootstrap.sh in the kit artifact")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="substrate-init",
        description="Verify (against an embedded key) and install the Agent Substrate Kit.",
    )
    ap.add_argument(
        "--from",
        dest="src",
        help="local signed kit .zip (expects <zip>.minisig alongside) OR a kit directory",
    )
    ap.add_argument("--url", help="URL of a signed kit .zip (also fetches <url>.minisig)")
    ap.add_argument("--target", default=".", help="repo to bootstrap into (default: .)")
    ap.add_argument(
        "--allow-unverified",
        action="store_true",
        help="use an unsigned/dir source (dev only; skips verification, warns)",
    )
    ap.add_argument("--version", action="version", version=f"substrate-init {__version__}")
    ap.add_argument(
        "bootstrap_args",
        nargs=argparse.REMAINDER,
        help="args after `--` are passed through to bootstrap.sh",
    )
    a = ap.parse_args(argv)
    if not a.src and not a.url:
        print("substrate-init: one of --from or --url is required", file=sys.stderr)
        return 2
    if not EMBEDDED_PUB.is_file():
        print(
            "substrate-init: embedded trust key missing from the package (fail-closed)",
            file=sys.stderr,
        )
        return 2

    extra = [x for x in a.bootstrap_args if x != "--"]
    verified_commit = None  # parsed from the verified trusted comment (provenance, v3.7.16 P2b)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # 1. resolve source
        if a.src and Path(a.src).is_dir():
            if not a.allow_unverified:
                print(
                    "substrate-init: a directory source is unverified — pass --allow-unverified "
                    "(a signed .zip is the trusted path).",
                    file=sys.stderr,
                )
                return 2
            kit_root = Path(a.src)
            print("substrate-init: WARNING using UNVERIFIED directory source", file=sys.stderr)
        else:
            zip_path = tmp / "kit.zip"
            # Fetch BOTH sidecars (best effort) so the shared verifier can auto-detect the
            # backend — minisign (.minisig) OR keyless Sigstore (.sigstore). (v3.7.19)
            if a.url:
                try:
                    _download(a.url, zip_path)
                except Exception as e:
                    print(f"substrate-init: download failed: {e}", file=sys.stderr)
                    return 2
                for ext in (".minisig", ".sigstore"):
                    try:
                        _download(a.url + ext, tmp / ("kit.zip" + ext))
                    except Exception:
                        pass  # sidecar for the OTHER backend simply won't exist
            else:
                src = Path(a.src)
                if not src.is_file():
                    print(f"substrate-init: source not found: {src}", file=sys.stderr)
                    return 2
                shutil.copy2(src, zip_path)
                for ext in (".minisig", ".sigstore"):
                    cand = Path(str(src) + ext)
                    if cand.is_file():
                        shutil.copy2(cand, tmp / ("kit.zip" + ext))
            # 2. verify with the SAME multi-backend policy as the kit (fail-closed) against the
            #    EMBEDDED trust anchors — minisign pubkey + (if the kit signs keyless) identity.
            if not a.allow_unverified:
                r = verify(zip_path, minisign_pub=EMBEDDED_PUB,
                           sigstore_identity=(EMBEDDED_IDENTITY if EMBEDDED_IDENTITY.is_file() else None),
                           root=tmp, require=True)
                if r.rc != 0:
                    print(f"substrate-init: verification FAILED — {r.detail} (fail-closed)", file=sys.stderr)
                    return 2
                print(f"substrate-init: verified ({r.backend}) against embedded trust anchor — {r.detail}")
                verified_commit = r.commit
            else:
                print("substrate-init: WARNING --allow-unverified — signature NOT checked", file=sys.stderr)
            ex = tmp / "extract"
            ex.mkdir()
            shutil.unpack_archive(str(zip_path), str(ex))
            kit_root = _find_bootstrap(ex).parent

        # 3. bootstrap into target
        target = Path(a.target).resolve()
        target.mkdir(parents=True, exist_ok=True)
        cmd = ["bash", str(kit_root / "bootstrap.sh"), "--target", str(target)] + extra
        # Pass verified provenance to bootstrap → write_install_json (a .zip extract has no
        # .git, so bootstrap would otherwise record kit_commit=none — v3.7.16 P2b). The commit
        # comes from the VERIFIED, tamper-evident trusted comment.
        env = os.environ.copy()
        if verified_commit:
            env["SUBSTRATE_KIT_COMMIT"] = verified_commit
        env["SUBSTRATE_KIT_SOURCE"] = a.url or (str(Path(a.src)) if a.src else "")
        print(f"substrate-init: bootstrapping into {target} …")
        r = subprocess.run(cmd, env=env)
        return r.returncode


if __name__ == "__main__":
    sys.exit(main())
