#!/usr/bin/env python3
"""Deterministic, metadata-clean review-bundle builder — the ONE place the one-file audit
tarball is produced, shared by package_release.sh (local/minisign) and the keyless release
template (v3.7.21). Building it one way for every signing backend removes the duplication that
let the keyless tier drift from minisign.

Built with Python tarfile (NOT platform tar): macOS bsdtar embeds com.apple.provenance as a
LIBARCHIVE.xattr PAX header even after `xattr -cr`, so a bsdtar-built bundle warns on extraction
elsewhere. tarfile never reads xattrs, and every TarInfo is normalized (mtime/mode/uid/gid/
uname/gname) in USTAR format → deterministic + clean on every platform.

Internal hygiene (fail-closed, exit 1): the bundle must contain EXACTLY the requested files and
no macOS metadata (._* / .DS_Store). package_release additionally runs a platform `tar -tzf`
warning check for the canonical path.

Usage: build_review_bundle.py <review_dir> <bundle.tar.gz> <file> [<file>...]
"""
from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: build_review_bundle.py <review_dir> <bundle> <file>...", file=sys.stderr)
        return 1
    review, bundle, files = Path(argv[0]), Path(argv[1]), argv[2:]
    with tarfile.open(bundle, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        for rel in files:
            p = review / rel
            if not p.is_file():
                print(f"build_review_bundle: missing file {rel}", file=sys.stderr)
                return 1
            data = p.read_bytes()
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tf.addfile(info, io.BytesIO(data))
    # hygiene: re-read the bundle and assert exactly the requested files, no macOS metadata.
    with tarfile.open(bundle, "r:gz") as tf:
        names = tf.getnames()
    if any(Path(n).name.startswith("._") or n.endswith(".DS_Store") for n in names):
        print(f"build_review_bundle: BLOCK — macOS metadata in bundle: {names}", file=sys.stderr)
        return 1
    if sorted(names) != sorted(files):
        print(f"build_review_bundle: BLOCK — bundle is not exactly the expected files: {names}",
              file=sys.stderr)
        return 1
    print(f"build_review_bundle: ok ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
