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


def _build(review: Path, tmp: Path, files: list[str]) -> str | None:
    """Write the normalized tar to `tmp`; return an error string or None."""
    with tarfile.open(tmp, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        for rel in files:
            # Containment: entries are bundle-relative FILENAMES. An absolute path or a
            # `..` segment would read (and label) content from outside the review dir —
            # callers are maintainer-controlled, but the hygiene claim should not depend
            # on that (v3.7.22 review #2).
            rp = Path(rel)
            if rp.is_absolute() or ".." in rp.parts:
                return f"refusing non-contained entry {rel!r} (absolute or '..')"
            p = review / rel
            if not p.is_file():
                return f"missing file {rel}"
            data = p.read_bytes()
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tf.addfile(info, io.BytesIO(data))
    # hygiene: re-read and assert exactly the requested files, no macOS metadata.
    with tarfile.open(tmp, "r:gz") as tf:
        names = tf.getnames()
    if any(Path(n).name.startswith("._") or n.endswith(".DS_Store") for n in names):
        return f"BLOCK — macOS metadata in bundle: {names}"
    if sorted(names) != sorted(files):
        return f"BLOCK — bundle is not exactly the expected files: {names}"
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: build_review_bundle.py <review_dir> <bundle> <file>...", file=sys.stderr)
        return 1
    review, bundle, files = Path(argv[0]), Path(argv[1]), argv[2:]
    # Atomic publish: build + verify a .tmp, rename only on success — a failure never leaves
    # a partial/unverified tarball at the destination for a caller that ignores the exit code
    # to ship (v3.7.22 review #1).
    tmp = Path(str(bundle) + ".tmp")
    try:
        err = _build(review, tmp, files)
    except Exception as e:
        err = f"internal error: {e}"
    if err:
        tmp.unlink(missing_ok=True)
        print(f"build_review_bundle: {err}", file=sys.stderr)
        return 1
    tmp.replace(bundle)
    print(f"build_review_bundle: ok ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
