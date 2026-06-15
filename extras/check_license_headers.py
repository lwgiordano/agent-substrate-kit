#!/usr/bin/env python3
"""License-header enforcement for source files.

Scans tracked source files for an SPDX-License-Identifier comment.
Catches files that ship without proper license attribution — a
common pre-acquisition / open-source-due-diligence finding.

The kit ships with EMPTY _REQUIRED_HEADER_PATHS. Populate the tuple
with the path-prefixes you want to enforce headers on. Add an
allowlist for files that legitimately don't need headers (e.g.,
data files, test fixtures, generated code).

Header format (SPDX, machine-readable, language-agnostic):

  Python / shell:    # SPDX-License-Identifier: <license>
  TypeScript / Java: // SPDX-License-Identifier: <license>
  CSS / SQL:         /* SPDX-License-Identifier: <license> */

The license value should be a valid SPDX identifier (Apache-2.0,
MIT, GPL-3.0-or-later, etc.) or the literal string
"LicenseRef-Proprietary" for closed-source code.

Operator workflow:
  python scripts/check_license_headers.py
  python scripts/check_license_headers.py --add MIT  # auto-prepend missing headers

Exit codes: 0 ok | 1 missing headers | 2 environment problem.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# Path-prefixes (relative to repo root) where license headers are
# REQUIRED. Empty by default — populate as you adopt the policy.
# Prefixes match `Path.is_relative_to`, so 'src' matches 'src/foo.py'.
_REQUIRED_HEADER_PATHS: tuple[str, ...] = (
    # Examples (uncomment + customize):
    # "src",
    # "scripts",
    # "apps",
)


# Files that are exempted even if under a required prefix. Useful for
# auto-generated files, test fixtures, vendor code, etc.
_EXEMPT_PATHS: tuple[str, ...] = (
    "tests/fixtures",
    "build",
    "dist",
)


# File extensions to scan + their comment style.
_COMMENT_STYLES: dict[str, str] = {
    ".py": "# ",
    ".sh": "# ",
    ".bash": "# ",
    ".rb": "# ",
    ".pl": "# ",
    ".ts": "// ",
    ".tsx": "// ",
    ".js": "// ",
    ".jsx": "// ",
    ".java": "// ",
    ".kt": "// ",
    ".go": "// ",
    ".rs": "// ",
    ".c": "// ",
    ".cpp": "// ",
    ".h": "// ",
    ".hpp": "// ",
    ".cs": "// ",
    ".swift": "// ",
}


_HEADER_RE = re.compile(r"SPDX-License-Identifier:\s*(?P<id>\S+)")


def _is_exempt(rel: Path) -> bool:
    rel_str = rel.as_posix()
    return any(rel_str.startswith(p) for p in _EXEMPT_PATHS)


def _under_required(rel: Path) -> bool:
    rel_str = rel.as_posix()
    return any(rel_str.startswith(p) for p in _REQUIRED_HEADER_PATHS)


def _has_header(path: Path, head_lines: int = 10) -> bool:
    """Check the first `head_lines` for an SPDX identifier."""
    try:
        with path.open("r", encoding="utf-8") as f:
            head = []
            for _, line in zip(range(head_lines), f, strict=False):
                head.append(line)
        return any(_HEADER_RE.search(line) for line in head)
    except (OSError, UnicodeDecodeError):
        return False


def _add_header(path: Path, license_id: str, comment: str) -> None:
    """Prepend an SPDX header to `path`. Preserves shebang lines."""
    text = path.read_text(encoding="utf-8")
    header = f"{comment}SPDX-License-Identifier: {license_id}\n"
    if text.startswith("#!"):
        # Preserve shebang on line 1; insert header on line 2.
        first_nl = text.find("\n")
        if first_nl == -1:
            new_text = text + "\n" + header
        else:
            new_text = text[: first_nl + 1] + header + text[first_nl + 1 :]
    else:
        new_text = header + text
    path.write_text(new_text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--add",
        metavar="LICENSE",
        help="SPDX identifier to PREPEND to files missing a header "
        "(e.g., 'MIT', 'Apache-2.0', 'LicenseRef-Proprietary')",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional list of paths to check (default: scan all required prefixes)",
    )
    args = parser.parse_args(argv)

    if not _REQUIRED_HEADER_PATHS:
        print(
            "check-license-headers: _REQUIRED_HEADER_PATHS is empty — "
            "no enforcement. Populate the tuple in scripts/check_license_headers.py "
            "to enable."
        )
        return 0

    # Collect candidate files.
    if args.paths:
        candidates = [Path(p) for p in args.paths]
    else:
        candidates = []
        for prefix in _REQUIRED_HEADER_PATHS:
            base = REPO / prefix
            if not base.is_dir():
                continue
            for ext in _COMMENT_STYLES:
                candidates.extend(base.rglob(f"*{ext}"))

    findings: list[tuple[Path, str]] = []
    for path in candidates:
        if not path.is_file():
            continue
        rel = path.relative_to(REPO) if path.is_absolute() else path
        if _is_exempt(rel):
            continue
        if not _under_required(rel):
            continue
        ext = path.suffix
        if ext not in _COMMENT_STYLES:
            continue
        if _has_header(path):
            continue
        findings.append((rel, _COMMENT_STYLES[ext]))

    if not findings:
        n = sum(
            1
            for p in candidates
            if p.is_file()
            and not _is_exempt(p.relative_to(REPO) if p.is_absolute() else p)
        )
        print(f"check-license-headers: ok ({n} files, all have SPDX header).")
        return 0

    if args.add:
        for path, comment in findings:
            _add_header(REPO / path, args.add, comment)
            print(f"  + added SPDX-License-Identifier: {args.add} → {path}")
        print(f"\ncheck-license-headers: added headers to {len(findings)} files.")
        return 0

    print("check-license-headers: MISSING SPDX HEADERS", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    for rel, comment in findings:
        print(
            f"  {rel} (expected: {comment.rstrip()}SPDX-License-Identifier: <id>)",
            file=sys.stderr,
        )
    print(
        f"\n{len(findings)} file(s) missing SPDX license headers.",
        file=sys.stderr,
    )
    print(
        "\nFix: prepend the SPDX comment to each file, OR run:",
        file=sys.stderr,
    )
    print(
        "  python scripts/check_license_headers.py --add <SPDX-ID>\n"
        "  (e.g., MIT, Apache-2.0, LicenseRef-Proprietary)",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
