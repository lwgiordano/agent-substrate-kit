#!/usr/bin/env python3
"""Append a four-field entry to docs/HISTORY.md.

CLI:
  python scripts/append_history.py \\
    --summary  "<one-line>"        \\
    --files    "<comma,separated>" \\
    --intent   "<why>"             \\
    --knowledge "<what next sessions need>" \\
    [--commit-hash <short-sha>]

Each field is required and must be >= 10 characters (M15).

a prior audit (2026-04-28): the captured `<sha>` in the entry header
should be the commit this entry documents. Default behavior is to use
`git rev-parse --short HEAD` at script-run time — which captures the
PARENT commit when the script runs before `git commit` (the historical
workflow). Pass `--commit-hash <sha>` explicitly if you know the actual
commit SHA the entry refers to (typical post-commit usage:
`append_history.py --commit-hash $(git rev-parse --short HEAD)` after
the commit is made; the HISTORY entry then lands in a follow-up commit
or a future amend).

Exit codes: 0 ok | 1 invalid args | 2 file I/O error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Explicit local import path so this works under `python -I` (isolated mode
# does NOT auto-prepend the script dir). Stdlib imports above resolve first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import (
    git_short_sha,
    locked_atomic_append,
    repo_root,
    safe_read_text,
    utc_now_iso,
)


def _other_files_dirty(root: Path) -> list[str]:
    """Return modified-or-staged repo-relative paths that are NOT
    docs/HISTORY.md. Used by the off-by-one guard.

    Empty list means: working tree is either clean or only has the
    HISTORY.md edit append_history.py is about to make — safe to
    fall back to git HEAD as the documented SHA. Non-empty means:
    user is mid-commit; refuse the fallback (forces --commit-hash)."""
    # timeout=30 per blind-spot-checklists/commit-msg-hooks.md #14.
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root, check=True, capture_output=True, text=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return []  # No git or call failed — caller proceeds without warning.
    dirty: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        # porcelain format: 2-char status + space + path
        path = line[3:].strip()
        if path == "docs/HISTORY.md":
            continue
        # Manifest auto-regenerates from append_history; allow.
        if path == "docs/manifest.json":
            continue
        dirty.append(path)
    return dirty

SESSION_TOKEN_RE = re.compile(r"^\*\*Session token:\*\*\s+(\S+)\s*$", re.MULTILINE)
# v3.8.42 (round-25 P2): the token is copied verbatim into an append-only HISTORY
# header, so it must be a machine-token shape and nothing else. `(\S+)` alone
# accepts anything non-space — including the U+FFFD run that lossy-decoding
# undecodable bytes produces — which would embed garbage in the log permanently.
_SAFE_SESSION_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._:@+-]{1,128}\Z")
HISTORY_HEADER = """\
# HISTORY.md — Append-only project changelog

**DO NOT EDIT prior entries.** Update only via `scripts/append_history.py`.
This file is `merge=union` in `.gitattributes` — concurrent branches' entries
combine without conflicts.

"""


def read_session_token(history_root: Path) -> str:
    session_file = history_root / "docs" / "CURRENT_SESSION.md"
    if not session_file.exists():
        return "NO_SESSION"
    # v3.8.41 (round-24 P2): CURRENT_SESSION.md is agent-writable, untrusted
    # state. A symlinked OR hard-linked leaf would read an OUTSIDE file and copy
    # its `**Session token:**` value verbatim into the append-only HISTORY entry.
    # v3.8.42 (round-25 P2): the leaf guard ran but the read that FOLLOWED it was
    # still a bare read_text — so a FIFO hung and undecodable bytes raised
    # UnicodeDecodeError out of the CLI. safe_read_text does the guard AND the
    # read as one operation (O_NOFOLLOW|O_NONBLOCK, S_ISREG, bounded, lossy
    # decode), so every unsafe shape degrades to NO_SESSION instead.
    text = safe_read_text(session_file, history_root, max_bytes=256 * 1024)
    if text is None:
        return "NO_SESSION"
    m = SESSION_TOKEN_RE.search(text)
    if not m or not _SAFE_SESSION_TOKEN_RE.match(m.group(1)):
        return "NO_SESSION"
    return m.group(1)


def compose_entry(
    timestamp: str,
    token: str,
    sha: str,
    summary: str,
    files: str,
    intent: str,
    knowledge: str,
) -> str:
    return (
        f"## {timestamp} — {token} — {sha}\n"
        f"**Summary:** {summary}\n"
        f"**Files:** {files}\n"
        f"**Intent:** {intent}\n"
        f"**Knowledge:** {knowledge}\n"
        f"\n"
    )


def atomic_append(target: Path, entry: str) -> None:
    """Serialized atomic append — see _doc_common.locked_atomic_append.

    v3.8.31: the previous read/mkstemp/replace here was atomic for readers but
    raced concurrent WRITERS — two simultaneous appends kept only one entry
    (Codex reproduced it against append_rejected, which had mirrored this
    function verbatim). Both appenders now share the one flock-serialized
    implementation."""
    locked_atomic_append(target, entry, HISTORY_HEADER, ".HISTORY.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--summary", required=True, help="One-line index summary")
    parser.add_argument("--files", required=True, help="Comma-separated paths touched")
    parser.add_argument("--intent", required=True, help="The WHY (>=10 chars)")
    parser.add_argument(
        "--knowledge",
        required=True,
        help="Non-obvious facts for future sessions (>=10 chars)",
    )
    parser.add_argument(
        "--commit-hash",
        default=None,
        help="Short SHA the entry documents (overrides git HEAD capture). "
             "Use post-commit to avoid the parent-vs-current off-by-one.",
    )
    args = parser.parse_args()

    fields = {
        "summary": args.summary.strip(),
        "files": args.files.strip(),
        "intent": args.intent.strip(),
        "knowledge": args.knowledge.strip(),
    }
    # Length contract differs by field. `files` is a path list — a
    # single short path (e.g., "a.py") is valid. The narrative fields
    # (summary/intent/knowledge) need length to ensure substantive
    # content; without it, future-session searches return junk.
    empty = [name for name, value in fields.items() if not value]
    too_short_narrative = [
        name for name in ("summary", "intent", "knowledge")
        if len(fields[name]) < 10
    ]
    if empty:
        print(
            "append_history: required field is empty: "
            + ", ".join(empty),
            file=sys.stderr,
        )
        return 1
    if too_short_narrative:
        print(
            "append_history: narrative field must be >=10 characters. "
            "Too short: " + ", ".join(too_short_narrative),
            file=sys.stderr,
        )
        return 1

    root = repo_root()
    timestamp = utc_now_iso()

    # refuse the parent-of-current fallback when dirty.
    # The off-by-one (a prior audit finding) happens when append_history
    # is invoked BEFORE `git commit`, so git HEAD is the PARENT of the
    # commit being documented. Caller's intent is "document the commit
    # I'm about to make" — but we capture HEAD, which is the commit
    # BEFORE that. Result: 130+ HISTORY entries with off-by-one SHAs.
    #
    # Detection: if --commit-hash is not provided AND the working tree
    # has non-HISTORY files modified, the user is mid-commit. Refuse
    # the fallback and force them to use --commit-hash explicitly.
    if not args.commit_hash:
        non_history_dirty = _other_files_dirty(root)
        if non_history_dirty:
            print(
                "append_history: working tree has non-HISTORY files modified "
                "AND --commit-hash was omitted.\n"
                "  This is the parent-vs-current off-by-one trap.\n"
                "  Workflow: commit first, then run:\n"
                "    python scripts/append_history.py "
                "--commit-hash $(git rev-parse --short HEAD) ...\n"
                f"  Modified non-HISTORY files: {sorted(non_history_dirty)[:5]}",
                file=sys.stderr,
            )
            return 1
    sha = args.commit_hash.strip() if args.commit_hash else git_short_sha(cwd=root)
    token = read_session_token(root)
    entry = compose_entry(timestamp, token, sha, **fields)

    target = root / "docs" / "HISTORY.md"
    try:
        atomic_append(target, entry)
    except OSError as e:
        print(f"append_history: file I/O error: {e}", file=sys.stderr)
        return 2

    sys.stdout.write(entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
