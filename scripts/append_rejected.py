#!/usr/bin/env python3
"""Append a rejected-approach entry to docs/REJECTED.md.

CLI:
  python scripts/append_rejected.py \\
    --what "<the approach that was rejected>" \\
    --why  "<why it was rejected>"

WHY THIS EXISTS (v3.8.28). The ADR template already marks "Alternatives
Considered / Rejected because" REQUIRED, with the right rationale: "Without it,
future sessions re-derive the same alternatives." But ADRs are heavyweight, and
after 27 releases `docs/decisions/` held only the template — the capture path
existed and was empirically never used. This is the low-ceremony sibling: one
line, one command, so the rejection actually gets recorded. ADRs remain the home
for full decisions with context and consequences.

The last few entries are injected at SessionStart by scripts/session_handoff.py
under their own 500-char budget, sanitized exactly like HISTORY summaries.

ADVISORY ONLY — no gate reads this file. The substrate's security claim is that
deterministic gates cannot be talked out of a decision by repo prose; a rejection
log is context for the agent, never an input to an enforcement decision.

Each field is required and must be >= 10 characters (mirrors append_history.py).

Exit codes: 0 ok | 1 invalid args | 2 file I/O error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Explicit local import path so this works under `python -I` (isolated mode
# does NOT auto-prepend the script dir). Stdlib imports above resolve first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import locked_atomic_append, repo_root, utc_now_iso

REJECTED_HEADER = """\
# REJECTED.md — Append-only log of rejected approaches

**DO NOT EDIT prior entries.** Append only via `./manage.sh reject`
(`scripts/append_rejected.py`). The newest entries are injected at SessionStart
so a future session does not re-propose something already ruled out.

This file is `merge=union` in `.gitattributes` — concurrent branches' entries
combine without conflicts.

For a decision that needs full context and consequences, write an ADR in
`docs/decisions/` instead; this file is for one-liners.

"""

MIN_FIELD_CHARS = 10


def compose_entry(timestamp: str, what: str, why: str) -> str:
    """One line per rejection — the shape session_handoff tail-reads."""
    return f"- [{timestamp}] {what} — rejected because {why}\n"


def atomic_append(target: Path, entry: str) -> None:
    """Serialized atomic append — see _doc_common.locked_atomic_append.

    v3.8.31: the previous read/mkstemp/replace here (mirrored verbatim from
    append_history) was atomic for readers but raced concurrent WRITERS — two
    simultaneous `./manage.sh reject` calls lost an entry. Both appenders now
    share the one flock-serialized implementation."""
    locked_atomic_append(target, entry, REJECTED_HEADER, ".REJECTED.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Append a rejected-approach entry to docs/REJECTED.md.")
    ap.add_argument("--what", required=True,
                    help="the approach that was rejected")
    ap.add_argument("--why", required=True,
                    help="why it was rejected")
    a = ap.parse_args(argv)

    for name, value in (("--what", a.what), ("--why", a.why)):
        collapsed = " ".join(str(value).split())
        if len(collapsed) < MIN_FIELD_CHARS:
            print(f"append_rejected: {name} must be at least {MIN_FIELD_CHARS} "
                  f"characters (got {len(collapsed)}).", file=sys.stderr)
            return 1

    what = " ".join(a.what.split())
    why = " ".join(a.why.split())
    # A newline in either field would forge a second entry on a later line;
    # collapsing whitespace above already removes them. Keep it one line.
    entry = compose_entry(utc_now_iso(), what, why)

    root = repo_root()
    target = root / "docs" / "REJECTED.md"
    try:
        atomic_append(target, entry)
    except OSError as e:
        print(f"append_rejected: cannot write {target}: {e}", file=sys.stderr)
        return 2
    print(entry.rstrip("\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
