#!/usr/bin/env python3
"""Validate that every HISTORY.md entry header REFERENCES A
RESOLVABLE git commit.

The header format (see scripts/append_history.py) is:

    ## <ISO timestamp> — <ULID> — <git-sha-short | "WORKING" | "Correction*">

What this validator catches (claims it CAN make):
  - SHA references where `git cat-file -e <sha>^{commit}` fails —
    typo, branch deleted, forgotten rebase, or aspirational SHA
    (entry written but commit never made it).
  - Headers whose third field doesn't match the documented format
    (allowed: 7-40 hex chars; "WORKING" for bootstrap; "Correction"
    or any text starting with "Correction" for explicit correction
    entries that don't pin a fresh SHA).
  - Commits whose author date is FUTURE relative to the entry
    timestamp — heuristic catch for a future-dated SHA snuck into
    HISTORY (rare but real).

What this validator EXPLICITLY DOES NOT catch: an entry referencing
the WRONG real commit. The off-by-one class — where
append_history.py was invoked BEFORE git commit and captured the
parent commit — leaves the entry pointing at a real SHA that ALSO
touched the same files (both parent and child often do during
HISTORY-only commits). The validator can't disambiguate without
out-of-band knowledge of which commit the entry intends to
document. The structural fix lives at the AUTHORING layer (the
--commit-hash flag in append_history.py + the AGENTS.md
"commit first, then append HISTORY" workflow rule), not here.

Exit codes: 0 ok | 1 drift detected | 2 environment problem.

Usage (prefix with `uv run` / `poetry run` per your dep manager):
    python scripts/check_history_sha.py
    python scripts/check_history_sha.py --verbose
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_HISTORY = _REPO / "docs" / "HISTORY.md"

sys.path.insert(0, str(Path(__file__).resolve().parent))
# v3.8.43 (round-26 sweep): HISTORY.md is agent-writable and append-only, so the
# SHA gate must not read it through a link or block on a FIFO. Found by
# check_raw_file_io.py, not by an external audit round.
try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None

# `## <ts> — <token> — <sha|WORKING|Correction...>` with em-dash
# separators. The token is usually a ULID (uppercase Crockford-32:
# 0-9 + A-Z minus I,L,O,U) but can also be `NO_SESSION` when
# append_history runs without an active CURRENT_SESSION.md, OR a
# project-specific token shape. Accept any [0-9A-Z_]+ to cover both.
_HEADER_RE = re.compile(
    r"^## (?P<ts>\S+) — (?P<ulid>[0-9A-Z_]+) — (?P<sha>.+)$",
    re.MULTILINE,
)
_SHA_HEX_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _all_commits() -> dict[str, str]:
    """Return a dict mapping every FULL 40-char SHA in this repo's
    history to its commit ISO-8601 author date. ONE subprocess call
    (vs O(N) `git cat-file -e` calls); critical on slow filesystems
    (Google Drive checkouts can take hundreds of ms per spawn).

    the audit tool P2c7-audit-r3 Finding 3: prior implementation indexed by
    `%h` (default short, usually 7 chars). HISTORY entries with an
    8/12/40-char SHA — all valid by the header regex — would miss
    the table and report as unresolved. Indexing by `%H` (full)
    plus a prefix-match lookup (`_resolve_commit` below) handles
    every length.
    """
    out = subprocess.run(
        ["git", "log", "--all", "--pretty=format:%H %aI"],
        cwd=_REPO,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    table: dict[str, str] = {}
    for line in out.splitlines():
        if " " not in line:
            continue
        full, iso = line.split(" ", 1)
        table[full] = iso
    return table


def _resolve_commit(short_or_full: str, commits: dict[str, str]) -> str | None:
    """Return the commit's ISO date if `short_or_full` matches any
    full SHA in the table by exact match OR prefix. Returns None
    if no match. Linear scan; N is the repo's commit count and the
    constant is small."""
    if short_or_full in commits:
        return commits[short_or_full]
    matches = [iso for full, iso in commits.items() if full.startswith(short_or_full)]
    if len(matches) != 1:
        # 0 matches → unknown; >1 matches → ambiguous (extremely
        # rare; only happens with a SHA prefix shorter than the
        # collision floor for this repo). Both treated as "unresolved"
        # to keep the validator strict.
        return None
    return matches[0]


def _is_future_dated(commit_iso: str, entry_ts: str) -> bool:
    """Return True iff the commit's author date is more than 24h AFTER
    the entry's recorded timestamp. The HISTORY entry is appended
    AFTER the commit lands, so its timestamp should be at-or-after
    the commit's author date. A 24h grace allows for tz/clock skew
    and the legitimate case where the entry is appended a day later.
    """
    from datetime import datetime, timedelta
    try:
        ct = datetime.fromisoformat(commit_iso.replace("Z", "+00:00"))
        et = datetime.fromisoformat(entry_ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    return ct - et > timedelta(hours=24)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="print every checked entry, not just findings",
    )
    args = parser.parse_args()

    if not _HISTORY.is_file():
        print(f"check-history-sha: missing {_HISTORY}", file=sys.stderr)
        return 2

    text = _safe_read_text(_HISTORY, _REPO, max_bytes=64 << 20)
    if text is None:
        print(f"check-history-sha: {_HISTORY} is unreadable or not a private "
              "regular file", file=sys.stderr)
        return 2
    headers = list(_HEADER_RE.finditer(text))
    if not headers:
        # Two indistinguishable cases: a bootstrapped repo with no
        # HISTORY entries yet, or a HISTORY whose entry headers have
        # all drifted away from the format. Distinguish heuristically:
        # if the file is short enough to be just the bootstrap header,
        # treat as "no entries yet" (exit 0). Otherwise treat as drift
        # (exit 1).
        body_lines = [
            line for line in text.splitlines()
            if line.strip() and not line.startswith("#") and not line.startswith("**")
        ]
        if len(body_lines) <= 2:
            print(
                "check-history-sha: HISTORY.md has no entries yet — fresh "
                "bootstrap. The first append_history.py call lands the "
                "first entry."
            )
            return 0
        print(
            "check-history-sha: 0 headers parsed but HISTORY.md has body "
            "content — format may have drifted from the canonical "
            "`## YYYY-MM-DDTHH:MM:SSZ — <token> — <sha>` shape.",
            file=sys.stderr,
        )
        return 1

    # Batch ALL commits + their dates in one subprocess. Per-entry
    # `git cat-file` would invoke ~50 subprocesses on a slow FS
    # (Google Drive observed at ~2s per spawn → 100s+ total).
    try:
        commits = _all_commits()
    except subprocess.CalledProcessError as e:
        print(
            f"check-history-sha: `git log` failed: {e}",
            file=sys.stderr,
        )
        return 2

    findings: list[str] = []
    n_sha = n_working = n_correction = 0
    for m in headers:
        ts = m.group("ts")
        sha = m.group("sha").strip()

        # 1) Bootstrap entries (genuinely no HEAD yet)
        if sha == "WORKING":
            n_working += 1
            if args.verbose:
                print(f"  {ts} {sha} (bootstrap; no commit to verify)")
            continue

        # 2) Explicit correction entries — the third field starts with
        #    "Correction" and signals that a prior entry's SHA was off.
        #    The body of the entry should explain which entry was wrong;
        #    we don't enforce that here (operator-readable).
        if sha.lower().startswith("correction"):
            n_correction += 1
            if args.verbose:
                print(f"  {ts} {sha} (correction entry; SHA-less by design)")
            continue

        # 3) Real SHA — must look like a hex SHA AND resolve in this repo.
        if not _SHA_HEX_RE.match(sha):
            findings.append(
                f"{ts}: third field {sha!r} is neither a hex SHA, "
                "'WORKING', nor a 'Correction*' marker."
            )
            continue
        commit_iso = _resolve_commit(sha, commits)
        if commit_iso is None:
            findings.append(
                f"{ts}: SHA {sha!r} does not resolve to a commit. "
                "Possible causes: typo, branch deleted, rebase moved the "
                "commit, or the entry was written before the commit landed. "
                "Fix by appending a 'Correction' entry that names the right "
                "SHA — never edit prior entries (AGENTS.md hard rule)."
            )
            continue
        # Future-dated SHA heuristic — see module docstring. The
        # validator cannot detect parent-vs-child off-by-one (real
        # SHA, both touch same files) but it CAN reject obviously
        # future-dated SHAs. False-positive rate is low because
        # entries timestamp themselves at append-time, after commit.
        if _is_future_dated(commit_iso, ts):
            findings.append(
                f"{ts}: SHA {sha!r} resolves but its commit date "
                f"({commit_iso}) is more than 24h AFTER the entry's "
                "timestamp. Likely a future-dated SHA from a different "
                "branch or a clock-skew bug; double-check the entry."
            )
            continue
        n_sha += 1
        if args.verbose:
            print(f"  {ts} {sha} ok")

    if findings:
        print("check-history-sha: HISTORY SHA DRIFT DETECTED", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            f"\n{len(findings)} drift issue(s) "
            f"({n_sha} sha-verified / {n_working} bootstrap / "
            f"{n_correction} correction).",
            file=sys.stderr,
        )
        return 1

    total = n_sha + n_working + n_correction
    print(
        f"check-history-sha: {total} entries verified "
        f"({n_sha} sha-resolved / {n_working} bootstrap / "
        f"{n_correction} correction)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
