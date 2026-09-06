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
  - Correction entries that supersede nothing: one naming a SHA no
    entry references, or naming a SHA that RESOLVES (so the entry it
    claims to correct was never broken). Without these the escape
    hatch below would be a silencer.

CORRECTING A BAD SHA (v3.8.49). HISTORY is append-only, so a wrong
SHA cannot be edited out — the remedy has to be additive. Append an
entry whose third field is `Correction-of-<bad-sha>`; that supersedes
the unresolvable-SHA finding for every EARLIER entry naming that SHA (a
repeated typo needs one correction, not one per occurrence), and the body should
name the right commit for human readers. This gate PRINTED that advice
from the start but never implemented the pairing: the marker was
counted and skipped, so following the printed instruction changed
nothing and a repo that hit it stayed red with no permitted way out.
The supersede applies ONLY to "does not resolve" — a future-dated SHA
is a different finding and is never silenced this way.
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
# A correction entry that names WHICH SHA it supersedes, so the pairing is
# machine-checkable rather than operator-readable prose. Separators are
# liberal (`-`, `_`, `:`, space) because this is hand-typed under pressure,
# but the target must be a bare hex SHA — anything else stays a plain
# `Correction` marker, which is still accepted and supersedes nothing.
_CORRECTION_OF_RE = re.compile(
    r"^correction[-_: ]*of[-_: ]+(?P<sha>[0-9a-fA-F]{7,40})$",
    re.IGNORECASE,
)


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


def _is_shallow_clone() -> bool:
    """True when git reports a shallow repository. Errors (no git, no repo) are
    NOT shallow: those surface as their own failures downstream, and this must
    never turn a real gate result into a silent skip."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=_REPO, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="print every checked entry, not just findings",
    )
    args = parser.parse_args()

    # v3.8.51 (self-audit P2): in a SHALLOW clone every SHA older than the
    # fetch boundary is simply absent, and this gate reported each one as
    # "does not resolve" with the standard remedy — append Correction-of-<sha>.
    # Following that advice in a shallow checkout corrupts HISTORY permanently:
    # in every full clone those corrections then name SHAs that RESOLVE, which
    # the v3.8.50 guard rightly treats as drift, on an append-only file that
    # cannot be edited back. GitHub Actions checks out depth=1 by default; this
    # kit's CI only avoided the trap via fetch-depth: 0, and the workaround had
    # been recorded in a knowledge note instead of in the gate. Refuse to judge
    # what cannot be seen, and name the real remedy.
    if _is_shallow_clone():
        print(
            "check-history-sha: SHALLOW CLONE — commit history is truncated, so "
            "HISTORY SHAs cannot be verified here. This is not drift. Run "
            "`git fetch --unshallow` (or check out with fetch-depth: 0) and re-run. "
            "Do NOT append Correction entries in this state.",
            file=sys.stderr,
        )
        return 2

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

    # PRE-PASS: which SHAs does a Correction entry supersede?
    #
    # v3.8.49: this gate printed "Fix by appending a 'Correction' entry that
    # names the right SHA" and then ignored the entry — a correction marker
    # was counted and `continue`d past with no pairing to what it corrected.
    # Because HISTORY is append-only (AGENTS.md hard rule) the prior entry
    # cannot be edited, so the ONLY permitted remedy was a no-op and a repo
    # that hit this was red forever. Observed for real on v3.8.48: an entry
    # named a pre-rebase SHA that never landed, and the branch could not go
    # green by any route the tooling allowed.
    #
    # The pairing is deliberately narrow so the escape hatch cannot become a
    # silencer: a correction supersedes ONLY the "does not resolve" finding,
    # never the future-dated one, and a correction that does not correspond
    # to a real broken entry is itself a finding (see below).
    #
    # v3.8.50 (round-32 P2) — the v3.8.49 pre-pass keyed corrections by SHA
    # ALONE, with no entry-order binding, so it retired matching entries
    # anywhere in the file. Two ways that silenced a live finding: a
    # `Correction-of-X` written BEFORE any X entry pre-forgave a bad SHA that
    # had not been recorded yet, and an X entry appended AFTER a correction
    # for an earlier X reused the same retirement. HISTORY is append-only and
    # chronological, so a correction can only speak to what was already
    # written: superseding is now bound to entry ORDER — a correction at
    # index j clears an unresolvable entry only at index i < j.
    #
    # The same defect, in the same shape, as v3.8.47's binding pre-pass: an
    # identity-keyed lookup built without the document order that gives the
    # identity meaning. That one was mine too, two releases earlier.
    entry_shas = [m.group("sha").strip() for m in headers]
    corrections: list[tuple[int, str]] = []
    for idx, marker in enumerate(entry_shas):
        cm = _CORRECTION_OF_RE.match(marker)
        if cm:
            corrections.append((idx, cm.group("sha").lower()))

    def _superseding_correction(i: int, sha_l: str):
        """The first correction that appears strictly AFTER entry `i`."""
        for j, target in corrections:
            if j > i and target == sha_l:
                return j
        return None

    findings: list[str] = []
    n_sha = n_working = n_correction = 0
    for entry_i, m in enumerate(headers):
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
            cm = _CORRECTION_OF_RE.match(sha)
            if cm:
                # A correction that supersedes nothing is itself drift: it
                # would let anyone append `Correction-of-<sha>` and quietly
                # retire a SHA that was never broken. Both guards fail CLOSED.
                target = cm.group("sha").lower()
                # ORDER-BOUND (v3.8.50): only entries written BEFORE this
                # correction count. A correction cannot pre-forgive a SHA that
                # has not been recorded yet.
                matches = [
                    s for s in entry_shas[:entry_i] if s.lower() == target
                ]
                if not matches:
                    findings.append(
                        f"{ts}: correction {sha!r} names a SHA that no EARLIER "
                        "HISTORY entry references. A correction supersedes an "
                        "entry already written above it — check the SHA, and "
                        "check that you appended the correction AFTER it."
                    )
                elif all(_resolve_commit(s, commits) is not None for s in matches):
                    findings.append(
                        f"{ts}: correction {sha!r} names a SHA that RESOLVES, "
                        "so the entry it corrects was never broken. "
                        "Corrections supersede unresolvable SHAs only; they "
                        "cannot retire a live finding."
                    )
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
            corr_j = _superseding_correction(entry_i, sha.lower())
            if corr_j is not None:
                # Superseded by a correction appended AFTER this entry — the
                # documented, append-only remedy, which this gate now actually
                # honours. Counted on the correction entry itself, not here, so
                # the summary still reports one correction per correction.
                if args.verbose:
                    print(
                        f"  {ts} {sha} unresolvable but superseded by the "
                        f"correction at entry {corr_j + 1}"
                    )
                continue
            findings.append(
                f"{ts}: SHA {sha!r} does not resolve to a commit. "
                "Possible causes: typo, branch deleted, rebase moved the "
                "commit, or the entry was written before the commit landed. "
                f"Fix by appending an entry whose third field is "
                f"'Correction-of-{sha}' and whose body names the right SHA — "
                "never edit prior entries (AGENTS.md hard rule)."
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
