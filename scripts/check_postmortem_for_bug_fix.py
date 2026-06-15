#!/usr/bin/env python3
"""Postmortem-workflow commit 3/3 — commit-msg hook that requires a
postmortem cross-link on bug-fix commits.

Runs at pre-commit's `commit-msg` stage with the commit message file
path as argv[1]. Reads the message, classifies whether the commit is
a "bug fix" (per the heuristics below), and if so verifies the
message contains EITHER:

  1. A postmortem reference: `docs/postmortems/<YYYY-MM-DD>-<slug>.md`
     pointing at an existing file (the postmortem is staged in the
     same commit, so the file must exist in the working tree).
  2. The opt-out tag: `[no-postmortem: <reason>]` with non-empty
     reason text.

Otherwise, fails with an actionable message.

Why this hook exists: across 6 rounds of external audits, 21 stale-claim
findings were closed by fix-commits that captured the *what* (in the
diff) but not the *lesson* (carry-forward rule). The cumulative meta-
postmortem at docs/postmortems/2026-04-29-codex-second-pass-meta-
failure.md grew rules 1-11 ad-hoc; this hook closes the discipline
gap by making the postmortem cross-link the default.

Bug-fix detection (subject-line heuristics):

  - Conventional-commit `fix(...)?:` or `bug(fix)?:` prefix.
  - `<phase>-fix(-rN)?:` (e.g. `P3c2-fix:`, `P3c2-fix-r2:`).
  - The literal word `fix` or `bug` appearing as a token, with
    a colon nearby (subject section).
  - (Optional extension) audit-pass subjects like `^audit YYYY-MM-DD`
    if your team uses a fixed agent-name prefix.

Non-bug commits that look like bug commits — false positives — are
escapable via `[no-postmortem: <reason>]`. Examples we *want* to
catch as bug-fix:
  - "2026-04-29 pass-6: 3 fixes ..."
  - "fix(web): pre-bundle apache-arrow"
  - "P3c2-fix r2: drop /32-/25 bucket"
And examples we *don't* (subject doesn't trip the heuristics):
  - "P3 commit 1: chart codegen + revenueByBlockSize"
  - "docs: HISTORY for postmortem workflow ..."
  - "P3 commit 3 (P3c3): 10 CMA-* drill-down facet tables"

Exit codes: 0 ok | 1 missing postmortem cross-link | 2 env error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

#
# Extension point: if your team uses a fixed agent-name prefix for
# external audit-pass commits, prepend the appropriate pattern, e.g.:
#     re.compile(r"^Codex \d{4}-\d{2}-\d{2}\b", re.IGNORECASE),
# Keep these patterns in lock-step with check_finding_response.py so
# both commit-msg gates fire on the same set of commits.
_BUG_FIX_SUBJECT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Conventional-commit fix:/bug:/bugfix: prefix (with optional scope)
    re.compile(r"^(fix|bug|bugfix)(\([^)]+\))?:\s+", re.IGNORECASE),
    # Phase-fix subject (e.g. P3c2-fix:, P3c2-fix-r2:, P3-fix:)
    re.compile(r"^[A-Z]\d+(c\d+)?(-fix(-r\d+)?)\b", re.IGNORECASE),
    # Loose: `fix` or `bug` as a word followed by a colon within
    # the first 60 chars (catches "2026-04-29 pass-2: 3 fixes")
    re.compile(r"^.{0,60}\b(fix|bug)(es|ed|ing|fix|fixes)?\b.{0,30}:", re.IGNORECASE),
)


# Regex used to detect a postmortem reference in the body. We accept
# any path matching this shape — verify the file exists separately.
_POSTMORTEM_REF = re.compile(
    r"docs/postmortems/(\d{4}-\d{2}-\d{2})-([a-z0-9][a-z0-9-]*)\.md"
)

# Self-found during pass-12 development (sibling-parity per rule 13):
# regex must be line-anchored so an inline mention of `[no-postmortem:
# <reason>]` in a commit body (e.g., describing the tag in
# documentation) doesn't fire as an actual opt-out. Same fix as the
# corresponding regex in scripts/check_finding_response.py.
_NO_POSTMORTEM_TAG = re.compile(
    r"^[ \t]*\[no-postmortem:[ \t]*([^\n\]]+?)[ \t]*\][ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


# Sibling-parity defense: the [no-postmortem: <reason>] opt-out had
# the same placeholder-acceptance gap the four-field finding-response
# hook had. `[no-postmortem: <reason>]` literally would have satisfied
# the prior empty-reason check because `<reason>` is non-empty. Same
# defense: reject placeholder-shaped reasons.
# See scripts/check_finding_response.py for the helper's full
# rationale; duplicated here because the three hooks run as
# standalone scripts without a shared module.
_PLACEHOLDER_BRACKET_RE = re.compile(r"^\s*[<\[{].*[>\]}]\s*$")
_PLACEHOLDER_MARKER_RE = re.compile(
    r"^\s*(?:TODO|FIXME|XXX|TBD|\?+|\.{3,}|N/?A)\s*$",
    re.IGNORECASE,
)
_PLACEHOLDER_PHRASES: tuple[str, ...] = (
    "your text here",
    "fill me in",
    "fill in",
    "to be determined",
)


def _looks_like_placeholder(value: str) -> bool:
    """Reject template-placeholder-shaped values. See
    scripts/check_finding_response.py::_looks_like_placeholder
    for the canonical commentary."""
    stripped = value.strip()
    if not stripped:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(stripped):
        return True
    if _PLACEHOLDER_MARKER_RE.match(stripped):
        return True
    lower = stripped.lower()
    return any(phrase in lower for phrase in _PLACEHOLDER_PHRASES)


def _repo_root() -> Path:
    """Walk upward from CWD until a `.git` directory is found.
    The pre-commit framework runs us from the repo root by default,
    but be defensive."""
    p = Path.cwd().resolve()
    for cand in (p, *p.parents):
        if (cand / ".git").exists():
            return cand
    return p


def _path_is_staged_or_tracked(repo: Path, rel: str) -> bool:
    """Return True iff `rel` is in the index (staged for the pending
    commit) OR already tracked from a prior commit. Files that exist
    only in the working tree (untracked) return False — the contract
    is that postmortem references must be in the repo, not just on
    disk in the local checkout.

    2026-04-29 pass-7 P2 fix. Pre-pass-7 the hook accepted any
    postmortem path that existed on disk; an untracked postmortem
    file would slip through and the committed message would point at
    a file absent from history."""
    # `git ls-files --error-unmatch <rel>` exits 0 iff `rel` is a
    # tracked path in the repo's index (covers both already-tracked
    # files and newly-staged ones).
    try:
        r = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", rel],
            cwd=repo,
            capture_output=True,
            check=False,
        timeout=30,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _is_bug_fix_subject(subject: str) -> str | None:
    """Return the matching pattern's source string if subject looks
    like a bug-fix commit, else None."""
    for rx in _BUG_FIX_SUBJECT_PATTERNS:
        m = rx.search(subject)
        if m:
            return rx.pattern
    return None


def _is_merge_commit(message_lines: list[str]) -> bool:
    """Pre-commit's commit-msg hook runs on auto-generated merge
    messages too. They start with `Merge branch ` or `Merge pull
    request `; we skip them — merges don't introduce new bug fixes
    on their own."""
    if not message_lines:
        return False
    return message_lines[0].startswith(
        ("Merge branch ", "Merge pull request ", "Merge remote-tracking ")
    )


def _is_revert_commit(message_lines: list[str]) -> bool:
    """Reverts are bug-related (you only revert when something broke)
    BUT git auto-generates the message and forcing the operator to
    edit it is brittle. We require the postmortem in a follow-up
    commit instead. For now, skip auto-generated revert subjects."""
    if not message_lines:
        return False
    return message_lines[0].startswith("Revert ")


def _strip_comments(message: str) -> str:
    """Git's commit message file includes `# comment` lines that
    don't make it into the final commit. Strip them before scanning
    so an opt-out hidden in a comment doesn't satisfy the hook."""
    return "\n".join(
        line for line in message.splitlines() if not line.lstrip().startswith("#")
    )


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(
            "check-postmortem-for-bug-fix: usage: check_postmortem_for_bug_fix.py "
            "<commit-msg-file>",
            file=sys.stderr,
        )
        return 2
    msg_path = Path(args[0])
    if not msg_path.is_file():
        print(
            f"check-postmortem-for-bug-fix: commit-msg file not found: {msg_path}",
            file=sys.stderr,
        )
        return 2

    repo = _repo_root()
    raw = msg_path.read_text(encoding="utf-8")
    cleaned = _strip_comments(raw)
    lines = cleaned.splitlines()

    if not lines or not lines[0].strip():
        # Empty commit message — git itself will reject it; not our problem.
        return 0

    if _is_merge_commit(lines) or _is_revert_commit(lines):
        return 0

    subject = lines[0].strip()
    matched_pattern = _is_bug_fix_subject(subject)
    if matched_pattern is None:
        return 0

    # Scan the FULL message (subject + body) for either a postmortem
    # reference or the opt-out tag.
    full = cleaned

    # Opt-out path
    opt = _NO_POSTMORTEM_TAG.search(full)
    if opt:
        reason = opt.group(1).strip()
        if not reason:
            print(
                "check-postmortem-for-bug-fix: [no-postmortem:] tag is "
                "present but the reason is empty. Provide a brief reason "
                "(typo, rename, refactor, etc.) so the opt-out is "
                "auditable.",
                file=sys.stderr,
            )
            return 1
        if _looks_like_placeholder(reason):
            print(
                f"check-postmortem-for-bug-fix: [no-postmortem: {reason}] "
                "reason looks like an unfilled template placeholder "
                "(bracket-wrapped, TODO/FIXME marker, or a template-"
                "prompt phrase). Replace with a real reason.",
                file=sys.stderr,
            )
            return 1
        # Soft-warn so the operator at least sees the bypass on screen
        print(
            f"check-postmortem-for-bug-fix: bug-fix commit accepted with "
            f"[no-postmortem: {reason}]",
            file=sys.stderr,
        )
        return 0

    # Postmortem-reference path
    # 2026-04-29 pass-7 P2: a referenced postmortem must be
    # tracked OR staged — not just present in the working tree.
    # An untracked file would let the commit pass with a dangling
    # reference (the message points at a file absent from history).
    found_refs: list[str] = []
    untracked_refs: list[str] = []
    for m in _POSTMORTEM_REF.finditer(full):
        rel = m.group(0)
        if not (repo / rel).is_file():
            continue   # missing entirely — flagged separately below
        if _path_is_staged_or_tracked(repo, rel):
            found_refs.append(rel)
        else:
            untracked_refs.append(rel)
    if found_refs:
        return 0

    # Neither path satisfied — report and fail
    print(
        "check-postmortem-for-bug-fix: BUG-FIX COMMIT MISSING POSTMORTEM "
        "CROSS-LINK",
        file=sys.stderr,
    )
    print("=" * 72, file=sys.stderr)
    print(
        f"  subject:           {subject!r}\n"
        f"  matched pattern:   {matched_pattern}\n"
        f"  postmortem refs:   none found in body\n"
        f"  [no-postmortem:]:  not present",
        file=sys.stderr,
    )
    # Surface stale references too — a typo'd path is a frequent cause
    # and easier to fix once flagged
    typo_refs = [
        m.group(0)
        for m in _POSTMORTEM_REF.finditer(full)
        if not (repo / m.group(0)).is_file()
    ]
    if typo_refs:
        print(
            f"  body mentioned these paths but the files don't exist: "
            f"{typo_refs}",
            file=sys.stderr,
        )
    if untracked_refs:
        print(
            f"  body mentioned these paths but they're untracked "
            f"(not staged for this commit, not committed previously): "
            f"{untracked_refs}\n"
            "  Run `git add <path>` before committing — the commit-msg "
            "hook requires the postmortem to be in the repo, not just "
            "the working tree.",
            file=sys.stderr,
        )
    print(
        "\nFix one of:\n"
        "  1. Author or extend a postmortem in docs/postmortems/ "
        "(template at _template.md), then add a body line like:\n"
        "       Postmortem: docs/postmortems/<YYYY-MM-DD>-<slug>.md\n"
        "  2. If no postmortem is needed (typo, rename, refactor without\n"
        "     behavior change), add a tag with a brief reason:\n"
        "       [no-postmortem: <reason>]\n"
        "\n"
        "See AGENTS.md 'Bug fixes — WRITE A POSTMORTEM' for the protocol.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
