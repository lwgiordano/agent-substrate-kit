#!/usr/bin/env python3
"""Calibrate DIY ultrareview against known-bug commits.

of the make-DIY-ultrareview-catch-more-bugs plan.

Loads a hand-curated list of known-bug commits from this project's
audit history (audit passes 6-13 + operator-driven rounds 10/13/17),
runs the round-17 domain detection on each, and verifies the detected
domains match the human-labeled expected domains.

This is regression-testing the DIY ultrareview itself: every time a
detection regex changes (was the most recent), the
calibration set re-validates that the past known bugs are still
correctly classified.

Recall and precision are reported separately:
  - Recall  = of the EXPECTED domains, how many did detection find?
  - Precision = of the DETECTED domains, how many were expected?

Run:  python3 scripts/calibrate_diy_ultrareview.py
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Import the production detection helper (— AST-based,
# replaces the regex-only fallback). Rule 13 sibling-parity:
# calibration uses the EXACT same detection logic as the commit-
# msg hook, so a regression in one is caught by the other.
sys.path.insert(0, str(REPO))
from scripts.check_finding_response import (  # noqa: E402
    _COMMIT_MSG_HOOK_FILES,
    _detect_python_uses,
)


@dataclass(frozen=True)
class CalibrationCommit:
    """A known-bug commit + the domains a perfect detector would
    surface for it. ``found_by`` records who originally caught the
    bug — for transparency on the calibration's source bias.

    added is_ground_truth: True means a HUMAN labeled
    expected_domains by reading the diff (the original 17 the audit tool /
    operator / self-audit entries). False means the entry was
    auto-curated by running detect_domains() on the commit and
    accepting the result (Phase 3.12's 33 added entries).

    Auto-curated entries are CIRCULAR — they lock current detector
    behavior, but a detector bug present today is locked in as
    'correct'. Ground-truth entries break the circularity: a detector
    regression on a ground-truth entry is a real bug.

    Calibration reports both recall numbers separately when --strict
    so operators can distinguish 'detector still passes its self-test'
    from 'detector still passes the human-labeled test.'"""

    sha: str
    title: str
    expected_domains: frozenset[str]
    found_by: str  # "external-audit" | "operator" | "self-audit (DIY ultrareview)"
    notes: str = ""
    is_ground_truth: bool = True  # default True (entries flip to False)


# Calibration set. Curated by reading docs/HISTORY.md +
# docs/postmortems/2026-04-29-postmortem-workflow-gaps.md +
# git log for external audit-pass commits.
#
# Add entries when:
#   1. A new audit finding lands → add the fix-commit here.
#   2. A self-audit (DIY ultrareview / steelman) finds something
#      → add the fix-commit here.
#   3. Detection-regex changes (etc.) → re-run calibration
#      to catch regressions.
CALIBRATION: tuple[CalibrationCommit, ...] = (
    # Add entries here as you find real bugs that exercise the
    # detection logic. Pattern (uncomment + adapt for a real commit):
    #
    # CalibrationCommit(
    #     sha="abc1234",                                           # short SHA of the fix-commit
    #     title="<commit subject>",
    #     expected_domains=frozenset({"regex", "yaml-parsing"}),   # human-labeled
    #     found_by="external-review",                              # who caught it
    #     notes="<what's noteworthy>",
    #     is_ground_truth=True,                                    # True for human-labeled
    # ),
    #
    # Set is_ground_truth=True for the first ~5-10 entries (you've
    # read the diff and labeled the domains manually). Auto-curated
    # entries (run detect_domains() over a commit and accept the
    # result) get is_ground_truth=False.
)


def _files_in_diff(sha: str) -> list[str]:
    """List files modified by <sha>. Uses <sha>~..<sha> to mirror
    the helper.sh single-ref auto-conversion."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{sha}~..{sha}"],
        cwd=REPO, capture_output=True, text=True, check=False,
    timeout=30,
    )
    if result.returncode != 0:
        return []
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]


def _file_content_at(sha: str, path: str) -> str:
    """Read the post-image of <path> at <sha>, or empty string."""
    result = subprocess.run(
        ["git", "show", f"{sha}:{path}"],
        cwd=REPO, capture_output=True, text=True, check=False,
    timeout=30,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def detect_domains(sha: str) -> set[str]:
    """Apply the round-17 / Phase-2.5 detection rules to the diff
    introduced by <sha>. Returns the set of detected domains."""
    domains: set[str] = set()
    for f in _files_in_diff(sha):
        if f in _COMMIT_MSG_HOOK_FILES:
            domains.add("commit-msg-hooks")
        if f.endswith((".yaml", ".yml")):
            domains.add("yaml-parsing")
        if f.endswith(".py"):
            content = _file_content_at(sha, f)
            uses_re, uses_yaml, uses_ast = _detect_python_uses(content)
            if uses_re:
                domains.add("regex")
            if uses_yaml:
                domains.add("yaml-parsing")
            if uses_ast:
                domains.add("ast-parsing")
    return domains


def calibrate(*, strict: bool = False) -> int:
    """Run calibration and print a report.

    Returns 0 in lenient mode (default) if no recall miss surfaces;
    extras (precision regressions) print a warning but don't fail.

    Returns 0 in strict mode (--strict, pre-commit hook usage) only
    if all calibration commits are perfect — any miss OR extra fails.
    Strict mode is for the pre-commit gate so a detection-regex
    tweak that silently regresses precision is caught at commit
    time. Operator's manual runs default to lenient so a temporary
    extra (e.g., during incremental refactor) doesn't block them.
    """

    print("=" * 70)
    print(f"DIY ultrareview calibration — (strict={strict})")
    print("=" * 70)
    n_total = len(CALIBRATION)
    if n_total == 0:
        # Empty CALIBRATION is the default kit shipping state. Nothing
        # to regress against until the operator populates entries
        # (see customization.md §"calibrate_diy_ultrareview.py").
        print("Calibration set: empty (no known-bug commits curated yet).")
        print()
        print("  Skipped: populate CALIBRATION with entries from your")
        print("  HISTORY/postmortems to enable detection regression-testing.")
        print("  See customization.md for the pattern.")
        return 0
    n_ground = sum(1 for cc in CALIBRATION if cc.is_ground_truth)
    n_locked = n_total - n_ground
    print(f"Calibration set: {n_total} known-bug commits "
          f"({n_ground} ground-truth + {n_locked} locked-current-behavior)")
    print()

    perfect = 0
    miss_count = 0  # expected but not detected
    extra_count = 0  # detected but not expected
    misses_by_domain: dict[str, int] = {}
    extras_by_domain: dict[str, int] = {}
    # track ground-truth pool separately. A locked-current-
    # behavior miss is a regression on a self-locked claim (still useful
    # but circular). A ground-truth miss is a real detection regression
    # on a human-labeled commit — that's the load-bearing signal.
    gt_perfect = 0
    gt_miss_count = 0

    for cc in CALIBRATION:
        detected = detect_domains(cc.sha)
        expected = set(cc.expected_domains)
        missing = expected - detected
        extra = detected - expected

        symbol = "✓" if (not missing and not extra) else "✗"
        print(f"  {symbol} {cc.sha[:7]}  ({cc.found_by:^25s})  {cc.title[:55]}")
        print(f"        expected: {sorted(expected) or '∅'}")
        print(f"        detected: {sorted(detected) or '∅'}")
        if missing:
            print(f"        MISSED:   {sorted(missing)}")
            for d in missing:
                misses_by_domain[d] = misses_by_domain.get(d, 0) + 1
            miss_count += 1
            if cc.is_ground_truth:
                gt_miss_count += 1
        if extra:
            print(f"        EXTRA:    {sorted(extra)}")
            for d in extra:
                extras_by_domain[d] = extras_by_domain.get(d, 0) + 1
            extra_count += 1
        if not missing and not extra:
            perfect += 1
            if cc.is_ground_truth:
                gt_perfect += 1
        if cc.notes:
            print(f"        notes:    {cc.notes}")
        print()

    print("=" * 70)
    print("Summary")
    print("=" * 70)
    n = len(CALIBRATION)
    print(f"  Perfect:          {perfect:>2d}/{n} ({100 * perfect // n}%)")
    print(f"  Misses (recall):  {n - miss_count:>2d}/{n} commits no missed domain")
    print(f"  Extras (precision): {n - extra_count:>2d}/{n} commits no extra domain")
    if n_ground:
        gt_pct = 100 * gt_perfect // n_ground
        print()
        print(f"  Ground-truth pool ({n_ground} human-labeled commits — "
              f"breaks circularity):")
        print(f"    Perfect:        {gt_perfect:>2d}/{n_ground} ({gt_pct}%)")
        print(f"    Misses:         {gt_miss_count:>2d} (load-bearing — a "
              f"regression here is a real detector bug)")
    if misses_by_domain:
        print(f"  Missed-domain frequency:  {dict(misses_by_domain)}")
    if extras_by_domain:
        print(f"  Extra-domain frequency:   {dict(extras_by_domain)}")
    print()

    if miss_count == 0 and extra_count == 0:
        print(f"  Detection is calibrated against history — all "
              f"{n}/{n} perfect.")
        return 0
    if miss_count > 0:
        print(f"  WARN: {miss_count} commits have MISSED domains. The "
              "detection is too narrow on these.")
    if extra_count > 0:
        print(f"  INFO: {extra_count} commits have EXTRA domains. False-"
              "positives — usually safe (extra-conservative checklist "
              "nudges) but worth tracking trend.")
    if strict and (miss_count > 0 or extra_count > 0):
        print()
        print("  STRICT MODE: any miss or extra fails. Pre-commit will "
              "block this commit. Update calibration labels in "
              "scripts/calibrate_diy_ultrareview.py CALIBRATION list "
              "if the detection change is intentional.")
        return 1
    return 1 if miss_count > 0 else 0


if __name__ == "__main__":
    strict_mode = "--strict" in sys.argv
    sys.exit(calibrate(strict=strict_mode))
