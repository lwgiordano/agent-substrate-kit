---
date: YYYY-MM-DD
severity: low | medium | high | critical | meta
caught_by: external-audit | self-audit | operator | runtime
related_commits:
  - <SHA-or-WORKING> (<short-description>)
related_audit_entries:
  - <slug from AUDIT_REGRESSIONS.yaml — optional, project-specific>
gates_added:
  - <e.g. scripts/check_X.py STALE_PHRASES entry>
  - <e.g. tests/test_validator_Y.py::test_Z>
---

# YYYY-MM-DD — <slug>

<!--
This is the canonical per-bug postmortem template. Use it for any
non-trivial bug, audit finding, or near-miss you want future
sessions to learn from. Modeled on `docs/decisions/0000-template.md`.

The YAML front-matter MUST be the first thing in the file (above
this comment, above the title). `scripts/_doc_common.parse_front_matter`
only matches `---` blocks at file start. The
`gates_added:` field is required by `check_postmortem_gates_resolved`.

Filename convention: `YYYY-MM-DD-<short-slug>.md` (date is when the
bug was caught, not necessarily when fixed).

Required sections: What, Why, Why our tooling didn't catch it,
Preventative gate added, Carry-forward rule. Free-form sections
(e.g. "Diagnosis," "Reproduction," "Round 2 / Round 3" if the
finding recurred) may be added below.

Cross-link contract (project-specific, optional): if your project
maintains an audit-regressions registry (e.g.,
`docs/AUDIT_REGRESSIONS.yaml`), every postmortem should be referenced
from at least one entry in that registry via a `lessons:` field, e.g.
    lessons:
      - postmortem: "docs/postmortems/YYYY-MM-DD-X.md"
        section: "carry-forward-rule"
The kit does NOT ship an audit-regressions validator (project-
specific). Author one following the four-step pattern in
docs/Agent Substrate Kit/customization.md if you want this cross-link
enforced. Without it, postmortems are still useful — the registry
just isn't auto-validated.
-->

## What happened

One short paragraph: what was wrong, where it lived, what surface it
affected. Lead with concrete artifacts (file paths, function names,
SHAs). A reader who skims only this section should know the shape
of the bug.

## Why it happened

Root cause, not the proximate symptom. If "I scoped the fix too
narrowly" or "I trusted a load-bearing claim without verifying," say
so. Diagnose the human / process / tooling failure that allowed the
bug to land.

If multi-cause, list them. The strongest postmortems name a
**meta-pattern** — the class of bug, not just the instance.

## Why our tooling didn't catch it

The repo has many gates (pre-commit, audit-routing, validators).
Either:

- A gate exists but is configured wrong → name the gate, name the
  config gap.
- No gate exists for this class → say what gate would have caught it.
- The gate exists but ran but its check was incomplete → name what
  the check missed.

If "the gate fired but I dismissed the signal," say so — that's a
discipline failure, not a tooling failure, and a structural
defense (forcing function in the hook itself) is needed.

## Preventative gate added

The fix has two parts: the **fix** (closing the immediate bug) and
the **gate** (preventing recurrence). Document the gate here:

- **Validator addition / extension:** new `scripts/check_X.py`, new
  entry in `STALE_PHRASES`, new regex in `check_stale_terminology.py`,
  etc.
- **Test addition:** new `tests/test_X.py::test_Y` that fails on
  the bug pattern.
- **Doc edit + drift catcher:** if the fix is documentation, point at
  the validator that prevents redrift.

If you can't add a gate, EXPLAIN WHY in this section. "Hard to
gate" is acceptable when the bug class is genuinely unguardable;
"didn't have time" is not.

## Carry-forward rule

One short, imperative sentence the next session can apply blindly.
Examples:

- "When fixing a stale-claim finding in file F, read the entire
  file F, not just the section the symptom lives in."
- "When adding a contract check, enumerate the FULL contract before
  the commit lands — not just the part that closes the immediate
  finding."

The rule is the load-bearing part of this postmortem. If you can't
state one, the postmortem isn't done. Vague rules ("be careful with
allowlists") fail the test; specific habits ("grep `<pattern>` in
the whole repo before committing") pass.

## (Optional) Reproduction

How to reproduce the bug from a clean checkout. Sometimes critical
for class-of-bug postmortems. Skip for one-off catches where the
fix-commit diff is enough.

## (Optional) Diagnosis trail

What you tried, what was wrong about each guess, what unblocked
you. Useful for the bug classes where future sessions are likely
to chase the same wrong leads.
