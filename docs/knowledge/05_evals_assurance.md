---
purpose: Behavioral evals, deterministic validators, audits, and assurance limits.
last_human_reviewed: 2026-08-25
covers:
  - manage.sh
  - extras/calibrate_diy_ultrareview.py
  - extras/check_license_headers.py
  - extras/check_stale_phrases.py
  - scripts/agent_system_audit.sh
  - scripts/build_review_bundle.py
  - scripts/check_bandit_skip_baseline.py
  - scripts/check_coverage_floors.py
  - scripts/check_finding_response.py
  - scripts/check_harness_patterns.py
  - scripts/check_harness_smoke.py
  - scripts/check_history_sha.py
  - scripts/check_import_shadowing.py
  - scripts/check_policy_code_integrity.py
  - scripts/check_postmortem_for_bug_fix.py
  - scripts/check_postmortem_gates_resolved.py
  - scripts/check_python_syntax.py
  - scripts/check_secrets.py
  - scripts/check_validator_input_coverage.py
  - scripts/code_shape.py
  - scripts/diy_ultrareview.sh
  - scripts/run_security_scanners.py
  - scripts/run_smoke_verification.py
  - scripts/run_substrate_evals.py
  - scripts/substrate_audit.py
---

# Evals and assurance

[Back to the substrate map](00_substrate.md).

`manage.sh check` proves structure and deterministic test outcomes.
`manage.sh evals` proves policy behavior against malicious and benign tasks. A
release is green only when malicious tasks block, benign tasks remain allowed,
and any required containment task actually runs.

## Eval semantics

Each eval records `ok`, `status`, and detail. A task that cannot run because a
backend is absent reports `status=skipped` and `ok=null`; it is excluded from the
block-rate numerator and denominator. Requiring sandbox evals converts that skip
into failure. The single-task diagnostic uses the same semantics.

The benign corpus tests false positives in real kit and consumer layouts.
Staged fixtures resolve both source assets and their installed `.substrate`
locations. A missing required fixture is an error, not a vacuous pass.

A hang is a failure, not a pending result. Tasks that exercise a blocking shape
(a FIFO in place of a lock, a log, or a governed surface) assert that the tool
fails fast inside the per-subprocess cap, and a `TimeoutExpired` is reported as
a failed block rather than allowed to wedge the run. Evidence-suppression
attacks are in the malicious corpus for the same reason a bypass is: an eval
covers the gate that reads forged evidence, not only the gate that writes it.

`evals --report` regenerates `BENCHMARK.md` with version, counts, surfaced skips,
and a reproduction command. Exact commit, source-tree, and artifact provenance
belongs to the release manifest rather than a mutable pre-commit hash embedded in
the benchmark.

## Deterministic assurance layers

Syntax checks, configuration validation, secret scanning, policy AST pins,
coverage floors, import-shadowing detection, doc assertions, hook smoke tests,
and the real agent-context scanner form separate layers. The harness smoke uses
randomized encoded families and runs the actual scanner against disposable
context. Each governed surface must block independently so a working root scan
cannot mask an ignored sibling.

`code_shape.py` reports reviewability risks in project code while excluding the
vendored substrate and generated caches. Governance-only diffs remain visible.
Its governance classification includes governed project context such as
knowledge siblings and Superpowers plans even though those files are not
substrate-owned for upgrade purposes.
Finding-response and postmortem gates connect significant fixes to regression
evidence without asking a model to decide whether code is correct.

Deep security scanners and dependency cooldown require explicit availability and
configuration. Advisory tools cannot upgrade missing evidence into a pass.
Auditor agents add independent review, but their verdicts supplement rather than
replace deterministic gates.

The eval corpus measures its listed attacks and benign tasks. A perfect reported
rate is not a proof against unmodeled classes, host compromise, or an attacker
who can replace the gate and every integrity anchor together.
