---
purpose: Deterministic validator layers, pinned copies, and append-only gates.
last_human_reviewed: 2026-10-31
covers:
  - extras/check_license_headers.py
  - extras/check_stale_phrases.py
  - scripts/check_bandit_skip_baseline.py
  - scripts/check_coverage_floors.py
  - scripts/check_harness_patterns.py
  - scripts/check_harness_smoke.py
  - scripts/check_history_sha.py
  - scripts/check_import_shadowing.py
  - scripts/check_policy_code_integrity.py
  - scripts/check_python_syntax.py
  - scripts/check_leaks.py
  - scripts/check_secrets.py
  - scripts/code_shape.py
  - scripts/run_security_scanners.py
---

# Deterministic validators

[Back to the substrate map](00_substrate.md). The behavioural corpus that runs
beside these layers is in [evals and assurance](05_evals_assurance.md).

Syntax checks, configuration validation, secret scanning, policy AST pins,
coverage floors, import-shadowing detection, doc assertions, hook smoke tests,
and the real agent-context scanner form separate layers. The harness smoke uses
randomized encoded families and runs the actual scanner against disposable
context. Each governed surface must block independently so a working root scan
cannot mask an ignored sibling.

The credential-pattern scanner is `check_leaks.py`. A name matching the
substrate's own read deny rule or the exfil guard's sensitive-path pattern would
stop an agent reading or running the kit's scanner source, so the scanner's name
avoids both rather than either guard being weakened. The old path is a `runpy` shim so
configs that still name it keep working, and a test derives the protected
names from the deny rules and the command policy so no substrate file wears
one again. The scan skips nested session worktrees.

`code_shape.py` reports reviewability risks in project code while excluding the
vendored substrate and generated caches. Governance-only diffs remain visible.
Its governance classification includes governed project context such as
knowledge siblings and Superpowers plans even though those files are not
substrate-owned for upgrade purposes.
Finding-response and postmortem gates connect significant fixes to regression
evidence without asking a model to decide whether code is correct.

Copies of a shared definition are pinned, not trusted. The canonical surface
inventory in `_substrate_surfaces.py` has three hand-maintained fallbacks for a
stripped install — `substrate_doctor.py`, `write_install_json.py`, and
`code_shape.py` — and each is either byte-parity with canonical or an explicitly
documented divergence, enforced by a discovery test that fails on an unclassified
copy. The same lock-down now covers the `_doc_common` safety primitives: every
`except: def _safe_*` fallback behind a `from _doc_common import` must be a
fail-closed stub (return None, or raise), never a reimplementation. A "same
algorithm" mirror drifts behind the primitive it copies: a fallback that opens
the parent by multi-component path, or skips the post-op liveness check, runs an
OLDER guard, which is the fail-open shape a dropped guard has, only slower to
notice. `_doc_common` is never stripped, so such fallbacks would be dead code in
every profile anyway.

A gate over an APPEND-ONLY record needs an additive remedy that the gate
actually implements. `check_history_sha.py` requires local proof for new or
modified `shipped-green` claims, reports unchanged committed imports with
unavailable proof as unverified-here, and still refuses invalid local evidence.
It reads a missing label as
`unverified` (a required label could not be cleared after a union merge), and
`check_lessons.py` requires every test or gate lesson's evidence to exist
([lessons, records, and recall](10_lessons_recall.md)). `check_history_sha.py` validates `docs/HISTORY.md`, which
must never be edited, so the only permitted fix for a wrong SHA is a further
entry. It printed exactly that advice from the start and ignored it — the
`Correction` marker was counted and skipped with no pairing — so a repository
that recorded an unresolvable SHA was red forever with no route the tooling
allowed. Since v3.8.49 an entry whose third field is `Correction-of-<sha>`
supersedes the unresolvable-SHA finding for that SHA alone. The hatch is
deliberately narrow: it never silences the future-dated finding, a correction
naming a SHA no EARLIER entry references is itself drift, and a correction
naming a SHA that resolves is itself drift. Superseding is bound to entry
ORDER — a correction clears only entries written above it. Keying the hatch by
SHA alone would let a correction pre-forgive a bad SHA not yet recorded, and let
a corrected SHA appended again reuse the same retirement. In a SHALLOW clone
the gate refuses to judge at all (exit 2, naming `git fetch --unshallow`): every
SHA older than the fetch boundary is an absent object, not drift, and printing the
append-a-Correction remedy there would corrupt HISTORY permanently once a full
clone resolved those SHAs. The same shape is handled for `AGENT_BUS.md` by
the harness scanner's legacy line-and-content-hash evidence pairs.

Deep security scanners and dependency cooldown require explicit availability and
configuration. Advisory tools cannot upgrade missing evidence into a pass.
Auditor agents add independent review, but their verdicts supplement rather than
replace deterministic gates.

The eval corpus measures its listed attacks and benign tasks. A perfect reported
rate is not a proof against unmodeled classes, host compromise, or an attacker
who can replace the gate and every integrity anchor together.
