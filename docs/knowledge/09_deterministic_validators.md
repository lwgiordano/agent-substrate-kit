---
purpose: Deterministic validator layers, pinned copies, and append-only gates.
last_human_reviewed: 2026-09-06
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
fail-closed stub (return None, or raise), never a reimplementation. Two "same
algorithm" mirrors — `memory_log._safe_read_text` and
`session_handoff._safe_atomic_write` — were found two fixes behind the primitive
they copied, still opening the parent by multi-component path (the v3.8.44
window) with no post-op liveness check (v3.8.45). `_doc_common` is never stripped,
so those fallbacks were dead code in every profile; a fallback that runs an OLDER
guard is the fail-open shape a dropped guard has, only slower to notice.

A gate over an APPEND-ONLY record needs an additive remedy that the gate
actually implements. `check_history_sha.py` validates `docs/HISTORY.md`, which
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
SHA alone (v3.8.49) let a correction pre-forgive a bad SHA not yet recorded, and
let a corrected SHA appended again reuse the same retirement. In a SHALLOW clone
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
