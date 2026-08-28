---
date: 2026-08-10
severity: medium
caught_by: self-audit
related_commits:
  - WORKING (v3.8.32 knowledge ownership migration)
related_audit_entries: []
gates_added:
  - tests/test_hook_scripts.py::test_new_kit_engine_retires_legacy_project_knowledge_baseline
  - tests/test_hook_scripts.py::test_upgrade_still_blocks_drift_in_installed_knowledge_files
  - tests/test_hook_scripts.py::test_upgrade_non_string_hash_is_not_a_vouch
  - tests/test_hook_scripts.py::test_upgrade_missing_baseline_coverage_aborts_before_render
  - tests/test_hook_scripts.py::test_upgrade_missing_canonical_inventory_aborts_before_render
---

# 2026-08-10 — Knowledge ownership migration

## What happened

The v3.8.32 knowledge split correctly stopped new installs from adding
project-authored `docs/knowledge/*.md` siblings to provenance, but
`scripts/substrate_upgrade.py::_drifted` still trusted those entries when they
already existed in a pre-v3.8.32 baseline. The first upgrade therefore rejected
an ordinary project-knowledge edit unless the operator supplied broad `--force`.
The same review found that a forged non-string hash value was skipped during
comparison but its path was still counted as vouched, allowing local machinery
drift to be overwritten without `--force`.

## Why it happened

The ownership change was modeled only as a new-state invariant. We proved fresh
install and repeated-upgrade behavior after v3.8.32, but did not model the old
serialized baseline or old installed upgrader as inputs. The same stale entries
fed both drift comparison and owned-destination safety, so fixing only the
reported hash mismatch would have left the class incomplete. Separately, the
code treated membership in the serialized map as equivalent to a validated
path/hash pair even after rejecting the value's type.
The first canonical-coverage refactor then treated an unavailable new-kit writer
as “skip completeness,” so malformed provenance could again survive until after
the render had already run.
Its first structural validator was also circular: a writer using its duplicated
fallback constants could agree with itself when the canonical inventory was
missing.

## Why our tooling didn't catch it

The original consumer regression bootstrapped with the new writer, then created
project context. The first migration regression fabricated an old map but still
called the newly installed target engine. Neither test exercised the temporal
ordering of a real upgrade, where the old target CLI runs old code before new
code can install. The architecture auditor reproduced that ordering failure.
No regression supplied a malformed value inside an otherwise valid drift map,
so the split validation and completeness paths were never forced to agree.
The first fix tested valid new-kit coverage only and did not exercise an absent
or unusable canonical provenance writer.
The next regression used only a missing writer, not a present self-consistent
writer whose canonical `_substrate_surfaces.py` dependency was absent.

## Preventative gate added

`test_new_kit_engine_retires_legacy_project_knowledge_baseline` inserts regular
and in-repo-symlink project knowledge into a real consumer's baseline, then
invokes the new kit engine externally against that old target. It requires a
no-force upgrade to preserve both paths and remove their obsolete provenance
entries. The paired installed-file regression requires drift in both exact
installed knowledge artifacts to remain blocking, preventing an overly broad
migration exemption. `test_upgrade_non_string_hash_is_not_a_vouch` sets an exact
installed file's hash to `null` and proves upgrade refuses while preserving the
local edit. Operator docs pin the one-time new-engine command and explain why an
old target or scheduled workflow cannot cross the boundary transparently.
`test_upgrade_missing_baseline_coverage_aborts_before_render` supplies a kit
whose bootstrap writes a sentinel but whose provenance writer is absent; even
with `--force`, upgrade must exit 2 without creating the sentinel.
`test_upgrade_missing_canonical_inventory_aborts_before_render` proves the
writer's own fallback cannot replace the selected kit's canonical inventory.

## Carry-forward rule

When changing a serialized ownership boundary, test the previous executable and
serialized state separately, and require every map consumer to accept only the
same fully validated key/value pairs.

## Reproduction

Bootstrap a consumer, add the SHA-256 of `docs/knowledge/project.md` to
`.substrate/install.json`, edit that document, and run an upgrade without
`--force`. Before the fix, upgrade exits 2 and reports the project document as
locally modified machinery.
