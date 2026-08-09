# Substrate Knowledge Boundaries and Integration Hardening

**Status:** Approved design; implementation pending operator review of this file

**Date:** 2026-07-30

**Release target:** v3.8.32+

**Scope:** Source-repository knowledge organization and its deterministic
integration checks

## Goal

Replace the 936-line, 78,446-byte (`~19,612` estimated tokens)
`docs/knowledge/00_substrate.md` with a compact entry point and seven
function-oriented knowledge documents. The result must improve progressive
disclosure without weakening documentation coverage, declarative claims, consumer
installation behavior, harness scanning, or append-only project history.

The audit found four integration defects that require code changes alongside
the document split:

1. staged covered shell/config files do not trigger documentation review;
2. the context budget reports only knowledge docs that happen to appear in its
   global top-ten contributors;
3. the harness scans all knowledge siblings but its negative-control smoke test
   exercises only `00_substrate.md`; and
4. `docs/superpowers/**/*.md` stores agent-execution plans but is absent from
   the canonical context and ownership inventory.

The release closes those defects as part of the same unit so the new boundaries
are enforced by running code rather than described only in prose.

## Current-State Evidence

- Source `docs/knowledge/00_substrate.md` contains the whole release narrative,
  eleven declarative `asserts`, and coverage for the substrate script surface.
- `bootstrap.sh` does not copy the source document into consumers. It generates
  a compact consumer-local `docs/knowledge/00_substrate.md` from the installed
  `scripts/` inventory. Source-only sibling docs therefore need not be packaged.
- `scripts/substrate_upgrade.py` likewise treats the generated consumer
  `00_substrate.md` as the installed knowledge artifact.
- `scripts/check_doc_drift.py` accepts many-to-many `covers` relationships, but
  `_staged_code()` filters staged paths through `CODE_SUFFIXES`. A staged covered
  `.sh`, JSON, YAML, or extensionless configuration path can therefore evade the
  pending-review check.
- `scripts/context_report.py` discovers all knowledge docs for its aggregate
  on-demand size, but `_budget()` derives per-document rows from
  `largest_contributors`, which is capped at ten. A disposable repository with
  twelve oversized knowledge docs reported only ten rows.
- `scripts/check_agent_harness.py` scans all non-template knowledge siblings.
  `scripts/check_harness_smoke.py` injects only the hard-coded
  `docs/knowledge/00_substrate.md`, leaving sibling scanning without a behavioral
  negative control.
- The Superpowers workflow requires plans and specs under `docs/superpowers/`.
  Those files can direct later agent execution, but `_substrate_surfaces.py`
  neither scans them as context nor requires ownership when the directory is
  present. A disposable-repository payload in that path passed the real harness.
- v3.8.31 already fixed concurrent HISTORY and REJECTED appends through
  `_doc_common.locked_atomic_append`. The split must carry its new declarative
  assertion and release knowledge into `03_memory_sessions.md`; it must not
  reopen or duplicate that shipped implementation.

## Document Architecture

### Stable entry point

`docs/knowledge/00_substrate.md` remains the source repository's stable starting
point. It becomes a compact orientation document containing:

- the substrate's purpose and source-of-truth order;
- the local, remote-governance, sandbox, and release trust boundaries;
- a functional index to the seven sibling documents;
- explicit notice that those siblings are kit-source documentation, while a
  consumer install intentionally receives one generated local
  `00_substrate.md`;
- links to `CHANGES_V3.md` for pre-v3.8 chronology and `docs/HISTORY.md` for
  v3.8+ release chronology; and
- cross-cutting limitations that do not belong to only one subsystem.

It must stand alone sensibly if read without following a link. The source-only
links are supplements, not prerequisites for understanding the installed
contract.

### Function-oriented siblings

The source repository adds these non-template siblings:

| Document | Responsibility |
|---|---|
| `01_install_adoption.md` | Bootstrap, generated consumer files, profiles/languages/runners, adoption into existing repositories, setup/doctor, and installer write safety |
| `02_upgrade_integrity.md` | Source verification, drift baselines, authority/capability floors, trusted execution, upgrade transactions, postconditions, and known upgrade integrity limits |
| `03_memory_sessions.md` | Hash-chained memory, verification signatures, session capture/restore, HISTORY/REJECTED injection, completion gate, and append-only log behavior |
| `04_policy_governance.md` | Command policy, hooks, validator wiring, remote governance, sandbox/exfil controls, CODEOWNERS, and trusted-base enforcement |
| `05_evals_assurance.md` | Malicious/benign corpus semantics, behavioral smoke checks, deterministic assertion gates, audit layers, and measured assurance limits |
| `06_release_distribution.md` | Packaging, manifests, signatures, release verification, distribution artifacts, and release gate behavior |
| `07_agent_context_governance.md` | Agent-facing instruction surfaces, injection scanning, context budgets, doc drift, progressive disclosure, and harness parity |

Install and adoption remain together because adoption is the installation
contract applied to a non-empty repository. Evals and release distribution stay
separate because measured policy behavior and artifact provenance have different
failure modes, operators, and change cadence.

## Front Matter and Coverage

Every knowledge document retains the existing front-matter schema:

```yaml
---
purpose: <one functional responsibility>
asserts:
  - path::substring
last_human_reviewed: 2026-07-30
covers:
  - repo/relative/path
---
```

Coverage is deliberately many-to-many. A root entry point or helper appears in
every document whose claims depend on it; there is no artificial single-owner
rule. In particular:

- `bootstrap.sh` is covered by install/adoption and any policy, context, or
  distribution document whose installed behavior it renders;
- `manage.sh` is covered wherever its command routing is part of the contract;
- `package_release.sh` is covered by release/distribution and any install or
  verification document that depends on the package boundary.

Every existing covered path remains covered by at least one migrated document,
and every new or changed governed source path is covered before release.
`scripts/update_manifest.py --fix` is the only mechanism used to register the
new knowledge docs in `docs/manifest.json`.

The existing eleven declarative assertions are preserved exactly and redistributed
by responsibility:

- `01_install_adoption.md`
  - `bootstrap.sh::_safe_mkdir_p`
  - `bootstrap.sh::wappend`
  - `scripts/run_python_gate.sh::_ruff_args`
- `02_upgrade_integrity.md`
  - `scripts/substrate_upgrade.py::_exec_module_from_source`
  - `scripts/substrate_upgrade.py::_apply_capability_floor`
- `03_memory_sessions.md`
  - `scripts/memory_log.py::_raw_tracked_hash`
  - `scripts/memory_log.py::_write_tree_oid`
  - `scripts/_doc_common.py::locked_atomic_append`
  - `scripts/session_handoff.py::_safe_history_line`
  - `scripts/session_handoff.py::_rejected_block`
- `04_policy_governance.md`
  - `scripts/command_policy.py::looks_dangerous_command`

No assertion may be silently dropped, weakened, or replaced with executable
content from Markdown.

## Consumer Boundary

The seven functional siblings and the source index are source-repository
documentation. Consumer installation remains intentionally compact:

1. bootstrap creates one local `docs/knowledge/00_substrate.md`;
2. its front matter covers the scripts actually installed in that consumer;
3. upgrade continues to treat that generated file as the installed knowledge
   artifact; and
4. no new source sibling is added to the release overwrite set or owned-file
   baseline.

Tests must distinguish these two modes explicitly. A source checkout must contain
and validate all eight documents. A freshly bootstrapped disposable consumer must
contain only the generated `00_substrate.md` unless the consumer already owns
additional knowledge docs.

## Integration Changes

### Staged documentation review

`check_doc_drift` must separate two concepts:

- **module discovery:** which source files require at least one knowledge cover;
- **staged covered-path review:** whether any staged path already named in a
  document's `covers` changed without that document being reviewed.

The staged review must not be limited by `CODE_SUFFIXES`. A staged existing file
that appears in `covers` must participate regardless of suffix, including shell,
JSON, YAML, workflow, and extensionless configuration files. Deleted/renamed
paths must be handled deliberately rather than disappearing through an
`exists()` filter. Module-discovery coverage rules remain bounded by the existing
source inventory so the change does not turn every arbitrary repository file
into a required knowledge document.

### Complete knowledge budget enumeration

`context_report` keeps the global top-ten contributor list as a compact summary,
but knowledge budget rows are computed directly from the full, sorted
`docs/knowledge/*.md` inventory. The human and JSON forms must report every
non-template knowledge doc over the configured per-document budget. Ordering is
deterministic: estimated tokens descending, then path ascending.

The release may promote the per-document limit from warning-only to enforced only
after the source split is green. If promoted, enforcement applies to every
non-template knowledge doc, including `00_substrate.md`, with the existing
environment override retained for controlled tests.

### Harness behavioral parity

The harness smoke test must exercise a dynamically named sibling knowledge
document in addition to the stable entry point. Its disposable repository should
prove that the actual scanner blocks injection text in:

- the root instruction surface;
- HISTORY;
- `docs/knowledge/00_substrate.md`; and
- another non-template `docs/knowledge/*.md` sibling; and
- an arbitrary `docs/superpowers/plans/*.md` execution plan.

The sibling name must not be added as a one-off scanner special case. The smoke
test validates the same discovery rule used by the production scanner.

### Agent-plan surface governance

The canonical substrate inventory adds `docs/superpowers/**/*.md` to context
scanning. `docs/superpowers` becomes an optional-owned directory: source repos
and projects that use the workflow require CODEOWNER coverage, while consumer
repos that do not create the directory remain valid. The audit-trigger paths
continue to derive from that inventory.

## Decision Record

Implementation adds
`docs/decisions/0001-substrate-knowledge-boundaries.md` with status Accepted.
The ADR records:

- functional rather than chronological partitioning;
- stable source entry point plus source-only detail documents;
- intentional compact consumer boundary;
- many-to-many coverage;
- deterministic integration enforcement; and
- the cost of maintaining cross-links and distributed coverage metadata.

The ADR's rejected alternatives match the append-only rejection log:

- chronological/version-range files, rejected because they optimize release
  narration rather than current subsystem lookup; and
- retaining one file with prose trimming, rejected because it leaves unrelated
  change domains coupled and recreates the size problem.

## Verification and Acceptance

Implementation is not complete until all of these are proven:

### Document migration

- the source checkout has exactly the stable entry point and the seven named
  functional siblings, excluding `_template.md`;
- every document has valid front matter, a distinct purpose, working internal
  links, and no unresolved placeholder;
- the union of new `covers` includes every old covered path;
- all eleven assertion strings exist exactly once in the intended functional
  docs;
- explicit trust boundaries and known limitations survive the migration;
- each document is within the configured token budget; and
- the generated manifest matches disk.

### Behavioral regressions

- staging a covered `.sh`, JSON/YAML, or extensionless config change without its
  doc produces a pending-review finding;
- staging the covering doc clears that finding without weakening coverage;
- twelve oversized knowledge docs produce twelve budget rows, not ten;
- a randomized injection in a non-`00` knowledge sibling is blocked by the real
  scanner;
- a randomized injection in a Superpowers execution plan is blocked by the real
  scanner and the directory is optional-owned when present;
- a bootstrapped consumer contains the generated compact `00_substrate.md`
  without source-only siblings.

### Full gates

- focused tests for document consistency, hook scripts, bootstrap packaging, and
  harness smoke pass;
- `python scripts/update_manifest.py --fix` produces no unstaged follow-up;
- `./manage.sh check` exits `0`;
- `./manage.sh evals` reports every malicious case blocked and zero benign false
  positives;
- `./manage.sh release` verifies the built artifact;
- the `self-audit` skill is recorded after the final project-file change; and
- documentation, test, harness, architecture, and security auditors report no
  unresolved BLOCK.

## Release and History Discipline

The implementation ships as one coherent v3.8.32+ release unit:

1. land code, tests, split docs, ADR, version/readme/benchmark updates, and the
   generated manifest;
2. run the full deterministic gates and auditors;
3. commit that finished unit without bypassing hooks;
4. append HISTORY with `scripts/append_history.py --commit-hash <landed-sha>`;
5. commit the append-only HISTORY entry separately;
6. post a bus RELEASE summarizing results and known limitations; and
7. push each finished commit without squashing published history.

The design-spec commit itself is documentation of the approved direction, not a
claim that v3.8.32 is implemented.

## Non-Goals

- Changing the documented v3.8.24 upgrade-baseline limitation without a locally
  enforceable integrity anchor.
- Reworking the v3.8.31 append-log serialization that already passed its focused
  regressions, full gate, evals, and release matrix.
- Packaging the seven source-only knowledge siblings into consumer repositories.
- Rewriting historical HISTORY or CHANGES entries.
- Executing commands declared in Markdown.
- Replacing deterministic gates with model judgment.
- Expanding the source-module coverage inventory to arbitrary product files.
