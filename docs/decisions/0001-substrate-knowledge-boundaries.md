# 0001: Functional boundaries for substrate knowledge

**Status:** Accepted
**Date:** 2026-08-09
**Deciders:** operator, Codex
**Related:** [Design specification](../superpowers/specs/2026-07-30-substrate-knowledge-split-design.md)

## Context

The source substrate knowledge file grew to about 20,000 estimated tokens because
it accumulated release chronology for unrelated subsystems. The on-demand model
could avoid loading the file, but any task that needed one contract paid for all
of them. The v3.8.30 budget named the problem without blocking existing installs.

The source and consumer layouts differ. Source maintainers need detailed current
contracts; consumer repositories need a compact local inventory of the scripts
actually installed there.

## Decision

Keep `docs/knowledge/00_substrate.md` as the stable source entry point. Split
detail into seven source-only documents organized by function: installation,
upgrade, memory, policy, assurance, release, and agent context.

Bootstrap and upgrade continue to generate and own only the compact consumer
`docs/knowledge/00_substrate.md` plus `docs/knowledge/_template.md`. Coverage remains
many-to-many, including root entrypoints
where their behavior supports several contracts. Deterministic tests pin the
document names, purposes, assertions, links, size limit, complete source-module
coverage, and consumer boundary.

Staged covered-path review, budget enumeration, and harness smoke use complete
governed inventories rather than suffix or top-ten shortcuts. Superpowers plans
and specs join the canonical agent-context inventory as context governed when
present, without becoming install-owned.
Project-authored knowledge siblings and plans remain outside substrate install
ownership and the upgrade drift baseline while retaining scanning and CODEOWNER
governance.

Crossing from a pre-v3.8.32 install requires invoking the verified v3.8.32 kit's
upgrade engine with the old repository as `--root`. An old target CLI cannot
execute migration logic it does not yet contain. This is a one-time transition;
the rewritten baseline makes later target-local upgrades steady-state again.

## Consequences

- **Positive:** An agent can load one current subsystem contract without paying
  for the full release history. Coverage and assertions remain deterministic.
- **Negative:** Maintainers must keep cross-links and many-to-many coverage
  metadata consistent across several documents.
- **Negative:** Existing consumers need one explicit new-engine invocation at
  the v3.8.32 boundary; pre-v3.8.32 scheduled auto-upgrade cannot cross it alone.
- **Neutral:** CHANGES and HISTORY remain the chronology sources. Consumer
  installations keep their existing compact generated document.

## Alternatives Considered

- **Chronological or version-range files:** Rejected because they optimize for
  release narration instead of locating a current subsystem contract. Future
  releases would recreate the same cross-domain coupling.
- **Keep one file and trim duplicated release paragraphs:** Rejected because the
  file would still bind unrelated change domains and exceed the context budget as
  they evolve.
- **Install all source siblings into consumers:** Rejected because those docs
  describe source-kit implementation and would expand the owned overwrite set
  without improving a consumer's local inventory.
