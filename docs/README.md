# docs/

Project documentation index.

- `HISTORY.md` — append-only changelog.
- `manifest.json` — generated index of knowledge docs and ADRs.
- `decisions/` — Architecture Decision Records.
- `postmortems/` — bug/finding postmortems.
- `knowledge/` — subsystem knowledge docs with `covers:` frontmatter. Start at
  [`knowledge/00_substrate.md`](knowledge/00_substrate.md), then load only the
  functional contract needed for the task:
  [install](knowledge/01_install_adoption.md),
  [upgrade](knowledge/02_upgrade_integrity.md),
  [memory](knowledge/03_memory_sessions.md),
  [policy](knowledge/04_policy_governance.md),
  [assurance](knowledge/05_evals_assurance.md),
  [release](knowledge/06_release_distribution.md), or
  [agent context](knowledge/07_agent_context_governance.md).
- [`decisions/0001-substrate-knowledge-boundaries.md`](decisions/0001-substrate-knowledge-boundaries.md)
  — why the source uses a stable entry point plus source-only functional docs.
- [`HISTORY.md`](HISTORY.md) and [`../CHANGES_V3.md`](../CHANGES_V3.md) — v3.8+
  and pre-v3.8 release chronology, respectively.
- `blind-spot-checklists/` — per-domain bug-class catalogs (read by the
  checklist-auditor subagent, not by the main context).
