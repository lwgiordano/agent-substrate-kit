---
purpose: Entry point for current substrate contracts and functional knowledge.
last_human_reviewed: 2026-08-21
covers:
  - bootstrap.sh
  - manage.sh
  - package_release.sh
---

# Substrate knowledge map

The Agent Substrate Kit installs deterministic project checks, agent hooks,
tamper-evident session memory, policy evals, and release verification. Running
code and deterministic results outrank this documentation. Current ADRs rank
next, followed by these knowledge docs and then append-only HISTORY.

The source kit keeps detail in function-oriented documents:

- [Install and adoption](01_install_adoption.md)
- [Upgrade integrity](02_upgrade_integrity.md)
- [Memory and sessions](03_memory_sessions.md)
- [Policy and governance](04_policy_governance.md)
- [Evals and assurance](05_evals_assurance.md)
- [Release and distribution](06_release_distribution.md)
- [Agent context governance](07_agent_context_governance.md)

## Operating model

The local substrate is offline-complete. Profiles (`starter`, `standard`, and
`strict`) select governance strength. Language, runner, sandbox, and remote
governance are separate capabilities. Frozen `required_*` files set minimums
that local configuration may raise but may not lower.

Remote governance adds CODEOWNERS and trusted-base checks. It does not let an
offline command prove that GitHub branch protection is active. Sandbox mode
routes executable project commands through an available host backend and fails
closed when a required backend or containment proof is missing.

The source checkout and an installed consumer have different layouts. These
eight documents belong to the source kit. Bootstrap generates one compact,
consumer-local `docs/knowledge/00_substrate.md` whose front matter inventories
the installed top-level Python and shell scripts. The seven source siblings are
not package-owned consumer files.

## Trust boundary

Local manifests, drift maps, knowledge text, and repository configuration are
useful deterministic evidence, not independent cryptographic authorities. The
signed release plus remote trusted-base enforcement provide the stronger
integrity anchors. A process with concurrent write and execute access can force
operations to abort; the substrate aims to prevent that process from turning a
failed or inconsistent state into a successful claim.

Release-by-release history lives in [CHANGES_V3.md](../../CHANGES_V3.md) for the
pre-v3.8 line and [HISTORY.md](../HISTORY.md) for v3.8 and later. These knowledge
docs state current contracts and known limits instead of repeating that
chronology.
