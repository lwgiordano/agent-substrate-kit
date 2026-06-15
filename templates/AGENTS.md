# AGENTS.md — Canonical AI + human project instructions

Read this file before doing any work in this repository.
Keep this file byte-stable: it sits at the top of the cached prompt
prefix. Volatile state (session handoffs, todo state) is injected by
hooks at context tail — never add it here.

## Startup protocol (keep it light)

1. Read the last 5 entries in `docs/HISTORY.md`.
2. If a session-handoff block was injected at session start, verify it
   against `git log -5 --oneline` before trusting it.
3. Read `docs/knowledge/*.md` and `docs/decisions/*.md` ONLY for the
   area you are about to touch (just-in-time, not wholesale).

## Source-of-truth order

1. Running code and deterministic check results.
2. Current ADRs in `docs/decisions/`.
3. Knowledge docs in `docs/knowledge/`.
4. HISTORY entries.
5. Agent memory or chat context.

## What the hooks already do (don't duplicate this work)

- Every Edit/Write is linted immediately (`lint_on_write.py`); fix
  reported errors before moving on.
- Every TodoWrite is mirrored to `docs/.todo_state.json`.
- Compaction and session end capture STRUCTURED state to
  `.substrate/memory/tasks/current.json`; session start restores from that
  JSON. `docs/CURRENT_SESSION.md` is a derived human view only — never
  re-injected, never trusted as input.

## Docs/code parity contract

For non-trivial work:

1. Read the docs that claim to cover the target area.
2. Read the actual code.
3. State internally: `Docs claim X; code does Y; discrepancy Z.`
4. If code changes invalidate a knowledge doc, update the doc and bump
   `last_human_reviewed`.

## Definition of done

1. The requested behavior is implemented.
2. The smallest relevant deterministic checks pass.
3. Relevant docs are updated or explicitly not needed.
4. Substantial work has run the `self-audit` skill.
5. Security-sensitive changes have a security-auditor pass.
6. UI changes have a design-auditor pass when this repo has UI.
7. No BLOCK auditor findings remain unresolved.

## Hard rules

- Never read, print, or commit secrets.
- Never edit previous `docs/HISTORY.md` entries.
- Never hand-edit `docs/manifest.json`; use `scripts/update_manifest.py --fix`.
- Strict mode reserves `scripts/` for the substrate; put PROJECT scripts in
  `tools/`, `bin/`, or `project-scripts/` — a project file under `scripts/`
  trips the trusted-base freeze.
- Never claim completion if deterministic checks failed.
- Never bypass hooks or CI unless the operator explicitly authorizes it.
- Never mutate production systems or live credentials without explicit
  operator approval.
- Do not run Superpowers and GSD as competing primary workflow
  controllers in the same repo.

## Primary workflow

This repo's selected primary workflow is: `{{WORKFLOW}}`.
Substrate profile: `{{PROFILE}}` (see `.substrate/config`).

## Commands

```bash
./manage.sh doctor    # readiness: file/hook wiring, security, operational
./manage.sh check      # full validator chain + lint/typecheck/test + pre-commit
./manage.sh evals      # prove the policy BEHAVES (block-rate / false-positive-rate)
./manage.sh audit      # quick self-audit report
./manage.sh release    # package + verify from the built artifact
```

## Auditor agents — spawn, don't inline

Use read-only auditor subagents for substantial changes; they burn
their own context and return a compact verdict (≤500 tokens):

- security-auditor
- test-auditor
- architecture-auditor
- documentation-auditor
- design-auditor
- harness-auditor
- checklist-auditor (pass it the domain: regex, yaml-parsing,
  ast-parsing, commit-msg-hooks)

Each reports PASS / WARN / BLOCK with `file:line` evidence.
Do NOT read blind-spot checklists or review-prompt files into the main
context — that is what checklist-auditor and the `ultrareview` skill
reference layer are for.

## Project-specific instructions

### Project name

TODO

### Stack

TODO

### Build and test commands

```bash
./manage.sh check
./manage.sh evals
./manage.sh release
```

### Architecture docs

- `docs/ARCHITECTURE.md`
- `docs/INTENT.md`

### Design system

UI enabled for this install: `{{UI_ENABLED}}`.
If UI work exists, read `design-system/MASTER.md` first and page
overrides in `design-system/pages/` second.
