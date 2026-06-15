# GitHub Copilot instructions

This repository is governed by the Agent Substrate Kit. The canonical
rules live in [`AGENTS.md`](../AGENTS.md) at the repo root — read it
first; Copilot loads `AGENTS.md` automatically.

## Non-negotiables (mirror of AGENTS.md hard rules)

- Never read, print, or commit secrets (`.env`, credentials, keys).
- Never edit prior `docs/HISTORY.md` entries; append via
  `scripts/append_history.py`.
- Never hand-edit `docs/manifest.json`; use
  `scripts/update_manifest.py --fix`.
- Never claim completion until `./manage.sh check` passes.
- Bug fixes follow the finding-response pattern: name the bug class,
  grep for siblings, add a lock-down.

## Where detailed procedures live

Detailed, task-specific procedures are in `.github/instructions/`
(path-scoped) and in the substrate skills under `.claude/skills/`.
Copilot custom instructions are for behavior that applies broadly;
the skills carry the step-by-step procedures.

## What the hooks enforce

Deterministic hooks are wired for all three hosts:
- Claude Code: `.claude/settings.json` (lint-on-write, todo mirror,
  PreCompact/SessionEnd handoff, PreToolUse exfil guard).
- Copilot: `.github/hooks/exfil-guard.json` (preToolUse exfil guard via
  `copilot_hook_adapter.py`; sessionStart/End handoff).
- Codex: `.codex/hooks.json`.

Copilot's preToolUse exfil guard denies obvious secret-read/exfil
commands. It is a tripwire, not a sandbox — still run `./manage.sh
check` before finishing and `./manage.sh handoff` before stopping
mid-task.
