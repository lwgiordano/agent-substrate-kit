---
applyTo: "**"
---

# Substrate instructions (all files)

This repo is governed by the Agent Substrate Kit. Canonical rules are
in `AGENTS.md` at the repo root — GitHub Copilot loads `AGENTS.md`
automatically; read it first.

- Never read, print, or commit secrets (`.env`, credentials, keys).
- Never edit prior `docs/HISTORY.md` entries; append via
  `scripts/append_history.py`.
- Never hand-edit `docs/manifest.json`; use `./manage.sh manifest`.
- Run `./manage.sh check` before claiming completion.
- Bug fixes follow the finding-response pattern: name the bug class,
  grep for siblings, add a lock-down.

Deterministic enforcement (lint-on-write, exfil guard, session
handoff) runs via hooks in `.github/hooks/` (Copilot), `.claude/
settings.json` (Claude Code), and `.codex/hooks.json` (Codex).
