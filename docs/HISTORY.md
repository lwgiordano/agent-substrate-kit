# HISTORY.md — Append-only project changelog

**DO NOT EDIT prior entries.** Update only via `scripts/append_history.py`.
This file is `merge=union` in `.gitattributes` so concurrent branch entries combine.

## 2026-07-03T15:00:22Z — NO_SESSION — 77340e6
**Summary:** v3.8.0: SessionStart injects last 5 HISTORY summaries (sanitized, budgeted) and records session_start.json git baseline; startup protocol step 1 is now self-executing.
**Files:** scripts/session_handoff.py,scripts/lint_on_write.py,scripts/run_substrate_evals.py,tests/test_hook_scripts.py,AGENTS.md,templates/AGENTS.md,skills/session-recovery/
**Intent:** Release 1 of 4 in the discipline-mechanization sequence: convert the 'read HISTORY' startup instruction into hook behavior before shipping the riskier completion gate.
**Knowledge:** HISTORY text is treated as untrusted despite SHA validation: sanitized via redact + instruction-prefix strip + invisible-char/HTML/role-prefix removal, capped at 1500 chars. lint_on_write now honors ruff extend-exclude via --force-exclude. session_start.json is the baseline the v3.8.3 completion gate will compare against.

## 2026-07-04T05:04:08Z — NO_SESSION — 1ed7a6b
**Summary:** v3.8.1: ./manage.sh new-validator scaffolds check_<name>.py + adversarial test pair and prints the pre-commit block; wired into finding-response lock-down step.
**Files:** scripts/new_validator.py,manage.sh,templates/manage.sh.template,skills/finding-response/SKILL.md,customization.md,tests/test_hook_scripts.py
**Intent:** Release 2 of 4: make bugs-into-validators a one-command workflow instead of a hand-copied convention.
**Knowledge:** Scaffold never auto-edits .pre-commit-config.yaml (profile-rendered + drift-tracked; auto-edit would trip the upgrade drift gate). Generated skeleton defers yaml import so check_validator_input_coverage stays quiet until real parsing lands; test stub pre-stages non-string fixtures for layer 2.

