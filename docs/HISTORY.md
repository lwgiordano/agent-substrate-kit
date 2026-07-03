# HISTORY.md — Append-only project changelog

**DO NOT EDIT prior entries.** Update only via `scripts/append_history.py`.
This file is `merge=union` in `.gitattributes` so concurrent branch entries combine.

## 2026-07-03T15:00:22Z — NO_SESSION — 77340e6
**Summary:** v3.8.0: SessionStart injects last 5 HISTORY summaries (sanitized, budgeted) and records session_start.json git baseline; startup protocol step 1 is now self-executing.
**Files:** scripts/session_handoff.py,scripts/lint_on_write.py,scripts/run_substrate_evals.py,tests/test_hook_scripts.py,AGENTS.md,templates/AGENTS.md,skills/session-recovery/
**Intent:** Release 1 of 4 in the discipline-mechanization sequence: convert the 'read HISTORY' startup instruction into hook behavior before shipping the riskier completion gate.
**Knowledge:** HISTORY text is treated as untrusted despite SHA validation: sanitized via redact + instruction-prefix strip + invisible-char/HTML/role-prefix removal, capped at 1500 chars. lint_on_write now honors ruff extend-exclude via --force-exclude. session_start.json is the baseline the v3.8.3 completion gate will compare against.

