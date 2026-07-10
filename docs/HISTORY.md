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

## 2026-07-04T05:16:13Z — NO_SESSION — 222076c
**Summary:** v3.8.2: in-place RAISE-only profile ratchet via enable profile / upgrade --profile; bootstrap stages raw pre-commit template + strict extras under .substrate/.
**Files:** scripts/substrate_profile.py,scripts/substrate_upgrade.py,scripts/_doc_common.py,bootstrap.sh,manage.sh,templates/manage.sh.template,tests/test_hook_scripts.py,scripts/run_substrate_evals.py
**Intent:** Release 3 of 4: ratchet, don't max out — one command to climb starter->standard->strict when postmortems justify it, no kit checkout needed.
**Knowledge:** Renderer is a Python port of bootstrap render_precommit, verified byte-identical. Ratchet must re-apply config/required_profile AFTER upgrade _restore (preserve-set undoes bootstrap's fresh values). .substrate/ is now excluded from doc-drift code scanning (staged extras are dormant artifacts).

## 2026-07-04T05:34:21Z — NO_SESSION — 79394a4
**Summary:** v3.8.3: memory skill-run evidence (logger captures git state itself) + opt-in warning-only Stop-hook completion gate, default OFF; strict block deferred to v3.8.4 post-dogfood.
**Files:** scripts/completion_gate.py,scripts/memory_log.py,.claude/settings.json,templates/claude/settings.json.template,templates/codex/hooks.json.template,skills/self-audit/SKILL.md,AGENTS.md,templates/AGENTS.md,templates/OPERATOR_ENABLEMENT.md
**Intent:** Release 4 of 4: make 'self-audit before done' verifiable evidence instead of prose, with the reviewer-mandated soft rollout (default off, warn-only, kill-switch).
**Knowledge:** Gate ignores its own side effects: .substrate/, todo mirror, CURRENT_SESSION.md, __pycache__ (the audit's own .pyc write must not re-arm it); porcelain paths are position-encoded (never strip() the block output — first-line path mangling); untracked dirs collapse without -uall; event ts is second-resolution so ties go to the audit. skill-run records self-audit after the LAST project change, not merely after session start.

## 2026-07-04T05:46:42Z — NO_SESSION — 737f6a0
**Summary:** v3.8.3 audit polish: skill-run text hardened like handoff text; render byte-parity test; atomicity docs made honest (3 WARNs closed, 0 BLOCKs).
**Files:** scripts/memory_log.py,scripts/substrate_profile.py,tests/test_hook_scripts.py
**Intent:** Close the harness-audit WARNs on the v3.8.x cluster before review.
**Knowledge:** Any durable agent-authored text surface needs the same sanitization as the handoff path at WRITE time, even if nothing reads it back yet — retrofitting after a consumer exists is how injection channels ship.

## 2026-07-05T18:30:26Z — NO_SESSION — d90d04c
**Summary:** ci: green-notify job comments on the PR when the release matrix passes, converting CI success (no webhook) into a deliverable event; wake signal only, verify before acting.
**Files:** .github/workflows/release-matrix.yml
**Intent:** Event-driven PR watching without hourly polling: make the terminal green state generate the one event type webhooks deliver.
**Knowledge:** Comment is forgeable (anyone can comment) so watchers must re-verify via the checks API; permissions caged to the notify job; sticky upsert keeps one wake per push. Kit-self CI only, not a consumer template.

## 2026-07-10T13:29:00Z — NO_SESSION — 777ed1d
**Summary:** v3.8.4 audit remediation: fixed a P1 profile-floor downgrade (stale install.json), homoglyph/leet sanitizer bypass, unscanned templates, manage.sh false-positive, gameable self-audit (added --verify), green-notify fork fail-red, new-validator --desc; deduped _git; corrected doc drift.
**Files:** scripts/_text_safety.py,scripts/substrate_upgrade.py,scripts/substrate_profile.py,scripts/session_handoff.py,scripts/memory_log.py,scripts/completion_gate.py,scripts/_substrate_root.py,scripts/_substrate_surfaces.py,scripts/new_validator.py,scripts/run_substrate_evals.py,tests/test_hook_scripts.py,principles.md,docs/knowledge/00_substrate.md,.github/workflows/release-matrix.yml
**Intent:** Remediate two independent audits of the v3.8.x cluster; close the one P1 (self-introduced profile-floor downgrade) and harden the sanitizers/evidence honestly.
**Knowledge:** Profile floor must be max(config,required_profile,install.json) and locks written max(existing,target) — never trust agent-writable provenance alone. Sanitizers are a bounded reduction (confusables+NFKC+leet+invisible fold for the scan only), NOT an injection firewall; the durable defenses are budgets, labels, capability limits, deterministic gates. --verify ties skill-run evidence to a real check result for future block-mode.

