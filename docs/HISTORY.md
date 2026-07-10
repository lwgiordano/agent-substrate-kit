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

## 2026-07-10T20:32:51Z — NO_SESSION — f8b5cc4
**Summary:** v3.8.5: remediate Codex's independent re-audit of v3.8.4 — 7 verified findings, all eval/test-locked (profile-floor equality trap, unscanned+unowned template sources, YAML name: injection in new-validator, --verify exit code + TOCTOU, green-notify pagination).
**Files:** scripts/substrate_profile.py,scripts/substrate_upgrade.py,scripts/_substrate_surfaces.py,scripts/new_validator.py,scripts/memory_log.py,.github/workflows/release-matrix.yml,tests/test_hook_scripts.py,docs/knowledge/00_substrate.md,README.md,BENCHMARK.md,VERSION
**Intent:** Close every finding from a second independent audit (Codex) with the same rigor as the first; keep the green baseline honest (22/22 blocked, 0/11 FP) with a red->green regression per fix.
**Knowledge:** Profile floor is TWO constraints, not one max(): never below the required_profile lock (anchored on the owned/frozen lock, not agent-writable install.json) AND raise-only vs live config — so a stale-below-lock config is repairable UP to the lock (the v3.8.4 <= max-floor trapped this). Scan template SOURCES that ship verbatim into context surfaces. Quote generated YAML scalars. --verify must exit nonzero on failure and re-check the tree (TOCTOU).

## 2026-07-10T21:04:39Z — NO_SESSION — 8a94acf
**Summary:** v3.8.6: remediate Codex's re-audit of v3.8.5 — 6 verified findings, 2 of them incomplete v3.8.5 fixes (plain-upgrade render bypassing the lock via install.json; TOCTOU guard comparing porcelain strings not content), plus control-char/files-regex YAML safety in new-validator and a stale doctor fallback inventory.
**Files:** scripts/substrate_upgrade.py,scripts/memory_log.py,scripts/new_validator.py,scripts/substrate_doctor.py,tests/test_hook_scripts.py,docs/knowledge/00_substrate.md,README.md,BENCHMARK.md,VERSION
**Intent:** Close a second-round independent audit that caught my own v3.8.5 fixes being incomplete; render must be floored to the frozen lock on every path, verification evidence must be content-sensitive and fail-closed.
**Knowledge:** The render profile (not just the --profile CLI check) must be floored to required_profile — a plain upgrade rendered install.json provenance verbatim, so forged-low provenance dropped strict hooks while the lock read strict. TOCTOU evidence must compare CONTENT (porcelain + git diff + untracked content), not porcelain strings — an already-dirty file re-edited mid-check has an unchanged porcelain line. Mirror-or-fail-closed any hardcoded fallback of a canonical inventory; lock the mirror with a test.

## 2026-07-10T21:43:12Z — NO_SESSION — a745ecb
**Summary:** v3.8.7: remediate Codex's 3rd-round re-audit (of v3.8.6) — 6 verified findings, 2 again poking holes in v3.8.6 fixes (upgrade render still trusting provenance for remote_governance/HIGH profile; memory content-signature blind via git-diff ext-diff/textconv + C-quoted non-ASCII paths), plus U+FFFE/empty-regex in new-validator and a test-parity gap.
**Files:** scripts/substrate_upgrade.py,scripts/memory_log.py,scripts/new_validator.py,tests/test_hook_scripts.py,docs/knowledge/00_substrate.md,README.md,BENCHMARK.md,VERSION
**Intent:** Close a third independent-audit round with the same rigor; render must derive security tiers from live config and floor every required_* tier, verification evidence must hash real bytes and fail closed, generated YAML must be serialized not denylisted.
**Knowledge:** Derive render SECURITY tiers from live config, not agent-writable install.json, and floor EVERY required_* tier (profile AND remote_governance) — a forged provenance value dropped the trusted-base workflow. A content signature must hash raw on-disk bytes via status --porcelain -z -uall (no git diff: honors GIT_EXTERNAL_DIFF/textconv; no non-z: C-quotes non-ASCII paths) and fail closed. Serialize generated YAML scalars with json.dumps (a YAML subset) instead of hand-rolled denylists; reject empty/uncompilable regex.

## 2026-07-10T22:13:03Z — NO_SESSION — 9aaca4a
**Summary:** v3.8.8: remediate Codex's 4th-round re-audit (of v3.8.7) — 2 substantive findings (upgrade render still trusted provenance for the OTHER config-backed tiers lang/runner/sandbox; memory content-signature was index-blind + discarded rename old-names). Codex posted a convergence verdict; adopted substantive-only posture.
**Files:** scripts/substrate_upgrade.py,scripts/memory_log.py,tests/test_hook_scripts.py,docs/knowledge/00_substrate.md,README.md,BENCHMARK.md,VERSION
**Intent:** Close the two substantive round-4 findings and converge: render must derive ALL config-backed tiers from live config and floor every required_* lock; verification evidence must cover the git index and rename identity.
**Knowledge:** Render derivation must take EVERY config-backed tier (profile, lang, runner, sandbox, remote_governance) from live .substrate/config and floor EVERY frozen required_* lock (profile, remote_governance, sandbox) — provenance only supplies ui/workflow. A tamper-evidence signature over a git worktree must also hash the INDEX (ls-files -s -z) and rename old-names, not just working-tree bytes. Convergence discipline: once findings are only cosmetic/test-hygiene, switch to substantive-only and stop extending rounds.

## 2026-07-10T22:46:47Z — NO_SESSION — 7da7d6a
**Summary:** v3.8.9: remediate Codex's 5th-round re-audit (of v3.8.8) — 2 substantive findings, both edges of v3.8.8 fixes (config parser leaked bootstrap inline comments once live config became the render authority; memory content-signature blind to skip-worktree/assume-unchanged hidden paths).
**Files:** scripts/substrate_upgrade.py,scripts/memory_log.py,tests/test_hook_scripts.py,docs/knowledge/00_substrate.md,README.md,BENCHMARK.md,VERSION
**Intent:** Close the two substantive round-5 findings under the substantive-only posture; the render's config authority must parse config canonically, and the tamper-evidence signature must cover git's assume-unchanged/skip-worktree escape hatches.
**Knowledge:** When live config becomes an authority, it MUST be parsed with the canonical comment-aware/quote-aware parser (shared _parse_config mirroring check_substrate_config) — naive .strip('"') leaks bootstrap's inline # comments. A git worktree tamper-evidence signature has many escape hatches that each need explicit cover: ext-diff/textconv (use raw bytes), non-z C-quoting (use -z), the index (ls-files -s), and assume-unchanged/skip-worktree (ls-files -v + hash flagged bytes). Fail closed on any unreadable input.

