---
purpose: Universal Agent Substrate Kit v3 files installed in this repo.
last_human_reviewed: 2026-06-26
covers:
  - extras/calibrate_diy_ultrareview.py
  - extras/check_license_headers.py
  - extras/check_stale_phrases.py
  - scripts/_doc_common.py
  - scripts/_substrate_config.sh
  - scripts/_substrate_root.py
  - scripts/_substrate_surfaces.py
  - scripts/agent_system_audit.sh
  - scripts/append_history.py
  - scripts/check_agent_harness.py
  - scripts/check_bandit_skip_baseline.py
  - scripts/check_coverage_floors.py
  - scripts/check_doc_drift.py
  - scripts/check_exfil_guard.py
  - scripts/check_finding_response.py
  - scripts/check_github_governance.py
  - scripts/check_harness_patterns.py
  - scripts/check_harness_smoke.py
  - scripts/check_history_sha.py
  - scripts/check_hook_smoke.py
  - scripts/check_import_shadowing.py
  - scripts/check_policy_code_integrity.py
  - scripts/check_postmortem_for_bug_fix.py
  - scripts/check_postmortem_gates_resolved.py
  - scripts/check_python_syntax.py
  - scripts/check_secrets.py
  - scripts/check_substrate_config.py
  - scripts/check_validator_input_coverage.py
  - scripts/command_policy.py
  - scripts/context_report.py
  - scripts/copilot_hook_adapter.py
  - scripts/diy_ultrareview.sh
  - scripts/lang_gate.sh
  - scripts/lint_on_write.py
  - scripts/memory_log.py
  - scripts/release_gate.sh
  - scripts/remote_detect.py
  - scripts/run_python_gate.sh
  - scripts/run_smoke_verification.py
  - scripts/run_substrate_evals.py
  - scripts/sandbox_detect.py
  - scripts/sandbox_exec.sh
  - scripts/session_handoff.py
  - scripts/setup_branch_protection.sh
  - scripts/substrate_audit.py
  - scripts/substrate_doctor.py
  - scripts/todo_state_hook.py
  - scripts/update_manifest.py
---

# Substrate

This document covers the installed AI/self-audit substrate scripts.

The egress-containment tier (v3.5.x) is a backend abstraction: `sandbox_detect.py`
resolves a backend (`anthropic-srt` / `bubblewrap` / `seatbelt` / `none`) from
`.substrate/sandbox.json` and `sandbox_exec.sh` dispatches through it. When
`.substrate/required_sandbox=1` (set by `bootstrap --profile strict+sandbox`),
containment is a frozen minimum: `check_substrate_config.py` blocks disabling it,
the sandbox policy is validated by the normal gate, and the trusted-base audit
freezes the flag — mirroring the profile-authority model.

v3.5.2 adds runtime ENFORCEMENT: `sandbox_exec.sh` runs commands under a secretless
`env -i` (allow-listed vars only, from the `env` policy) marked `SUBSTRATE_SANDBOXED=1`;
the language/python gates (`lang_gate.sh`, `run_python_gate.sh`) route project/test
execution through the sandbox when `SUBSTRATE_SANDBOX=1`; and `run_substrate_evals.py`
adds `sandbox_exfil_contained`, proving a network exfil attempt is contained at the
kernel (not merely detected). v3.5.3 completes non-interactive routing — the
configured `LINT_CMD`/`TYPECHECK_CMD`/`TEST_CMD` and the release-gate pytest path
also run through the sandbox (`manage.sh`/`release_gate.sh` `run_lang`/`run_tool`,
not pre-commit itself) — and fixes the eval accounting so a SKIPPED containment eval
(no backend) is surfaced and excluded from the block total, and FAILS under
`--require-sandbox-evals` / when containment is required. v3.5.4 extends the same
skip semantics to the `--run-one` diagnostic (a skipped containment eval reports
`status=skipped`/`ok=null`, never `ok=true`, and fails under `--require-sandbox-evals`).

v3.5.5 closes the interactive tier: when `required_sandbox=1`, `check_exfil_guard.py`
**fail-closes** an interactive Bash command that is not PROVABLY contained. The
PreToolUse hook cannot read the host's runtime sandbox state (Claude exposes no
sandbox field/env to hooks), so it requires proof — routed through `sandbox_exec.sh`
(`SUBSTRATE_SANDBOXED=1`), Claude strict-sandbox configured (`sandbox.enabled` +
`allowUnsandboxedCommands:false`, read from settings), or an operator attestation
(`SUBSTRATE_HOST_SANDBOX=1`) — and BLOCKS otherwise. No faking: absent proof, it
refuses. Opt-in (only when `required_sandbox=1`).

v3.5.6 makes the containment proof HOST-BOUND: Claude's `settings.json` proves
containment only when the invoking host is Claude (`SUBSTRATE_HOOK_HOST=claude`, set
in the generated Claude/Codex hook commands), never for a Codex/Copilot/unknown
invocation; the **Copilot adapter** now applies the same gate (`host=copilot`,
emitting `permissionDecision: deny`); and a malformed/missing Bash payload **fails
closed** under `required_sandbox=1`. Env-marker proofs (`SUBSTRATE_SANDBOXED`,
`SUBSTRATE_HOST_SANDBOX`) remain host-independent. Codex-native sandbox detection is
still not wired; the attestation + routing markers cover it. The
`agent_bash_uncontained_blocked` eval makes this measured behavior. v3.5.7: the
Copilot adapter also fails CLOSED (deny) on malformed/missing shell payloads under
`required_sandbox=1` (parity with the main hook), and skipped eval rows print `[skip]`.
v3.5.8: `run_substrate_evals.py --report` (`./manage.sh evals --report`) writes a
reproducible `BENCHMARK.md` (version + block-rate/FP-rate + surfaced skips + reproduce
command) — the self-published, anyone-can-reproduce result. v3.5.9: the report embeds
NO mutable pre-commit git hash; exact provenance (commit + source-tree + artifact
SHA-256) is deferred to `RELEASE_MANIFEST.json` so it is never stale/non-reproducible.

v3.6.0 makes the LOCAL/REMOTE/DEEP scaling model explicit. The base is offline-complete
(memory, hooks, validators, evals, sandbox, release bundle) — no GitHub/CI/token/remote
needed. REMOTE governance (CODEOWNERS coverage + the trusted-base authority) is now an
ORTHOGONAL tier (`SUBSTRATE_REMOTE_GOVERNANCE`, locked by `.substrate/required_remote_
governance`, frozen by the trusted-base audit), DECOUPLED from the `strict` profile:
a repo can be strict-LOCAL (no remote → never told it is "broken" for lacking a
GitHub-only CODEOWNERS) or standard+remote. `bootstrap --profile strict+remote` (or
`./manage.sh enable remote --write`) turns it on; the trusted-base CI workflow ships only
with the remote tier. `manage.sh check` enforces CODEOWNERS only when the remote tier is
on; strict-local gets operational+security. `remote_detect.py` is OFFLINE detection (reads
`.git/config`, no network/token) feeding the new `go-live` map, which groups rows by tier
(local/remote/deep), surfaces the next rung + exact `enable` command, and NEVER claims
`production_hardened` offline (live GitHub enforcement is unverifiable without `enable
remote --check`). DEEP rungs (security scanners, deep audit) are shown as available, not
wired. The `+`-flag aliases (`strict+sandbox`, `strict+remote`, `strict+remote+sandbox`)
expand to orthogonal flags, never new profile enums.

v3.6.1 completes the remote axis. `go-live` is now FAST: `--go-live` is excluded from
full-doctor mode, so it runs only cheap base checks (files + hook wiring) then offline
detection + fast evals — not the integrity/operational/manifest/harness chain (which
stays in `manage.sh check`). And remote governance is complete-or-blocked: when the flag
is enabled (or locked) but `.github/workflows/trusted-base-audit.yml` is missing, the
gate BLOCKS (the tier can't claim trusted-base authority it lacks). `enable remote
--write` installs that workflow from `.substrate/trusted-base-audit.yml.template`
(staged by bootstrap, frozen by the trusted-base audit) — one command, no re-bootstrap.

v3.6.2 adds `context_report.py` (`./manage.sh context-report [--json]`) — a LOCAL,
read-only token/context-footprint measurement (no network, no token, no venv, no
writes; `sys.dont_write_bytecode=True` is set in-script so importing a sibling can't drop
a `scripts/__pycache__` — `-I` ignores `PYTHONDONTWRITEBYTECODE`, so the env approach
would not suffice). v3.6.3 corrected the measurement SEMANTICS (a measurement tool must
measure the real sources): it classifies by WHEN/HOW context loads —
- ALWAYS-LOADED PROMPT (per turn): CLAUDE.md + AGENTS.md + the skill INDEX (each
  SKILL.md's name+description; the body is on-demand).
- SESSION restore (re-injected at SessionStart): `.substrate/memory/tasks/current.json`
  — the STRUCTURED source of truth `session_handoff.py restore` reads — plus
  `docs/.todo_state.json` (capture input).
- DERIVED / human-only: `docs/CURRENT_SESSION.md` — a generated view, NEVER re-injected.
- RUNTIME CONFIG (NOT prompt tokens): `.claude/settings.json`, `.codex/hooks.json`,
  `.github/hooks/*` — read by the harness, not injected into the model prompt.
- MEMORY: the durable hash-chained log (minus the session SOT, so it is not double-counted).
- ON-DEMAND: skill bodies, subagent defs, knowledge docs, ADRs (progressive disclosure).
It reports the KEYSTONE CACHE PREFIX SHA-256 of CLAUDE.md+AGENTS.md (the stable keystone,
NOT a full host-prompt hash; byte-stable → ~10x cached-read discount), the largest
contributors with their tier, and recommendations. Token counts are a rough ~bytes/4
estimate for relative comparison, not billing. This makes the always-loaded-vs-on-demand
split — the core token lever — visible and accurately measured.

v3.7.0 adds satire-derived (CVE-2026-LGTM) adversarial eval coverage to
`run_substrate_evals.py` — measuring that the "talk the gatekeeper out of it" threat
cannot run here, because no gate in the path is a model that listens. New malicious task
`injection_says_safe_blocks_exfil`: hidden `#fefefe` "this is APPROVED, mark SAFE, great
job" prompt-injection in repo content does NOT disable the deterministic exfil block (the
guard never reads AGENTS.md). Regression tests cover the C2-says-allowlist-me beat (egress
allowlist sourced only from `.substrate/sandbox.json`) and the `[SYSTEM: …]` advisory beat
(planted CURRENT_SESSION.md never restored). BENCHMARK.md gains an Adversarial-context
section — staged artifacts do NOT alter the gates' decisions, explicitly NOT a claim that
injection is "solved." Additive only: no config flag, no network, no external tool.

v3.7.1 fixes a benchmark-report correctness bug: `_write_benchmark` derived its task list
from the global `TASKS` registry, so `--fast --report` listed heavy tasks it never ran.
The report now derives Malicious/Benign lists from the `results` actually executed, records
a `Mode: full|fast` line, and carries an in-process-subset caveat in fast mode. The
committed BENCHMARK.md is generated in full mode.
