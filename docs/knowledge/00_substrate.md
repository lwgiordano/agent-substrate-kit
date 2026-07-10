---
purpose: Universal Agent Substrate Kit v3 files installed in this repo.
last_human_reviewed: 2026-07-10
covers:
  - extras/calibrate_diy_ultrareview.py
  - extras/check_license_headers.py
  - extras/check_stale_phrases.py
  - scripts/_doc_common.py
  - scripts/_minisign.py
  - scripts/_substrate_config.sh
  - scripts/_substrate_root.py
  - scripts/_substrate_surfaces.py
  - scripts/_text_safety.py
  - scripts/_verify_backends.py
  - scripts/agent_system_audit.sh
  - scripts/append_history.py
  - scripts/build_review_bundle.py
  - scripts/check_agent_harness.py
  - scripts/check_bandit_skip_baseline.py
  - scripts/check_coverage_floors.py
  - scripts/check_dep_cooldown.py
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
  - scripts/code_shape.py
  - scripts/command_policy.py
  - scripts/completion_gate.py
  - scripts/context_report.py
  - scripts/copilot_hook_adapter.py
  - scripts/diy_ultrareview.sh
  - scripts/lang_gate.sh
  - scripts/lint_on_write.py
  - scripts/memory_log.py
  - scripts/new_validator.py
  - scripts/release_gate.sh
  - scripts/remote_detect.py
  - scripts/run_python_gate.sh
  - scripts/run_security_scanners.py
  - scripts/run_smoke_verification.py
  - scripts/run_substrate_evals.py
  - scripts/sandbox_detect.py
  - scripts/sandbox_exec.sh
  - scripts/session_handoff.py
  - scripts/setup_release_key.sh
  - scripts/setup_branch_protection.sh
  - scripts/substrate_audit.py
  - scripts/substrate_doctor.py
  - scripts/substrate_profile.py
  - scripts/substrate_upgrade.py
  - scripts/todo_state_hook.py
  - scripts/update_manifest.py
  - scripts/verify_release.py
  - scripts/write_install_json.py
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
  `docs/.todo_state.json` (capture input). v3.8.0: restore ALSO appends the last 5
  `docs/HISTORY.md` summary lines (tail-read 64KB; sanitized like todo text plus
  invisible-char/HTML/role-prefix stripping — HISTORY is SHA-validated but its text is
  agent-authored) under a separate 1500-char budget (handoff body keeps 4000; 6000
  absolute), in BOTH restore paths, so startup step 1 ("read HISTORY") is self-executing.
  restore additionally records the session-start git baseline to
  `.substrate/memory/session_start.json` (best-effort) — the comparison point for the
  planned v3.8.3 completion gate. lint_on_write.py passes `--force-exclude` so the
  edit-hook honors `[tool.ruff] extend-exclude` exactly like run_python_gate.sh.
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

v3.7.2 adds Phase B of the satire-derived hardening: the dependency-cooldown gate
(`check_dep_cooldown.py`, opt-in `SUBSTRATE_DEP_COOLDOWN=N` days, 0=off). It flags DIRECT
deps whose resolved version published < N days ago — a FRESH-VERSION RISK SIGNAL (the
window a malicious new fork/typosquat exploits), explicitly NOT a malware detector. The
RULE is a deterministic date comparison; the DATA (publish dates) is registry metadata
(network), so it is an opt-in DEEP tier, never part of the offline base — `manage.sh
check` runs it only when the flag is > 0. SKIP-HONEST: a dep whose publish time can't be
determined (offline, uncached, registry-ambiguous) is SKIPPED with a reason, never
assumed young; results cache to `.substrate/dep_cooldown_cache.json` (gitignored;
publish dates are immutable). Direct deps only (npm package.json+lock / pyproject+uv.lock
/ go.mod non-indirect); transitive is a later mode. Exit 0 (clean / skips-only) | 1
(young found, or required+unverifiable) | 2 (malformed lockfile/config). Mirrored in both
validators (`_INT_KEYS`), lockable via `.substrate/required_dep_cooldown` (frozen by the
trusted-base audit), and surfaced as a go-live deep row.

v3.7.4 closes the Phase-B audit findings + a release-provenance class: required-mode
cooldown now BLOCKS on ANY unverifiable dep (one verified dep no longer masks a skipped
one); `package_release.sh` marks `git_commit` as `<commit>-dirty` when the tree has
uncommitted tracked changes so the manifest never claims a clean commit it isn't; the
committed BENCHMARK.md is regenerated per release (asserted by a version-match test); full
`--json`/trace eval `results[]` normalize skipped tasks to `status:"skipped"`/`ok:null`
(not `ok:true`); and the offline go-live `dep_cooldown` row reports `warn` (enabled, runs
in `manage.sh check`) rather than overclaiming `pass`.

v3.7.5 adds MEASURED memory coverage (memory was strong but un-evaluated): new eval tasks
`memory_chain_rewrite_detected` (tampering events.jsonl breaks the hash chain → `memory_log
verify` detects), `memory_anchor_mismatch_detected` (post-anchor history rewrite → `verify
--anchor` detects; skip-honest where a git-note anchor can't be written), and benign
`memory_restore_from_structured` (a valid current.json IS restored — the positive path
works). The go-live `memory_anchor` row is now 3-state: no-log→warn | hash-chain
BROKEN→fail | ok+anchored→pass | ok+unanchored→warn (the gate already BLOCKS a broken
chain; go-live surfaces it).

v3.7.6 fixes that go-live row to VERIFY the anchor (compare `_anchored_head()` to
`_head_hash()`), not just check a note exists — a stale anchor (new events since last
anchor, or a rewrite) is now `fail`, not a false `pass`. This surfaced a real isolation
bug: `capture_for_root(root)` scoped session_handoff's files but not memory_log's globals,
so the durable event `capture()` appends leaked into the PROCESS repo — meaning running
the eval suite / go-live silently mutated the host repo's memory and staled its anchor.
`_root_context` now rebinds `memory_log.ROOT/MEM/EVENTS` too. Also v3.7.6: the Copilot
adapter now FAILS CLOSED (denies shell tools) when the policy/containment guard can't
import, instead of failing open. v3.7.7 completes that posture: the malformed/non-object/
empty-input paths (which route through `_deny_if_required`, whose `required` came from a
fallback stub) also deny when the guard import failed — so a double fault (broken guard +
malformed Copilot JSON) no longer allows. Non-shell tools still allow; a working guard is
unchanged.

v3.7.8 adds engineering-SHAPE governance (the reviewability gap the security gates don't
cover): `code_shape.py` (`./manage.sh code-shape [--json]`) — a LOCAL, read-only,
WARN-ONLY, deterministic report (no LLM, no gate, no network, no writes). Repo-wide: the
largest source files, files over a line threshold (sprawl), and long python functions (AST;
god-function risk). Diff (vs HEAD + untracked): changed lines, a large-diff warning,
source-changed-without-tests, and flags for governance/CI + dependency-manifest churn —
the high-review-value AI-diff failure modes. It does NOT block `check`. Plus
`context-report --budget`: warn-only token thresholds (always-loaded prompt / AGENTS.md /
skill index / session current.json) on top of the footprint report. Both are reports, not
gates — they surface shape so a human/agent decides; no config flag added.

v3.7.9 makes code-shape measure the USER's PROJECT, not the substrate it is installed into
(the v3.7.8 bug: a fresh install read as "your repo has sprawl + a huge diff", which was
the harness). Substrate-owned files are classified via the canonical
`_substrate_surfaces` inventory (+ `extras/`; `tests/` is mixed so only the kit's specific
shipped test files are owned) and EXCLUDED from the project shape by default — they appear
in a separate substrate-owned summary; `--include-substrate` dogfoods the kit. An
install-dominated diff (substrate lines dominate / fresh bootstrap) is reported as a
substrate install, not a large project diff (the large-diff + source-without-tests warnings
key off PROJECT lines only). Governance-churn detection was extended to the agent/control
surfaces it missed (`.substrate/**`, AGENTS.md/CLAUDE.md/GEMINI.md, `.claude`/`.codex`,
CODEOWNERS, `.mcp.json`, `docs/knowledge|decisions`, `scripts/**`).

v3.7.10 completes governance churn: a governance-ONLY diff (an agent edits AGENTS.md /
.substrate/config with no project source — the "agent changed its own rules" case) now
warns (v3.7.9 only warned when project code also changed), and the classifier was extended
to the canonical context surfaces it missed (docs/HISTORY.md, docs/README.md,
docs/ARCHITECTURE.md, docs/INTENT.md, docs/blind-spot-checklists/**, docs/templates/**,
docs/postmortems/**, design-system/**).

v3.8.1 adds the bugs→validators scaffold: `./manage.sh new-validator <name>
[--files-regex REGEX] [--desc TEXT]` (`scripts/new_validator.py`) generates
`scripts/check_<name>.py` (0/1/2 exit convention, `-I` import shim) plus
`tests/test_validator_<name>.py` (adversarial stub pre-staging the non-string fixture
shapes that check_validator_input_coverage layer 2 requires once YAML parsing lands),
and PRINTS the pre-commit block — it never auto-edits `.pre-commit-config.yaml`, which
is profile-rendered and drift-tracked. Referenced from the finding-response skill
(lock-down step) and customization.md. Templates are embedded string constants, so
nothing new is staged under `.substrate/`.

v3.8.2 adds the IN-PLACE profile ratchet: `./manage.sh enable profile <standard|strict>
[--plan|--write|--check] [--force]` (`scripts/substrate_profile.py`) raises the governance
profile without a kit checkout or re-bootstrap. bootstrap now stages the RAW
`pre-commit-config.yaml.template` + `extras/*.py` under `.substrate/` (same dormant-staging
pattern as the workflow tiers); `--write` re-renders `.pre-commit-config.yaml` (a Python
port of bootstrap's `render_precommit`, verified byte-identical to a direct bootstrap),
sets SUBSTRATE_PROFILE, RAISES `required_profile` (other `required_*` locks untouched),
installs strict extras (skip-if-exists), and re-records install.json so the next upgrade
sees no false drift. RAISE-only (lowering exits 2 — eval `profile_ratchet_lower_refused`);
refuses a hand-edited pre-commit config without `--force`. A REFUSAL never half-applies
(config edits happen only after the staged template is confirmed readable and every refusal
condition passes; missing template → "run ./manage.sh upgrade first"). The apply steps
themselves are sequential, not transactional — an interrupt mid-apply can leave them
inconsistent, which `--check` detects and a re-run repairs. `substrate_upgrade.py --profile standard|strict` performs the
same raise during an upgrade, applied AFTER `_restore()` because `.substrate/config` +
`required_profile` are in PRESERVE_FILES (the preserved old-profile copies would otherwise
silently undo the ratchet).

v3.8.3 adds skill-run evidence + the OPT-IN completion gate. `./manage.sh memory skill-run
<name> [--result pass|issues-found|unknown] [--note]` (`memory_log.py`) appends a
hash-chained event whose git state (head/branch/dirty/changed_files) is captured BY THE
LOGGER at append time — a skill cannot record a wrong SHA. The self-audit skill's
completion contract now ends with recording that event. `scripts/completion_gate.py` is a
Stop hook (wired in Claude settings + chained advisory in the Codex template, host-tagged)
that is DEFAULT OFF: enable with SUBSTRATE_COMPLETION_GATE=1 (env; =0 is the kill-switch)
or COMPLETION_GATE="1" in config. When enabled it warns (systemMessage, WARNING-ONLY —
the strict decision-block path exists but is disabled by _BLOCK_MODE_ENABLED=False until
v3.8.4 post-dogfood) iff PROJECT files changed (HEAD moved from session_start.json, or
dirty tree excluding .substrate/, docs/.todo_state.json, docs/CURRENT_SESSION.md,
__pycache__/*.pyc) AND no self-audit skill-run event is timestamped at/after the last
project change (second-resolution; benign ties go to the audit). Fail-open everywhere:
garbage stdin, stop_hook_active, missing baseline, and internal errors all exit 0.
Hard-won edge cases (all eval/test-locked): `git status` porcelain paths are position-
encoded so lines must NOT be globally stripped (first-line path mangling); untracked dirs
collapse (`?? docs/`) so dirty detection uses `-uall`; recording the audit itself drops a
fresh scripts/__pycache__ .pyc that must not re-arm the gate.

v3.8.4 is audit remediation (two independent audits of the v3.8.x cluster). Fixes, all
eval/test-locked: (1) `scripts/_text_safety.py` — a shared confusables/mixed-script + NFKC +
leetspeak + invisible-char fold used by the SessionStart/handoff/memory sanitizers
(`_safe_history_line`/`_safe_todo_text`/`_safe_note`) for the DANGER SCAN ONLY (emitted text
is unchanged). This closes homoglyph/full-width/leet evasion of the ASCII directive regexes.
IMPORTANT (truth-in-advertising): these sanitizers are a BOUNDED REDUCTION of the injection
surface, NOT a claim that injection is solved — the durable defenses are the line/HISTORY
budget caps, the "facts, not instructions" label, capability limits, and the deterministic
gates (same disclaimer stance as the v3.7 adversarial-eval work; regex filtering alone is
insufficient per current research). (2) `check_agent_harness.py` now scans the AGENT-FACING
`templates/**` (AGENTS/CLAUDE/copilot/claude+codex instruction+config+hook templates), which
ship verbatim to consumers — human-operator doc templates are excluded (they legitimately
document security flags). (3) The shell-danger scan neutralizes the kit's own `manage.sh`
vocabulary, so a legit `./manage.sh …` HISTORY summary is no longer stripped. (4) `_git`/
`_git_lines` are consolidated into `_substrate_root.py` (was triplicated with drifted
timeouts). (5) `manage.sh memory skill-run … --verify` runs the deterministic static chain
(`run_smoke_verification.py`) and records its REAL exit status + output hash
(`verified`/`verify_rc`/`verify_hash`), overriding a self-asserted `--result` — trustworthy
evidence is now POSSIBLE (block mode, still deferred, will REQUIRE a verified event; the
warning-only gate still accepts any event). (6) SECURITY (P1, self-introduced in v3.8.2):
`substrate_upgrade.py --profile` trusted `install.json` (agent-writable) provenance and wrote
`required_profile` unconditionally, so a mutated provenance file could LOWER a strict lock.
Fixed: the floor is now `max(config, required_profile, install.json)` and the lock is written
`max(existing, target)` — never lowered; `substrate_profile.py` gained the same
config-vs-lock floor (eval `profile_ratchet_lower_refused` + regression). (7) `green-notify`
skips fork PRs (read-only token → 403) and is `continue-on-error`, so it never reds an
external PR. (8) `new_validator.py` sanitizes `--desc` (strips `"""`/backslashes) so a hostile
description can't generate uncompilable Python. (9) the flaky `sleep(1.1)` completion-gate tie
tests are deterministic via `os.utime`. Docs corrected: the recovery protocol and the
"startup is honor-system" line in `principles.md` (HISTORY injection is hook-executed since
v3.8.0), and the ratchet's "never half-applies" is scoped to REFUSALS (apply steps are
sequential, `--check`-detectable, re-run-repairable). Known-and-documented residuals: the
completion gate accepts unverified events (acceptable while warning-only); Copilot has no
completion-gate equivalent (`copilot_hook_adapter.py` is tool-call decisioning only), by
design.
