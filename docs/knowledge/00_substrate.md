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

v3.8.5 is remediation of an independent re-audit (Codex) of the v3.8.4 cluster; 7 findings,
all real, all eval/test-locked. (1) The v3.8.4 profile floor `max(config, required_profile,
install.json)` compared with `<=`, which TRAPPED the documented repair path: a config stale
BELOW its lock could never reach the lock because `target == floor` was refused — and with a
strict lock (the ceiling) NO target could exceed it, so the config was permanently
unrepairable. Both `substrate_profile.py` and `substrate_upgrade.py --profile` now use TWO
independent constraints — (a) refuse `target < required_profile` (never below the hard floor,
anchored on the owned+frozen lock, NOT agent-writable install.json), and (b) refuse
`target <= current live profile` (raise-only) — so repairing a stale config UP to its lock is
allowed while lowering and no-ops stay refused (regression: `enable_profile_repairs_config_
stale_below_lock`). (2) `check_agent_harness` now also scans the remaining agent-read template
sources bootstrap ships verbatim into downstream CONTEXT surfaces — `finding_response.md`,
`diy_ultrareview_prompts.md`, `blind-spot-checklists/**`, and the ADR/knowledge/postmortem
scaffolds; and `templates/` is required-owned-when-present (`OPTIONAL_DIRS`), closing the gap
where a poisoned template passed the scan and had no CODEOWNER. (3) `new_validator.py` now
DOUBLE-QUOTES the generated pre-commit `name:` scalar — an unquoted `--desc 'x: y'` was invalid
YAML and a leading `#` nulled the name; `_safe_desc` already folds `"`→`'` (regression:
`new_validator_desc_cannot_break_generated_yaml`). (4) `memory_log skill-run --verify` now
EXITS NONZERO when the deterministic check does not pass (it previously always returned the
append rc, so automation read a failed verification as success) AND closes a TOCTOU gap by
re-reading git state after the up-to-120s check — if HEAD/status moved, the event is marked
`verify_stale` and not claimed verified (regression: `memory_log_verify_failure_exits_
nonzero`). (5) the `green-notify` sticky-comment lookup now PAGINATES all PR comments (was one
page of 100), so past 100 comments it still finds its marker instead of stacking duplicate
notifiers.

v3.8.6 is remediation of Codex's re-audit of v3.8.5 — 6 findings, all real, and TWO were
INCOMPLETE v3.8.5 fixes. (1/P1) `substrate_upgrade.py`: the v3.8.5 floor only guarded the
`--profile` branch, so a PLAIN `upgrade --write` still rendered `_profile_alias(answers)` from
the agent-writable `install.json` — a forged `profile=starter` on a strict install produced a
starter `.pre-commit-config.yaml`, silently dropping the strict hooks the frozen lock promises.
Fixed: the render profile is floored to `required_profile` on EVERY path
(`answers["profile"] = max(answers, lock)`), and the `--profile` raise-baseline is the LIVE
config only (not forgeable provenance), so forged-HIGH answers can't block a legit repair.
(2/P2) `memory_log.py` TOCTOU: the v3.8.5 guard compared porcelain STRINGS, so re-editing an
already-dirty file (its `?? `/` M ` line unchanged) went undetected. It now compares a CONTENT
signature — porcelain + `git diff` (staged+unstaged) + untracked-file content — and FAILS
CLOSED if git status is unreadable before/after. (3/P2) `new_validator.py`: `_safe_desc` now
strips C0/C1 control chars (BEL/ESC survived `.split()` and PyYAML rejects them even quoted),
and `--files-regex` runs through `_safe_regex` (drops control chars + doubles single quotes)
before entering the single-quoted `files:` scalar. (4/P3) `substrate_doctor.py`'s import-failure
fallback inventory now mirrors `_substrate_surfaces` exactly (was missing DESIGN.md/
required_profile/README.md + design-system/templates + trust anchors), locked by
`test_doctor_fallback_matches_canonical_inventory` so it can't drift again. Each behavioral fix
has a regression test; the v3.8.5 green-notify pagination fix has no unit test (GitHub-Actions
JS) — documented, not silently uncovered.

v3.8.7 is remediation of Codex's THIRD-round re-audit (of v3.8.6) — 6 findings, all real, and
again two poked holes in v3.8.6 fixes. (1/P2) `substrate_upgrade.py`: the v3.8.6 fix only floored
`profile` DOWNWARD; render answers still came from agent-writable `install.json`, so a forged
`remote_governance=0` on a required-remote repo dropped the trusted-base workflow, and a forged
HIGH profile rendered strict hooks inconsistent with config/lock. Now render answers for SECURITY
tiers are derived from LIVE CONFIG (not provenance), and EVERY frozen `required_*` tier is floored
— `required_profile` and `required_remote_governance` (new `_read_required_remote_governance`).
(2/P2) `memory_log.py` content signature: the v3.8.6 signature used `git diff` (honors
GIT_EXTERNAL_DIFF/textconv → a real change can render empty) and parsed non-`-z` porcelain
(git C-quotes non-ASCII names → wrong path, change missed). Now it reads `status --porcelain -z
-uall` and hashes the RAW on-disk BYTES of every changed/untracked path directly, failing CLOSED
if any path is unreadable or git status fails. (3/P2) `new_validator.py`: the C0/C1 denylist still
missed U+FFFE/U+FFFF and could yield `files: ''` (match-everything). Replaced with JSON
serialization of the `name:`/`files:` scalars (JSON is a YAML subset — escapes controls, quotes,
noncharacters, and preserves the regex exactly) plus REJECTION of an empty/uncompilable
--files-regex. (4/P3) `substrate_doctor.py` fallback parity is now also asserted for
`_COVERAGE_SKIP_PARTS`. (5) test-quality: the new_validator regression drives the real CLI (not
templates directly); upgrade regressions cover forged-HIGH and required-remote render state.
Standing residual (documented): the green-notify pagination fix remains JS-only (no unit harness).

v3.8.8 is Codex's FOURTH-round re-audit (of v3.8.7) — 2 substantive findings (Codex also posted an
explicit convergence verdict: fix these two, do not extend for cosmetic). (1/P1) `substrate_upgrade.py`:
the v3.8.7 fix overrode only profile+remote_governance from live config, but lang/runner/sandbox are
ALSO config-backed and still came from provenance — a forged `lang=none` on a python install dropped
the ruff/pytest hooks. Now EVERY config-backed render tier (profile, lang, runner, sandbox,
remote_governance) is taken from live `.substrate/config`; only ui/workflow (not stored in config) come
from provenance; and all three frozen locks are floored (required_profile, required_remote_governance,
new required_sandbox). (2/P2) `memory_log.py` signature: it hashed working-tree bytes but not the git
INDEX (a staged-blob swap with unchanged working bytes/status was invisible) and discarded rename
old-names. Now it also folds the rename old-name into the signature and hashes `ls-files -s -z` (staged
mode/OID/path), failing closed if the index can't be read. After this round Codex's verdict drove a
shift to a SUBSTANTIVE-ONLY posture (cosmetic/test-hygiene observations are logged, not chased).

v3.8.9 is Codex's FIFTH-round re-audit (of v3.8.8) — 2 substantive findings, both edges of v3.8.8
fixes. (1/P2) `substrate_upgrade.py` `_answers_from_config`: making live config the render authority
exposed that its parser was naive — `.strip('"')` left bootstrap's inline `# ...` comments in the
value, so `SUBSTRATE_REMOTE_GOVERNANCE="1"   # ...` parsed to `1"   # ...` and read as OFF (dropping
the trusted-base workflow). Now a shared comment-aware/quote-aware `_parse_config` (mirroring
`check_substrate_config`) backs BOTH `_answers_from_config` and `_read_cfg_profile`. (2/P2)
`memory_log.py` signature: `skip-worktree`/`assume-unchanged` HIDE a tracked path from porcelain AND
leave its staged OID unchanged, so a working-byte change was invisible. Now the signature also hashes
`ls-files -v -z` (flag map) and the on-disk bytes of every flagged path, failing closed on read error.
The memory content-signature has now been hardened across three rounds (working bytes → +index →
+skip-worktree/flags) — a good illustration that a "hash the tree" evidence primitive has many git
escape hatches (ext-diff/textconv, C-quoting, the index, assume-unchanged) each needing explicit cover.

v3.8.11 is Codex's SEVENTH-round re-audit (of v3.8.10) — 6 substantive findings incl. an external-write
P1. UPGRADE: (P1) `_drifted`/bootstrap `cp` followed a symlinked owned destination → an external write;
added `_unsafe_owned_dests` (refuse if any owned dest is a symlink or resolves outside root, even with
--force). (P1) the authority TOCTOU still had a check→backup gap; made restore TRANSACTIONAL — the
backup's authority files are forced to the `_auth0` snapshot the answers were derived from. (P2) partial
provenance schema — `_drifted` guards a non-dict `owned_file_sha256`, and `ui`/`workflow` are coerced to
strings before argv; (P2) the finalizer is trusted by RESULT (install.json is a regular file carrying the
new version), not just its exit code. MEMORY: the three findings (gitlink/fsmonitor/filemode) shared one
root cause — trusting git's *change-reporting*, which mutable config/env/flags control. Fixed
architecturally with a FULL tracked-content pass: enumerate every tracked path (`ls-files -z`, fsmonitor
off) and hash its lstat type/mode + content (symlink target / file bytes / gitlink HEAD) read directly
from the filesystem; plus `_clean_env` now strips `GIT_CONFIG*` and every snapshot command runs with
`-c core.fsmonitor=false`. Lesson: don't ask git "what changed" for a tamper-evidence signature — read
the filesystem yourself for the full tracked set, because every git reporting path is config-steerable.

v3.8.12 is CLAUDE-self-found (staying ahead of the audit loop): the v3.8.11 external-write guard was
INCOMPLETE. bootstrap's `copy()` (`cp "$s" "$d"`) and `render()` (`sed … > "$d"`) both FOLLOW a
symlinked destination, and they write to EVERY rendered path — but `_unsafe_owned_dests` only checked the
OLD baseline's owned set + preserve files, so a symlink planted at a NEW-version render target (a path not
in the old baseline) was still followed → external write. `_unsafe_owned_dests` now ALSO does a whole-tree
scan (`os.walk`, followlinks=False, skipping .git/venv/caches) and refuses ANY symlink under root whose
target escapes root — the actual external-write vector — regardless of whether the path is baseline-listed.
Lesson: when a guard enumerates "the things that will be written", make sure the enumeration is the SUPERSET
the writer actually touches (here: every render destination, present and future), not a historical snapshot.

v3.8.13 is Codex's EIGHTH-round re-audit (of v3.8.11) — 6 substantive findings, fixed as ONE combined
release (operator directive). (P1 external-write) the guard was still enumeration-based; the real fix is at
the WRITE layer — bootstrap's copy()/render() now `rm -f "$d"` before `cp`/`sed >`, so a symlinked render
target is replaced by a fresh regular file (no-follow) for EVERY destination; the whole-tree guard stays as
defense-in-depth. (P1 authority) answers were derived BEFORE the `_auth0` snapshot; now `_auth0` is taken
FIRST and answers derive EXCLUSIVELY from it (`_answers_from_snapshot`/`_lock_from_snapshot`), with a pre-
render re-check that ABORTS (root still unmutated) on any authority change — replacing the v3.8.12
transactional overwrite, which could LOWER a concurrently-raised lock (raise-only violation). (P2 provenance)
a malformed `owned_file_sha256` (non-dict) is now treated as an UNTRUSTED/ABSENT baseline (—write needs
—force), not proof of zero drift. (P2 memory) the identity now hashes `st_dev/st_ino/st_nlink` (catches a
hard-link/alias swap to an external same-content victim) and fails closed if a tracked path's realpath
ESCAPES root (a symlinked ancestor redirecting to an external tree). Cross-cutting lesson: a tamper-evidence
signature must pin filesystem IDENTITY (inode/nlink/topology), not just content+mode; and a mutating tool
should FIX-AT-THE-WRITE (no-follow, snapshot-derived, fail-closed) rather than chase every enumeration gap.

v3.8.14 is Codex's NINTH-round re-audit (of v3.8.13) — 5 substantive findings, fixed combined. (P1
hash-canonicalization) the memory signature concatenated `path + NUL + content` without length-prefixes,
so two DIFFERENT untracked-file states hashed to the SAME byte stream (a record-boundary collision). Fixed
with an injective encoding: `_hu()` length-prefixes EVERY variable field (8-byte big-endian). (P1 symlinked
PARENT) the v3.8.13 write-layer `rm -f "$d"` removed only the leaf; a symlinked ANCESTOR dir was still
followed by cp/mkdir. bootstrap now refuses at startup if ANY symlink in the target escapes it (python3
os.walk realpath scan) — guarding DIRECT bootstrap, not only the upgrade path (which the _unsafe_owned_dests
tree scan already covered). (P1 authority race) the check->render window let a concurrent raise be clobbered;
the upgrade now captures the locks as the LAST read before the render and reconciles required_* RAISE-ONLY
after restore (never lowers a concurrent raise) — the residual sub-ms window vs a non-cooperating raw writer
is documented, not silently claimed closed. (P2 dirty gitlink) the gitlink identity now hashes HEAD + the
submodule's dirty porcelain, not just HEAD. (P2 missing drift map) a MISSING owned_file_sha256 key (not only
a non-dict value) now makes the baseline untrusted/absent (--write needs --force). Cross-cutting: hash
encodings feeding a security decision must be INJECTIVE (length-prefix), and "remove the leaf before writing"
is not "no-follow" until ancestors are covered too.

v3.8.15 is Codex's TENTH-round re-audit (of v3.8.14) — 4 substantive findings, fixed combined. (P2 memory
gitlink) hashing a submodule's HEAD+porcelain is still evadable (submodule-local skip-worktree/filemode/
staged swaps); the signature now FAILS CLOSED on any tracked gitlink — a repo with a submodule never gets
verified=true (honest over a false pass). (P1 bootstrap TOCTOU) the startup escaping-symlink scan is
check-then-write; added a PER-WRITE `_safe_dest` guard in copy()/render() that re-resolves the destination's
real parent (`pwd -P`) and refuses if it is outside the repo — a per-write invariant, not a one-time scan
(sub-ms plant-between-check-and-cp residual documented). (P1 upgrade race) the v3.8.14 raise-only
reconciliation preserved the lock but left config/hooks stale (internally inconsistent "success"); now if a
concurrent raise is reconciled the upgrade FAILS (rc 2) so a re-run renders consistently against the raised
lock. (P2 upgrade baseline) a valid owned_file_sha256 dict with one entry REMOVED still fail-opened; _drifted
now cross-checks the security-critical managed dir (scripts/) and flags any present file the render would
overwrite that the baseline does not vouch for -> drift (needs --force). Cross-cutting: when you cannot
cheaply VERIFY something (submodule integrity), FAIL CLOSED rather than approximate; a check-then-act guard
needs a per-operation invariant; and never claim success after a security reconciliation left state
internally inconsistent.

v3.8.16 is an ARCHITECTURAL re-design of the memory `--verify` signature, not another point patch —
it retires the whack-a-mole tail that produced findings v3.8.10 (a,b,c), v3.8.14, and v3.8.15's memory
items. Every prior memory finding was the same shape: the hand-rolled `_worktree_state` re-derived the
worktree fingerprint by hand (walking git-status paths, lstat-ing types/modes/inodes, hashing hidden
files, length-prefixing to avoid collisions), and each round Codex found one more attribute the walk
did not canonicalize the way git does (symlink target vs bytes, filemode, skip-worktree, gitlink,
hardlink-swap, path encoding). Re-deriving git's own content model in Python is a losing game. The fix:
delegate canonicalization to git. `_worktree_state` now stages the FULL worktree into a throwaway index
(`GIT_INDEX_FILE` pointed at a `tempfile.TemporaryDirectory`, `git -c core.fsmonitor=false -c
core.fileMode=true add -A`) and takes `git write-tree` — a content-addressed tree OID over exactly the
bytes+modes+paths git tracks, computed by git, gitignored files excluded, no skip-worktree bits on a
fresh index. The verify signature is that OID folded with a hash of the temp index (so index-only staging
differences still register), and it still FAILS CLOSED on any tracked gitlink (mode 160000 in the index)
since a submodule's content is not in the superproject tree. This DELETES the entire lstat/inode/flag/
length-prefix walk and the class of "you missed attribute N" findings with it: whatever git's content
model canonicalizes, the OID reflects, by construction. All git calls still run under the sanitized
`_clean_env` (routing vars stripped) and identity (full HEAD OID + symbolic ref, fail-closed) is
unchanged. Cross-cutting lesson: when you are verifying a property some other tool already computes
canonically (here, git's notion of tracked content), ANCHOR the check to that tool's output instead of
reconstructing it — a reconstruction has to chase every attribute the real thing already handles.

v3.8.17 continues the architectural convergence (following v3.8.16's memory re-design) into the upgrade
engine's drift gate — closing finding upgrade:252 (baseline completeness scope). The v3.8.15 completeness
cross-check catches an attacker who EDITS a substrate-owned file AND DELETES its `owned_file_sha256` entry
(so the hash-diff loop never sees it) by scanning a managed dir for present-but-unvouched files — but it
scanned ONLY `scripts/`. A RESERVED top-level managed FILE, `manage.sh`, lives under no scanned dir, so the
same edit+delete evasion on the substrate CLI entrypoint slipped through and `--write` without `--force`
would overwrite it silently. Fix: `_drifted` now also completeness-scans `_COMPLETENESS_SCAN_FILES =
("manage.sh",)`. The deliberate scope choice mirrors the memory lesson (anchor to the canonical thing, but
don't over-broaden): it does NOT scan the full `write_install_json` owned set (tests/, .claude/,
.github/workflows/, docs/knowledge/) because projects legitimately author their own files there and flagging
an unvouched file as drift would FALSE-FLAG a well-behaved repo — cutting functionality. Only
substrate-RESERVED surfaces a project never authors (scripts/ by the hard rules, plus manage.sh) are safe to
treat present-but-unvouched as tamper. A security-auditor pass confirmed manage.sh is the correct/sufficient
addition (AGENTS.md/CLAUDE.md/.substrate/config are preserve-listed and project-editable; pytest.ini and
.pre-commit-config.yaml a project may author, so they stay out). Cross-cutting: a completeness/coverage scan
is only as good as its SURFACE — enumerate the reserved surface deliberately, and never widen it onto
paths where legitimate project content lives.

v3.8.18 is Codex's TWELFTH-round re-audit — two of the four findings, both verified real against the
code, and both correcting an OVER-CLAIM in the v3.8.16/v3.8.17 architectural work. (P2 memory:209) the
v3.8.16 `git write-tree` signature attests git's OBJECT model, which applies `clean` filters and (via the
fresh temp index's `add -A`) drops gitignored paths — so a `filter.*.clean` that canonicalizes differing
raw bytes to one blob, or a tracked-but-gitignored file, could change on disk with the tree OID unmoved
and `verified=true` recorded. The signature now folds in a third component, `_raw_tracked_hash`: a
length-prefixed SHA-256 over the RAW on-disk bytes of every `git ls-files` path (symlink targets via
readlink), which is what makes it faithful to the bytes the CHECKER actually reads. This is strictly
ADDITIVE content coverage on top of write-tree (which still canonicalizes mode/symlink/structure), not a
return to the pre-v3.8.16 hand-rolled signature. (P1 bootstrap:136) the v3.8.13 no-follow write guard
(`_safe_dest` + leaf `rm -f`) was wired ONLY into copy()/render(); ~15 DIRECT redirection sites
(`.substrate/config`, the required_* locks, sandbox.json, the docs seeds, dependabot) wrote via raw
`>`/`cat >` with no guard, so a planted symlink — in-repo-POINTING, which evades the escaping-symlink
startup scan — was followed straight through, clobbering its target. Added `wprep` (mkdir parent +
_safe_dest + leaf unlink) for truncating writes and `wappend` (refuse a symlinked leaf) for the two `>>`
appends, and routed every direct-write site through them, plus `_safe_dest` on the skills `cp -R`
targets. Cross-cutting: when you "delegate to a canonical tool" (git write-tree), verify the tool's
canonicalization matches YOUR property — write-tree canonicalizes for STORAGE (filters, ignores), not for
raw-byte attestation; and a per-write invariant must cover EVERY write site, not the two most obvious
helpers. The other two round-12 findings (upgrade:593 concurrent-raise render staleness, upgrade:258
completeness scope) are handled together in the upgrade staging-swap re-architecture, since both need the
new kit's exact overwrite set.

v3.8.19 closes the remaining round-12 pair, both in the upgrade engine. (P1 upgrade:593) the v3.8.15
concurrent-raise failure was HISTORY-based: it fired only when the reconcile loop itself had to write a
lock back up. A raise landing after `_restore` but BEFORE the reconcile read made `_cur` already equal
the raised value — `_reconciled` stayed False and the upgrade claimed success with config/hooks stale vs
the lock. The fix makes success a property of the END STATE: a post-render POST-CONDITION re-derives the
render answers from the CURRENT on-disk authority snapshot (config + required_* locks, floored exactly
like the pre-render derivation) and compares them with the answers actually rendered; any mismatch on
profile/lang/runner/sandbox/remote_governance → rc 2 ("stale render, re-run"), locks never lowered. This
catches a raise landing in ANY window up to the final read (the read→exit residual is documented — no
smaller window exists without OS locking). (P2 upgrade:258) the completeness scan now cross-checks the
NEW KIT's EXACT overwrite set: `_kit_overwrite_set(kit)` derives every destination `bootstrap --force`
may write from the kit's own contents (scripts, extras, tests, agents, skills, workflows, the fixed
template→dest map, the direct-write regenerated files), deliberately over-inclusive on profile/lang
conditionals. Crucially it is INTERSECTED with `_baseline_coverage(root)` (= write_install_json
owned_files — the exact surface hash_owned enumerates): a kit dest present locally, inside the vouch
surface, but absent from the owned map is a deleted/forged entry or post-install addition → drift (needs
--force). Kit dests OUTSIDE the vouch surface (the dormant `.substrate/` staged templates) are NOT
flagged — no baseline ever hashed them, so "unvouched" is their normal state and flagging would
false-drift every legitimate upgrade (that residual is a pre-existing coverage gap of the baseline
schema, documented, distinct from this finding). A parity regression runs the REAL bootstrap into a
fresh repo and asserts every file it creates is inside `_kit_overwrite_set` ∪ a small exempt set
(append-only/only-if-missing/regenerated) — so the hand-mirrored dest map can never silently drift from
bootstrap. Cross-cutting: claim success from the END STATE, not from the code path taken; and when a
guard needs a surface enumeration, tie it to the enumeration the protected artifact was BUILT with
(baseline coverage), then guard the guard with a parity test against the real producer.

v3.8.20 is Codex's THIRTEENTH-round re-audit (of v3.8.19) — 4 substantive findings, all verified and
fixed combined. (P1 bootstrap:85) `_safe_dest`'s "real parent inside the repo" invariant passed an
in-repo-POINTING alias: `.substrate -> .git` kept every write under root while routing it into git
internals (`wprep .substrate/config` overwrote `.git/config`). The invariant is now EXACT-PARENT — the
destination's real parent must EQUAL its literal logical parent (`$REPO_ROOT_REAL/<dirname>`), refusing
ANY symlinked ancestor: escaping, aliasing, or git-internal. Bootstrap mkdir -p's real dirs for all its
dests, so no legitimate install trips it. The upgrade engine got the same class closed pre-flight:
`_unsafe_owned_dests` clause 3 flags any owned/preserve path whose resolved path differs from its literal
path. (P1 upgrade:750) the v3.8.19 postcondition compared DERIVED answers, and `_answers_from_snapshot`
maps a MISSING config to all-DEFAULT answers — so on a standard-profile render (answers == defaults),
deleting `.substrate/config` after `_restore` compared EQUAL ("default-equivalent absence") and the
upgrade claimed success with no config on disk. The postcondition now requires the CONCRETE end state
first: all four authority files present as regular non-symlink files with readable bytes, and config
carrying an explicit SUBSTRATE_PROFILE key (only that key, so an ancient restored config lacking the
newer optional keys is not false-failed). (P2 memory:255) `_raw_tracked_hash` hashed bytes but not
metadata: a 0644->0755 flip on a tracked-but-IGNORED path under core.filemode=false is invisible to the
temp-index write-tree (ignored paths never staged), the real index (filemode=false), and a bytes-only
hash — the permission bits (S_IMODE, octal) are now folded into each regular-file record. (P2
upgrade:350) `_kit_overwrite_set` enumerated new-kit LEAVES, but bootstrap replaces skill dirs WHOLESALE
(`rm -rf` + `cp -R`), so a local file under a replaced dir that is NOT a new-kit leaf was silently
DELETED with no drift flag; `_kit_replaced_dirs` now mirrors bootstrap's replacement semantics and
`_drifted` completeness-checks every present-but-unvouched file under those dirs (a local
`.claude/skills/custom-skill/` dir NOT in the kit is untouched by bootstrap and correctly not flagged).
Cross-cutting: "inside the repo" is not a write-safety property when aliasing exists — the invariant must
bind the LITERAL path; a postcondition must assert concrete artifact EXISTENCE before comparing derived
values (absence can equal defaults); and an overwrite-set is incomplete without the DELETION effects of
wholesale directory replacement.

v3.8.21 is Codex's FOURTEENTH-round re-audit (of v3.8.20) — 6 substantive findings, all verified and
fixed combined; the theme is that bootstrap TRUSTED pre-existing leaves and MUTATED before/around its
write guard. (P1 bootstrap:110) `wappend` refused a symlink leaf but FOLLOWED a hard link — the `>>`
ignore block grew an external same-inode victim; it now breaks the link first (copy to a same-dir
tempfile, `mv -f` over the target) so the external inode is untouched and the append hits our fresh copy.
(P1 bootstrap:152) a SKIPPED (pre-existing, non-force) script was still `chmod +x`ed, flipping an
external hard-linked inode 0644->0755; `copy`/`render` now take an optional mode applied ONLY inside the
write branch, so a preserved/aliased leaf's bits are never touched. (P1 bootstrap:323) a non-force
install into a repo with a pre-existing `scripts/update_manifest.py` collision SKIPPED the copy then
EXECUTED the target's (attacker's) file as trusted code; the three bootstrap-invoked tools
(update_manifest, write_install_json, substrate_doctor) now run from `"$KIT_DIR/scripts/..."` — trusted
code, resolving the target repo via cwd/`--root .` (the opt-in `--install-tools` `./manage.sh setup` path
still runs the target manage.sh; documented, not auto). (P2 bootstrap:274) the exact-parent guard was not
mutation-free — `mkdir -p` FOLLOWED a symlinked ancestor (`.github -> .git`) and created `.git/workflows`
BEFORE `_safe_dest` could refuse; `_safe_mkdir_p` now builds each path component, refusing an existing
symlink ancestor before any mkdir, and replaced every body `mkdir -p` (the top-of-file
`mkdir -p "$TARGET"` stays plain — it predates the function and handles absolute paths). (P1
upgrade:846) the post-render authority postcondition ran only ONCE, BEFORE the finalizers, so a lock
raise during update_manifest/write_install_json still claimed success; it is now a closure re-evaluated
AFTER the finalizers too (the last read before exit). (P2 upgrade:296) the replaced-skill-dir drift scan
skipped non-regular entries, but bootstrap's `rm -rf` deletes a symlink too — an unvouched in-repo
symlink under a replaced dir was silently deleted; the scan now flags any present entry (file OR symlink)
under a wholesale-replaced dir that the baseline does not vouch for (a clean install has every kit file
in ownkeys, and a custom skill dir NOT in the new kit is untouched, so neither false-flags).
Cross-cutting: a no-follow write guard must also defeat HARD links (same-inode aliasing), not just
symlinks; NEVER execute or chmod a leaf you merely preserved rather than wrote; a check-then-mutate guard
must validate every ancestor BEFORE the first mkdir; and a success postcondition must be re-checked after
the LAST state-changing step, not before it.

v3.8.22 is Codex's FIFTEENTH-round re-audit (of v3.8.21) — 8 findings: 6 fixed, 1 documented as a
known limitation, 1 cosmetic-doc fixed. (P1 bootstrap:368) `--install-tools` runs `./manage.sh setup`,
executing the local manage.sh — a non-force install into a repo with a pre-existing manage.sh collision
would run the target's (attacker's) copy; bootstrap now force-renders the kit's manage.sh before
executing it (manage.sh is substrate-owned, so replacing a collision is correct). (P1 upgrade:320)
`_baseline_coverage` did `from write_install_json import`, resolving to the TARGET's possibly-modified
module and RUNNING its top-level code during `upgrade --plan` (before drift is even refused); it now execs
the TRUSTED KIT copy in an isolated module with sys.path restored. (P2 bootstrap:137) my v3.8.21 hardlink-
safe `wappend` rewrote EVERY existing append target via mktemp+mv, dropping a normal 0644 dotfile to
0600 — it now rewrites ONLY when the leaf is actually hard-linked (nlink>1) and preserves the mode.
(P2 bootstrap:367) direct bootstrap swallowed a provenance-finalizer failure (rc 0 with no baseline); it
now fails closed (install.json must be a regular file), like upgrade. (P2 upgrade:298) the replaced-dir
drift scan `continue`d on a symlinked dir ROOT, so bootstrap's `rm -rf` would delete the operator's
symlink without a --force gate; the replaced-root symlink is now flagged as drift itself. (P2 upgrade:812)
the postcondition accepted a config that canonical `check_substrate_config.py` rejects (e.g. an unknown
key); it now runs the canonical validator and fails on a real (rc 2) validation error — and a companion
`_apply_capability_floor` raises the PRESERVED config's SUBSTRATE_REMOTE_GOVERNANCE/SUBSTRATE_SANDBOX to
match a frozen lock so the render+config end state is internally consistent. (P3 BENCHMARK.md) the
reproduce block hard-coded "v3.8.4" — the benchmark is now REGENERATED (not sed-relabeled) so header and
reproduce block both carry the live VERSION.

KNOWN LIMITATION (Codex round-15 upgrade:220, WONTFIX-local): the upgrade drift baseline
(`.substrate/install.json` `owned_file_sha256`) is AGENT-WRITABLE by design — it is rewritten on every
install/upgrade. An attacker who edits an owned file AND recomputes that file's digest in install.json can
suppress the drift WARNING, and `upgrade --write` will overwrite the edit without demanding --force. This
is NOT a locally-closeable security boundary: there is no non-agent-writable anchor on the local disk, and
the failure mode is benign for integrity (the tampered file is replaced by the clean kit version) — the
loss is only the drift *warning*. The real trust anchor for machinery integrity is the SIGNED release
(minisign-verified before an upgrade reads it) plus the REMOTE trusted-base authority (CODEOWNERS +
branch-protected `git diff` freeze of `scripts/`/`manage.sh`/workflows). `write_install_json` already
documents the baseline as "a safety aid, not a gate"; treat local drift as advisory and rely on the signed
artifact + remote governance for a real boundary. (The recurring "`./manage.sh check` exits 143" Codex
reports is a SIGTERM/timeout on its host during the ~2-min pytest run, not a substrate bug — `check` is
consistently exit 0 here.)

v3.8.23 is Codex's SIXTEENTH-round re-audit (of v3.8.22) — 5 substantive findings, all verified and
fixed; three of them are INCOMPLETE-FIX regressions of my own v3.8.18/v3.8.22 work, which is the lesson
of the round. (P1 upgrade:916) the v3.8.22 canonical-config gate ran the TARGET's validator and failed
OPEN on a crash (`rc == 2 and "Traceback" not in out`) — exactly the residual my own security-auditor
flagged as "acceptable as designed", which Codex then weaponized: a concurrent writer replaces
`check_substrate_config.py` with a crashing file and the upgrade claims success. Worse, the `rc == 2`
test never covered rc 1 at all (= dangerous LINT/TEST command values). Now the gate runs the KIT's
trusted copy (its `__file__`-relative siblings resolve in the kit; cwd=root keeps the TARGET's config as
the subject) and fails on ANY nonzero rc — no fail-open path remains. (P1 upgrade:32) `from
_verify_backends import verify` sat at MODULE level, so the sibling executed at interpreter start —
before arg parsing, before verification, before the drift gate — meaning `--plan` on a repo with a
modified helper RAN the modification even when the source was then rejected; the import is now lazy
(`_load_verify()`, sys.path saved/restored) so every rejection path avoids it. Note the honest scope:
running the TARGET's `substrate_upgrade.py` is already trusted-by-execution, so this narrows a window
rather than creating a boundary the entry point lacks. (P2 bootstrap:370) my v3.8.22 fail-closed
provenance guard proved only that install.json was a REGULAR FILE — a pre-created STALE one (read-only,
kit_version=OLD) let the silently-failed writer pass, leaving a baseline vouching for the WRONG tree; the
guard now verifies the CONTENT records this install (kit_version == the rendered kit), the same
trust-the-result-not-the-rc rule the upgrade engine already used. (P2 bootstrap:388) `./manage.sh setup
|| true` reported a successful install while setup had failed (e.g. `.substrate/venv` pre-created as a
regular FILE); `--install-tools` now fails closed — a documented behavior change from "best-effort",
recorded in the README/usage text. (P2 memory:244) `_raw_tracked_hash` joined ROOT with each tracked path
and lstat'd it: lstat does not follow the FINAL component but DOES follow every PARENT, so replacing
`tracked/` with a symlink to an outside directory hashed the OUTSIDE bytes while still recording
verified=true — regressing the documented fail-closed realpath-escape behavior. Each tracked path's real
parent must now stay inside `_ROOT_REAL` (realpath'd once, so a repo legitimately reached through a
symlink does not false-fail), else the signature is None and verify fails closed. Cross-cutting: an
"acceptable residual" in a security gate is a FINDING waiting to be filed — close fail-open paths rather
than documenting them; an existence check is not a completion check (verify the CONTENT the writer should
have produced); and when you add a containment invariant, re-derive it for EVERY path-joining site, since
lstat/realpath differ precisely on ancestors. Also resolved this round: Codex's recurring
`./manage.sh check` exit 143 did NOT recur (its own run completed green) — it was a SIGTERM/timeout on
its host, never a substrate bug, as diagnosed in v3.8.22.

v3.8.24 is Codex's SEVENTEENTH-round re-audit (of v3.8.23) — 4 substantive findings, all verified and
fixed. The round's theme is TRUSTED-TOOL PROVENANCE: every place the engine still ran, imported, or
believed code/state from the tree it was auditing. (P1 upgrade:209) v3.8.23's lazy verifier import still
loaded the TARGET's `_verify_backends.py`, so a `verify()` stubbed to return rc=0 made an UNSIGNED zip
print "source: verified" — verification is the trust anchor for the source, so trusting a target-modifiable
verifier defeats it. `_load_verify(root)` now hash-checks the helper against the drift baseline BEFORE
importing it, whenever the engine runs from the target tree and the baseline vouches for the file, and
aborts on mismatch. Honest limits stated in code: the baseline is itself agent-writable (see the
upgrade:220 limitation) and running the target's engine is already trusted-by-execution, so an attacker
editing BOTH is outside any in-process check — the anchors remain the signed release and the remote
trusted-base freeze. (P1 upgrade:961) the finalizers still executed the TARGET's
`update_manifest.py`/`write_install_json.py` AFTER the drift gate, so a replacement landing in that window
ran target code and still produced a successful upgrade; both now run the KIT's copies (`_tool()`), with a
pinned env (SUBSTRATE_PROJECT_DIR=root) and cwd=root so the TARGET stays the subject. (P2 bootstrap:391)
v3.8.23's content check compared only `kit_version`, so a pre-created STALE but SAME-VERSION install.json
(empty owned map) still masked a failed writer; the guard now captures the writer's REAL exit status
(`_WJ_RC=0` + `|| _WJ_RC=$?`, so `set -e` cannot abort before the guard explains why) and requires the
baseline to VOUCH FOR THE RENDERED TREE — non-empty owned map whose recorded `manage.sh` hash equals the
live one. (P2 memory:264) v3.8.23's containment guard covered escaping ANCESTORS but not an escaping
tracked SYMLINK LEAF: the signature recorded only the link TEXT while `--verify` EXECUTED the outside
target (tracked `run_smoke_verification.py` symlinked out), recording verified=true. The leaf's realpath
must now stay inside the root, AND `_run_deterministic_check` refuses to execute a check tool that
resolves outside the repo (defense in depth, independent of the signature). Cross-cutting: when you fix
"don't trust code from the audited tree", fix EVERY loader (imports, subprocess finalizers, executed check
tools) — one narrowed window is not the class; and a freshness check on state an attacker can pre-place
must be anchored to something they cannot forge (here, the writer's rc plus a hash of the file just
rendered), never to a version label alone.

v3.8.25 is Codex's EIGHTEENTH-round re-audit (of v3.8.24) — 6 substantive findings (4 P1), and the
round exposed a whole class the substrate had never modeled: VERIFYING BYTES THAT ARE NEVER EXECUTED.
(P1 upgrade:79) v3.8.24's source hash-pin hashed `scripts/_verify_backends.py` and then `import`ed it
normally — but a PEP 552 UNCHECKED hash-based `.pyc` is used WITHOUT being validated against its source,
and `__pycache__` is GITIGNORED, so it is covered by neither the drift gate nor the memory signature. A
planted .pyc therefore executed while the pinned .py stayed clean, approving an unsigned zip. The fix is
the general rule: HASH-THEN-EXECUTE THE SAME BYTES — `_exec_module_from_source()` does
`compile(path.read_bytes())` + exec into a fresh module, never consulting the cache (also applied to
`_baseline_coverage`). (P1 _verify_backends:29) pinning only the wrapper still trusted its
target-controlled dependency: `_verify_backends` imports `_minisign`, so a poisoned `_minisign.py`
approved a forged `.minisig` while the wrapper matched the baseline. The pin now covers the whole
DEPENDENCY CLOSURE (`_VERIFIER_CLOSURE`), loaded in order so `_minisign` is already in sys.modules and
the wrapper's `from _minisign import ...` binds the trusted module. (P1 upgrade:63) the pin ran only
`if isinstance(_want, str)`, so DELETING the verifier's owned-map entry made the check skip entirely —
a trust anchor that fails open is not an anchor; a missing/non-string entry now REFUSES (with
--allow-unverified as the explicit opt-out). (P1 write_install_json:105) `dest.write_text()` writes
THROUGH the inode, so a HARD-LINKED `.substrate/install.json` (nlink>1 — invisible to every symlink
check) had its outside same-inode twin overwritten with provenance; the writer now uses same-dir
mkstemp + `os.replace`, which replaces the directory entry, breaks the link, follows no symlink, and is
atomic. (P2 memory:264) the v3.8.24 leaf guard allowed a tracked symlink resolving INSIDE the repo — but
to an untracked/ignored file, whose bytes are in no part of the signature; `_raw_tracked_hash` now
requires a tracked symlink's target to itself be TRACKED, and `_run_deterministic_check` refuses a
SYMLINKED check tool outright. (P2 run_smoke_verification:52) the same pyc bypass applied to the
validators the smoke runner imports, letting planted bytecode run outside all signed state; the runner
now redirects `sys.pycache_prefix` to a fresh temp dir (and sets dont_write_bytecode +
invalidate_caches) BEFORE any validator import, forcing compilation from real source — done in-process
because `-I` strips the equivalent env vars. Cross-cutting: a hash/signature over a FILE proves nothing
unless the runtime is forced to execute that file's bytes — enumerate every cache, alternate loader, and
dependency in the closure; and gitignored paths (`__pycache__`) are exactly where covered-by-nothing
code hides.

v3.8.26 is the first ADOPTION-path release, and it exists because a question no audit round had
asked — "can a developer actually install this into a real product?" — found two hard blockers in
minutes that 18 rounds of adversarial security auditing never touched. Both fire on the most common
real-world case: a Python repo that ALREADY has a pyproject.toml. (1) bootstrap correctly refuses to
clobber an operator-owned pyproject.toml, but that file is where the kit's
`[tool.ruff] extend-exclude = ["scripts", "extras", ...]` lives — so an existing-pyproject repo never
received it, ruff fell back to its DEFAULTS (E4 includes E402), linted the VENDORED substrate in
scripts/, and blocked EVERY commit on the substrate's own code. Fixed in `run_python_gate.sh`: the
adapter now FILTERS substrate-reserved paths (scripts/, extras/) out of the ruff file arguments, so
the invariant lives where an operator cannot lose it. Filtering ARGUMENTS beats `--config`/`--exclude`
because it is purely additive — it never overrides the repo's own excludes (the kit's own config
excludes tests/ and installer/, which a `--config` override would have silently dropped) and it works
for `ruff check` and `ruff format`, which do not accept the same exclude flags. `tests/` is
deliberately NOT filtered: it is consumer-owned and the vendored consumer tests are ruff-clean.
(2) bootstrap gitignored only `.substrate/memory/tasks/` while the kit's own .gitignore covers
`.substrate/memory/` WHOLESALE — so in a consumer repo `events.jsonl` and `session_start.json` were
TRACKED, the hooks rewrote them on every pre-commit run, and pre-commit's "files were modified by this
hook" meant the commit could NEVER converge (re-staging just reproduced it). One-line fix to match the
kit. Verified end to end: fresh product repo + existing pyproject -> bootstrap -> setup -> adopt commit
converges -> a normal day-to-day product commit passes first try with ZERO failed gates. Regression:
test_adoption_into_repo_with_existing_pyproject. Cross-cutting, and the real lesson of this release:
an adversarial auditor testing disposable repos measures whether the gates can be BROKEN, never whether
a user can SUCCEED — those are different bug classes, and the second one had no coverage at all.
Remaining known adoption cost (by design, not a bug): the docs/code parity gate is unconditional at
every profile, so each pre-existing source module needs a knowledge-doc `covers:` entry before the
first commit passes.

v3.8.27 is the second adoption-path finding, surfaced by testing a REAL upgrade (a v3.7.14 tool
cloned and upgraded to v3.8.26) rather than by any audit round — and it is the same class as v3.8.26:
a defect visible only when the substrate runs in a CONSUMER repo, never in the kit's own tree.
`t_profile_ratchet_raise_succeeds` staged its fixtures from `templates/pre-commit-config.yaml.template`
and `extras/*.py`, which are kit-SOURCE dirs a consumer install never receives — bootstrap stages that
content under `.substrate/pre-commit-config.yaml.template` and `.substrate/extras/` instead. Both
lookups are guarded by `is_file()`/`glob`, so in an installed repo they silently staged NOTHING,
`substrate_profile --write strict` then failed with "template is missing", and a BENIGN task was scored
as a FALSE POSITIVE — every consumer install reported `benign FP 1/11 (rate 0.09)` while the kit's own
tree reported 0/11. The eval suite is the kit's central honesty claim ("re-run it on your host"), so a
suite that cannot report clean ON a host was undermining exactly the property it exists to prove. Both
lookups now fall back to the installed layout; verified 0/11 in the kit AND in two consumer repos (one
fresh v3.8.26 install, one upgraded from v3.7.14). Regression:
test_evals_resolve_staged_assets_in_consumer_layout, which asserts both fallbacks statically and runs
the task behaviorally. Cross-cutting: when a tool ships INTO another repo, every path it resolves has
two layouts — source and installed — and a silent `if is_file()` guard turns the missing-layout case
into a wrong ANSWER rather than an error. Prefer resolving both, and test the tool where it will
actually run.

v3.8.10 is Codex's SIXTH-round re-audit (of v3.8.9) — 6 substantive findings (operator stopping rule:
fix everything substantive until a clean pass). THREE in `memory_log.py`: (a) the hidden-path loop
hashed `read_bytes()` (follows symlinks) not lstat type/mode or `readlink`, so a retargeted symlink
(identical target bytes) or a 0644->0755 flip was invisible — now hashes lstat S_IFMT/S_IMODE +
readlink; (b) git snapshot commands inherited `GIT_INDEX_FILE`/`GIT_DIR`/`GIT_WORK_TREE`, so a routed
alternate index could authenticate a clean state — now ALL git calls (and the check) run under a
sanitized env (routing vars stripped); (c) identity was not fail-closed — HEAD failures collapsed to
`"none"`, only the short OID was compared, the branch was never re-read — now a success-aware full
HEAD OID + symbolic ref are compared before/after, failing closed on an unborn/unreadable HEAD or a
same-commit branch switch. THREE in `substrate_upgrade.py`: (d) authority (config + required_* locks)
was read BEFORE `_resolve_kit`, a TOCTOU — now `_authority_snapshot` is re-compared just before the
write and aborts on any change; (e) `_load_install_json` accepted any JSON shape (a bare string
crashed later `.get()`/`dict()` with AttributeError) — now any non-mapping is treated as absent, and
the `answers` sub-shape is guarded; (f) finalizer return codes (`update_manifest`, `write_install_json`)
were ignored so "applied" printed even when provenance was never written — now a finalizer failure
returns nonzero and surfaces stderr. (v3.8.10)
