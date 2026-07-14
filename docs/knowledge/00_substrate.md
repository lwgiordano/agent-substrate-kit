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
