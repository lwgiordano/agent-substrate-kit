# Agent Substrate Kit v3

A portable, self-auditing substrate for Claude Code, Codex, and human
developers. v3 is the evidence-aligned revision of v2: deterministic
hooks replace honor systems, progressive disclosure replaces mandatory
reads, and ceremony is profile-gated.

## Install

```bash
cd your-project
bash /path/to/agent_substrate_kit_v3/bootstrap.sh --profile standard --lang auto
./manage.sh setup
./manage.sh doctor
./manage.sh check
./manage.sh evals     # prove the policy behaves (block-rate / false-positive-rate)
./manage.sh release   # package + verify from the built artifact
```

## Bootstrap options

```text
--target PATH              Install into PATH instead of current directory
--runner auto|uv|python|poetry
--workflow superpowers|gsd|none
--ui yes|no
--profile starter|standard|strict
--lang auto|python|node|go|none
--force                    Overwrite existing substrate-owned files
--install-tools            Best-effort install of dev tooling
--no-doctor                Skip final doctor check
```

## Profiles

| | starter | standard (default) | strict |
|---|---|---|---|
| Core validators (drift, secrets, harness, HISTORY SHA, manifest) | yes | yes | yes |
| Lifecycle hooks (lint-on-write, todo mirror, session handoff) | yes | yes | yes |
| Lint/format/test pre-commit + postmortem gate cross-ref | — | yes | yes |
| 4-field bug-fix commit protocol + postmortem-per-bugfix hooks | — | — | yes |
| Extras (calibration, stale-phrases, license headers) | — | — | yes |

## Current status (v3.8.14)

**Local-first, remote-expandable.** The base is offline-complete (memory,
hooks, validators, evals, sandbox, release bundle) — no GitHub/CI/token/remote
required. Three orthogonal capability axes layer on top: governance **profile**
(starter/standard/strict), egress **sandbox** (`SUBSTRATE_SANDBOX`), and **remote
governance** (`SUBSTRATE_REMOTE_GOVERNANCE` — CODEOWNERS coverage + the
trusted-base authority). v3.6.0 **decoupled remote governance from the strict
profile**: a repo can be strict-LOCAL (no remote → never told it is "broken" for
lacking a GitHub-only CODEOWNERS) or standard+remote. `./manage.sh go-live` is the
map across all three tiers — it surfaces the current state, the next rung, and the
exact `enable` command, and **never claims production-hardening offline** (live
GitHub enforcement needs `enable remote --check`). Turn the tier on with
`bootstrap --profile strict+remote` or `./manage.sh enable remote --write` (which
installs the trusted-base workflow from a staged template — no re-bootstrap). go-live
is the **fast** map (cheap base checks + offline detection only, never the full gate),
and enabling remote governance is **complete-or-blocked**: `check` refuses if the flag
is on but the trusted-base workflow is missing — the tier can't claim authority it
doesn't have. `./manage.sh context-report` measures the token/context footprint locally
(always-loaded vs on-demand, the cache-prefix hash, largest contributors) so the lean
keystone + progressive-disclosure design stays honest and visible.

Credible for controlled trial in **standard mode** across Python, Node,
Go, and no-language repos. The **remote-governance tier** enforces CODEOWNERS
coverage of the actual privileged files (last-match semantics, `*`/`**`/trailing-
slash matching, placeholder rejection, 3 MB load-limit check),
subdirectory-safe exfil policy, and environment-independent audits.
Untrusted model/tool state — transcript turns AND TodoWrite labels — is
sanitized before it can re-enter context through the compaction handoff;
the shared command policy (owned by `command_policy.py`, with
`check_exfil_guard.py` a thin adapter) fails **closed**, including on an
invalid runtime `SUBSTRATE_PROFILE` (a typo can't downgrade strict at the
hook boundary). The substrate **pins three layers**, so a weakening at any
of them BLOCKS the gate and requires an explicit, reviewed, CODEOWNED pin
update: pattern **DATA** (`REQUIRED_PATTERN_SHA256` / `INTEGRITY_SHA256`
regex hashes), policy + scanner **LOGIC** (`check_policy_code_integrity.py`
pins the **whole source** of `command_policy.py` and `check_agent_harness.py`
with a version-portable raw-byte SHA-256 — any edit, added top-level code,
reassignment, or fake object changes the hash and BLOCKS), and scanner/hook
**BEHAVIOR** (`check_harness_smoke.py` + `check_hook_smoke.py` run the real
scanner/hooks against randomized multi-family payloads, with live-regex
hash + real-`re.Pattern`-type checks). The kit source tree is self-governed
with these same rules, and `package_release.sh` runs the suite from the
extracted artifact (with early hang diagnostics) as a reproducible release
gate.

**Measured behavior, not just pinned code.** `run_substrate_evals.py` runs the
real validators/hooks against staged adversarial states and scores
block-rate / false-positive-rate (every malicious task must BLOCK, every benign
task must be ALLOWED), failing on any slip — turning "it works" from a claim into
a measured property and a behavioral regression net. In-process tasks run
serially; the heavy subprocess-backed tasks run concurrently (adaptive
`min(4, cores)` workers, env-tunable per-subprocess cap default 30s), so it
completes in constrained runtimes and a timeout is a bounded FAILURE, never a
wedge. `--fast` (in-process only) and `--run-one <id>` give quick/isolated paths;
traces + `subprocess_timeout`/`heavy_workers` metrics make any failure
attributable. It is a lightweight repo-local eval suite, NOT a hosted
longitudinal observability system.

The validators also defend their own EXECUTION environment: a repo-local
file that shadows a stdlib module (`scripts/hashlib.py` …) is blocked by
`check_import_shadowing.py`, and every validator runs under `python -I`
(isolated) so the repo's `scripts/` dir cannot hijack a validator's stdlib
imports and defeat the hash pins.

**Root of trust (strict).** The local gate runs validators FROM the PR, so
on its own it cannot stop a PR that edits both a policy file and the
validator that judges it — a repo-local gate is developer feedback, not the
final authority. The **remote-governance tier** therefore ships
`.github/workflows/trusted-base-audit.yml` (written by `bootstrap --profile
*+remote` / `enable remote`, not by `strict` alone — v3.6.0), which **freezes** the
validator, policy, profile, AND CI-execution code relative to the protected **base
branch**: a `git diff` guard FAILS the check on any change to `scripts/`,
`manage.sh`, `.pre-commit-config.yaml`, `.github/workflows/`, or
`.substrate/required_profile`, and on any diff that changes `SUBSTRATE_PROFILE`
(the one extensible DATA file, `harness_patterns.json`, and `.substrate/config`
command values stay editable). The now-provably-base validators then run
(isolated) against the PR's data and agent context, plus a static strict
**governance** pass (`substrate_doctor.py --strict-governance` — CODEOWNERS
coverage/placeholder/3 MB, no venv). A companion `check_github_governance.py`
queries the GitHub API to confirm the branch protection that makes this binding
(the trusted-base audit AND ordinary CI are required checks, code-owner review
is required, force-push/deletion blocked). **Strict mode reserves `scripts/`
for substrate-controlled code** — put project scripts elsewhere. Make the
trusted-base check **required** via branch protection and own the validators
(and `.substrate/required_profile`) with CODEOWNERS; that combination — not the
local gate alone — is the strict root of trust.

**Profile authority.** `.substrate/required_profile` (written by bootstrap)
pins the minimum profile. A PR can RAISE the profile but never silently LOWER
it: `check_substrate_config.py` rejects a config below the minimum, and the
runtime hook (`command_policy.profile()`) clamps UP to it, so a downgraded
`SUBSTRATE_PROFILE` can't disable strict-only behavior even before CI runs.

Known limitations, by design:
- The exfil guard is a **tripwire, not a sandbox** — pattern matching,
  not shell parsing. It covers the common upload/transfer forms but a
  determined attacker can mutate command shape. For real **containment**,
  set `SUBSTRATE_SANDBOX=1` (or `bootstrap --profile strict+sandbox`) and run
  agent commands through `scripts/sandbox_exec.sh`, which selects a **backend**
  (`.substrate/sandbox.json`, resolved by `scripts/sandbox_detect.py`,
  fail-closed): **`@anthropic-ai/sandbox-runtime` (`srt`)** when present
  (whole-process network deny+allowlist + filesystem write-scope — used only if
  already installed, never a forced Node dependency), else the OS-native
  primitive (Linux `bwrap` / macOS `sandbox-exec`, **network containment only**),
  else refuse (exit 3). `./manage.sh go-live` reports the resolved backend and
  its **honest capabilities** (it never claims allowlist/fs-scope on a
  network-only backend). The sandbox is an **optional backend the substrate
  selects**, not the product — governance/memory/eval/release remain the core.
- The CODEOWNERS validator implements the main `*`/`**`/trailing-slash/
  ownerless/last-match behaviors and the 3 MB load limit offline, but it
  is **not a full GitHub CODEOWNERS validator** — it cannot prove owner
  existence or write access without the GitHub API (operator step).
- Memory is hash-chained + anchorable but the anchor only binds if its
  git note is pushed to a protected remote.
- The eval harness is a **lightweight repo-local** adversarial suite (block-rate
  / FP-rate over staged states), NOT a hosted longitudinal observability or
  trend-reporting system — pair with one for long-running high-stakes agents.

See `CHANGES_V3.md` for the full per-version remediation history (v3.2.0–v3.5.10).
See `BENCHMARK.md` for the reproducible block-rate / false-positive-rate result
(regenerate with `./manage.sh evals --report`).

## What is new in v3.2 / v3.2.1

- **Default install path works.** `bash bootstrap.sh` no longer
  deadlocks on the operational doctor before the venv exists (runs
  `--quick`). Verified rc=0 + doctor PASS for python/node/go/none.
- **Copilot security hook actually fires.** The exfil adapter parses
  GitHub's documented `toolName`/`toolArgs` and the VS Code
  `tool_name`/`tool_input` payloads (it previously allowed `cat .env`).
- **Release gate + all hooks are subdirectory-safe.** Pre-commit runs
  from the substrate venv; hook scripts resolve the repo root via
  `_substrate_root.py` instead of `cwd`.
- **Coherent strict readiness.** `doctor --strict` = operational +
  security + governance; setup never blocks on a not-yet-active
  CODEOWNERS, but strict `check`/CI do.
- **Memory anchor.** `./manage.sh memory anchor` pins the chain head to
  a git note; `verify --anchor` catches a full chain rewrite. File
  locking on append.
- **Harness scans Copilot surfaces** and flags hook-trust bypass flags.

See `CHANGES_V3.md` for the full remediation tables (historical).

## Earlier (v3.2.0)

- **Works in any language out of the box.** A dedicated `.substrate/venv`
  runs validators + pre-commit regardless of project language; `setup`
  and `check` pass for python/node/go/none. Node/Go gates auto-skip when
  the repo hasn't opted in (`scripts/lang_gate.sh`).
- **Operational readiness check.** `./manage.sh doctor --operational`
  verifies the substrate can actually RUN, not just that files exist.
- **Hooks wired for all three hosts.** Claude (`.claude/settings.json`),
  Codex (`.codex/hooks.json`, canonical `hooks = true`), and Copilot
  (`.github/hooks/` via `copilot_hook_adapter.py`).
- **Tamper-evident memory.** `.substrate/memory/events.jsonl` is an
  append-only SHA-256 hash chain (`./manage.sh memory verify`);
  `CURRENT_SESSION.md` is now a derived, disposable view.
- **Expanded exfil tripwire.** Tiered by profile; catches env dumps,
  `os.environ`, `git grep` secrets, archive-to-/tmp, `find -exec`, and
  shell-var indirection. It is a tripwire, not a sandbox.
- **Stronger doc-consistency gate** over `.py`/`.template` too.

See `CHANGES_V3.md` for the full remediation history and the
cross-agent support matrix.

## What is new in v3 (3.0/3.1)

- **Hook-wired compaction recovery.** PreCompact/SessionEnd capture
  STRUCTURED state to `.substrate/memory/tasks/current.json`; SessionStart
  restores from that JSON as additionalContext. `docs/CURRENT_SESSION.md` is
  a derived human view only and is NEVER re-injected (no Markdown fallback).
  No more honor-system snapshots.
- **Todo state actually wired.** PostToolUse hook on TodoWrite mirrors
  state to `docs/.todo_state.json` (v2 documented this but shipped no
  mechanism).
- **Lint-on-write.** PostToolUse hook lints every edited file at write
  time and feeds errors straight back to the agent.
- **Real skills with progressive disclosure.** Skill bodies carry the
  workflow; checklists and review prompts stay on disk until a
  subagent needs them. New `checklist-auditor` agent walks blind-spot
  checklists outside the main context.
- **Cache-stable keystone.** AGENTS.md is byte-stable and ~25% shorter;
  volatile state never goes in it.
- **Profile-gated ceremony.** Commit-msg forcing functions and
  calibration machinery are strict-profile only.
- **Polyglot core.** `--lang` flag + `.substrate/config` command
  indirection; python-only gates are stripped for node/go installs.
- Removed `manage.sh tools`/`graphify` commands (they installed
  unpinned third-party packages — supply-chain risk).
- Removed `snapshot_session.py`, superseded by `session_handoff.py`.

See `CHANGES_V3.md` for the evidence behind each change.

## Philosophy

Agents may propose; deterministic gates decide. Hooks beat honor
systems. The keystone stays small and byte-stable; everything else
loads just-in-time. Auditors are read-only and return compact
verdicts. Bugs produce postmortems and future gates. HISTORY is
append-only. Ceremony must pay for itself — when it doesn't, it lives
behind the strict profile, not in everyone's default.
