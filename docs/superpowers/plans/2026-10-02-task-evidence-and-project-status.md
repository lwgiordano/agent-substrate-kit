# Task Evidence and Project Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Give agents current task context, honest check receipts, and read-only multi-project status without duplicating governance state.

**Architecture:** Three opt-in commands over small reusable evidence APIs. Repository documents remain canonical, receipts remain local observations, and remote status is explicitly unknown without a separate network adapter. Repair the existing cross-clone HISTORY blocker before feature work.

**Tech Stack:** Python 3.11 standard library, existing guarded readers/writers and sanitizers, Bash command dispatch, pytest.

**Spec:** `docs/superpowers/specs/2026-10-02-task-evidence-and-project-status-design.md` (approved scope and design, 2026-10-02).

## Global Constraints

- No new hosted service, embeddings, agent scheduler, automatic project discovery, credentials store, or automatic startup injection.
- Existing context budgets remain unchanged.
- Network access is off for new report commands; unknown is not a passing result.
- Keep full tests in check, pre-push, CI, and release; never bypass hooks.
- Claim exact files on AGENT_BUS.md, push, and wait for conflicts before product edits.
- Publish each finished unit with its checks, append HISTORY using append_history.py, and never edit old HISTORY or hand-edit the manifest.
- New substrate modules belong in scripts/ and must ship to consumers; project extensions remain outside scripts/.

## Review Focus

- A clone with a valid unrelated memory chain must not reject unchanged imported history; a broken chain must still fail (Task 0).
- Small output budgets and Unicode cannot erase identity or hide omitted evidence (Task 1).
- A check can change its own inputs and exit zero; that is not a verified state (Task 2).
- A killed process or edited receipt cannot invent a successful terminal observation (Task 2).
- Git filters, fsmonitor, and repository-routing environment variables cannot execute target code during read-only inspection (Task 3).

## File structure and shared interfaces

- `scripts/check_history_sha.py`: distinguish unavailable imported evidence from invalid local evidence.
- `scripts/_doc_common.py`: typed outcome-evidence observation, preserving strict append-time rules.
- `scripts/recall.py`: structured collection with source identity and diagnostics, preserving collect/search/render behavior.
- `scripts/session_handoff.py`: expose structured lesson/objective selection without changing existing injection budgets or host behavior.
- `scripts/_task_evidence.py`: safe read-only Git facts and content fingerprint, bounded text/JSON rendering, small schema helpers.
- `scripts/task_brief.py`: brief command and assembly.
- `scripts/task_receipt.py`: receipt command, run observation storage, execution and annotation lifecycle.
- `scripts/project_status.py`: explicit-root aggregation using trusted kit code only.
- Dedicated test modules: `tests/test_history_evidence_portability.py`, `tests/test_task_brief.py`, `tests/test_task_receipt.py`, `tests/test_project_status.py`.
- Integration: `manage.sh`, `templates/manage.sh.template`, bootstrap shipping and .gitignore entries as needed; knowledge coverage and ARCHITECTURE parity.

## Task 0: Repair evidence portability without inventing verification

**Files:** scripts/check_history_sha.py, scripts/_doc_common.py, tests/test_history_evidence_portability.py, affected outcome tests in tests/test_hook_scripts.py, docs/knowledge/09_deterministic_validators.md, docs/knowledge/10_lessons_recall.md, generated docs/manifest.json.

**Interfaces:** `release_evidence_status(root: Path, commit: str) -> tuple[str, str]`, states verified/unavailable/invalid. `history_outcome_problem(...)` remains strict for append_history; missing evidence is still a write-time refusal.

- [x] Reproduce the current exact gate in a disposable clone: succeeds without a local chain, then fails after a benign local note is recorded, with identical committed HISTORY. Evidence: `/tmp/substrate-history-portability.PNVODW/repo`, history gate rc 0 with four unverifiable labels before the note; `memory_log.py append --type note` then `verify` rc 0; unchanged history gate rc 1 with four missing-release-pass errors afterward.
- [ ] Add tests for unchanged committed imported entries with no chain and with an unrelated healthy chain; expect NOT verifiable here, never verified. Test broken/linked chain and a matching dirty-start release-pass; both remain failures.
- [ ] Add tests for a newly added or modified success entry lacking evidence. Unlike already committed unchanged entries, it must fail even if the chain is absent. Compare full entry content and multiplicity against Git-committed HISTORY, not just its claimed SHA or date. For an in-progress merge include resolved MERGE_HEAD parents as reported provenance, never as release proof; handle union order and duplicate entries without blanket exemptions. Git failures are errors.
- [ ] Preserve label syntax and reference validation, and strict append_history tests. Introduce explicit evidence states instead of parsing error-message strings. Report imported-unverified, locally-verified, and invalid counts separately.
- [ ] Verify the original disposable-clone scenario now succeeds with warnings; the new/modified, dirty-pass, and broken-chain regressions must fail when their guards are removed.
- [ ] Resolve the claim-publication dependency through a disposable clean clone only if necessary: normal hooks must pass there before publishing the bus claim; retain this checkout's chain untouched. Do not set skip variables or bypass a hook. A successful commit in another checkout is not a green result for this checkout.
- [ ] Run affected outcome tests, check and evals; security review; docs/manifest update; commit and push the finished repair. Append its HISTORY entry with the actual SHA and an honest outcome.

## Task 1: Current task brief

**Interfaces:** `_task_evidence.git_facts(root: Path) -> dict` returns schema_version=1, root, head, branch, dirty status, collection time, diagnostics. `recall.collect_with_diagnostics(root: Path) -> tuple[list[dict], list[dict]]` returns source items with path/line/title/body/content hash/source state. `task_brief.build(root: Path, task: str, paths: list[str], budget: int) -> dict` assembles bounded evidence.

- [ ] Write tests selecting known objectives, ADRs, and committed lessons for two distinct tasks; assert path/line/hash provenance and missing-source diagnostics. Test Unicode, no matches, unborn HEAD, dirty docs, malformed bus, and budget exhaustion.
- [ ] Run `pytest tests/test_task_brief.py -q`; confirm failures identify missing behavior.
- [ ] Add structured collection APIs beneath existing renderers. Keep lesson status/evidence filtering and committed-source restrictions. Do not copy the bus grammar, config parser, or lesson selector. Include reported findings without asserting which are unresolved.
- [ ] Add `./manage.sh brief TASK [--path PATH ...] [--budget N] [--json]`. Default budget 800 byte-estimated tokens, range 200..6000; JSON cap 64 KiB with explicit omitted counts. Reserve identity/diagnostics space, then fit complete evidence items where possible. Treat task text as data. Return 2 on invalid arguments/root or failed essential identity lookup, otherwise 0 with visible partial-source diagnostics.
- [ ] Wire both manage entrypoints, add source coverage, and correct ARCHITECTURE's commit-stage description. Test exact CLI parity in a generated consumer, including paths with spaces.
- [ ] Run focused tests, full check, relevant evals, and architecture/documentation reviews. Commit/push, append HISTORY, and post RELEASE only for this finished unit.

## Task 2: Structured work receipts

**Interfaces:** `_task_evidence.fingerprint(root: Path) -> dict` returns status/digest/coverage/exclusions/diagnostics using a read-only algorithm. `task_receipt.start(root, task) -> str`, `run_check(root, task_id, kind, timeout_seconds) -> dict`, `annotate(root, task_id, completion, note, author, review_ref) -> dict`, `show(root, task_id) -> dict`. All stored JSON has schema_version=1.

- [ ] Write tests for a passing check, nonzero exit, spawn failure, timeout, interruption, state mutation followed by exit 0, malformed stored observations, unsafe IDs, and concurrent attempts. Completion assertions never change measured check results. Test unknown inner-test coverage and stale HEAD/index/content.
- [ ] Test digest-only output handling and opt-in redacted excerpts across task text, subprocess output, exception diagnostics, and edited stored records. Capture at most 64 KiB of sanitized diagnostic text; digest all drained output without retaining it. Redaction limits are explicit.
- [ ] Run `pytest tests/test_task_receipt.py -q`; confirm initial failures, then implement bounded receipt records using guarded I/O. Limits: UUID task/attempt IDs, task/note 2000 chars, author 100 chars, relative review reference 500 chars, metadata 64 KiB, maximum 1000 attempt/annotation records per task; overflow refuses visibly.
- [ ] Fingerprint index and raw working bytes without staging, object writes, filters, or fsmonitor. Store algorithm version and exclusions. Regular tracked and eligible nonignored untracked inputs are covered; unsupported or unreadable file types yield unknown. Receipt store and normal ignored build outputs are excluded and disclosed. Before/after disagreement yields state-changed, not a passing-state certification.
- [ ] Run only check/evals/prove through explicit `receipt check`. Default timeout 1800 seconds, operator override 1..7200. Use a dedicated process group on supported POSIX hosts, drain streams with bounded storage, TERM then KILL after 5 seconds on timeout/cancel, and record incomplete state if terminal writing fails. Unsupported process control is a refusal, not silent degradation. No automatic gate reruns on show/projects.
- [ ] Add start/check/annotate/show dispatch and consumer .gitignore entries. Summaries keep assertion, observed process outcome, coverage, applicability, and release verification distinct. Unknown schema or invalid history is an error, not an empty successful task.
- [ ] Test clean bootstrap and upgrade preserving project fixtures and existing receipts. Run full check/evals and discriminating guard tests; security/test reviews; commit/push plus HISTORY and bus RELEASE.

## Task 3: Explicit-root project status

**Interfaces:** `project_status.inspect(root: Path) -> dict`, `project_status.report(roots: list[Path]) -> dict`. Reuse git_facts/fingerprint and receipt read-side validation; never load target Python or shell.

- [ ] Write tests against marker-writing target scripts, hostile Git filters/fsmonitor, unsafe config/install metadata, duplicate roots, linked worktrees, unreadable roots, no installed kit, stale receipts, and unknown remote controls. Inventory objects and files before/after to prove read-only behavior.
- [ ] Run `pytest tests/test_project_status.py -q`; confirm failures, then implement `./manage.sh projects --root ROOT ... [--json]` with maximum 100 explicit roots and per-Git-call timeout 10 seconds. No home scan, implicit registration, fetch, credentials access, or target-script execution.
- [ ] Report per-root installed kit version/provenance, revision and dirty state, declared hook wiring and observed local hook files, applicable receipts, and local governance configuration. Show remote enforcement and anchor publication as not checked. Treat unsupported fields as unknown, not healthy.
- [ ] Continue after individual errors, retain diagnostics, return 2 if any inspection failed; otherwise return 0. Bound JSON to 1 MiB with explicit truncation; sanitize all terminal text. Use the kit's trusted implementation for every target.
- [ ] Validate generated and upgraded consumers, full check/evals, and security/architecture review. Commit/push, append HISTORY, and release the finished command on the bus.

## Final verification and handoff

- [ ] Read bus again, inspect final diff, run self-audit, and record its honest result.
- [ ] Run packaged-artifact consumer verification and relevant guard-removal proofs; disclose skips and known limits.
- [ ] Publish branch/PR only through normal hooks; attach any created PR to the task. No merge or repository-admin changes are part of this implementation.
- [ ] Demonstrate all three commands on this repo and disposable consumers. Show optional usage on other projects only when explicit paths are supplied.
- [ ] Summarize exact commits, completed units, command results, and outstanding limitations. Do not claim product parity, live-hook activation, or cost savings from static configuration alone.
