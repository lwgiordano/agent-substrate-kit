---
purpose: Work receipts and read-only multi-project status.
last_human_reviewed: 2026-10-28
covers:
  - scripts/task_receipt.py
  - scripts/project_status.py
asserts:
  - scripts/task_receipt.py::state-changed-during-check
  - scripts/task_receipt.py::digest-only
  - scripts/task_receipt.py::result-without-start
  - scripts/task_receipt.py::harness_changed
  - scripts/project_status.py::not checked
  - scripts/project_status.py::inspection-failed
  - scripts/check_substrate_config.py::def parse_config_text
  - scripts/_task_evidence.py::def trusted_executable
  - scripts/task_receipt.py::_CHECK_SELECTION_ENV = frozenset
  - scripts/project_status.py::profile-below-lock
  - scripts/task_receipt.py::chained-record-missing
  - scripts/task_receipt.py::receipt-deleted
  - scripts/memory_log.py::def chained_receipts
---

# Work receipts and project status

[Back to the substrate map](00_substrate.md). Task briefs, the third command of
this set, are in [lessons, records, and recall](10_lessons_recall.md).

## Work receipts

`./manage.sh receipt start --task "<outcome>"` records a task under
`.substrate/receipts/<uuid4>/` (Git-ignored in the kit and in every consumer):
the requested outcome, repository root, HEAD, branch, dirty state and the raw
fingerprint from `_task_evidence.git_facts`. Task, note, author and review
text pass the context filter that guards session start; text it would withhold
(a shell tool name standing as a word of its own, `$(`, a backtick, an
instruction-like lead) is refused with a request to rephrase, never stored as a
placeholder. Paths and branch names are facts, not prose: they skip the
command-word filter, so a root under `.../node/` stays readable, but the
instruction and role filters still apply, and a path with a space in it reads
as prose and gets the full filter. Every
later record is a new file
named `<time_ns>-<id>-<kind>.json`; nothing is overwritten, at most 1000 records
fit one task, each record is capped at 64 KiB, and the store is reached through
the guarded directory walk, so a symlinked store is refused.

`receipt check ID --kind check|evals|prove` runs exactly `bash ./manage.sh
<kind>`, with `bash` resolved from absolute PATH entries only; no other command
is accepted. It writes a `running` record before the process starts and a
`result` record after it ends. The child runs in its own process group with
stdin closed; output is drained in full, but only its byte count and SHA-256 are
stored (`digest-only`). `--excerpt` keeps the tail of the output: whole lines
that assign to a bare or quoted key whose name carries a password, token, key,
cookie or auth word (`DB_PASSWORD=`, `"api_token":`), `--password VALUE`
flags, URLs with a `user:password@` part, HTTP authorization values and every
line of a PEM block (including a block whose BEGIN line fell outside the
window) are withheld and counted, the rest is sanitized line by line, and the
excerpt is trimmed so the record stays under its cap even when every character
escapes. Redaction covers known shapes, not every possible value. Environment
variables are never stored, and the check runs without inherited `GIT_*`
variables so it cannot be pointed at a different repository than the one
fingerprinted, nor with `SKIP`, `PRE_COMMIT_ALLOW_NO_CONFIG`, `PYTEST_ADDOPTS` or
`PYTEST_PLUGINS`, so the caller's shell cannot trim which hooks or tests run.
The credential-line match reads the first 1000 characters of a line as it will
be displayed (invisible characters and markup removed, whitespace collapsed), so
padding cannot push a value past it; the excerpt never shows more than 500. A timeout (1 to 7200 seconds, default 1800) sends TERM to the
whole group, waits five seconds, then KILLs the whole group regardless, so
children that ignore TERM die too. When the check exits on its own, group
members it left behind are KILLed before the leader is reaped (where
`os.waitid` exists; elsewhere they are left). Outcomes are distinct: `passed`,
`failed`, `timeout`, `interrupted` (SIGINT/SIGTERM/SIGHUP to the receipt, or
the child killed by a signal), and `spawn-failed`. Without process-group
control the command refuses to run. A child that starts its own session
escapes the group kill; the three checks do not.

An attempt run while its own gate (`manage.sh`, `scripts/`, `.substrate/`, the
pre-commit config) differs from HEAD, or after gate files were committed since
the task started, lists those paths as `harness_changed`, and `show` and
`projects` flag the check with a warning: a pass from a weakened gate is not an
ordinary pass. The check runs the toolchain the project has installed (its
Git-ignored virtualenvs); a receipt does not fingerprint that toolchain, so a
replaced test runner is outside what it can see.

The fingerprint is taken before and after the run. Equal means `unchanged`;
different means `state-changed-during-check`, even when the exit code is 0;
either missing means `unknown`. Inner test coverage is `unknown`, because no
producer reports skip counts yet. The CLI exits 0 only for `passed` on an
`unchanged` tree.

`receipt annotate ID --completion complete|incomplete [--note] [--author]
[--review-ref]` adds a self-reported assertion. It never changes a measured
result; the author is recorded as unverified and the review reference must be
repository-relative. Release verification stays with `./manage.sh release`; a
receipt cannot mint a `shipped-green` HISTORY outcome.

`receipt show ID [--json]` re-reads every record, rejects unknown schema
versions, unexpected files, malformed or over-deep JSON, records that do not
match their file name, a result whose start state differs from its `running`
record, an outcome that contradicts its exit code (a `passed` that is not 0, a
`failed` that is not positive, an `interrupted` with a code), and a stored
state that differs from the one its own before/after fingerprints give. Hashes must
be hashes, and stored text is re-sanitized on read, so a hand-edited record
cannot inject terminal controls or a known credential pattern. Error messages
quote file names only through the same sanitizer. A `running` record with no
result reads `incomplete`; a result with no `running` record is listed as
`result-without-start` and not counted. For each check kind the summary shows
the latest outcome, how many attempts passed, and whether the latest attempt's
input fingerprint equals the current one (`current`, `stale`, or `unknown`). An
earlier pass never hides a later failure. Receipts are unsigned local evidence:
they bound accident and sequential edits, not a same-user process rewriting them
during a run (ADR 0002).

## Receipts in the memory chain

A receipt's records are bound to the memory chain, so a hand-edit that stays
internally consistent, or a deleted attempt, is visible. Every
record a receipt writes is also listed in the memory chain of the same
repository (`.substrate/memory/events.jsonl`) as a `receipt` event holding its
file name and SHA-256. `start` and `annotate` chain their record at once; `check`
chains its `running` and `result` records together after the second fingerprint,
so the chain write never falls inside the window the fingerprints compare, and
an untracked `.substrate/memory/` is outside the fingerprint, like the receipt
store. `receipt` is a reserved event type: `memory append` cannot write one.

`show` reads the chain only if it verifies, then compares it with the store. A
listed record that is missing (`chained-record-missing`) or whose bytes differ
(`chained-record-changed`) makes the chain summary `records-missing-or-changed`:
the text view warns and `show` exits 1. `show` on a receipt whose directory is
gone but which the chain lists reports `receipt deleted` and exits 2. A record
the chain does not list (`record-not-chained`) leaves the summary
`partly-chained`: it was written before v3.10.6, or the chain refused it, and the
writer warned at the time. Without a readable chain that verifies (absent, linked,
over 64 MiB, or broken) the summary is `unavailable` and says deletions cannot be
detected. Deleting the events as well means rewriting the chain, which `verify
--anchor` fails once a published anchor covers them ([the memory
anchor](08_memory_anchor.md)); before that, it is the limit of an unkeyed chain.

## Project status

`./manage.sh projects --root DIR [--root DIR ...] [--json]` inspects up to 100
explicitly named projects with this kit's own code. Nothing in a target runs: no
target Python is imported, no `manage.sh`, hook or helper is executed, `git`
resolves from absolute PATH entries only and the inspector drops relative PATH
entries for its whole process (shared helpers find their root with a bare
`git` when first imported), the
config is parsed as data with `check_substrate_config.parse_config_text` (the
validator's own grammar, split on newline only as the shell loader does) and
never sourced, Git runs through the same isolated, filter-free, fsmonitor-free
observation as briefs, and nothing is written. Roots are canonicalized and
deduplicated; a linked worktree is its own row.

Each row shows Git state, worktree kind, installed kit version and whether an
install baseline exists, config status and profile/sandbox/remote-governance
values, the three `required_*` locks, hook scripts referenced by
`.claude/settings.json` with whether each file exists, Git hook files (by
`lstat`, never resolved, with whether the hooks directory the target's
`core.hooksPath` selects lies inside or outside its root), and the latest
receipt (newest by creation time, ties ordered by a nanosecond stamp) with
per-check applicability and its memory-chain status, labelled unsigned and
recorded by that project. Every receipt the inspected chain lists is checked, not
only the latest: a receipt whose directory is gone (`receipt-deleted`), listed
records that are gone (`receipt-records-missing`), or changed records in the
shown receipt (`receipt-records-changed`) are error diagnostics, so deleting the
newest, failing receipt cannot quietly promote an older pass. Hook
files that exist mean configured, never that the host runs them. Branch protection, rulesets and
memory-anchor publication read `not checked`: this command makes no network
calls. Missing, non-Git and unborn roots, unsafe or malformed metadata (an
invalid config or lock, malformed settings JSON, a profile below its
`required_profile` lock, `disableAllHooks`), unreadable receipts and Git
failures are diagnostics on an error row; only a tracked file the fingerprint
cannot read (`unsupported-input`, such as a symlink) is listed without making
the row an error. The text view shows each receipt check's state and flags gate
changes. Any other failure inside one project
becomes an `inspection-failed` row, so one hostile project never aborts or hides
the others; the report finishes and exits 2. Target values are bounded: version
and install time over 40 characters read as unknown, a hook path with `..`, an
absolute path or a NUL reads `unsafe`, and a row keeps at most 50 diagnostics
with an omitted count. JSON is capped at 1 MiB; projects that do not fit are
counted in `truncated_projects` and the command exits 2. The report names the inspecting kit's version: its
`VERSION` file in the kit source, its install record in a consumer.

## Packaging

`package_release.sh` leaves `.substrate/receipts/` and `.superpowers/` out of
the source hash, the zip and the zip-hygiene check, alongside the memory chain
and traces, so a maintainer's local evidence never ships.
