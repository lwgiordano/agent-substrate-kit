---
purpose: Work receipts and read-only multi-project status.
last_human_reviewed: 2026-10-15
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
---

# Work receipts and project status

[Back to the substrate map](00_substrate.md). Task briefs, the third command of
this set, are in [lessons, records, and recall](10_lessons_recall.md).

## Work receipts

`./manage.sh receipt start --task "<outcome>"` records a task under
`.substrate/receipts/<uuid4>/` (Git-ignored in the kit and in every consumer):
the requested outcome, repository root, HEAD, branch, dirty state and the raw
fingerprint from `_task_evidence.git_facts`. Every later record is a new file
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
fingerprinted. A timeout (1 to 7200 seconds, default 1800) sends TERM to the
whole group, waits five seconds, then KILLs the whole group regardless, so
children that ignore TERM die too. When the check exits on its own, group
members it left behind are KILLed before the leader is reaped (where
`os.waitid` exists; elsewhere they are left). Outcomes are distinct: `passed`,
`failed`, `timeout`, `interrupted` (SIGINT/SIGTERM/SIGHUP to the receipt, or
the child killed by a signal), and `spawn-failed`. Without process-group
control the command refuses to run. A child that starts its own session
escapes the group kill; the three checks do not.

An attempt run while its own gate (`manage.sh`, `scripts/`, `.substrate/`, the
pre-commit config) differs from HEAD lists those paths as `harness_changed`,
and `show` flags the check with a warning: a pass from a locally weakened gate
is not an ordinary pass.

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
quote file names only through the same sanitizer. A hand-edit that stays
internally consistent cannot be detected: receipts are unsigned. A `running` record with no
result reads `incomplete`; a result with no `running` record is listed as
`result-without-start` and not counted. For each check kind the summary shows
the latest outcome, how many attempts passed, and whether the latest attempt's
input fingerprint equals the current one (`current`, `stale`, or `unknown`). An
earlier pass never hides a later failure. Receipts are unsigned local evidence:
they bound accident and sequential edits, not a same-user process rewriting them
during a run (ADR 0002).

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
per-check applicability, labelled unsigned and recorded by that project. Hook
files that exist mean configured, never that the host runs them. Branch protection, rulesets and
memory-anchor publication read `not checked`: this command makes no network
calls. Missing, non-Git and unborn roots, unsafe or malformed metadata, and Git
failures are diagnostics on an error row. Any other failure inside one project
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
