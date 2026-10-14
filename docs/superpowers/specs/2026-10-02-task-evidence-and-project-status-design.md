# Task briefs, work receipts, and project status

Status: operator-approved design (2026-10-02); no implementation shipped.
Baseline: v3.9.3, main merge 24c2316.

## Purpose and scope

The operator approved three additions after comparing the substrate with
Packmind, Snipara, and Claudexor: a current task brief, a structured task
receipt, and a multi-project status report. Their purpose is to reduce stale
handoffs, unsupported completion claims, and repeated manual project checks.

Keep repository records canonical, preserve offline operation, and use no model
in the enforcement chain. No new hosted service, embeddings, agent scheduler,
automatic project discovery, credentials store, or automatic startup injection
is included. Existing context budgets remain unchanged. External products are
not installed as part of this work. Remote governance changes and release
publication remain separate operational work.

## Approach and alternatives

Extend the existing command-line interface with three opt-in commands. Reuse
guarded readers, text sanitization, recall ranking, canonical configuration
parsing, and bus folding through small reusable APIs where necessary. Do not
scrape human command output or introduce a second history, policy, or lease
database. These reports describe evidence; they are not new trust anchors.

A hosted context service would add synchronization, access control, and network
requirements before retrieval quality has been measured. A full execution
manager would duplicate the agent host. Both remain possible integrations,
outside this increment. A single large status command would mix different
permissions: brief and project status are read-only; receipt recording writes
local evidence and can execute explicitly requested checks. Keep them separate.

## 1. Current task brief

Proposed interface:

```
./manage.sh brief "task description" --path scripts/example.py --budget 800
./manage.sh brief "task description" --json
```

The command reports repository identity, full HEAD, branch or detached state,
dirty state, collection time, explicit task text, and relevant evidence. Repeat
`--path` for scope; without it use the current change set and recent commits,
and disclose that inference. An empty scope never implies the whole repository
was reviewed. Non-Git roots, failed Git reads, and unborn HEAD receive explicit
states instead of fabricated clean results.

Evidence includes sourced INTENT objectives, current ADR/knowledge sections,
applicable committed lessons, and bus lease state. Reuse recall and lesson
selection; do not copy their parsers. Preserve the distinction between committed
and modified local documents. Each item carries path, line or stable identifier,
source revision/content hash, selection reason, and freshness information.
Evidence existence does not establish its relevance or correctness.
Refactor collectors to return structured items and diagnostics while retaining
their existing CLI renderers. Current collectors can silently omit unreadable
sources or return rendered strings; do not wrap those strings or re-read files
to reconstruct provenance from a different observation.

Free-form bus FINDING prose is shown as recent reported findings, never counted
as a definitive list of unresolved defects. Lease violations, unparsed claims,
missing sources, and truncated reads remain visible. Required-check guidance
comes from known substrate commands; project-specific acceptance criteria are
operator-provided text, not inferred executable commands from documentation.

Reserve space for identity and missing-evidence warnings before ranked context.
The budget is explicitly a byte-based token estimate, not provider billing.
JSON is schema-versioned, bounded separately, and preserves truncation metadata.
Terminal text is sanitized. Nothing from retrieved prose is executed.

## 2. Structured work receipt

Proposed interface:

```
./manage.sh receipt start --task "requested outcome"
./manage.sh receipt check TASK_ID --kind check
./manage.sh receipt annotate TASK_ID --completion incomplete --note "remaining work"
./manage.sh receipt show TASK_ID --json
```

`start` records a generated ID, requested outcome, timestamp, repository and
worktree identity, HEAD, and starting change-state fingerprint. It creates a
new local record through the existing guarded writer; it does not overwrite a
prior task. Storage is `.substrate/receipts/TASK_ID/`, excluded from Git by the
consumer installation contract. ID validation prevents path traversal.

`check` explicitly executes one known command: check, evals, or prove. No
arbitrary shell command is accepted, and report-only commands never execute
checks. The runner records argv, time, exit status, and before/after revision and
content fingerprints. Output capture is bounded and defaults to digest-only;
an explicitly requested diagnostic excerpt is sanitized before persistence.
Never persist environment variables. Task text, review notes, and exception
messages use the same sanitizer and limits. Redaction detects known patterns;
it does not guarantee detection of every credential. On sanitization failure
retain only typed error metadata, not the rejected content. Read-side schema,
size, and text checks also apply to edited receipts. Command execution is delegated
to the project's normal gate; callers must trust the repository to request it.

Each attempt is retained as a separate immutable observation. Write a running
observation before execution and a terminal observation afterward. An orphaned
running attempt is reported as incomplete; it is not inferred successful from
partial output. Timeout, cancellation, spawn failure, and nonzero exit are
distinct outcomes. Define process cleanup and bounded runtime in the execution
plan before implementing the runner.

The summary distinguishes task completion, check results, review, and release
verification. `annotate` records a completion assertion (complete or incomplete),
sanitized note, declared author, and optional repository-relative review reference
as a new observation. It never overwrites check results; author identity is
self-reported, not authenticated. Review references are data and never executed.
Absent assertions show not-recorded. Assertions remain visibly separate from
measured checks, and acceptance criteria are informational text, not proven by
an assertion. Release verification remains the existing release-pass machinery,
not a new receipt capability. It cannot manufacture a
`shipped-green` outcome. A zero return code means the command passed, not that
every nested task ran: structured skip counts are included only when supported
by the producer; otherwise coverage is unknown.

A receipt applies only to its captured input state. Changed HEAD, index,
tracked bytes, or relevant untracked inputs make it stale. Differing before/after
fingerprints explicitly mean state-changed-during-check, even with exit code 0;
unreadable fingerprints mean unknown. Neither certifies a passing input state.
Applicability collection must not stage files, write Git objects, run filters,
or invoke project helpers; the memory verification signature is not reusable
unchanged because its staging step can do those things. Specify fingerprint
coverage and exclusions, including the receipt store itself. Older passes remain
historical after a later failure. Malformed inputs and sequential tampering
remain in scope; ADR 0002 excludes timed concurrent same-user rewriting.
Unsigned receipts cannot authenticate their author. Exported receipts are reported
evidence unless independently reverified in the receiving environment.

## 3. Multi-project status

Proposed interface:

```
./manage.sh projects --root /path/to/project-one --root /path/to/project-two
./manage.sh projects --root /path/to/project-one --json
```

Roots are explicit; no scan of the home directory and no saved registry in the
first release. Canonicalize and deduplicate roots; distinguish linked worktrees
without conflating their working state. Read only bounded known metadata through
the trusted kit's implementation, with each root as the containment boundary.
Never import another project's Python, source its configuration, run its
manage.sh/doctor/hooks, or initialize its environment just to inspect it.

For each project show installed version and provenance availability, Git state,
declared hook wiring, actual hook-file observations, latest receipt applicability,
and local governance configuration. Static hook inspection reports configured
or unknown, never proves that the host invoked the hook. Repository identity and
time are visible on every row. Unreadable, malformed, linked, missing, and
unsupported data are distinct from a passing check.

Network access is off. Remote enforcement and anchor publication therefore show
not checked, not absent or secure. Existing evidence may be displayed only with
its timestamp and revision. Live GitHub checking is a later explicit adapter
that must cover both branch protection and rulesets; this increment does not
make network calls or manage remote settings.

Bound Git operations with timeouts, disable optional Git writes and executable
helpers such as fsmonitor, and sanitize inherited Git routing/config variables.
Do not use staging, worktree conversion, textconv, external diff, or clean filters
to compute status. A failed project remains an error row while
the report finishes other roots. CLI returns 2 for invalid invocation or any
inspection error, 0 for a completed report; unknown remote status alone is not
an error. No project is modified.

## Integration and compatibility

Use small substrate-owned modules under scripts/, separate from project code.
Wire commands into both manage.sh and its consumer template; ship required
modules on every supported profile. Existing commands retain their contracts.
Add machine-readable APIs only where existing parsers need reuse, preserving
their current CLI behavior. Respect guarded-I/O inventory and install ownership.

Update the appropriate knowledge docs and generated manifest. Correct
ARCHITECTURE's outdated commit-stage claim: full tests run at pre-push and in
check/CI/release, while commit-stage validators remain. Keep historical entries
append-only and label design/implementation history honestly. Version selection
and implementation claims are made after spec approval and a fresh bus read.

## Acceptance and validation

- Brief: deterministic fixtures select the expected lesson/decision, preserve
  source identity, disclose absent/unsafe inputs, and stay within output budgets.
  A fresh invocation reads current state, not an old handoff cache.
- Receipt: passing, failing, skipped-coverage, interrupted, and spawn-failed
  checks remain distinct. A later edit or index change invalidates applicability.
  Previously passing attempts cannot hide a later failure. A check that edits an
  input then exits zero yields state-changed-during-check. Synthetic secrets in
  task text, exceptions, output, and edited receipts test the documented redaction
  behavior; digest-only mode never stores output text.
- Projects: a target containing a marker-writing manage.sh is inspected without
  the marker being created. Missing roots, unsafe metadata, worktrees, no installed
  kit, and unknown remote enforcement are displayed accurately. Hostile Git
  filters and fsmonitor fixtures never execute; object-store inventory stays
  unchanged. No writes occur.
- Consumer: exercise all three interfaces in a fresh generated consumer and an
  upgraded consumer with project fixtures; confirm parity with the kit interface.
- Runtime: Bash 3.2 and paths with spaces are included in relevant tests.
- Release: full check exits 0; policy-adjacent evals pass with skips disclosed;
  relevant guard proofs discriminate. Security, test, architecture, and
  documentation auditors have no unresolved BLOCKs.

## Delivery order

Baseline blocker observed during design: `./manage.sh check` exits 1 on this Mac
because four imported shipped-green HISTORY entries have no release-pass event
in its existing local four-event memory chain. The commits all resolve; the
chain itself verifies. A clean-clone exemption does not cover an existing clone
whose local chain lacks another clone's evidence. Preserve the chain and past
HISTORY entries. Resolve the evidence-portability contract before claiming a
green implementation; do not delete the chain, fabricate passes, or bypass hooks.

Deliver brief first, receipt second, projects third. Each is a separately
reviewable implementation unit with documentation, deterministic tests, HISTORY,
and a bus RELEASE only after it passes. The shared evidence representation stays
small and versioned. No claims of product parity or token savings are made until
consumer measurements support them.
