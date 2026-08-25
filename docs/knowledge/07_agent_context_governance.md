---
purpose: Agent context inventory, harness scanning, budgets, and doc drift.
last_human_reviewed: 2026-08-25
covers:
  - agentsync.sh
  - manage.sh
  - scripts/_doc_common.py
  - scripts/_substrate_root.py
  - scripts/_substrate_surfaces.py
  - scripts/_text_safety.py
  - scripts/bus_claims.py
  - scripts/check_agent_harness.py
  - scripts/check_doc_drift.py
  - scripts/check_harness_patterns.py
  - scripts/check_harness_smoke.py
  - scripts/context_report.py
  - scripts/new_validator.py
  - scripts/session_handoff.py
  - scripts/todo_state_hook.py
---

# Agent context governance

[Back to the substrate map](00_substrate.md).

The substrate classifies agent-facing text by when and how a host loads it. Root
instructions and the skill index are always-loaded. Structured session state and
sanitized HISTORY or rejection summaries load at session start. Knowledge docs,
ADRs, postmortems, auditor references, skill bodies, and execution plans are
on-demand. Hook configuration is runtime data, not prompt text.

`context_report.py` measures these real sources without network access, tokens,
venv creation, or bytecode writes. Token counts use `round(bytes / 4)` for
relative comparison, not billing. The keystone hash covers the stable
`CLAUDE.md` plus `AGENTS.md` prefix; it is not a complete host-prompt hash.

## Canonical context inventory

`_substrate_surfaces.py` is the shared inventory for harness scanning, strict
CODEOWNERS checks, and CI audit triggers. Context files receive secret,
shell-danger, and prompt-injection scans. Executable code receives secret and
shell-danger scans without prompt-pattern false positives.

The inventory includes all non-template knowledge siblings and agent-execution
plans or specs under `docs/superpowers/**/*.md`. The Superpowers directory is
governed when present: a source or project that has it requires review coverage,
while a consumer that never creates it remains valid. It is deliberately not an
install-owned directory. Human-operator documentation does not become agent
instruction merely because it lives under `docs/`.

Governance and install ownership are separate classifications. Project-authored
knowledge siblings and Superpowers plans require scanning, CODEOWNERS coverage,
and CI audit triggers without entering provenance or upgrade drift. Only the
generated consumer knowledge entry point and installed knowledge template are
substrate-owned.

The behavioral smoke runs the real scanner independently for root instructions,
HISTORY, the stable knowledge entry point, a randomized knowledge sibling, and a
randomized Superpowers plan. One blocked surface cannot hide an ignored one.

A tampered governed surface never shrinks or redirects the scan while returning
green: the harness BLOCKs a symlinked governed FILE, a symlinked governed
DIRECTORY or any ANCESTOR of one, and — since a skill root is a glob root in the
canonical inventory rather than a walked directory list — a direct symlink at a
skill root (`.agents/skills`, `.claude/skills`, `.github/skills`) too. The walk
covers `_SKILL_ROOTS` explicitly so a linked skill root cannot slip the
per-file scan by being neither followed nor flagged. A NON-REGULAR surface
(FIFO, socket, device) is blocked for the same reason: being neither a symlink
nor a regular file, it used to drop silently out of the inventory and lower the
count while the run still reported ok.

The scan result is itself a trust signal. The scanner resolves its root through
a helper it cannot verify before it has scanned anything, so a poisoned helper
pointing at an empty tree once produced a clean `ok (0 files scanned)`. Finding
NO governed surface is therefore a BLOCK: a real install always has some, so an
empty inventory means the root is wrong or the inventory was redirected.
Asserting instead that the scanner's own file sits under the discovered root was
rejected — running the scanner from outside the tree it scans is a legitimate,
tested pattern, so that check would fail valid runs.

## Documentation drift

Knowledge front matter declares `purpose`, `covers`, review date, and optional
`asserts`. Coverage is many-to-many. Every discovered source module needs at
least one covering doc; root entrypoints may be covered explicitly even when
their suffix is outside module discovery.

Declarative assertions use `path::substring`. The gate reads bounded text and
checks that the named file still contains the claim. It never executes Markdown
content. Missing files, malformed assertions, and missing substrings are
findings.

Committed staleness compares code and document commit dates. Staged review is a
separate contract: every staged path already named in `covers` must bring its
covering doc into review, independent of file suffix. Both names of a rename and
deleted old names remain visible. A review date equal to the current day is not
a substitute for staging the doc with the change. Git name-status is read as
raw NUL-framed bytes, and an unreadable index is a blocking error rather than an
empty staged set. New-module coverage discovery stays language/suffix-based so
arbitrary project data does not require a knowledge doc.

## Budgets and progressive disclosure

Each non-template knowledge document has a default 3,000-token estimate. Drift
reports oversize docs as advisory unless `SUBSTRATE_ENFORCE_DOC_BUDGET=1` opts
into enforcement. `context-report --budget` enumerates every knowledge doc for
per-document rows; the separate largest-contributors display remains a compact
top ten.

Budgets guide document shape. They do not prove relevance or accuracy. The
source map uses one current-contract document per function, while release
chronology remains in CHANGES and HISTORY.

Bus claims are leases: `scripts/bus_claims.py` derives ACTIVE/EXPIRED/RELEASED
deterministically from AGENT_BUS.md entries (default TTL 72h; HEARTBEAT and
CLAIM EXPANSION refresh; an expired lease is reclaimable by any agent, and ONLY
via an explicit RECLAIM — a foreign CLAIM/HEARTBEAT/RELEASE on a lapsed lease is
a reported no-op, not a silent takeover). Advisory only — coordination state is
never a gate input.

`agentsync.sh` is the transport: it appends a one-line entry to the bus and
pull/pushes the branch so two agent checkouts share work. As a governed root
execution surface it is content-scanned and review-gated like the other
entrypoints. Its bus append is defensive — it refuses a symlinked or
hard-linked `AGENT_BUS.md` (an external-write primitive), fails fast rather than
hanging on a FIFO, collapses newlines so a multiline message cannot forge extra
lease lines, and propagates commit/push failure so a message is never reported
"synced" when it did not land on the remote.
