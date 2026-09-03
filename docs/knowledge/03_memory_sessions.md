---
purpose: Tamper-evident memory, session restore, completion, and append-only logs.
asserts:
  - scripts/memory_log.py::_raw_tracked_hash
  - scripts/memory_log.py::_write_tree_oid
  - scripts/_doc_common.py::locked_atomic_append
  - scripts/session_handoff.py::_safe_history_line
  - scripts/session_handoff.py::_rejected_block
last_human_reviewed: 2026-09-03
covers:
  - manage.sh
  - scripts/_doc_common.py
  - scripts/append_history.py
  - scripts/append_rejected.py
  - scripts/completion_gate.py
  - scripts/lint_on_write.py
  - scripts/memory_log.py
  - scripts/session_handoff.py
  - scripts/todo_state_hook.py
---

# Memory and sessions

[Back to the substrate map](00_substrate.md).

The durable event log is hash-chained. Verification checks sequence, previous
hash, event hash, and any optional Git-note anchor. An absent anchor is distinct
from a broken or mismatched anchor; go-live reports those states separately.

The anchor is a git note on a commit recording the chain head at that moment.
`verify --anchor` finds the nearest annotated ancestor of HEAD and requires that
recorded hash to be a MEMBER of the current, link-verified chain. Ordinary growth
after anchoring therefore passes; a chain replaced wholesale by a different valid
chain, or truncated past the anchor, fails; no anchor anywhere in the ancestry
fails closed with the remedy named. Until v3.8.51 it demanded EQUALITY, so one
append read as "rewritten", and the release gate hedged by requiring an anchor
only when a note happened to exist — nothing ever wrote one, so the anchor failed
open on absence. Found by being hit: a workspace restore swapped in an older valid
chain and plain `verify` said OK. Strict now requires it unconditionally and every
release writes one; the first strict release needs a one-time
`./manage.sh memory anchor` as the human-established trust root. `substrate_doctor`
delegates to the same verifier, so there is one definition of "anchor valid".

A note is mutable state in the same writable repo as the log, so v3.8.51's
detection was one command from being undone: replace the chain, re-run `anchor`,
green again. Advancing is now MONOTONIC — a previous anchor's hash must still be
in the chain, which growth satisfies and replace-then-re-anchor does not. A real
reset uses `anchor --force`, which appends an `anchor-forced` event naming the
abandoned hash, putting the discontinuity in the record rather than erasing it.

`verify --anchor` reports which anchor it has, not one line for all:
`verified against origin`; `ANCHOR CONFLICT` (fail) when the local note
disagrees with the remote, which defeats a forced local rewrite; `LOCAL-ONLY`
when an origin exists but lacks it; and `LOCAL (no remote)`, which PASSES,
because the base tier is offline-complete and local is then the strongest
anchor obtainable. Strict requires publication and fails closed without it.

Publish FROM THE PRODUCING CLONE. Git does not transport `refs/notes/*` on a
normal push, clone, or fetch, so another clone never receives the ref and its
push fails with `src refspec ... does not match any`; delegating that step is an
impossible instruction. The release gate pushes the note itself and, when
refused, prints the payload plus the `git notes --ref=substrate-memory add -f -m`
command that recreates it anywhere — the payload travels in text where the ref
does not. A suffix rewrite after the anchor stays undetectable by any unkeyed
chain; the published anchor bounds it.

## Verified skill evidence

`memory skill-run <name> --verify` records a verification result only when the
deterministic check succeeds and the repository identity remains stable. The
signature includes the full HEAD and symbolic ref, Git's `write-tree` object ID,
the index, and raw filesystem identity and content for tracked paths. Length
prefixing keeps the hash encoding unambiguous.

Git routing and configuration variables are stripped. Files are read directly
with lstat identity, mode, link target, device, inode, and link count. Escaping
ancestors, untracked symlink targets, unreadable state, and tracked gitlinks fail
closed. Check tools must be regular tracked files inside the repository; a
symlinked or escaping tool is not executed. The second signature includes check
side effects, so a clean check that mutates the tree records stale verification.

The raw-byte pass complements `git write-tree`: Git's object model may apply
clean filters, while the raw pass attests the bytes and filesystem identity the
host actually exposes. This is tamper evidence, not isolation from a process
that can continuously rewrite the repository.

## Session capture and restore

`.substrate/memory/tasks/current.json` is the structured session source of
truth. `docs/CURRENT_SESSION.md` is a derived human view and never restore input.
Session start also records a Git baseline for completion checks. The state file
is read with `O_NOFOLLOW`: a symlinked `current.json` is treated as no state, so
restore can never be redirected to pull an outside file into context.

Restore sanitizes untrusted text and enforces separate budgets for structured
handoff content, the last five HISTORY summaries, and the newest rejected
approaches. `_safe_history_line` strips control, markup, and role-like prefixes.
`_rejected_block` reuses that sanitizer and keeps newest entries when the budget
truncates older context.

## Append-only coordination logs

HISTORY and REJECTED share `_doc_common.locked_atomic_append`. It takes a bounded,
nonblocking exclusive lock on the parent directory, rereads under the lock,
writes a same-directory temporary file, and replaces the leaf before unlocking.
Directory locking survives target inode replacement; target-inode locking would
not. Replacement preserves the no-write-through-symlink-or-hard-link property
that direct append would lose, but the reread of existing content happens BEFORE
the replace, so the target leaf itself is guarded first: `refuse_linked_leaf`
rejects an unsafe leaf — symlink, extra links (`st_nlink > 1`), or non-regular
type (a FIFO would otherwise block the read forever) — before any read.

Guards that run before a blocking wait have not run. Containment is therefore
re-validated AFTER the directory lock is acquired, and every post-lock operation
is anchored to the locked directory fd (`dir_fd=` plus basenames) rather than
re-resolved by path: a parent swapped while an appender waits on the lock now
fails closed instead of redirecting the write, and the bytes land in the inode
that was locked or nowhere.

`safe_atomic_write` is the write-side counterpart, and how it reaches the parent
is the load-bearing part. It never resolves a multi-component path: `open_dir_chain`
opens the ROOT once and descends ONE COMPONENT AT A TIME with
`O_DIRECTORY|O_NOFOLLOW` and `dir_fd=`, then the temp file is created, written and
`os.replace`d entirely through that fd using basenames. A dev/ino re-validation
after a whole-path open cannot work — by the time it runs the kernel has already
followed a swapped intermediate ancestor and the comparison approves the rerouted
directory against itself. Descending component by component removes the window
instead of checking for it, which makes containment a property of how the work is
done rather than a test performed beforehand.

Anchoring to a fd has one limit, and it is checked rather than assumed: the fd
says nothing about whether that inode is still REACHABLE at the requested path. A
parent renamed after capture leaves the write landing in a detached directory
while the live target is untouched, so `dir_fd_still_live` re-descends AFTER the
operation and compares identities; a mismatch is a refusal, not a success. The
same applies to reads, which return None rather than detached bytes.

`safe_mkdir` completes the set. A raw `mkdir(parents=True)` followed by a guarded
write creates the directory through a symlinked ancestor and only then gets
refused — the mutation has already happened outside the repo. Building the mkdir
on the same descent means every component is created inside the tree or not at
all. Order is part of the guard: the FIRST operation that touches the filesystem
is the one that needs it.

Where a guarded stat is followed by an open, the opened fd is re-verified against
the inode the stat approved — statting a path and then opening it by name is
check-then-use however well the stat is guarded. The memory chain's own signature
hasher reads every tracked file through the guarded reader for exactly this
reason: an `lstat` reporting `S_ISREG` is passed by a hard link too, and a
signature computed over bytes the guard never approved is the one thing a chain
must not produce.

Readers carry the same guarantees as writers. `safe_read_text` is the read-side
counterpart — containment, `O_NOFOLLOW | O_NONBLOCK`, `S_ISREG`, single link,
bounded read, lossy decode — and `memory_log`, `append_history`'s session-token
read, the session-handoff HISTORY/REJECTED tails, and the completion gate all
route through it. Size policy is per-caller because truncation is not uniformly
safe: the memory chain reads unbounded (a short read would verify as a clean
chain), tail consumers pass `tail_bytes`, and small bounded files treat
oversize as malformed. A refused read must stay distinguishable from an absent
one: an absent memory log is a legitimately empty chain, while a present but
linked or non-regular one BREAKs. Lossy decoding is not sanitization either —
the session token is charset-validated before it can enter a HISTORY header.
Interrupted lock calls retry, invalid timeout overrides fall back to the
default, and lock or I/O failure maps to each CLI's existing nonzero contract.

## Completion

The completion gate is opt-in. It compares the current repository state with the
session-start baseline and checks whether a verified self-audit event occurred
after the last project change. It warns by default; it does not turn an
agent-authored note into proof or silently claim that unfinished work is done.
Its evidence read is guarded like every other reader, because evidence sourced
through a link is a gate bypass: a hard-linked `events.jsonl` pointing at an
outside log with a forged recent self-audit would silence the nudge. Unsafe
evidence counts as no evidence, so the gate nudges rather than going quiet.

The structured handoff snapshot is untracked, agent-writable state whose
writer is not authenticated, so restore validates and sanitizes every field at
READ time. Validation is two layers: TYPE/SHAPE — scalar fields must be
scalars, list fields lists of strings, and todo lines must match the exact
grammar the capture hook writes; a forged wrong-typed field is discarded, and
any shape the builder did not anticipate degrades to no-state rather than
crashing the SessionStart hook. LEXICAL — every surviving string passes the
same chain HISTORY and REJECTED lines use.

STATED LIMIT: these filters decide SHAPE, not INTENT. A hostile directive
phrased as a grammatically valid, innocuous-looking task label passes any
deterministic filter — semantic detection is not claimed and would violate the
determinism the gates depend on. That residual is contained by FRAMING, not
detection, and the framing must not re-arm the forgery: restored todos are
injected as UNVERIFIED labels to confirm against git/HISTORY, and the recovery
text tells the reader to re-derive next steps from that verified state rather
than to resume a todo. Pairing rendered todos with a "resume the in-progress
item first" directive is exactly what turned a forged label back into an
actionable instruction, so that pairing is removed. No gate ever consumes
todos. Write-side sanitization alone is insufficient because the file can be
forged; read-side validation and non-actionable framing are where the
guarantee lives.
