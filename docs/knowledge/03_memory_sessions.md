---
purpose: Tamper-evident memory, session restore, completion, and append-only logs.
asserts:
  - scripts/memory_log.py::_raw_tracked_hash
  - scripts/memory_log.py::_write_tree_oid
  - scripts/_doc_common.py::locked_atomic_append
  - scripts/session_handoff.py::_safe_history_line
  - scripts/session_handoff.py::_rejected_block
last_human_reviewed: 2026-08-26
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
from a broken or stale anchor; go-live reports those states separately.

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

`safe_atomic_write` is the write-side counterpart: it opens the parent
`O_DIRECTORY|O_NOFOLLOW`, re-validates that the path still names the opened
inode, and then creates, writes, and `os.replace`s entirely through that
directory fd using basenames. Replacing the directory entry breaks a hard link
and never writes through a symlinked leaf, and anchoring to the fd means a
parent swapped after the guard cannot redirect the write. Where a guarded stat
is followed by an open, the opened fd is re-verified against the inode the stat
approved — statting a path and then opening it by name is check-then-use however
well the stat is guarded.

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
