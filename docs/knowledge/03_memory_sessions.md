---
purpose: Tamper-evident memory, session restore, completion, and append-only logs.
asserts:
  - scripts/memory_log.py::_raw_tracked_hash
  - scripts/memory_log.py::_write_tree_oid
  - scripts/_doc_common.py::locked_atomic_append
  - scripts/session_handoff.py::_safe_history_line
  - scripts/session_handoff.py::_rejected_block
last_human_reviewed: 2026-08-09
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
Session start also records a Git baseline for completion checks.

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
that direct append would lose. Interrupted lock calls retry, invalid timeout
overrides fall back to the default, and lock or I/O failure maps to each CLI's
existing nonzero contract.

## Completion

The completion gate is opt-in. It compares the current repository state with the
session-start baseline and checks whether a verified self-audit event occurred
after the last project change. It warns by default; it does not turn an
agent-authored note into proof or silently claim that unfinished work is done.
