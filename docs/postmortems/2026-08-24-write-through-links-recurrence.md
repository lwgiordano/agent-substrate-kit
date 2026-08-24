---
date: 2026-08-24
severity: high
caught_by: external-audit
related_commits:
  - WORKING (v3.8.38 — round-21 remediation)
gates_added:
  - tests/test_hook_scripts.py::test_agentsync_msg_refuses_hardlinked_bus
  - tests/test_hook_scripts.py::test_handoff_capture_does_not_write_through_links
  - tests/test_hook_scripts.py::test_handoff_restore_refuses_hardlinked_state
---

# 2026-08-24 — write-through symlink/hard-link in file I/O (class recurrence)

## What happened

A single defect class — **writing through, or reading through, a symlinked or
hard-linked leaf to an inode outside the repo** — recurred across three
independent code paths that all handle agent-writable files:

- `agentsync.sh` appended a bus line through a hard-linked `AGENT_BUS.md`
  (`O_NOFOLLOW|O_APPEND` stops symlinks but `st_nlink > 1` writes through the
  shared inode) — an arbitrary external-write primitive.
- `session_handoff.py` capture wrote `docs/CURRENT_SESSION.md`,
  `.substrate/memory/tasks/current.json`, and `session_start.json` with
  `Path.write_text()`, which opens the existing path and thus writes through a
  symlinked or hard-linked leaf.
- `session_handoff.py` restore read `current.json` with `O_NOFOLLOW` (v3.8.37)
  but still accepted a **hard-linked** state file, pulling an outside file's
  todos into model-facing context.

The same shape — symlink handled, hard link forgotten — was first fixed in
`write_install_json.py` in **v3.8.25**. It reappeared because each new writer
was hardened against the symlink half of the class without re-applying the hard
link half.

## Why it happened

Root cause: **the fix for the class was never centralized, so each writer
re-derived it and each re-derivation stopped at symlinks.** `O_NOFOLLOW` and
`is_file()`/`is_symlink()` are the reflexes that come to mind; `st_nlink > 1` is
the half that is easy to forget because a hard link *is* a regular file and
passes every "is this a real file?" check. When v3.8.37 added `O_NOFOLLOW` to
the handoff readers/writers, it closed the visible (symlink) half and moved on —
scoping the fix to the symptom that was reported, not the full class that
v3.8.25 had already named.

Meta-pattern: **a partial class-fix is a latent regression.** Closing the
reported half of a known class, without re-deriving the whole class from its
prior postmortem, guarantees the other half resurfaces in the next audit.

## Why our tooling didn't catch it

No gate encoded the v3.8.25 lesson as a reusable check — it lived only as a
comment in `write_install_json.py` and prose in a knowledge doc. Nothing forced
a new file writer to go through a link-safe path, and no eval exercised capture
or the bus append against a hard-linked target. The class was documented but
not *mechanized*, so each new writer was free to reintroduce it.

## Preventative gate added

- **Fix (centralized):** a shared `session_handoff._atomic_write_text` (same-dir
  `mkstemp` + `os.replace`) that breaks hard links and follows no symlink,
  now used by all three capture writers; `agentsync.sh` refuses `st_nlink > 1`
  and non-regular bus files; restore adds an `st_nlink == 1` check.
- **Tests:** hard-linked-bus refusal, capture-through-symlink-and-hard-link
  no-op, and hard-linked-restore refusal (listed in `gates_added`).
- **Evals:** two behavioral evals (`t_handoff_capture_no_write_through_symlink`,
  `t_agentsync_refuses_hardlinked_bus`) so the class is exercised in the
  adversarial corpus every run, not just in unit tests.

## Carry-forward rule

When hardening any file **read or write** against a symlinked leaf, in the same
change also reject `st_nlink > 1` (hard links) or route the write through
`mkstemp` + `os.replace` — a symlink guard alone is half a fix, and this class
has recurred twice (v3.8.25, v3.8.38). Before landing a link-safety fix, grep
the repo for every `write_text`/`open(...O_APPEND...)`/`read_text` on an
agent-writable path and fix them together.

## (Optional) Reproduction

In a disposable repo: `ln victim.txt AGENT_BUS.md` then
`AGENT_NAME=x ./agentsync.sh msg "…"` — pre-fix, the line lands in `victim.txt`.
For capture: `ln -s /outside docs/CURRENT_SESSION.md` then
`session_handoff.py capture` — pre-fix, `/outside` is overwritten.
