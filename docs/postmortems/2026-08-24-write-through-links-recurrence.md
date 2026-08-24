---
date: 2026-08-24
severity: high
caught_by: external-audit
related_commits:
  - WORKING (v3.8.38 — round-21 remediation)
  - WORKING (v3.8.39 — round-22 remediation)
  - WORKING (v3.8.40 — round-23 remediation)
  - WORKING (v3.8.41 — round-24 remediation)
gates_added:
  - tests/test_hook_scripts.py::test_refuse_linked_leaf_symlink_and_hardlink
  - tests/test_hook_scripts.py::test_read_lock_refuses_hardlinked_lock
  - tests/test_hook_scripts.py::test_locked_atomic_append_refuses_hardlinked_leaf
  - tests/test_hook_scripts.py::test_memory_log_refuses_hardlinked_leaf
  - tests/test_hook_scripts.py::test_read_session_token_refuses_linked_current_session
  - tests/test_hook_scripts.py::test_harness_blocks_symlinked_skill_root
  - scripts/run_substrate_evals.py::t_lock_hardlink_lowers_no_floor
  - tests/test_hook_scripts.py::test_agentsync_msg_refuses_hardlinked_bus
  - tests/test_hook_scripts.py::test_handoff_capture_does_not_write_through_links
  - tests/test_hook_scripts.py::test_handoff_restore_refuses_hardlinked_state
  - tests/test_hook_scripts.py::test_within_root_rejects_in_repo_alias
  - tests/test_hook_scripts.py::test_config_gate_rejects_aliased_substrate
  - tests/test_hook_scripts.py::test_append_refuses_symlinked_leaf
  - tests/test_hook_scripts.py::test_memory_log_refuses_routed_parent
  - tests/test_hook_scripts.py::test_memory_log_fallback_fails_closed_on_routed_parent
  - tests/test_hook_scripts.py::test_capture_symlinked_substrate_creates_no_outside_dir
  - tests/test_hook_scripts.py::test_bus_claims_refuses_hardlinked_bus
  - tests/test_hook_scripts.py::test_harness_blocks_symlinked_governed_ancestor
  - scripts/run_substrate_evals.py::t_lock_in_repo_alias_no_floor
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

A link-safety fix has FOUR parts, all required in the same change, or the
missing one becomes the next audit finding:
1. **Leaf symlink** — `O_NOFOLLOW` (or `is_symlink()` refusal), on WRITES *and*
   the read-of-existing-content that precedes a replace.
2. **Leaf hard link** — reject `st_nlink > 1`, or write via `mkstemp` +
   `os.replace` (which breaks the link and never writes through a symlink).
   Apply to READERS too (a hard-linked bus/lock reads outside bytes).
3. **ANCESTOR directory, STRICTLY** — the parent must resolve to its EXACT
   lexical location under the repo root. A no-escape check is not enough: a
   symlinked ancestor that resolves to a *different in-repo* directory
   (`.substrate -> docs`) aliases a trust anchor to agent-writable content
   without leaving the tree. `_doc_common.within_root` enforces the exact-parent
   invariant.
4. **Guard BEFORE side effects** — run the containment check before any
   `mkdir`/`open`/lock, so a refused path creates no outside directory and takes
   no outside lock. Apply the guard to EVERY writer of the class (memory_log was
   the one missed), not just the newest.

This class has recurred FIVE times, each round closing one layer and exposing
the next: v3.8.25 (leaf symlink/hard link in provenance), v3.8.38 (leaf hard
link in the capture/bus writers), v3.8.39 (symlinked ANCESTOR, no-escape),
v3.8.40 (STRICT ancestor — in-repo aliasing — + read-through leaf + memory_log
containment + guard-before-mkdir + hard-linked readers), v3.8.41 (the HARD-LINKED
LEAF, on the lock readers / append log / memory log / session-token reader that
round-23 had only symlink-guarded, + the missed skill-root symlink). Before
landing a link-safety fix, grep the repo for every `write_text` /
`open(... O_APPEND ...)` / `read_text` / `mkstemp` / `mkdir` / `.open(` on an
agent-writable path and apply all four parts to each — the shared
`_doc_common.within_root` + `_doc_common.refuse_linked_leaf` (symlink AND
`st_nlink > 1`) are that fix in one place, but EVERY reader and writer must call
them. When you add a symlink leaf guard, add the hard-link half IN THE SAME EDIT
— that omission is the exact shape that recurred from round-23 to round-24.

## Round 2 — v3.8.39 (round-22): the ancestor layer

v3.8.38 protected the LEAF of each path; every one still routed through a
symlinked PARENT directory. A shared `_doc_common.within_root(target, root)`
(realpath the parent, require it inside realpath(root)) now guards
`read_lock`, `locked_atomic_append`, `session_handoff` capture + restore, and
the AST-pinned `command_policy` reader; the harness additionally BLOCKs a
symlinked governed *directory*, and both bus readers refuse a symlinked
`AGENT_BUS.md`. This round is why part 3 was added to the carry-forward rule
above — the leaf-only reflex was the exact incompleteness that recurred.

## Round 3 — v3.8.40 (round-23): strict ancestor + the missed writers

The v3.8.39 `within_root` checked only NO-ESCAPE (realpath within root), so a
symlinked ancestor resolving to a *different in-repo* directory
(`.substrate -> docs`) still redirected the trust anchor to agent-writable
content. Tightened to the EXACT-lexical-parent invariant. Three more gaps in
the same class surfaced together: `locked_atomic_append` read the existing
target through a symlinked leaf before replacing it; `memory_log.append` had no
containment at all; and the capture writers ran `mkdir` before the guard, so a
refused write still created an outside directory. Readers gained hard-link
refusal (bus_claims, agentsync `read`), and `agentsync read` moved its
validation AFTER the `git pull` (a remote push could swap the bus to a symlink
between an early check and the read). This round is why parts 1, 2, and 4 of the
carry-forward rule gained their qualifiers, and why part 3 became STRICT.

## Round 4 — v3.8.41 (round-24): the hard-linked LEAF

v3.8.40 refused a SYMLINKED leaf (`is_symlink()` / `O_NOFOLLOW`) on the append
log, the memory log, and the capture writers — but a HARD LINK is a regular
file: it passes `is_symlink()` AND the fd-based `O_NOFOLLOW`+`S_ISREG` checks,
so `read_lock`, the AST-pinned `command_policy` lock reader, `locked_atomic_append`
(before its `read_text`), and `memory_log.append` all still read/wrote a
hard-linked leaf that shared an OUTSIDE inode — lowering a containment lock or
importing an outside file's bytes into an in-repo log. `append_history.read_session_token`
had never been link-guarded at all and copied a hard-/sym-linked
`CURRENT_SESSION.md`'s token into HISTORY. And the harness ancestor walk (added
in round-22/23) covered the governed dir LISTS but not the skill-glob ROOTS
(`.agents/skills`, `.claude/skills`), so a direct symlink AT a skill root was
neither scanned nor flagged. Centralized fix: `_doc_common.refuse_linked_leaf`
(symlink OR `st_nlink > 1`, lstat-based) now guards every path-based leaf
reader/writer; the two fd-based lock readers add the `st_nlink > 1` rule on their
TOCTOU-free `fstat`; the harness walks `_SKILL_ROOTS` too. This round is why the
carry-forward rule now says the hard-link half must land in the SAME edit as the
symlink half — the round-23→24 gap was exactly that split.

## (Optional) Reproduction

In a disposable repo: `ln victim.txt AGENT_BUS.md` then
`AGENT_NAME=x ./agentsync.sh msg "…"` — pre-fix, the line lands in `victim.txt`.
For capture: `ln -s /outside docs/CURRENT_SESSION.md` then
`session_handoff.py capture` — pre-fix, `/outside` is overwritten.
Ancestor (v3.8.39): `ln -s /outside .substrate` then read a `required_*` lock —
pre-fix, the outside lock lowers the containment floor.
