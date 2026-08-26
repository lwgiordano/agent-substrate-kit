---
date: 2026-08-24
severity: high
caught_by: external-audit
related_commits:
  - WORKING (v3.8.38 — round-21 remediation)
  - WORKING (v3.8.39 — round-22 remediation)
  - WORKING (v3.8.40 — round-23 remediation)
  - WORKING (v3.8.41 — round-24 remediation)
  - WORKING (v3.8.42 — round-25 remediation)
  - WORKING (v3.8.43 — round-26 remediation + mechanization)
gates_added:
  - scripts/check_raw_file_io.py
  - tests/test_hook_scripts.py::test_safe_atomic_write_never_writes_through_links
  - tests/test_hook_scripts.py::test_locked_append_refuses_leaf_swapped_after_the_stat
  - tests/test_hook_scripts.py::test_todo_state_hook_redacts_and_refuses_linked_docs
  - tests/test_hook_scripts.py::test_fifo_config_never_hangs_a_gate
  - tests/test_hook_scripts.py::test_config_gate_treats_unusable_config_as_tampering
  - tests/test_hook_scripts.py::test_raw_file_io_gate_catches_regressions_without_false_positives
  - tests/test_hook_scripts.py::test_redactor_copies_stay_identical
  - tests/test_hook_scripts.py::test_refuse_linked_leaf_rejects_non_regular
  - tests/test_hook_scripts.py::test_safe_read_text_guards_every_unsafe_leaf
  - tests/test_hook_scripts.py::test_locked_atomic_append_refuses_parent_swap_under_lock
  - tests/test_hook_scripts.py::test_memory_log_read_side_breaks_on_tampered_leaf
  - tests/test_hook_scripts.py::test_read_session_token_degrades_on_fifo_and_bad_utf8
  - tests/test_hook_scripts.py::test_handoff_tails_refuse_linked_docs
  - tests/test_hook_scripts.py::test_completion_gate_ignores_linked_events
  - tests/test_hook_scripts.py::test_harness_blocks_non_regular_governed_surface
  - tests/test_hook_scripts.py::test_harness_blocks_empty_scan_root
  - scripts/run_substrate_evals.py::t_completion_gate_forged_linked_events
  - scripts/run_substrate_evals.py::t_memory_linked_events_break
  - scripts/run_substrate_evals.py::t_history_fifo_no_hang
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
2. **Leaf TYPE, all three properties** — a leaf is unsafe if it is a symlink, if
   it has extra links (`st_nlink > 1`), OR if it is not a regular file (FIFO,
   socket, device, directory). Enumerating two of the three is not a class fix:
   v3.8.41's helper checked links only, so a FIFO passed as safe and HUNG the
   caller. Writing via `mkstemp` + `os.replace` breaks a hard link and follows
   no symlink, but it does not save a reader — apply all three to READERS too
   (a hard-linked bus/lock/log reads outside bytes; a FIFO one blocks forever).
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

## Round 5 — v3.8.42 (round-25): leaf TYPE, the read side, and a real TOCTOU

Three things, only the first of which is this class continuing:

1. **The leaf-type axis was still incomplete.** `refuse_linked_leaf` (shipped
   the day before, as *the* centralized fix) asked "is it linked?" and never
   "is it a regular file?" — so a FIFO passed as SAFE and then **hung** the
   caller on `open()`. That is the same partial-class-fix shape for the THIRD
   time, now inside the very helper written to end it. The lesson is sharper
   than "remember hard links": an unsafe leaf has THREE independent properties
   (symlink, extra links, non-regular type), and a guard that enumerates two of
   them is not a class fix. Carry-forward part 2 is amended accordingly.

2. **Rounds 21-24 hardened every WRITER and never swept the READERS.** The
   readers had no guard at all — not a partial one, none. `memory_log._read_events`
   trusted an outside chain (and `verify` reported it OK), the SessionStart
   HISTORY/REJECTED tails piped outside bytes into **model context**, and
   `completion_gate` let a hard-linked forged self-audit event **suppress the
   Stop nudge**. Fixed with a read-side counterpart, `safe_read_text`, that every
   reader routes through. Two sub-lessons worth keeping: a tampered read must be
   distinguishable from an ABSENT one (returning "empty" for a symlinked
   events.jsonl traded a hang for a fail-open, so a present-but-unsafe log now
   BREAKs); and lossy decoding is not sanitization (the replacement characters
   still matched `(\S+)` and would have been written verbatim into the
   append-only HISTORY header, so the token now has a charset guard).

3. **The P1 was not a link bug at all** — it was check-then-use.
   `locked_atomic_append` validated containment, THEN opened and locked the
   parent, then re-resolved the target **by path** for `read_text`/`mkstemp`/
   `os.replace`. An appender that blocked on the lock wrote wherever the path
   pointed when it woke, so swapping the parent during the wait redirected it
   outside the repo. Every guard in rounds 22-24 was correct and none of them
   helped, because they all ran before the wait. Fixed by anchoring every
   post-lock operation to the locked directory fd (`dir_fd=` plus basenames) and
   re-validating under the lock that the path still names the locked inode.

## Carry-forward rule, part 5 — ordering and symmetry

The four parts above are about WHAT to check. These are about WHEN and WHERE:

5a. **A guard that runs before a wait has not run.** If any blocking operation
    (a lock, a subprocess, a network call) sits between the check and the use,
    the check must be REPEATED after the wait, and the use must be anchored to a
    handle captured before it — an fd, not a path. Path-based operations after a
    lock are check-then-use by construction.
5b. **Readers and writers are symmetric.** Every guard added to a writer of an
    agent-writable file must be added to that file's readers in the same change.
    Ask "who READS this?" for each hardened writer; four readers survived four
    rounds of writer hardening because nobody asked.
5c. **Unsafe must not look like empty.** When a guard refuses, the caller must
    distinguish "absent" from "present but refused". Collapsing them makes the
    refusal a fail-open wherever emptiness is the benign case.

## Round 6 — v3.8.43 (round-26): the loop was the bug

Round 26 found ten more, four P1. Two were incompleteness in fixes shipped the
previous day: `locked_atomic_append` lstat'd the leaf under the locked dir fd
and then opened the name **without fstatting the opened fd** (`O_NOFOLLOW`
rejects a symlink swapped into that window but a HARD LINK passes it, so the
guarded stat proved nothing about the fd actually read), and
`_atomic_write_text` was the round-25 parent-swap P1 *verbatim* in a function
that round simply hadn't touched.

That is the sixth consecutive round of the same story, so the honest conclusion
is not another entry in this list: **the remediation method was the defect.**
Every round fixed the reported instances correctly and left the rest of the
class untouched, so the next audit found the next sample. Measuring the surface
made this concrete — and corrected an inflated first estimate: a grep suggested
~176 raw-I/O sites, but an AST pass that resolves each call site to the BASE
symbol of its path expression showed only ~30 are **governed** (rooted at the
process's own repo root, therefore attacker-preparable). The rest write into
freshly created temp directories inside fixtures, where no attacker-controlled
link can exist. A finite, small, enumerable surface — which is what makes the
real fix affordable.

So v3.8.43 did three things instead of ten patches:

1. **Two shared fd-anchored helpers.** `safe_atomic_write` (parent opened
   `O_DIRECTORY|O_NOFOLLOW`, re-validated against the opened inode, then
   `mkstemp`/`replace`/`unlink` via `dir_fd=` and basenames) fixed three
   independent writers at once, and `locked_atomic_append` gained an
   fstat-after-open that pins the read to the exact inode the guard approved.
2. **A sweep, not a sample.** Every governed call site moved onto the guards —
   including six the audit had never reported (`check_history_sha`, two
   `completion_gate` reads, two in the evals runner, one in the doctor), and the
   FIFO-config root cause: `_doc_common._code_suffixes()` ran a raw read at
   MODULE IMPORT, so a FIFO `.substrate/config` wedged every consumer upstream
   of its own guards. The reported symptom was `command_policy.profile()`.
3. **`scripts/check_raw_file_io.py`** — the gate. It fails when raw file I/O
   targets a repo-derived path, with a short allowlist where each entry carries
   a reason and a stale entry is itself a failure.

Item 3 is the one that matters, and it is what the FIRST postmortem in this
series already prescribed: *"the class was documented but not MECHANIZED, so
each new writer was free to reintroduce it."* Six rounds were spent re-proving
that sentence. The gate found seven unguarded sites the moment it was written,
which is the proof it was the missing piece — and it will find the eighth, from
a contributor who has never read any of this.

**Carry-forward rule, part 6 — fix the class, then gate the class.** A fix that
only covers reported instances is a sampling strategy, not a remediation. When a
class recurs twice, stop patching and ask what mechanically prevents instance
N+1; if the answer is "reviewer diligence", the class will recur. Shared helpers
are necessary but insufficient — nothing forces a new call site through them
except a gate that fails the build.

## Round 7 — v3.8.44 (round-27): the primitive itself had the window

Round 27 found twelve, six P1, and the headline one is the best finding of the
series: `safe_atomic_write` — the shared helper every other fix now routes
through — had the defect in its own foundation.

It was described as fd-anchored. It anchored to the **parent**, and resolved
that parent as a **multi-component path**:

```python
if not within_root(target, root): refuse()
dir_fd = os.open(str(parent), O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
if (lstat(parent).st_dev, .st_ino) != (fstat(dir_fd)...): refuse()   # useless
```

`O_NOFOLLOW` constrains only the **final** component. Swap any *intermediate*
ancestor between `within_root()` and that `os.open` — `repo/state` renamed
aside and replaced with a symlink to `outside_state` — and the kernel resolves
the whole subtree through the swapped link. The dev/ino re-validation then
compares the already-rerouted directory **to itself** and approves it. Codex
reproduced it end to end: the write landed in `outside_state/tasks/out.txt` and
the in-repo parent was never touched. `safe_read_text` had the identical window
and returned OUTSIDE bytes while every leaf `fstat` check passed.

No check can close that window, because by the time any check runs the kernel
has already followed the swapped ancestor. The fix is to never hand the kernel
a re-resolvable path at all: `open_dir_chain()` opens the root once and walks
**one component at a time** with `O_NOFOLLOW|O_DIRECTORY` and `dir_fd=`, so no
intermediate component is ever name-resolved and there is nothing to swap. That
subsumes `within_root` for these callers — containment stops being a check
performed before the work and becomes a property of **how the work is done**.
`safe_read_text`, `read_lock` and `locked_atomic_append` all descend the same
way now; round 27 reported the window on the writer only, and fixing just that
one would have been round 26's mistake for the seventh time.

Round 27 also caught a bug the *hardening itself* introduced: the guarded
writers always created their temp file `0600` and never restored the target's
mode, so every guarded rewrite destroyed permissions — `scripts/tool.sh` went
`0755 -> 0600` (executable bit gone), `docs/HISTORY.md` `0644 -> 0600`. A safety
fix that breaks the file it protects is not a safety fix.

### The gate had six holes, and finding them was the point

Six of the twelve were in `check_raw_file_io.py`, the gate shipped the day
before — asked for explicitly, because it is new and load-bearing and had
already been wrong three times in its own release. It missed governed
**destinations** in multi-path calls (`os.replace(tmp, ROOT/dst)` inspected
argument 0 only), dropped three alias shapes in **silence** (`from os import
unlink as remove_file`, `op = open`, `fn = p.write_text`), let an unreachable
`if False: p = tmp/...` rebind erase a governed origin, read every candidate
with a blocking `read_text()` before any non-regular guard (a FIFO in
`scripts/` **hung** it — the fourth time a component of this system carried the
defect it polices), followed a symlinked `scripts/` under `--root`, and fell
back to `cwd` when root resolution failed.

The seventh matters most for the honesty of the whole exercise: a one-line
wrapper — `def raw_write(p): p.write_text(...)` called with a governed path —
demoted a violation to an `unresolved` line, and `unresolved` does not fail the
build. So the claim "a new unguarded governed write now fails the build" was
overstated as written. The gate now propagates GOVERNED into module-local
callees to a bounded fixpoint, and that single change immediately found **ten
more real governed sites** nobody had reported, including `update_manifest`'s
`write_atomic` (the round-26 parent-swap defect verbatim, invisible only
because the governed path arrived as a parameter), both `_sha256` drift-check
readers (hashing through a planted link makes a tampered file compare *clean*),
the postmortem-gate test-file reader, and the bus lease reader.

### Three in-release auditor findings, all in the new code

A read-only security auditor and the ast-parsing checklist auditor were run on
the finished v3.8.44 diff before commit, and both returned BLOCK-level findings
**in this release's own work** — the third release running where that has been
true, which is the argument for running them at all:

- **The mode-preservation fix widened permissions.** It copied the predecessor's
  `S_IMODE` verbatim, so a target an attacker could `chmod` kept setuid, setgid,
  sticky and world-write through every subsequent guarded rewrite: `0o4777`
  stayed `0o4777`. A permission-preserving fix that preserves *dangerous*
  permissions is a widening. Inheritance is now masked to `0o775`; an explicit
  `mode=` from the caller is a deliberate choice and is not masked.
- **The interprocedural pass resolved the wrong function.** It keyed definitions
  by bare name via `ast.walk` + `setdefault`, so a nested `def helper(q)` and a
  module-level `def helper(x)` collapsed into one entry — a finding on the
  definition the call never reached, and only an `unresolved` line for the write
  that did receive the governed path. Wrong in both directions simultaneously.
- **Positional-only parameters shifted the argument mapping.** `args.args`
  excludes `posonlyargs`, so `helper(ROOT, 1, 2)` against `def helper(a, b, /,
  c)` seeded `c`, which had received the literal `2`.

- **The descent made "not configured" look like "tampered with."** Routing
  `read_lock` onto the component walk collapsed *a component that does not
  exist* into *an ancestor that is unsafe*, so a repo with no `.substrate/` at
  all reported its locks BAD — and a bad lock means the tier IS required. Two
  security-scanner tests caught it. Worth stating precisely because the errno is
  not enough to tell the cases apart: on Linux, `O_DIRECTORY|O_NOFOLLOW` on a
  symlinked ancestor reports `ENOTDIR`, not `ELOOP`, so an errno allowlist that
  looks correct silently reclassifies real tampering as "absent". Only
  `FileNotFoundError` means absent; everything else stays "bad". Fail-closed is
  right for an ancestor that exists and is a symlink, and wrong for one that was
  never created.

Definitions and seeds are now keyed by SCOPE PATH and resolved innermost-first,
argument mapping uses `posonlyargs + args` for positions and skips a leading
`self`/`cls`, and `*args` collection is handled. Each has a regression that was
verified to fail before the fix.

**Carry-forward rule, part 7 — a guard that re-resolves a path is not a guard.**
Check-then-use is not fixed by making the check better; it is fixed by making
the check and the use the same operation. Anchor to a handle obtained one
component at a time, or accept that every ancestor is attacker-controlled.

**Carry-forward rule, part 8 — measure the gate against its own claim.** Each
time this gate was extended it found real bugs the previous version had passed
in silence, and each extension was prompted by someone attacking the gate
rather than the code. State its limits explicitly, then treat every stated
limit as a lead rather than a boundary.

## (Optional) Reproduction

In a disposable repo: `ln victim.txt AGENT_BUS.md` then
`AGENT_NAME=x ./agentsync.sh msg "…"` — pre-fix, the line lands in `victim.txt`.
For capture: `ln -s /outside docs/CURRENT_SESSION.md` then
`session_handoff.py capture` — pre-fix, `/outside` is overwritten.
Ancestor (v3.8.39): `ln -s /outside .substrate` then read a `required_*` lock —
pre-fix, the outside lock lowers the containment floor.
