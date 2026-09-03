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

## Round 8 — v3.8.45 (round-28): the gate shipped inert to every consumer

Round 28's most valuable finding is not a race. It is this: `check_raw_file_io.py`
was copied into every bootstrapped install and **nothing ran it**. Generated
`manage.sh check` and generated pre-commit never invoked it; only the kit's own
repo did. Two releases were spent arguing that this class recurs because the safe
path is available but not *mandatory* — and the mechanism that makes it mandatory
was shipped to consumers as an inert file.

The parity test that exists to catch exactly this listed validators **by hand**,
so it agreed with itself. That is the same shape as the defect: parity was
documented, not mechanized. The fix wires the gate into both templates *and*
replaces the hand-maintained list with a derived one — every validator the kit's
own `check` runs must appear in the template a consumer gets, or the build fails.
Verified by bootstrapping a consumer and watching its `manage.sh` gate block a
planted write.

### The fd anchor has a limit, and it is not the one that was fixed

Round 27's `open_dir_chain` stops the kernel following a hostile **new** path.
Round 28 showed what it does *not* do: it says nothing about whether the pinned
inode is still **reachable** at the path the caller asked for. Rename the parent
after capture and every `dir_fd=` operation works flawlessly on a **detached**
directory —

- the read returned `INSIDE-OLD` while the live target held `LIVE-NEW`;
- the write returned **success** with the bytes in the moved directory and the
  live target absent.

Round 28's repro keeps the moved directory in-repo. Move it outside instead and
the same mechanism puts the bytes outside. No fd can prevent that, because the
rename has already happened. So the fix is detection, deliberately placed *after*
the operation: `dir_fd_still_live()` re-descends from the root and compares
identities, and the caller turns a mismatch into a refusal. It cannot un-write
bytes already placed in a detached directory. It can stop the caller believing
they landed where they were asked to — which is the one shape this series exists
to remove. Applied to the read, the write, the append, and `read_lock`.

### Seven more gate holes, and one that found my own code

Keyword operands (`open(file=...)`, `shutil.copy(dst=...)`) were the round-27
positional multi-path bug in a second spelling. Wildcard imports were the alias
defect in a third. The propagation bound of 4 was a guess about other people's
code that a five-deep wrapper chain walked past — the seed set only grows, so the
loop already terminates on its own and the number is now a runaway backstop
rather than a depth limit. The `RecursionError` guard added in v3.8.44 wrapped
the visitor but not `ast.parse`, which is what actually raises first.

Three were the gate's own bookkeeping being keyed too loosely: the allowlist key
was a **basename**, so an exemption reviewed for `scripts/_doc_common.py` covered
a same-named file anywhere in the tree; the self-skip was by basename too, so a
nested `check_raw_file_io.py` was unscannable; and a symlinked **child**
directory under `scripts/` silently redirected part of the surface while only the
top-level symlink was refused.

The allowlist fix went further than reported. A key covered *every* matching call
site, so a second raw call with the same base and method silently inherited a
reason a human had read about a different line. Counting matches found two real
cases on the first run — and one of them was created by **v3.8.44's own new
eval**, which had inherited an exemption written for a different call site the
day before. A deliberate multi-site exemption is now declared as
`(reason, count)`.

### Four in-release auditor findings — two of them BLOCKs in the new code

- **The keyword-operand fix reintroduced the silent drop it was written to
  remove.** A `**` keyword node has `arg=None`, so filtering on `k.arg in
  PATH_KWARGS` discarded `shutil.copy(**{"src": ..., "dst": ROOT / "x"})`
  entirely — no finding, no `unresolved` line. The file's own docstring calls
  that a bug in the gate. A readable literal dict now resolves like any other
  operand; an unreadable `**d` is reported as unresolved.
- **The new liveness check leaked a file descriptor on every refusal.** In
  `read_lock` it sat between the leaf `open` and the `try/finally` that closes
  it, so 20 refusals leaked 20 fds. A guard that converts a race into a
  resource-exhaustion vector is not a guard — and a lock is precisely the file
  an attacker can make this fire on repeatedly.
- **The wildcard-import fix false-positived on ordinary code.** Registering
  every covered name from `from shutil import *` attributed a module's own
  `def copy(...)` to shutil, and `copy`/`move`/`remove` are common verbs. A gate
  people switch off for noise protects nothing; star names that the module
  itself defines are now skipped.
- **Raising the propagation bound from 4 to 64 moved the defect rather than
  fixing it** — a 65-deep chain would degrade the same way. The bound is now
  derived from the module's own parameter count, which the fixpoint provably
  reaches first, so it is a runaway backstop rather than a depth guess.

### The wiring immediately paid for itself

The first CI run after the templates were wired failed — in the **strict**
full-setup jobs, and for the right reason. `extras/*.py` are copied into
`scripts/` on a strict install, so they are governed scripts *there*, but they
live outside `scripts/` in the kit and the gate had never scanned them.
`check_license_headers.py` had kept a raw `read_text` and a raw `write_text`
through every sweep in this series, invisible because the sweep audited the
directory a file currently sits in rather than every directory a file can move
*into*.

That is the consumer blind spot one layer deeper than the one round 28 reported,
and it was found by a consumer's own gate within minutes of that gate existing.
Fixed in two parts: the extra is routed through the shared guards, and the kit's
gate now scans every tree that becomes `scripts/` under some profile —
namespaced by tree, because a staging file sharing an exemption with a same-named
file in `scripts/` would have reintroduced the basename collision this very
release fixed.

**Carry-forward rule, part 9 — ship the mechanism, not just the file.** A gate
that runs only in the repo that authored it protects nobody else. When a control
is added, the question is not "is it wired here" but "what makes it impossible to
add the next one without wiring it everywhere" — and the answer has to be a
derived check, because a hand-maintained parity list agrees with itself.

**Carry-forward rule, part 10 — an exemption is granted to a call site, not to a
shape.** If an allowlist entry silently starts covering more code than the
reviewer read, it has become the thing it was supposed to prevent. Count the
matches and fail when the count moves.

## Round 9 — v3.8.46 (round-29): the guard ran after the mutation

Round 29's three P2s are the most important findings of the round, above two of
its P1s. Three call sites created a directory with a raw `mkdir(parents=True)`
and *then* wrote into it with a guarded writer. The guard did its job and
refused — and the directory had already been created, outside the repo, through
a symlinked ancestor. `substrate_audit` left `<outside>/audits/<stamp>/`;
`run_substrate_evals` left `<outside>/traces/` **and printed `ok`**, because it
swallowed the guarded-write failure with `except: pass`.

The damning part is the allowlist. Each of those three raw mkdirs carried an
exemption I had written, and each reason said the same thing:

> "creates `.substrate/traces` **immediately before** a `safe_atomic_write` into
> it; that writer re-validates containment and anchors to the parent fd"

That states the wrong order, in my own words, three times, and it was reviewed
three times. The guarded writer's containment is *irrelevant* to a directory
that already exists by the time it runs. A control placed after the mutation is
a report.

`safe_mkdir()` now builds on `open_dir_chain(create=True)` — the descent that
never resolves a multi-component path — so every component is created inside the
tree or not at all. The three exemptions were deleted rather than reworded, and
the swallowed failure is now reported (the final trace failure marks the run
failed: an evals runner that cannot record its own result must not claim it did).

### Four P1s in the gate, and they were one design error

Aliases were learned *during* the same ordered visit that scans function bodies,
and kept in flat module-wide dicts. That single choice produced three separate
escapes: a function using an alias bound by a **later** import line was dropped
entirely (valid Python — the import runs before the call does); a nested `import
os as io` clobbered a sibling function's module-level `import shutil as io`; and
the v3.8.45 star-import shadow fix collected def names with `ast.walk`, so an
unrelated **nested** `def copy` suppressed a real `from shutil import *` call.

That last one deserves naming plainly: it is the `ast.walk` scope-collapse
mistake an auditor caught in v3.8.44, in a different function, which I fixed
there and then reintroduced two releases later in code written to fix something
else. Knowing a bug class is not the same as having a habit that prevents it.

Binding structure is a property of the module's *shape*, not of the order a
walker happens to reach things, so it is now resolved in a pre-pass with module
scope kept separate from function scope.

The fourth P1 was smaller and more embarrassing: `os.path.join(ROOT, ...)` was
not in the transparent-wrapper list. That list was the wrappers I happened to
think of — `str`, `Path`, `fspath`, `resolve` — and `os.path.join` is the most
ordinary way anyone builds a path. Adding it immediately surfaced a real
unguarded read **in the memory chain's own signature hasher**: every tracked
file was read with a bare `open(fp, "rb")` after an `lstat` said `S_ISREG`.
Stat-then-open, so a hard link passes both checks. A signature computed over
bytes the guard never approved is the one thing a memory chain must not produce.

### Four in-release findings, three of them BLOCKs in the new code

- **The binding pre-pass had two blind scopes.** `_scope_body` walked
  body/orelse/finalbody and handler bodies, but `match`/`case` keeps its
  statements under `.cases[i].body` — so an import inside a case was invisible
  and the call using it produced neither a finding nor an `unresolved` line.
  And `_descend` passed the scope path through unchanged for a `ClassDef`, so a
  method's key collided with a same-named module-level function and whichever
  the walk reached **last** overwrote the other's bindings: an order-dependent
  silent fail-open. Both were in the pass written *to make binding resolution
  correct*.
- **A fallback for one import disarmed another.** The `safe_mkdir` try/except
  was spliced into the `safe_atomic_write`/`safe_read_text` one, so on an
  install that had the reader but not the mkdir, the successfully imported
  reader was overwritten by a `None` stub — and the sandbox lock is read through
  it, so a tier that should have been REQUIRED silently became optional. There
  is now a test that reads the AST of every guarded-helper fallback and asserts
  no handler defines a stub for a helper its own `try` did not import.
- **Failing the run on any trace-write error was too broad.** A read-only
  checkout would hard-fail for an infrastructure reason, under a message about
  malicious tasks. Only a refusal is a security event, so refusals are now a
  distinct exception type (`GuardRefusal`, subclassing `OSError` so every
  existing contract holds) rather than a string match.
- **A `None` memory signature said nothing about why.** Fail-closed is right;
  fail-closed and silent is a chain break nobody can diagnose, so the refusal
  now names the file and the reason.

**Carry-forward rule, part 11 — order is part of the guard.** "Guarded write"
does not make a sequence safe; the *first* operation that touches the filesystem
is the one that needs the guard. When reviewing an exemption, read the reason as
a claim about ordering and check it against the code — three reasons here
described the wrong order and survived three reviews.

**Carry-forward rule, part 12 — a fixed bug class is not a fixed habit.** The
`ast.walk` scope collapse was found, understood, documented and fixed, and then
written again two releases later by the same author in new code. Bug classes
recur through the people who know about them, so the check has to live in the
tool, not in the memory of whoever last read the postmortem.

## Round 10 — v3.8.47 (round-30): one correct idea, applied to one of three

Round 29 moved IMPORT resolution out of the ordered walk and into a pre-pass,
because learning bindings in traversal order is not the same as knowing what
Python binds. Round 30 showed the fix stopped one third of the way:

- **ASSIGNMENT aliases were still learned during the walk**, so a module-level
  `op = open` written *after* the function that uses it was dropped — the module
  initialises completely before that function is ever called.
- **The pre-pass used a LIFO stack**, so `if True: import os as io` followed by
  `import shutil as io` resolved to whichever the stack happened to pop last.
  Later binding wins at runtime; the enumeration has to be in document order.
- **A class BODY EXECUTES.** Treating `ClassDef` as a namespace to skip made
  `class C: import shutil as io; io.copy(...)` — real I/O at definition time —
  vanish entirely.

Three symptoms, one root cause, and the root cause was a fix applied to one of
the three binding forms it should have covered.

The same shape appeared twice more in the same release. `dir_fd_still_live` was
written in v3.8.45 for reads, writes and appends; v3.8.46 added a **fourth**
fd-capturing primitive, `safe_mkdir`, and did not give it the check that already
existed for exactly this — so a rename mid-descent created the directory in the
moved-away tree while the live path stayed absent, and it returned normally. And
the all-operand `os.path.join` classification added in v3.8.46 was wired into the
ASSIGNMENT path only, so an inline `open(os.path.join("/tmp", ROOT, ...))` still
passed.

### Origins do not have to say ROOT

`open("docs/relative.txt", "w")`, `Path.cwd() / "docs" / x`, and
`Path(__file__).resolve().parent.parent / "docs" / x` are the checkout as plainly
as `ROOT` is — and the last is how half these scripts spell their own root.
Treating only the blessed symbol as governed was the same "list of the forms I
thought of" that `os.path.join` exposed one round earlier. Widening it surfaced
four more real sites, including `substrate_upgrade._exec_module_from_source`,
which **compiles and executes** the bytes it reads.

The first cut of that widening was far too broad: it counted any bare relative
string literal as a path, which made `raw.replace("Z", "+00:00")` a governed
write — 32 false positives, which is a gate nobody keeps switched on. A literal
counts as a path only where the call is unambiguously file I/O; `Path` methods
share names with `str` methods, and that ambiguity is not resolvable without
types.

### Scanning the audit channel without punishing the auditor

`AGENT_BUS.md` is read by agents and was outside the harness scan. Adding it
verbatim **blocked immediately** — on the round-30 finding that reported the gap,
because that finding quotes the attack phrase it tested. A gate that fails the
build when an auditor accurately quotes the string they used is worse than the
hole it closes.

So the bus is scanned, with inline-code spans treated as evidence rather than
instruction **on that surface only**. An unquoted injection line on the bus still
blocks; the carve-out does not extend to `AGENTS.md` or any other governed
surface, and a test pins all three behaviours.

### Two in-release BLOCKs, both in the round's own new work

- **The evidence carve-out was per-FILE where it should have been
  per-PATTERN-CLASS.** Blanking inline-code spans on the bus ran once, before
  all three pattern classes matched, so it exempted quoted credentials and a
  quoted pipe-to-shell command as well as the injection phrase it was written
  for.
  The justification — an auditor quoting the string they tested — applies to the
  injection class alone. A narrow exception implemented one level too coarse is
  a general bypass, and it was a bypass on the surface that had just been added
  to the scan.
- **Loop-target binding classified only the first element.** `for p in [td,
  ROOT / "x"]` bound the target FIXTURE for the whole body — and a
  fixture-classified write is not even reported as unresolved, so a governed
  write inside that loop produced neither a finding nor an unresolved line. The
  multi-operand fix in the same release already knew the answer: classify every
  element and let governed dominate.

The wrong-root invariant test also caught the fix for `check_exfil_guard`
passing a conditional `_r` instead of the function's own `root`. That test exists
because four wrong-root regressions escaped in v3.8.43, and it did its job on the
first run.

**Carry-forward rule, part 13 — when a fix generalises, check every sibling of
the thing you fixed.** Import bindings, assignment bindings and class-body
bindings are one problem; reads, writes, appends and mkdirs are one problem;
assignment operands and inline operands are one problem. Fixing the reported
member and stopping is how a root cause survives as three separate findings in
the next round.

**Carry-forward rule, part 14 — a control that punishes accurate reporting will
be removed.** When a gate covers the channel people use to report on the gate,
it needs an explicit, narrow, tested distinction between describing an attack and
performing one — or the gate loses to the reporting, and usually silently.

## Round 11 — v3.8.49: the gate prescribed a remedy it had never implemented

Not an audit round. This one surfaced by being HIT, which is why it is worth
recording: v3.8.48's HISTORY entry named a pre-rebase SHA that never landed, and
`check-history-sha` went red on the release commit.

The trigger was mundane — generate the entry, then amend the commit, and the
recorded SHA dies. The defect underneath was not. `docs/HISTORY.md` is
append-only by hard rule, so the only permitted remedy for a wrong SHA is a
further entry, and the gate printed exactly that: *"Fix by appending a
'Correction' entry that names the right SHA."* It then ignored the entry. The
marker was counted and `continue`d past with no pairing to what it corrected, so
following the printed instruction changed nothing. The entry could not be edited
and the correction did not clear it: **the branch was red by every route the
tooling allowed.**

Two things are worth keeping from how this was found and fixed.

First, the report was blocked by the thing it reported. The URGENT bus post
about the red gate was staged by `agentsync` and then REFUSED by the pre-commit
hook — because `check-history-sha` was red in that same tree. Part 14 predicted
a gate that punishes accurate reporting; this is that shape again, one release
later, from a different gate. It cost nothing only because the other agent fixed
the branch independently first.

Second, the sweep found the class was already half-solved. `AGENT_BUS.md` has the
identical shape — append-only record, gate over it, additive-only remedy — and
v3.8.48 had just given it exactly this hatch (legacy line-and-content-hash
evidence pairs). `docs/REJECTED.md` is append-only but has no content gate, so it
cannot deadlock. `check_doc_drift`'s advice was tested empirically by following
it, and it works. So the class has two members, one of which was fixed by someone
else a release earlier without either of us noticing they were the same problem.

The fix pairs `Correction-of-<sha>` with the entry it supersedes, and is
deliberately narrow so the hatch cannot become a silencer: it clears only the
unresolvable-SHA finding, never the future-dated one; a correction naming a SHA
no entry references is itself drift; and a correction naming a SHA that RESOLVES
is itself drift. The gate had NO regression coverage before this round, which is
most of why the advice went eight releases without anyone discovering it was a
no-op. Six tests now exist, and each was verified to fail for its own reason by
disabling the pairing and each guard in turn — which caught two of them
originally passing on the future-dated heuristic rather than on the guard under
test.

**Carry-forward rule, part 15 — a control that names a remedy must implement
it.** Printed remediation advice is part of the control's contract, not a comment.
If a gate tells the operator what to do, a test must follow that exact
instruction and assert the finding clears; otherwise the advice is decoration and
the first person to trust it is stuck. Three of the last five rounds were this
shape: v3.8.45's gate shipped to consumers as an inert file, v3.8.46's guard ran
after the mutation it was meant to prevent, and this one prescribed a no-op.

**Carry-forward rule, part 16 — the escape hatch for an append-only record is
part of the gate's design, not an afterthought.** Any validator over a record
that cannot be edited needs an additive remedy the validator honours, plus
fail-closed guards so the remedy cannot retire a live finding. Ask it when the
gate is written: *what does someone do when this fires and the evidence is
immutable?* If the answer is "edit the record", the gate is unshippable.

## Round 12 — v3.8.50 (round-32): the hatch I built retired live findings

One finding, and I asked for it: the v3.8.49 release note told the auditor to
attack the correction hatch specifically and to try retiring a live finding with
it. That is exactly what came back, in one round.

The v3.8.49 pre-pass collected `Correction-of-<sha>` markers into a map keyed by
SHA **alone**, with no binding to entry order. Two ways to abuse it, both
reproduced in disposable repos before I accepted the finding:

1. Write `Correction-of-badc0de` FIRST and a `badc0de` entry after it. The
   correction pre-forgives a bad SHA that had not been recorded yet.
2. Write `badc0de`, then its correction, then `badc0de` AGAIN. The second entry
   reuses the first one's retirement.

Both returned `rc=0` on v3.8.49. HISTORY is append-only and chronological, so a
correction can only speak to what is already above it; superseding is now bound
to entry order, and a correction that names no EARLIER entry is itself drift.

The part worth keeping is whose mistake this is and what shape it has.
**v3.8.47's headline fix was that bindings must resolve in DOCUMENT order rather
than traversal order** — an identity-keyed lookup built without the ordering that
gives the identity meaning. Two releases later I introduced a new
identity-keyed lookup with no ordering at all, in a mechanism written to fix a
different defect. Part 12 said a fixed bug class is not a fixed habit; this is
the same author repeating the same class inside three releases, in code written
while thinking about that class.

There is a narrower lesson too. An escape hatch is a privilege, and a privilege
needs a scope in every dimension the record has. I scoped the hatch by WHICH
finding it clears (unresolvable only, never future-dated) and by WHETHER the
target is real (must exist, must not resolve), and I simply did not ask the third
question — WHEN it applies. Two of three dimensions is how a narrow exception
becomes a general one.

**Carry-forward rule, part 17 — scope an exception in every dimension of the
record it acts on.** For an ordered, append-only log the dimensions are at least
*which finding*, *which target*, and *which position*. Enumerate them explicitly
when the exception is written; an unscoped dimension is not a smaller hole than a
missing check, it is the same hole.

## Round 13 — v3.8.51: the self-audit, and the trust anchor that failed open

Not an audit round from the other agent. The first full self-audit of `main`
after the merge — seven read-only auditors plus the deterministic gates — returned
zero BLOCKs. The finding that mattered was not in any of their reports. It was
hit.

During the audit the workspace was replaced under me: shallow re-clone, venv
gone, and `.substrate/memory/` swapped for an Aug-27 snapshot. The 113-event
tamper-evident chain vanished; a 2-event chain from a different state took its
place; **`memory verify` reported "chain OK."** It was not lying — the chain it
had was internally valid. It could not tell *intact* from *replaced wholesale*,
and `memory_log.py`'s own docstring said that was exactly what `anchor` /
`verify --anchor` existed for. Then `release_gate.sh:44`:

```sh
if [ "$SUBSTRATE_PROFILE" = "strict" ] && [ -n "$(git notes --ref=substrate-memory list)" ]; then
    verify --anchor
else
    verify
fi
```

No ritual had ever written a note. So even in strict, the *absence* of the trust
anchor silently downgraded to the unanchored check. `INTENT.md` forbids this in
so many words: *absence and unreadability are different states with different
verdicts.* Pre-existing, not from the merge; on `main`; guarding objectives #1
and #3 at once.

Why the hedge existed is the part worth keeping. `verify --anchor` required the
chain head to **equal** the anchored hash, so one legitimate append after
anchoring read as "history was rewritten", and it consulted only HEAD's own note,
so the anchor vanished at the very next commit. Under those semantics requiring
the anchor would have failed every run — so the gate was written to require it
only when it happened to be satisfiable. The eval corpus then **pinned the false
positive**: `memory_anchor_mismatch_detected` asserted that growth past the
anchor must be detected as tampering. A malicious task encoding the defect as the
expected behaviour, and a doctor row (`substrate_doctor.py:344`) restating the
same equality rule as a second definition of "anchor valid".

The fix is membership, not equality: `verify --anchor` finds the nearest
annotated ancestor of HEAD and requires that hash to be a member of the already
link-verified chain. Growth passes; replacement and truncation past the anchor
fail; no anchor anywhere in the ancestry fails closed with the remedy named. The
release gate requires it unconditionally in strict and *writes* one in every
profile once it has passed. The doctor delegates to the same verifier. The eval
was re-targeted at the real threat with a benign twin for growth. What no unkeyed
hash chain can detect — a rewrite of the suffix after the anchor point — is now
stated as the limit rather than implied away.

Three siblings landed in the same unit, all the same class:

- `check_history_sha` in a **shallow clone** reported every pre-boundary SHA as
  unresolvable and printed the append-a-Correction remedy. Followed, that
  corrupts HISTORY permanently — in every full clone those corrections name
  *resolving* SHAs, which v3.8.50's own guard rightly treats as drift on a file
  that cannot be edited back. GitHub Actions checks out `depth: 1` by default;
  this kit's CI escaped only via `fetch-depth: 0`, and the workaround had been
  written into a knowledge note instead of into the gate. It now refuses to
  judge what it cannot see.
- `manage.sh check` on a fresh clone auto-created its own venv, passed the
  validator chain, then failed fourteen pre-commit hooks with the one real cause
  buried per hook. One honest line before any gate runs.
- The `_doc_common` safety primitives had two "same algorithm" mirrors in
  fallback paths — `memory_log._safe_read_text`, `session_handoff._safe_atomic_write`
  — still opening the parent by multi-component path, the exact window v3.8.44
  closed, with no post-op liveness check. Two fixes behind, in dead code
  (`_doc_common` is never stripped) that would have silently reintroduced a
  closed class the day it ran. They are fail-closed stubs now, and a discovery
  test asserts every such fallback is stub-shaped — the v3.8.48 inventory
  lock-down, applied to the primitives that actually gate writes.

**Carry-forward rule, part 18 — when a control has to be hedged to stay
satisfiable, the semantics are wrong, not the hedge.** A gate that reads "require
X only if X happens to exist" is a confession that requiring X would fail
constantly. Do not ship the hedge; fix what makes X unsatisfiable. And when an
eval asserts the hedge's behaviour as correct, the corpus has become a record of
the defect, and passing it proves nothing.

## Round 14 — v3.8.52 (round-34): the guard one command from being undone

v3.8.51 fixed a trust anchor that failed open. Round 34 found the fix was one
command deep. Both findings reproduced before acceptance.

**P1.** A git note lives in the same writable repo as the log it vouches for.
So: anchor, replace `events.jsonl` with a different valid chain, re-run the
*shipped* `anchor` command — and `verify --anchor` goes green over the
replacement. Detection worked; it just could be erased by the same process that
tripped it. My own v3.8.51 docs said the real mitigation was pushing the note to
a protected remote, so I *knew* a local note was weaker — but the code had no
guard and the output printed the same confident "anchor verified" either way.
That is the recurring shape one level up: not a control that lies about what it
does, but a control whose **documented** limit was never **implemented**.

Closed in two layers. Advancing the anchor is now MONOTONIC: if a previous
anchor exists, its hash must still be in the chain, which growth satisfies and
replace-then-re-anchor does not. A genuine reset uses `--force`, which appends
an `anchor-forced` event naming the abandoned hash — the escape hatch writes the
discontinuity into the record rather than removing it, and repeated laundering
accumulates evidence instead of erasing it. Then `verify --anchor` stopped
conflating tiers: `verified against origin`, `ANCHOR CONFLICT` when the local
note disagrees with the remote (this is the layer that defeats a forced local
rewrite outright), `LOCAL-ONLY` when an origin exists but does not carry it, and
strict fails closed on an unpublished anchor.

The judgment worth recording is what I did *not* do: make an unpublished anchor a
failure everywhere. `INTENT.md` promises the base tier is offline-complete, so in
a repo with no remote a local anchor is the strongest one obtainable and reporting
it as deficient would be a false positive of exactly the kind that gets gates
switched off — the same mistake as telling a strict-LOCAL repo it is broken for
lacking a GitHub-only CODEOWNERS. Two existing tests asserting `pass` for that
case were right, and they caught the overreach.

**P2 was my error, not the code's.** v3.8.51's handoff told the operator to push
`refs/notes/substrate-memory` "from a machine without the egress policy." Git does
not transport `refs/notes/*` on a normal push, clone, or fetch: a fresh clone gets
zero notes and the command fails with `src refspec ... does not match any`. I
wrote an instruction that cannot be executed anywhere except the clone that was
blocked from executing it. The producer now publishes the note itself, and when
refused prints the payload plus the `git notes add -f -m` command that recreates
it anywhere — the payload travels in text where the ref does not.

**Carry-forward rule, part 19 — a documented limit is not an implemented one.**
Writing "the real guarantee needs X" in a docstring while shipping the version
without X leaves a control that reads as authoritative and behaves as advisory.
Either implement the bound, or make the output say plainly which one the caller
actually has. This gate now prints a different sentence per tier for exactly that
reason.

**Carry-forward rule, part 20 — a handoff step must be executable by whoever
receives it.** Before delegating a manual action, check that the receiving side
has what the action needs. A ref, a file, a credential, or a piece of state that
never reaches them makes the instruction impossible, and an impossible instruction
in a security remedy is worse than no instruction: it reads as covered.

## Round 15 — v3.8.53 (round-35): the trust layer read what the attacker writes

v3.8.52 closed the laundering path from round 34 by adding remote confirmation,
monotonic anchoring, and a recorded forced-break event. Round 35 found all three
were wrong, in the same way, and every one of them was mine, shipped in that
release. All three reproduced here before acceptance.

1. **The remote confirmation read a local ref.** `_remote_anchor` ignored the
   fetch's return code and then read `refs/notes/origin-substrate-memory` — a
   *local* ref any writer can create. One `git notes --ref=origin-substrate-memory
   add` turned a correctly-failing strict check (rc 1) into `anchor verified
   against origin` (rc 0), against an origin publishing no note at all.
2. **The git calls ran under ambient env.** `GIT_DIR` pointed at a fake repo
   carrying a matching note and no origin turned a genuine `ANCHOR CONFLICT` into
   a clean `LOCAL (no remote)` pass. `_clean_env()` had existed since v3.8.10 for
   precisely this, and five other call sites in the same module used it. I added
   new git calls to that module and did not follow its own convention.
3. **The evidence was optional.** `--force` appended its `anchor-forced` event
   without checking the result, then rewrote the note regardless. With the lock a
   FIFO, the event was never written, the note moved anyway, and verification went
   green — the recorded discontinuity was the entire justification for permitting
   the override.

One sentence covers all three: **I built a trust layer out of inputs the adversary
can write.** A local tracking ref is not the remote. An ambient environment
variable is not the repository. An unchecked append is not a record. Each is the
same unasked question in a different dimension, and the release that shipped them
was the one where I had just congratulated myself for closing round 34.

Fixes: confirmation now comes only from the remote *in this process* (an existence
check against origin, then a forced fetch whose rc is checked, so a failed or
absent fetch can never leave a planted ref readable); every git call in the anchor
path runs under `_clean_env()` with `cwd=ROOT`; and `--force` aborts with the note
untouched if its evidence append fails.

A methodological note worth more than the fixes. My first discriminating check
reverted the fetch-rc guard alone and **no test failed** — I nearly recorded that
as "verified discriminating". The two P1a guards are redundant for this attack:
either alone blocks it, so only reverting *both* fails the test. Redundancy is
good defence and bad evidence, and a single-line revert that proves nothing looks
exactly like one that proves something.

**Carry-forward rule, part 21 — ask what writes each input a control trusts.**
For every value a security check reads, name the parties who can write it. If the
adversary is among them, it is not evidence, however authoritative its name
sounds: `origin-*` refs, environment variables, and return values you discard all
read as trustworthy and are not.

**Carry-forward rule, part 22 — a redundant guard cannot be pinned by a
single-line revert.** When two checks independently block the same attack,
reverting either alone leaves the test green, which reads identically to a test
that never discriminated. Revert the whole mechanism to prove the test catches the
regression, and say which specific line each remaining test actually pins.

## Round 16 — v3.8.54 (round-36): the check and the thing it authorized were not the same

Three findings, all in the layer v3.8.53 had just hardened, and all three the
same shape: **the thing that was checked and the thing that was used were not
the same object.** Different environment input, different moment, different read
of the same file.

**P1a — a config file outside the repo chose which server answered.** `_clean_env`
strips the variables that redirect which *repository* git reads. It was written
in v3.8.10, when every git call in the module was local. v3.8.52 added calls
whose verdict comes from a *server*, and the denylist was never re-derived for
them: `XDG_CONFIG_HOME` still selected the user config file, so a
`url.<attacker>.insteadOf` entry rewrote the origin URL and a genuine
`ANCHOR CONFLICT` printed as `anchor verified against origin`. I reproduced the
reported vector and then the one that was not reported — the same config as
`~/.gitconfig`, reached through `HOME` — because fixing only the named variable
would have left the attack one variable away. Config files are now taken out of
the loop for the evidence calls (`GIT_CONFIG_GLOBAL`/`SYSTEM` at `/dev/null`,
system config refused, `XDG_CONFIG_HOME` dropped, no credential prompt), and
where that is impossible — git older than 2.32 — the anchor is reported
unconfirmed rather than confirmed on weaker evidence.

Isolation has a real cost: a globally configured credential helper, proxy, or
`safe.directory` goes with it. The trade is right — a remote reachable only
through a file outside the repository is not evidence about that repository —
but a cost that presents as an unexplained "local-only" is a gate people switch
off, so the fetch is retried once, purely to classify the failure, and the
message says user config is why. That retry never contributes to a verdict.

**P1b — the gate certified the state it started in.** The memory check runs
before the block that writes and pushes the fresh note, and `release-gate:
passed` printed before that block too. So an origin refusing `refs/notes/*` left
a strict release green over a repo whose very next `verify --anchor` failed.
Reproduced by executing the real gate tail verbatim against an origin with a
rejecting `pre-receive` — and the end state was worse than the report said: not
merely unpublished but `ANCHOR CONFLICT`, the tier that accuses the operator of
rewriting the note. **This one had already happened to me.** The v3.8.53 release
printed "passed" with its own note push refused, and I reported it as green.
The anchor is now written, published, and re-verified with the profile's own
check before the success line prints.

**P2 — the precondition held; what it authorized was bound to a different read.**
v3.8.53 made `--force` require its `anchor-forced` evidence append to succeed.
It then re-read `events.jsonl` to choose the note payload. `append` releases its
lock when it returns, so a writer in that gap produced rc 0, a note over a chain
containing no `anchor-forced` event, and `verify --anchor` green. `anchor` now
reads the chain once and certifies the hash the successful append returned.

**A fourth item, mine, found by my own P1b repro rather than reported.**
`ANCHOR CONFLICT` fired whenever the local note differed from the published one
— including when the local note is a legitimate *advance* whose push was
refused, with the published hash still in the chain. That called a failure the
tooling had just reported "the local note was rewritten". CONFLICT now means the
published hash is **not** in the chain; the benign case is reported as
not-yet-published, which still fails strict.

### The reverts that proved nothing, again

Seven revert cases, one per guard. Two came back green — reverting the
`ls-remote` call alone (the fetch that follows still reached the real remote)
and removing the anchor post-condition alone (the head binding already blocked
it). Both were fixed rather than recorded: an AST test now pins the env of every
evidence call site by shape, and the race regression asserts the note is
*untouched* and the return code is 1, which the binding alone does not produce.
After that, all seven reverts fail a test.

**Carry-forward rule, part 23 — a control's coverage must be re-derived when the
surface it protects changes.** `_clean_env` was correct for the calls that
existed when it was written. Adding calls of a different KIND — local reads
became remote evidence — silently changed what "sanitized" had to mean, and
nothing re-asked the question. When a helper's callers gain a new capability,
re-derive the helper's set from scratch rather than assuming the old list still
spans it.

**Carry-forward rule, part 24 — a skipped eval has left the denominator.**
Narrowing the conflict semantics turned one existing task's setup into a
non-conflict, and it reported `skipped` — indistinguishable from an absent
sandbox backend, excluded from the rate, and measuring nothing. A task that can
no longer build its own baseline must fail, not skip; failing that, read the
skip lines on any release that changes a semantic the corpus depends on.

## (Optional) Reproduction

In a disposable repo: `ln victim.txt AGENT_BUS.md` then
`AGENT_NAME=x ./agentsync.sh msg "…"` — pre-fix, the line lands in `victim.txt`.
For capture: `ln -s /outside docs/CURRENT_SESSION.md` then
`session_handoff.py capture` — pre-fix, `/outside` is overwritten.
Ancestor (v3.8.39): `ln -s /outside .substrate` then read a `required_*` lock —
pre-fix, the outside lock lowers the containment floor.
