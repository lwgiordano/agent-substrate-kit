---
date: 2026-11-02
severity: medium
caught_by: operator
related_commits:
  - 229fa63 (v3.10.8, anchored in a cloud container that was later reclaimed)
  - WORKING (receipts, ANCHOR UNVERIFIABLE HERE, ephemeral clones do not publish)
gates_added:
  - tests/test_hook_scripts.py::test_memory_anchor_from_another_clone_is_unverifiable_not_tampering
  - tests/test_hook_scripts.py::test_memory_anchor_rewrite_in_the_producing_clone_is_still_a_mismatch
  - tests/test_hook_scripts.py::test_memory_anchor_receipt_changes_the_message_never_the_verdict
  - tests/test_hook_scripts.py::test_release_gate_does_not_publish_an_anchor_from_an_ephemeral_clone
  - tests/guards.json
---

# 2026-11-02: anchor from another clone read as tampering

## What happened

The v3.10.8 release ran in a Claude Code cloud container. `release_gate.sh`
anchored that container's memory chain at commit `229fa639e386` (head
`3e271036bc05`), the session proxy refused the note push with a 403, and the
gate printed the payload with the instruction to recreate the note on any
clone. The operator did, on their own machine, and pushed it. The container was
then reclaimed, and the chain it anchored with it. Every clone that later
fetched `refs/notes/substrate-memory` got `ANCHOR MISMATCH ... history was
replaced or truncated past the anchor` from `memory_log.py verify --anchor`,
`anchor` refused with "the shape of a replaced or truncated log", and go-live
reported the row as a mismatch. A strict repo would have failed its gates on a
tamper alarm about a chain the clone had never held.

## Why it happened

The note travels and the chain does not: `events.jsonl` is Git-ignored, so a
note names a chain that exists only in the clone that wrote it. The anchor
design assumed that clone persists, so "the anchored head is not in this chain"
could only mean the chain had changed. Evidence that is unavailable here was
read as evidence that is invalid.

That is the same conflation the 2026-10-02 HISTORY evidence postmortem fixed
for release-pass proof in a receiving clone. Its carry-forward rule ("test
evidence readers against absent, unrelated valid, matching valid, and invalid
evidence") was applied to the HISTORY reader it came from and not to the other
reader of travelling-versus-local state, the anchor verifier. The gate's
"recreate it anywhere" payload then turned a refused push into a published
anchor for a chain about to be deleted.

## Why our tooling didn't catch it

Every anchor test built a single clone. None cloned the producer, fetched the
note, and ran the verifier where the producer's local files did not exist, so
the receiving-clone state was never exercised. The earlier carry-forward rule
was prose with no inventory of which readers it applied to.

## Preventative gate added

`anchor` writes a local-only receipt (`refs/notes/substrate-memory-held`)
before the note, and the receipt chooses between `ANCHOR MISMATCH` (this clone
wrote the anchor; its chain lost history) and `ANCHOR UNVERIFIABLE HERE` (no
receipt). Both exit 1, so no verdict moved. The release gate does not publish
from an ephemeral clone (`memory_log.py ephemeral`). ADR 0004 records the
alternatives and why a timestamp or chain-identity signal would have downgraded
a wholesale replacement.

Tests in `tests/test_hook_scripts.py` clone the producer, fetch its note, and
assert the receiving clone reports UNVERIFIABLE (with and without a chain of
its own), that the producing clone still reports MISMATCH for a truncation and a
wholesale replacement, that deleting a receipt never turns a failure into a
pass, and that the gate publishes from a persistent clone but not an ephemeral
one. Eighteen guards in `tests/guards.json` are proven by `./manage.sh prove`.

The in-change test audit found that 22 anchor tests skipped whenever `anchor`
returned nonzero, so a receipt that could never be written would have shown up
as nine quiet skips. They now go through `_anchor_or_skip`, which skips only
when a direct `git notes` write also fails. The evals' fixture environment drops
the host's ephemeral signals for the same reason: on a cloud host the gate would
skip the refused push those tasks exist to exercise.

No generic gate covers the class, because which state travels between clones is
a semantic fact, not a pattern in the code. The readers that compare travelling
state with clone-local state are few (HISTORY SHAs against git objects in a
shallow clone, HISTORY success labels against release-pass events, the anchor
note against the chain), and each now has a receiving-clone test.

## Carry-forward rule

Before a reader compares state another clone can hand over (`refs/notes/*`,
HISTORY, a release artifact) with Git-ignored local state, add a test that
clones the producer, fetches that state, holds none of the producer's local
files, and asserts the reader reports the evidence as unavailable, not
tampered; `grep -rn "git notes\|refs/notes\|verified_release_passes" scripts/`
lists the readers to check.

## Reproduction

```bash
git clone <repo> fresh && cd fresh
git fetch origin refs/notes/substrate-memory:refs/notes/substrate-memory
python3 scripts/memory_log.py verify --anchor   # before: ANCHOR MISMATCH
```
