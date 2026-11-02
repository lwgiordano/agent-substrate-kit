# 0004: An anchor bounds only the clone that holds its chain

**Status:** Accepted
**Date:** 2026-11-02
**Deciders:** operator, claude
**Related:** [ADR 0002](0002-anchor-threat-model-boundary.md),
[The memory trust anchor](../knowledge/08_memory_anchor.md)

## Context

The memory chain (`.substrate/memory/events.jsonl`) is Git-ignored local state.
The anchor is a git note (`refs/notes/substrate-memory`) that records the chain
head at a commit, and the note can travel: the release gate pushes it, and when
the push is refused it prints a payload that recreates the note on any clone.
The chain never travels. So a note names a chain that exists in exactly one
clone, the one that wrote it.

That held as long as the producing clone persisted. A Claude Code cloud session
broke it. On 2026-11-02 the v3.10.8 anchor (commit `229fa639e386`, head
`3e271036bc05`) had been written in a cloud container, its push refused by the
session proxy, recreated from the payload on the operator's machine and pushed.
The container was then reclaimed and the chain went with it. Every clone that
fetches `refs/notes/substrate-memory` now gets `ANCHOR MISMATCH ... history was
replaced or truncated past the anchor`: a tamper alarm about a chain that clone
never held. A fresh clone that does not fetch notes gets `NO ANCHOR` instead, so
the same clone reported two different states depending on a fetch.

The check cannot simply stop failing there. "The anchored head is not in this
chain" is also exactly what the primary threat looks like: a chain replaced
wholesale by a different valid one, observed live in the v3.8.50 self-audit.
Any signal that separates the two cases has to survive that replacement.

## Decision

1. **`anchor` leaves a receipt in this clone before it writes the note.** The
   receipt is a second notes ref, `refs/notes/substrate-memory-held`, holding
   `substrate-memory-held:<head>` on the anchored commit. It is appended, so an
   earlier receipt on the same commit survives a second anchor there. Git
   transports neither notes ref on a normal clone, fetch, or push, and the
   release gate pushes only `refs/notes/substrate-memory`, so a receipt stays
   in the clone that wrote it. The receipt is evidence written first, like the
   `anchor-forced` event: if it cannot be written, `anchor` refuses and leaves
   the note untouched.
2. **A receipt changes the diagnosis, never the verdict.** When the anchored
   head is missing from the chain, `verify --anchor` reports `ANCHOR MISMATCH`
   if this clone holds a receipt for that head (its own chain lost history) and
   `ANCHOR UNVERIFIABLE HERE` if it does not (the anchor describes a chain held
   elsewhere, or predates receipts). Both exit 1. `anchor` refuses to advance
   over either, naming the cause, and `--force` stays the one way past, with its
   evidence event. `ANCHOR CONFLICT` keeps its exit code and says which case it
   is. Deleting a receipt can soften a message; it cannot turn a failure into a
   pass. Planting one can only sharpen a message.
3. **An ephemeral clone does not publish.** `memory_log.py ephemeral` reports
   whether this clone will outlive its session: `SUBSTRATE_EPHEMERAL_CLONE=1` or
   `0` is the operator's word and wins; otherwise `CLAUDE_CODE_REMOTE=true` marks
   a Claude Code cloud session. On an ephemeral clone the release gate still
   writes the note locally but neither pushes it nor prints the payload, and
   says why. `verify --anchor` and the go-live row replace their "publish from
   this clone" advice with "do not publish from here". Exit codes do not depend
   on the host, so strict, which requires a published anchor, cannot release
   from an ephemeral clone. It never could: the proxy refused the push.
4. **Anchors bound a persistent clone, and the docs say so.** Only the clone
   that holds the chain can verify its anchor later. The payload fallback is
   kept for persistent clones, with that limit stated next to it.

## Consequences

- **Positive:** a fresh clone, a cloud session, or the operator's machine after
  recreating a note no longer reports tampering for a chain it never held. A
  rewrite in the clone that wrote the anchor is still `ANCHOR MISMATCH`, and no
  exit code changed anywhere. Cloud sessions stop being told to publish anchors
  that nobody can verify.
- **Negative:** a clone with no anchor of its own still fails `verify --anchor`
  until it runs `anchor --force`, which records the jump. That is deliberate: a
  foreign anchor and no anchor are the same state for this chain. Anchors
  written before receipts read as `UNVERIFIABLE HERE` even in the clone that
  wrote them, until its next `anchor`; their verdict is unchanged, but a real
  rewrite of such a chain shows as `warn` on the go-live row instead of `fail`
  in that window, because go-live reads a missing receipt as "no anchor for
  this chain". Its message says a rewrite cannot be ruled out. Linked
  worktrees share `refs/notes/*`, receipts included, so a worktree with its own
  chain still sees another worktree's receipt and reports `MISMATCH`. Anyone
  who pushes and fetches `refs/notes/*` wholesale carries receipts too, with the
  same result. Both fail toward the old, stricter message, never toward a pass.
- **Neutral:** the ephemeral signal is one environment variable. A host the kit
  does not recognise reads as persistent, which costs only the old advice;
  `SUBSTRATE_EPHEMERAL_CLONE=1` covers it.

## Alternatives considered

- **Call the anchor foreign when the chain's first event postdates the anchored
  commit.** Rejected because a wholesale replacement has the same shape: its
  genesis is written after the anchor too. This would have downgraded the
  primary threat to "unverifiable".
- **Record a chain identity (genesis hash or a nonce) in the note.** Rejected
  for the same reason: a replacement chain has a different identity, exactly as
  a foreign one does.
- **Let `UNVERIFIABLE HERE` pass in the base tiers.** Rejected because every
  anchor written before receipts has none, so deleting the chain and starting a
  new one would pass where it fails today; and because `NO ANCHOR` fails, and a
  foreign anchor leaves this chain in the same state.
- **Skip a foreign anchor and judge the nearest older one this clone holds.**
  Rejected for the same pre-receipt anchors: truncating past the newest anchor
  would verify against an older one.
- **Keep receipts in `.substrate/memory/`.** Rejected because the observed
  accident replaced that whole directory, which would take the receipt with the
  chain.
- **Keep receipts in a file in the git directory.** Rejected because a linked
  worktree's git directory sits outside the repository root, where the guarded
  file helpers refuse to write; a notes ref uses git's own ref machinery, like
  the note it qualifies.
- **Recognise more hosts (CI runners, other cloud agents).** Deferred. A CI
  checkout has no chain, since the log is Git-ignored, so the gate writes no
  anchor there. Other hosts can set `SUBSTRATE_EPHEMERAL_CLONE=1` until one is
  observed.
