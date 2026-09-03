---
purpose: The memory trust anchor — monotonic advance, remote confirmation, and limits.
last_human_reviewed: 2026-09-03
covers:
  - scripts/memory_log.py
  - scripts/release_gate.sh
---

# The memory trust anchor

[Back to the substrate map](00_substrate.md). The chain this anchors is
described in [memory and sessions](03_memory_sessions.md).

A hash chain proves internal consistency, not that it is the same chain as
yesterday: anyone who can edit an event can recompute every hash after it. The
anchor is what bounds that — the chain head recorded in a git note
(`refs/notes/substrate-memory`) on a commit, checked against the chain later.

## What verification requires

`verify --anchor` finds the nearest annotated ancestor of HEAD and requires that
recorded hash to be a MEMBER of the current, link-verified chain. Growth after
anchoring passes; a chain replaced wholesale by a different valid chain, or
truncated past the anchor, fails; no anchor anywhere in the ancestry fails
closed with the remedy named. (It once demanded EQUALITY, so a single append
read as "rewritten", and the gate hedged around that until absence failed
open — found by being hit; see the postmortem.) Strict requires an anchor
unconditionally, every release writes one, and the first strict release needs a
one-time `./manage.sh memory anchor` as the human-established trust root.
`substrate_doctor` delegates to the same verifier, so "anchor valid" has one
definition.

## Advancing is monotonic

A note is mutable state in the same writable repo as the log, so detection alone
was undoable: replace the chain, re-run `anchor`, green again. Advancing now
requires the previously anchored hash to still be in the chain, which growth
satisfies and replace-then-re-anchor does not. A reset uses `anchor --force`,
which first appends an `anchor-forced` event naming the abandoned hash and
aborts, note untouched, if it cannot: the discontinuity is a precondition, not a
side effect.

`anchor` reads the chain ONCE and anchors the hash that read produced — for
`--force`, the hash returned by the evidence append itself. Deciding from one
read and then re-reading a mutable file to pick the payload let a concurrent
writer swap in a chain the checks never saw. A second read remains, but it can
only REFUSE: if the chain no longer contains the hash about to be certified, the
note is left alone. Check and use must name the same bytes.

## Confirmation comes from the remote, in this process

An existence check on origin, then a fetch whose return code is checked — never
the local `origin-substrate-memory` ref, which any writer can forge. Those calls
run isolated from user and system git CONFIG FILES as well as from the routing
variables: `XDG_CONFIG_HOME` or `HOME` selecting a `url.<attacker>.insteadOf`
entry chose which server answered and turned a real conflict into "verified
against origin". Config files are therefore taken out of the loop rather than
one variable deleted, and on git older than 2.32 — where they cannot be — the
anchor is reported unconfirmed instead of confirmed on weaker evidence. What
survives is the repository's own config, the same trust boundary as the working
tree. The purely local reads and the note write keep the ordinary sanitized env:
user config cannot change which repository they reach, the write needs
`user.email`, and the local note is never treated as authority anyway.

Isolation costs a globally configured credential helper, proxy, or
`safe.directory`. A remote reachable only through a file outside the repository
is not evidence about that repository, so the trade stands — but it is named:
the fetch is retried once, purely to classify the failure, and the message says
that user config is why. That retry never contributes to a verdict.

## The tiers, and why they differ

`verify --anchor` reports which anchor it has, not one line for all:
`verified against origin`; `ANCHOR CONFLICT` (fail) when what origin publishes
is NOT in this chain; `LOCAL AHEAD` when the local note advanced past a
published anchor that IS still in the chain — a refused push, not a rewrite, and
saying otherwise accused operators of tampering for a failure the tooling
reported itself; `LOCAL-ONLY` when an origin exists but publishes nothing; and
`LOCAL (no remote)`, which PASSES because the base tier is offline-complete, so
local is then the strongest anchor obtainable. Strict requires publication and
fails closed on every tier below the first.

## Publishing, and the release gate

Publish FROM THE PRODUCING CLONE. Git does not transport `refs/notes/*` on a
normal push, clone, or fetch, so another clone never receives it and cannot push
it — delegating that step is an impossible instruction. The release gate pushes
the note itself and, when refused, prints the payload plus the `git notes
--ref=substrate-memory add -f -m` command that recreates it anywhere: the
payload travels in text where the ref does not.

The gate certifies the END state. Its memory check runs before the fresh note is
written, so announcing success there described the state the release started in:
a refused push left a strict release green over a repo whose next
`verify --anchor` failed outright. The anchor is written, published, and
re-verified with the profile's own check before the success line prints, and in
strict a failed publication fails the release.

## The limit

A suffix rewrite after the anchor point stays undetectable by any unkeyed chain;
the published anchor is what bounds it. Anchor at every release, and publish.
