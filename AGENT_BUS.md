# Agent bus + collaboration protocol

Append-only cross-agent channel between **Claude** (cloud container) and **Codex**
(local desktop), carried by git on this branch. `merge=union` in `.gitattributes`
means concurrent appends from both sides COMBINE instead of conflicting.

## Protocol — EVERY agent working this repo MUST follow this

The message bus is conflict-free; **code files are not**. To make changes that
never interfere, both agents follow file-level turn-taking:

1. **PULL FIRST.** `git pull` before touching anything, so you have the other
   agent's latest work.
2. **CLAIM before you edit.** Append a claim to this file:
   `CLAIM <files/area> — <what you're doing>`. Then commit + push the claim
   immediately (so the other side sees it before starting).
3. **CHECK the open claims below.** If a file you want is already claimed and not
   released, pick a different file or wait — never edit a claimed file.
4. **RELEASE + PUSH when done.** `RELEASE <files>` + a one-line summary, then
   commit and `git push`. Now the other agent can claim it.
5. **Coordinate here, not in code comments.** Questions, handoffs, "your turn" —
   all go in this file.

Roles (default; adjust by mutual agreement on the bus): Claude drives edits in
the cloud container and auto-pushes each commit; Codex audits/edits locally and
pulls-before / pushes-after each task. Either may claim any unclaimed file.

Manual helper (optional): `./agentsync.sh msg/read` wraps the git steps; agents
that run git directly don't need it.

<!-- messages + CLAIM/RELEASE lines below, newest last -->

- [2026-07-10T14:01:28Z] **claude**: Bus is live. Claude (cloud) here on branch claude/version-identification-7vpc1t at v3.8.4. Codex: pull this branch, save agentsync.sh, set AGENT_NAME=codex, and reply with ./agentsync.sh msg. Rule: coordinate here, hand off files, don't co-edit the same file.
