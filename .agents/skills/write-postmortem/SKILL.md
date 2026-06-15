---
name: write-postmortem
description: Write a postmortem for a significant bug or audit finding and connect it to a future gate. Use for bugs that shipped, near-misses with real blast radius, or recurring bug classes — not for typos or trivial one-line fixes.
---

# write-postmortem

## Severity threshold (standard profile)

Write a postmortem when ANY of: the bug shipped to a user-facing
surface; it silently corrupted data/state; it is the second instance
of its class; an audit flagged it as systemic. Skip for typos,
renames, and one-line fixes with no class — that is what
`[no-postmortem: <reason>]` is for in strict profile.

## Steps

1. Copy the template:

```bash
cp docs/postmortems/_template.md \
   docs/postmortems/$(date -u +%Y-%m-%d)-<slug>.md
```

2. Fill ALL five sections — a postmortem missing any is not done:
   - What happened
   - Why it happened
   - Why our tooling didn't catch it
   - Preventative gate added
   - Carry-forward rule

3. The Carry-forward rule MUST be specific and mechanically checkable.
   - Bad: "be careful with allowlists"
   - Good: "grep `<pattern>` across the repo before committing"

4. Frontmatter `gates_added:` lists the test/script pinning the
   regression. `check_postmortem_gates_resolved.py` verifies each
   reference resolves to a real file — a renamed test is a stale
   claim and blocks the commit.

5. Commit the postmortem with (or just before) the fix and reference
   it in the commit body: `Postmortem: docs/postmortems/<file>.md`.

## The load-bearing part

The gate, not the prose. A postmortem without a preventative gate
documents the bug; it does not prevent the next instance.
