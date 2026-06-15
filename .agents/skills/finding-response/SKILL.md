---
name: finding-response
description: Respond to a bug or audit finding as a class of bugs, not a one-off symptom. Use whenever fixing any bug regardless of who found it — forces sibling search and a lock-down before the fix lands.
---

# finding-response

The recurring failure this prevents: fixing the symptom the finding
flagged while identical siblings survive elsewhere.

## Protocol

1. **Name the bug CLASS in one line** — not the symptom.
   - "yaml field used without isinstance guard"
   - "validator silent-pass on null input"

2. **Grep the file, then the repo, for siblings.** Record the grep
   command + result count. Every hit is either fixed in this change
   or explicitly dispositioned.

3. **Pick a lock-down** — the mechanism that makes recurrence visible:
   new validator, new test, new checklist entry, or opt-out comment
   with reason. No lock-down → the class returns.

4. **Verify the lock-down catches the VERBATIM original bug shape.**
   Run the test/regex against the actual buggy code, not a
   paraphrased minimal example. Paraphrases pass tests that the real
   shape evades.

5. Significant finding (see `write-postmortem` severity threshold)
   → also write the postmortem.

## Commit message fields

In strict profile, `check_finding_response.py` blocks bug-fix commits
missing these; in standard profile they are discipline, not gate —
include them for any non-trivial fix anyway:

```
Bug class:           <one-line class summary>
Cluster searched:    <grep command + result count>
Lock-down:           <mechanism + path>
Verbatim-shape verified: <yes/no with evidence>
```

Opt-out for genuinely class-less fixes:
`[meta-fix-not-applicable: <reason>]` — reason must be real, not a
placeholder.

Copy-paste template: `docs/templates/finding_response.md`.
