---
date: 2026-10-02
severity: medium
caught_by: audit
related_commits:
  - c90863a (implementation baseline)
gates_added:
  - tests/test_task_brief.py
  - tests/guards.json
---

# Task brief report boundaries

## What happened

Independent review of the unshipped task brief found that the reused context
sanitizer preserved terminal controls. A malformed working-tree lesson could
also abort the report even though the brief uses committed lessons. Other
observations could disappear silently: grammar-shaped invalid dates and ranked
matches after the thirtieth. A fresh CLI invocation wrote bytecode caches.

## Why it happened

Helpers were reused by name without proving their full contract at the new
boundary. Context sanitization is not terminal-control filtering; a parser
returning no event is not proof that all input was valid. A fixed retrieval cap
and Python's import cache introduced hidden output omissions and writes.

## Why our tooling didn't catch it

Initial fixtures covered fake credential patterns and oversized bodies, but
not control characters or many small ranked candidates. The malformed-metadata
test combined two invalid fields, so either guard alone could satisfy it.
Consumer CLI parity checked output but not incidental bytecode creation.

## Preventative gate added

Reports compose the existing context and terminal sanitizers. Typed parser
failures become source diagnostics. The brief uses the canonical bus grammar
and date parser to report calendar-invalid claims, and lets the byte budget
govern ranked candidates rather than silently dropping matches beyond thirty.
The entrypoint disables bytecode writes before local imports.

Receipt integration exposed two shared-helper gaps before the brief was
committed: a permission hash collapsed all executable bits, and known-pattern
PEM filtering removed the header while retaining the private body. Owner
execution now drives Git-mode comparison, full permission bits enter the raw
fingerprint, and a recognized private-key header discards the whole display
field before truncation. The first report-boundary repair still lost to earlier
selector clipping: a late header vanished before the brief saw the field.
The canonical context sanitizer now supports whole-field secret suppression
before clipping, used by both selectors and report output after normalization.
Separate regressions and removal proofs cover each.

Tests pin malformed scalar/list triggers, committed-lesson preservation,
terminal controls, invalid dates, complete ranking, bytecode absence, and
independent ID/SHA validation. The smallest Unicode budget retains the full
HEAD and omission footer. Guard-removal probes distinguish terminal filtering,
ID/SHA validation, routing isolation, network refusal, and committed sources.

## Carry-forward rule

For a new read-only report, test terminal control bytes, input shape failures,
output-cap omissions, and before/after filesystem state separately. Mutate
each metadata constraint independently; a combined malformed fixture does not
prove that each guard is necessary.
