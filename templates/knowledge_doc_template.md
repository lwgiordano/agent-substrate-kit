---
covers:
  - <relative/path/to/source/file1.py>
  - <relative/path/to/source/file2.py>
  - <relative/path/to/config/file.yaml>
last_human_reviewed: YYYY-MM-DD
purpose: subsystem-<short-slug>
# OPTIONAL (v3.8.29) — claims this doc makes about the code, checked every commit.
# Format: <path>::<substring>. If the substring is gone (renamed/deleted), the
# drift gate fails, so the doc cannot silently lie about a symbol that no longer
# exists. DECLARATIVE ONLY: nothing here is ever executed.
asserts:
  - <relative/path/to/source/file1.py>::<function_or_phrase_the_doc_describes>
---

# <Subsystem name> — <one-line description>

<!--
This is the canonical knowledge-doc template. One doc per coherent
subsystem. Frontmatter:
  covers:              every source/config file the doc describes
  last_human_reviewed: date the human last verified the doc matches code
  purpose:             short-slug used for cross-referencing
  asserts:             OPTIONAL `path::substring` claims, verified every commit
                       (a renamed/deleted symbol fails the gate; never executed)

`scripts/check_doc_drift.py` walks the covered files' git log and fires
if any has been modified after `last_human_reviewed`. Bumping the date
asserts the human re-verified the doc matches code TODAY.

NEVER bump the date without actually reading the diffs.
-->

## What this subsystem guarantees

One paragraph: what the subsystem produces, what invariants it
maintains, what its inputs/outputs are. A reader who skims only this
section should understand the subsystem's contract.

## How it's organized

What lives in which file. If the subsystem has three modules, three
sub-headings. Lead with the load-bearing modules; relegate helpers
to a final "Helpers" section.

## What's in / what's out

Explicit scope. List what this doc DOES cover (the `covers:` files)
and what it intentionally doesn't (e.g., "the cleaning macros are
in transform/macros/ but their YAML config is documented in 02b").

This avoids the situation where a future session reads this doc
and assumes it's exhaustive when it's narrowly scoped.

## Operator-facing rules

If there are runbook-level rules ("always run X before Y"), put
them here in a numbered list. Cross-link to RUNBOOK.md if there's
a more detailed runbook.

## Pointers to related docs

- ADRs: docs/decisions/NNNN-<slug>.md
- Postmortems: docs/postmortems/YYYY-MM-DD-<slug>.md
- Sibling knowledge docs: docs/knowledge/<NN>_<other-topic>.md
