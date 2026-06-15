---
name: doc-drift-audit
description: Resolve docs/code drift when the drift gate fires or when auditing whether knowledge docs, ADRs, and code still agree. Use when check_doc_drift blocks a commit or before a release.
---

# doc-drift-audit

`scripts/check_doc_drift.py` fires when a file covered by a knowledge
doc (`covers:` frontmatter) changed after the doc's
`last_human_reviewed` date, or when coverage gaps/phantom refs exist.

## Resolution decision tree

1. **Doc still describes reality** → read the actual diff (mandatory
   — never bump blind), then bump `last_human_reviewed: <today>`.
2. **Doc no longer matches** → update the doc body, then bump.
3. **File belongs to a different subsystem** → move it to the right
   doc's `covers:` list, bump that doc.
4. **New file, no doc covers it** → add to an existing doc's
   `covers:` or create a new doc from `docs/knowledge/_template.md`.

Then: `./manage.sh manifest` to regenerate `docs/manifest.json`
(never hand-edit it).

## Hard rule

NEVER bump a date without reading the diff. Blind bumps turn the
drift signal into noise — the one failure mode this system cannot
defend against mechanically.

## Batch pattern

Editing fast across a covered area? Batch the bumps: one
doc-maintenance commit at the end of feature work covering all
touched docs, instead of fighting the gate per-commit.

## Full audit

```bash
python scripts/check_doc_drift.py --strict   # all categories
```

Categories reported: stale_doc, pending_stale_doc, coverage_gap,
phantom_doc, orphan_doc, missing_manifest.
