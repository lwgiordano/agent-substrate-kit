---
name: blind-spot-check
description: Walk a domain-specific bug-class checklist before committing changes that touch regex, YAML parsing, AST parsing, or commit-msg hooks. Use when a diff touches one of those domains and you want the canonical bug classes checked against it.
---

# blind-spot-check

Per-domain catalogs of canonical bug classes (12–15 each) live in
`docs/blind-spot-checklists/`:

- `regex.md` — anchoring, multiline, greediness, escaping classes
- `yaml-parsing.md` — type confusion, missing-key, isinstance guards
- `ast-parsing.md` — node-type coverage, version drift
- `commit-msg-hooks.md` — subject/body parsing, encoding, bypass paths
- `_template.md` — for adding new domains

## How to run it (token rule: spawn, don't read)

Do NOT read the checklist files into the main context. Spawn the
`checklist-auditor` subagent per domain the diff touches:

```
Prompt: "Domain: <domain>. Diff: <range or files>. Walk every bug
class in docs/blind-spot-checklists/<domain>.md against this diff.
Return PASS/WARN/BLOCK, ≤500 tokens, file:line per finding."
```

Multiple domains → multiple auditors in one parallel batch.

## When the diff has a checklist hit

Treat it as a finding: fix it, then apply the `finding-response`
skill (class-of-bug thinking, sibling grep, lock-down).

## Adding a domain

Copy `_template.md`, fill 12–15 bug classes with concrete grep
patterns, keep each class one paragraph. A checklist nobody can walk
in 3 minutes is too long.
