---
name: self-audit
description: Run the project self-audit loop before declaring substantial work complete. Use when finishing a feature, closing a multi-file change, or before claiming "done". Checks deterministic gates, docs/code drift, and auditor findings.
---

# self-audit

Three layers. Each catches a different bug class; skip none for
substantial work.

## Layer 1 — Deterministic gates (~2 min)

```bash
./manage.sh check
```

Must pass before any completion claim. A red gate means the work is
not done, regardless of how correct it feels.

## Layer 2 — Steelman review (~5 min, in your own context)

Write down: "An external reviewer sees this diff. What three
objections do they raise?" For each: real objection → fix it;
non-issue → note why. Do this BEFORE composing the commit message.

## Layer 3 — Auditor subagents (substantial changes only)

Spawn read-only auditors in parallel — do not inline their work into
the main context:

- security-auditor — always for auth/secrets/data-access changes
- checklist-auditor — pass the domain(s) the diff touches
  (regex, yaml-parsing, ast-parsing, commit-msg-hooks)
- test-auditor / architecture-auditor / documentation-auditor — as
  relevant

Each returns PASS / WARN / BLOCK in ≤500 tokens. Treat any BLOCK as
not-complete. For commit clusters that warrant a full multi-lens
review, use the `ultrareview` skill instead.

## Completion contract

- Deterministic checks green.
- No unresolved BLOCK findings.
- Docs updated or explicitly not needed (doc-drift gate enforces).
- HISTORY entry appended for meaningful changes (see workflows.md).
- Record the audit in the tamper-evident memory log (final step —
  the logger captures the audited HEAD itself; the opt-in Stop-hook
  completion gate looks for this event):

```bash
./manage.sh memory skill-run self-audit --result pass   # or issues-found
```
