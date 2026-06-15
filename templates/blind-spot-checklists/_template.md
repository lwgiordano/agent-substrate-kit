# Blind-spot checklist: <DOMAIN>

<!--
This is the canonical template for authoring a new blind-spot
checklist. Use it when:
  - Your project has a domain with recurring bug classes (regex,
    YAML parsing, commit-msg hooks, AST parsing, codegen, etc.).
  - You want LLM agents and human reviewers to consult a canonical
    list before authoring code in that domain.
  - The four built-in checklists (regex, yaml-parsing,
    commit-msg-hooks, ast-parsing) don't cover the domain.

Filename convention: `docs/blind-spot-checklists/<domain>.md`.

Reference this checklist from:
  - The substrate's three-layer self-audit (Layer 1 = domain
    checklist), invoked via the four-field commit-msg protocol's
    `Cluster searched:` field.
  - Pre-commit hooks that touch this domain (e.g., a new validator
    can name the checklist in its `--help` output).
  - The DIY ultrareview prompts (lens 1 / adversarial-input).

Pattern: 10-15 numbered classes per checklist. Each class has:
  - **Smell**: what to look for in the diff.
  - **Example bug**: a concrete code snippet that has the bug.
  - **Fix**: the canonical correct shape.
  - (Optional) **Counter**: when the fix doesn't apply / has trade-offs.
-->

Read before adding or modifying code that touches `<DOMAIN>`. Each
class is a recurring real-world bug.

## When to consult

- <Trigger 1: e.g., "Adding a `<library>.<call>` invocation">
- <Trigger 2: e.g., "Authoring a validator that reads <DOMAIN> config">
- <Trigger 3: e.g., "Reviewing a PR that touches `*.<ext>`">

---

## 1. <Bug class name>

**Smell**: <what to look for>

**Example bug**:
```<lang>
<concrete buggy code>
```

**Fix**: <canonical correct shape>
```<lang>
<corrected code>
```

---

## 2. <Bug class name>

(repeat the pattern)

---

## How to use this checklist

When you author or modify code in this domain:

1. Read the diff.
2. For each <DOMAIN> change, check the N classes above.
3. Add tests that plant the bug shapes verbatim.
4. Reference this checklist in the commit message's
   `Cluster searched:` field per the substrate's four-field protocol.
