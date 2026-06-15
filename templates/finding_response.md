# Audit-finding response — commit-message template

Copy the structure below into your commit message when responding to
an audit finding (external review, /ultrareview, DIY ultrareview, or
operator-driven review). The four required fields are enforced by
`scripts/check_finding_response.py` (commit-msg hook).

This template is the operationalization of the meta-pattern fix —
the forcing function paired with the discipline. The recurring shape
the hook defends against: a fix scopes to the symptom that was
flagged, not to the CLASS of bugs the symptom is part of. Rules
describe the discipline; this template + the hook is the structural
enforcement at commit time.

---

## Template

```
fix(<area>): <one-line summary of the fix>

<2-4 paragraph fix narrative — what was wrong, what changed, why.>

Bug class:           <single-line summary of the BUG CLASS — not the symptom>
Cluster searched:    <grep command + result count>
Lock-down:           <mechanism + path that prevents recurrence>
Verbatim-shape verified: <yes — confirmed via X / no — opt-out reason>

Postmortem: docs/postmortems/YYYY-MM-DD-<slug>.md

Co-Authored-By: <as appropriate>
```

The subject form can be conventional-commit (`fix:`, `bug:`,
`bugfix:`) or your project's phase-fix shape (e.g., `P3c2-fix:`). If
your team uses a fixed agent-name prefix for external audit-pass
commits (e.g., `Codex YYYY-MM-DD pass-N`, `Audit YYYY-MM-DD pass-N`),
add the corresponding pattern to `_BUG_FIX_SUBJECT_PATTERNS` in both
`check_finding_response.py` and `check_postmortem_for_bug_fix.py`
(keep them in lock-step).

---

## Field guidance

### Bug class (one line, NOT the symptom)

The class is the GENERAL pattern, not the specific instance the audit
flagged. Examples:

- ✅ "yaml-field used without isinstance guard before set membership"
- ❌ "closure_kind crashes on list value"  (that's the symptom, not the class)

- ✅ "stale-phrase regex matches single-line plant but misses multiline drift"
- ❌ "regex doesn't catch multiline shape"  (too narrow; doesn't generalize)

- ✅ "function docstring contradicts argparse help in same file"
- ❌ "Args block stale"  (insufficient — what kind of staleness?)

If you can't write the class as a one-liner that generalizes beyond
the audit's specific finding, you haven't found the class yet. Stop
and look harder.

### Cluster searched (grep command + result count + checklist)

Show your work. Whole-file grep is the file-review discipline;
whole-repo grep is the cluster-discipline; the domain checklist is
the layer-1 self-audit.

Examples:

```
Cluster searched: grep -nE "(entry|cfg)\.get\([^)]+\)\s+not in" scripts/check_*.py
                  → 3 sites in check_audit_regressions.py, 1 fixed in this commit,
                    2 already isinstance-guarded.
                  Checklist: docs/blind-spot-checklists/yaml-parsing.md (15
                  classes reviewed; class #6 type-confusion was the symptom).
```

```
Cluster searched: grep -rn "If empty or None.*scan all" --include='*.py' .
                  → 2 hits: 1 in scripts/check_validator_input_coverage.py
                    (fixed), 1 in docs/postmortems/YYYY-MM-DD-...md
                    (legitimate historical reference).
                  Checklist: no domain checklist exists for "argparse help vs
                  function docstring drift"; consider authoring one if this
                  class recurs.
```

If the grep returns 0 hits beyond the symptom that was named, write that:
`→ 0 other instances; the bug was a singleton.`

If the diff touches a domain with a checklist (regex / yaml-parsing /
commit-msg-hooks / ast-parsing), name the checklist + which classes
you reviewed. If the domain has no checklist yet, name it explicitly
so the gap is visible (and consider authoring one).

### Lock-down (mechanism + path)

What prevents this class from recurring? Lock down as PART of the
fix. Acceptable mechanisms:

- New stale-phrase entry: `Lock-down: STALE_PHRASES entry in scripts/check_stale_phrases.py:<line>`
- New validator/check: `Lock-down: scripts/check_<name>.py (commit-msg / pre-commit stage)`
- New negative test: `Lock-down: tests/test_<name>.py::test_<thing>`
- Type guard / regex / contract change: `Lock-down: isinstance check in scripts/check_X.py:<line>`
- Multiple: `Lock-down: STALE_PHRASES entry + tests/test_validator_X.py::test_Y`

If the fix is genuinely class-less (e.g. a typo in a comment that
doesn't recur), use the opt-out tag instead:

```
[meta-fix-not-applicable: <reason — be specific>]
```

Use sparingly. The hook accepts the opt-out but logs a soft warning.

### Verbatim-shape verified (yes/no)

For stale-phrase / regex / pattern fixes: the negative-test plant
must reproduce the BUG SHAPE verbatim, not a stylized minimal
example.

Examples:

```
Verbatim-shape verified: yes — re.search() returns match on the original
                          docstring's column-wrapped form before fix; None
                          after fix when the regex narrowing was applied.
```

```
Verbatim-shape verified: yes — the negative-test plant in
                          tests/test_validator_X.py copies lines 287-289
                          of the original buggy docstring verbatim.
```

```
Verbatim-shape verified: no — fix is type-guard isinstance check, not a
                          regex; the original bug shape is wrong-type
                          input which is exercised by the new
                          test_fires_on_list_<field> test.
```

If the fix is type-guard / isinstance / structural rather than
pattern-matching, "no — N/A for type-fix" is acceptable.

---

## Opt-out

For commits that respond to a finding but don't have a class-of-bug
shape (e.g. docs-only follow-up commits that record audit-registry
entries; trivial typo fixes; pure renames), use:

```
[meta-fix-not-applicable: <one-line reason>]
```

Common legitimate cases:

- `[meta-fix-not-applicable: docs-only follow-up to <SHA>; the postmortem
  reference and class identification land in the parent fix-commit]`
- `[meta-fix-not-applicable: typo rename of variable <X> to <Y>; no
  behavior change, no class of bug]`
- `[meta-fix-not-applicable: style/format fix from automated tool; no
  class identification needed]`

Empty reasons are rejected by the hook. Be specific.

---

## When the hook fires

If the commit-msg hook fires, you forgot one or more required
fields. The error message names the missing fields. Two correct
responses:

1. **Add the missing fields** (preferred) — the hook is asking you
   to do the class-of-bug thinking you skipped.
2. **Add the opt-out tag** (rare) — only if the commit is genuinely
   class-less per the guidance above.

Bypassing with `--no-verify` is forbidden by AGENTS.md hard rules.
If you believe the hook is wrong (false positive), fix the hook's
regex or expand the opt-out semantics — don't bypass.
