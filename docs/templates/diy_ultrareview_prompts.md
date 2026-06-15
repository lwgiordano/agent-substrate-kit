# DIY ultrareview — seven-specialist parallel + synthesizer review

The closest substitute for `/ultrareview` (the user-triggered cloud
multi-agent review) without leaving the current session: spawn six
subagents in parallel via the Agent tool (lenses 1-6 — five
project-internal lenses tuned to recurring failure modes plus one
external-corpus lens that brings CWE / OWASP / domain-specific
bug-class knowledge), optionally followed by a seventh synthesizer
agent that cross-checks the first six.

Use it after any non-trivial commit cluster (multi-commit fix, new
validator, structural defense) to catch what self-review would miss.

## When to invoke

- After landing a multi-commit fix series.
- After authoring a new validator or commit-msg hook.
- Before declaring "done" on a structural defense.
- When the diff under review touches code in domains the project
  has paid for repeatedly (regex, yaml-input, commit-msg hooks,
  AST parsing, etc. — see `docs/blind-spot-checklists/` if your
  project authors them).

## Setup

The review runs in two phases. Phase A is parallel (lenses 1-6);
Phase B is sequential (lens 7 reads the phase-A reports).

1. **Identify the diff under review.** Typically:
   ```sh
   git diff <base>...HEAD       # branch vs base
   git diff HEAD~3..HEAD        # recent commit cluster
   git show <SHA>               # single commit
   ```
2. **Phase A — spawn six subagents in parallel** — IN A SINGLE
   MESSAGE with six Agent tool calls. Concurrency requires this.
   Sequential calls serialize the review.
3. **Each subagent uses `subagent_type: "general-purpose"`** unless a
   more specific type fits. Specialist 6 (external-corpus) needs
   WebFetch access — verify the agent type has that tool.
4. **Phase B — spawn the synthesizer** with the six reports + the
   diff as input. Optional but recommended for non-trivial reviews.
5. **Synthesize findings** in your reply: dedupe, prioritize, triage.

---

## Specialist 1 — Adversarial-input reviewer

```
You are reviewing a diff for adversarial-input bugs. Apply the
adversarial-input grid to every input handler in the diff (config
field reads, regex patterns, CLI args, parsed JSON/YAML).

Adversarial-input grid:
  - Empty string ('')
  - Whitespace-only ('   ')
  - Wrong type (int, list, None, bool, dict)
  - Bracket-wrapped placeholder (<...>, [...], {...})
  - Path traversal (..)
  - Unicode / surprising whitespace
  - Extremely long
  - All-punctuation
  - Mid-string brackets vs whole-value brackets

For each input handler in the diff, ask:
  1. Does the validator isinstance-check before use?
  2. Is the wrong-type case tested?
  3. Does the test plant the actual bug shape verbatim (not a
     stylized minimal example)?
  4. Could the gate be gamed by template-literal-like input?

Read your project's relevant blind-spot checklists in
docs/blind-spot-checklists/ if any exist for the domain.

Report findings in this format:
  <file>:<line>: <severity P0|P1|P2|P3> <one-line description>

Be terse. Cite specific lines. Flag uncertainty with "(possibly)".

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 2 — Sibling-cluster reviewer

```
You are reviewing a diff for the "I fixed the symptom but missed
the cluster" failure mode.

For every fix in the diff:
  1. What is the BUG CLASS this fix addresses? (One line — not the
     symptom, the general pattern.)
  2. Search the rest of the codebase for that class. Does the
     fix-commit miss any siblings?
  3. If sibling instances exist, are they:
     a. Already correct (different shape, no bug),
     b. Buggy but not in this diff (out-of-scope but worth flagging),
     c. Buggy and SHOULD be in this diff?

Use grep / ripgrep / read patterns to find siblings. Show your work
(cite the search query and the hit count).

Report findings:
  <file>:<line>: <severity> <bug class> — <missed sibling at file:line>

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 3 — Documentation-drift reviewer

```
You are reviewing a diff for documentation drift between code and
its associated docs. Whenever the diff changes:
  - A function signature, return type, or behavior
  - A YAML/JSON config field name or shape
  - A CLI flag name or default
  - An exit-code semantics
  - A pattern the validator detects

…check the corresponding documentation:
  - Function docstring
  - argparse help string
  - knowledge doc (docs/knowledge/*.md) covering this file
  - README / customization / template that mentions it
  - Postmortems (if the behavior is documented there as carry-forward)

For each documentation site, ask:
  1. Does the doc still match the code after this change?
  2. Is there a numeric claim (count of patterns, size of registry)
     that needs bumping?
  3. Does the doc reference a now-stale function/flag/path name?

Report findings:
  <doc-file>:<line> — drifted: <what the doc says> vs <what the
  code now does>

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 4 — Verbatim-shape reviewer

```
You are reviewing a diff for the "regex / pattern test plants a
stylized minimal example instead of the actual bug shape" failure
mode.

For every regex / pattern / detector / validator change in the diff:
  1. What is the original BUG SHAPE this validator catches? (Find
     the postmortem or commit history.)
  2. Does the test plant the bug shape VERBATIM, or a stylized
     same-line minimal example?
  3. If the original bug spanned multiple lines, does the test cover
     the multi-line form?
  4. Does the bug shape contain unusual characters (unicode quotes,
     em-dashes, line wraps) that the test omits?

Manually run the regex against the actual buggy text and confirm
the match status (true positive AND true negative).

Report findings:
  <test-file>:<line> — verbatim-shape gap: <test plants X, real bug
  was Y>

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 5 — Forcing-function gameability reviewer

```
You are reviewing a diff for the "the gate accepts gamed input that
satisfies the letter but not the spirit" failure mode.

This applies to: commit-msg hooks, validators that read free-text
fields, audit-protocol enforcers, any gate that requires a human-
authored explanation.

For every gate / hook / validator in the diff:
  1. What does the gate actually CHECK (the letter)?
  2. What is the gate trying to ENFORCE (the spirit)?
  3. Can a contributor satisfy the letter without doing the spirit?
     - Empty value? (No — non-empty check.)
     - Whitespace-only? (Maybe — depends on `\s` in regex.)
     - Bracket-wrapped placeholder (<value>)?
     - Bare TODO/FIXME/N/A?
     - Single character?
     - Quoted-but-empty ('')?
     - Mid-paragraph mention vs anchored claim?
     - Inline opt-out tag matching anywhere vs line-anchored?
  4. Is the line-anchoring discipline (^...$ with MULTILINE)
     applied consistently across sibling regexes?

Report findings:
  <hook-file>:<line> — gameability: <how a contributor could pass
  this gate without doing X>

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 6 — External-corpus reviewer (WebFetch lens)

```
You are reviewing a diff for bug classes documented in EXTERNAL
sources (CWE, OWASP, language-spec docs, framework documentation,
Stack Overflow consensus answers) that the project's internal
checklists may not cover.

For every domain the diff touches (regex, yaml-parsing, AST
parsing, JSON parsing, subprocess invocation, etc.):
  1. WebFetch the canonical bug-class list for that domain. Suggested
     queries:
     - "common bugs in <language> <domain>"
     - "OWASP <domain> bug list"
     - "CWE <domain>"
     - "<framework> <domain> documentation gotchas"
  2. For each known bug class in the external corpus, check the
     diff: is this class possible? present? caught?
  3. Flag any class the project's existing internal checklists
     (docs/blind-spot-checklists/ if any exist) DON'T cover but
     the external corpus does. These are CHECKLIST-DOMAIN-GAPs —
     candidates for new internal checklist authoring.

Report findings:
  [EXTERNAL] <bug class from CWE/OWASP/etc.> — present/possible at
  <file:line> — internal-checklist coverage: yes/no/N/A

Diff to review (paste below):
[paste git diff output here]
```

---

## Specialist 7 — Synthesizer / cross-checker (Phase B, sequential)

```
You are reviewing six specialist reports (lenses 1-6) on a diff.

Your job:
  1. Dedupe findings (specialist N and specialist M may flag the
     same line for different reasons).
  2. Cross-pattern: identify findings that surface in MULTIPLE
     lenses. These are usually the highest-confidence findings.
  3. Per-severity tier: P0 (must-fix), P1 (should-fix), P2
     (consider), P3 (nice-to-have).
  4. CHECKLIST-CLASS-GAPs: external-corpus findings (specialist 6)
     that the project's internal checklists don't cover. Flag for
     follow-up.
  5. Final synthesis: a punch list, ordered by severity, with
     dedup'd and cross-referenced findings.

Use this output structure:

  [A] CROSS-PATTERN HIGH-CONFIDENCE (multiple specialists flagged):
    1. <file:line> — <description> — flagged by lenses [N, M, ...]
  [B] PER-SPECIALIST UNIQUE FINDINGS:
    Specialist 1 unique: ...
    Specialist 2 unique: ...
    (etc.)
  [C] EXTERNAL-CORPUS FINDINGS (specialist 6):
    <CWE/OWASP class> — present at <file:line>
  [D] CHECKLIST-CLASS-GAPs:
    - <bug class> not in any internal checklist — candidate for
      docs/blind-spot-checklists/<new-domain>.md

Inputs (paste below):
  Diff:
  [paste diff]
  Specialist 1 report: ...
  Specialist 2 report: ...
  Specialist 3 report: ...
  Specialist 4 report: ...
  Specialist 5 report: ...
  Specialist 6 report: ...
```

---

## Customization

Each specialist prompt is a starting point. Customize for your
project's domains:

- **Add a checklist reference**: if your project has
  `docs/blind-spot-checklists/<domain>.md`, append "Read
  docs/blind-spot-checklists/<domain>.md for canonical bug classes"
  to the relevant specialist prompt.
- **Project-specific lenses**: add an 8th specialist for any
  domain you've paid for repeatedly (e.g., "SQL codegen drift",
  "schema migration safety"). Add it to phase A.
- **Drop a specialist**: if your project doesn't touch a domain
  (e.g., no commit-msg hooks → drop specialist 5), skip it.

The synthesizer (specialist 7) handles N specialists, not just 6.
Update its prompt's "lenses [N, M, ...]" example to match your set.
