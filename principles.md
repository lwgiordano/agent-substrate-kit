# Agent Substrate Kit — Principles

Why each piece exists. The kit is opinionated; this doc explains the
opinions.

---

## Principle 1: The keystone runs every session

LLM context compaction is not a malfunction; it's the operating model.
Every long session loses prior turns. The substrate's response is to
make a SINGLE file the entry point: `AGENTS.md` at repo root.

**The keystone documents what the AI can't infer:**
- The startup-read order (which docs to load and why)
- The hard rules (do-not-violate)
- The four-field bug-fix protocol
- The three-layer self-audit discipline
- Where the rest of the meta-system lives

If the keystone goes stale, the system rusts. The keystone has its own
`last_human_reviewed` stamp at the bottom, and a stale-phrase regex
(`extras/check_stale_phrases.py`, strict profile) can be configured to fire on
descriptive claims that drift.

**Why one file, not multiple:** the AI can be relied upon to read ONE
file every session. Multiple = "I'll read the relevant ones" =
selective reading = drift.

---

## Principle 2: HISTORY is append-only with field discipline

Git log captures WHAT changed. HISTORY captures WHY and WHAT FUTURE
SESSIONS NEED TO KNOW. Four fields per entry, all required:

- **Summary** (one line, just the index)
- **Files** (comma-separated paths)
- **Intent** (why this change happened)
- **Knowledge** (what future sessions need to remember)

Intent and Knowledge are load-bearing. They're what someone in a
new session reads to understand the change without re-deriving it.
A summary alone can't carry that load.

**Why append-only:** prevents the "AI rewrites history to look better"
class of failure. The file's header says "DO NOT EDIT prior entries."
A drift-detector validates that each entry's SHA is real (no
hallucinated commits).

**Why merge=union:** concurrent branches add entries. `merge=union` in
`.gitattributes` makes both entries land without conflict.

**Why the off-by-one guard:** `append_history.py` falls back to
`git rev-parse HEAD` when `--commit-hash` is omitted. If invoked
BEFORE git commit, HEAD is the parent of the impending commit, and
HISTORY records the wrong SHA. The guard refuses the fallback when
the working tree has non-HISTORY files modified — forces explicit
`--commit-hash` in the dirty case.

---

## Principle 3: ADRs require Alternatives Considered

A "decision document" without alternatives is a summary. It tells the
reader WHAT was chosen but not WHY this and not the others.

Future sessions re-derive the same alternatives if Alternatives
Considered is missing. The documented alternatives ARE the gate
against the same decision being re-litigated.

**The ADR template REQUIRES four sections:** Context, Decision,
Consequences, Alternatives Considered. Without all four, the ADR
isn't done.

**Why numbered, not slugged:** sequential numbers make supersession
unambiguous ("ADR-0014 superseded by ADR-0023"). Slugs invite
collisions and ambiguity.

**Once Accepted, immutable:** changes to a decision = a new ADR that
references the old. Modifying an Accepted ADR breaks the chain of
reasoning future sessions follow.

---

## Principle 4: Postmortems require Carry-forward rules

A postmortem without a Carry-forward rule documents the bug but not
how to avoid the next instance.

The Carry-forward rule MUST be specific. "Be careful with allowlists"
fails the test. "Grep `<pattern>` in the whole repo before committing"
passes.

**Five required sections:**
- What happened
- Why it happened
- Why our tooling didn't catch it
- Preventative gate added
- Carry-forward rule

**Why "preventative gate added":** a postmortem's load-bearing output
is the gate that makes recurrence visible. Without a gate, the same
bug class returns. The validator
`scripts/check_postmortem_gates_resolved.py` walks postmortems'
`gates_added` frontmatter and verifies each gate reference resolves
to a real test/script. A renamed test = stale postmortem claim,
caught here.

---

## Principle 5: Knowledge docs have drift detection

`docs/knowledge/<NN>_<topic>.md` describes a subsystem. Frontmatter
has:
- `covers:` — list of source files
- `last_human_reviewed:` — ISO date

`scripts/check_doc_drift.py` walks each covered file's git log. If a
file has been modified after `last_human_reviewed`, the doc is flagged
stale. Bumping the date asserts "I read the diff and the doc still
describes reality."

**Why per-doc dates, not per-file:** a doc covers a coherent subsystem.
One date per subsystem matches the granularity of "I just reviewed
this area."

**Why dates instead of hashes:** dates survive rebases. Hashes don't.
And humans naturally think "I last looked at this in late April,"
not "I last looked at this at SHA abc123."

**The trap:** bumping the date without re-reading. There's no
mechanical defense against this. The discipline is: when the gate
fires, READ the diff, then bump.

---

## Principle 6: Compaction recovery via on-disk state

LLM compaction wipes prior turns. The substrate's response: snapshot
session state to a checked-in-but-gitignored file (`docs/CURRENT_
SESSION.md`).

**Snapshot cadence: hook-fired, not honor-system.** PreCompact and
SessionEnd hooks capture automatically; SessionStart re-injects the
handoff as additionalContext. v2 documented a manual cadence here —
v3's position is that any discipline a hook can enforce, a hook MUST
enforce (see Principle 14).

**Recovery protocol:**
1. Read `docs/CURRENT_SESSION.md` first.
2. Cross-reference with `git log -5 --oneline` and last 5 HISTORY
   entries.
3. Resume from the recorded TODO state.

`scripts/session_handoff.py` (hook-fired) writes from `docs/.todo_state.json`
(also gitignored) plus optional notes. The TODO state is regenerated
each turn from the agent's TodoWrite tool calls.

**Why gitignored:** session state is per-machine, per-run. Sharing
it via git would create false signals about what other operators are
doing.

---

## Principle 7: Validators are tested validators

A validator that's never tested is a validator that doesn't catch
bugs reliably. The substrate enforces a meta-rule: every
`scripts/check_*.py` that reads YAML field names must have a paired
adversarial test in `tests/test_validator_<name>.py`.

`scripts/check_validator_input_coverage.py` walks every check_*.py
that imports yaml + reads YAML-dict fields. For each field read, it
asserts EITHER:
- A paired test file exists with adversarial test cases for that
  field
- The read site has `# coverage-opt-out: <reason>` annotation

**Why the meta-rule:** prevents the recurring failure where someone
adds a validator, the validator looks correct, but a wrong-typed
input slips past because no test exercises that case.

**Why the opt-out has a reason:** without a reason, the opt-out is
free. The reason is the gate against "I don't feel like writing a
test, I'll just opt out." The reason has to name the upstream
guarantee that makes the field shape-safe.

---

## Principle 8: Calibration breaks the audit's circularity

Detection logic regresses silently. The substrate's response: a
list of known-bug commits with EXPECTED detection-domain labels.

`extras/calibrate_diy_ultrareview.py` (strict profile) runs detection against each
commit, compares to expected, fails if any drifts.

**Two pools, one signal:**
- **Ground-truth pool**: human-labeled. Expected domains derived by
  reading the diff. Auditing the substrate against these is real.
- **Locked-current-behavior pool**: auto-curated. Expected domains
  populated by running the current detector.

The ground-truth pool is load-bearing. If a fix to the detector
breaks ground-truth recall, that's a real bug. Locked-behavior is
useful as a regression test (catches drift) but is circular by
construction (it locks current behavior, even if current behavior
is wrong).

**Why both:** the ground-truth pool can't grow fast (humans are
slow). The locked pool grows freely (auto-curation from new commits).
Together they give regression coverage AND a real correctness signal.

**Floor test:** the calibration set has a minimum size. Trivial:
`CALIBRATION = ()` would pass strict mode (0/0 perfect). Set a floor
of 15 to make wholesale set-emptying impossible.

---

## Principle 9: Three-layer self-audit before commits

External review is rare. The substrate makes self-review structured:

**Layer 1: Domain blind-spot checklist.** Per-domain bug-class
catalogs (regex.md, yaml-parsing.md, commit-msg-hooks.md, etc.). Each
has 12-15 canonical bug classes. Spawn checklist-auditor per domain;
it reads the checklist in its own context and returns a <=500-token
verdict. ~3 min, near-zero main-context cost.

**Layer 2: Steelman review.** Write down: "Imagine an external
reviewer sees this diff. What three objections would they raise?"
Check each. Forces audit-mode thinking that doesn't happen
automatically when finishing implementation.

**Layer 3: DIY ultrareview.** For non-trivial commit clusters, spawn
6 specialist sub-agent reviews in parallel (adversarial-input,
sibling-cluster, doc-drift, verbatim-shape, forcing-function-
gameability, external-CWE-corpus). Then a synthesizer (lens 7).

Each layer catches a different class of bugs. Skipping any one
costs.

---

## Principle 10: The bug-fix four-field protocol

Bug fixes scope to the symptom unless forced otherwise. The forcing
function is the commit-msg hook requiring four fields:

```
Bug class:           <one-line summary — NOT the symptom>
Cluster searched:    <grep command + result count>
Lock-down:           <mechanism + path>
Verbatim-shape verified: <yes/no with evidence>
```

The hook (`scripts/check_finding_response.py`) detects when
the subject matches a bug-fix shape and enforces the fields. Opt-out
for genuinely class-less fixes: `[meta-fix-not-applicable: <reason>]`.

**Why four fields, not three:**
- Bug class forces class-of-bug thinking
- Cluster searched forces sibling-grep
- Lock-down forces a real prevention
- Verbatim-shape verified forces empirical proof the lock catches
  the original bug shape

Drop any field and the corresponding failure mode comes back.

---

## Principle 11: Pre-commit is the first line; CI is the second

Pre-commit runs locally on every commit. CI re-runs the same gates
on every push. Branch protection requires CI green before merge.

Three layers:
1. Pre-commit (local, ~2 min) — caught at commit time.
2. CI (remote, ~5 min) — caught at push time.
3. Branch protection (operator-set) — required for merge.

`--no-verify` bypasses pre-commit. CI re-runs the same hooks. If
both are green, the commit is verified. If pre-commit was bypassed
but CI is enabled, CI catches it.

**The discipline failure of `--no-verify`** has a concrete cost. In
the source project's audit round 7, 9 commits used `--no-verify` and
52 ruff lint errors landed that the gate would have caught. The fix
was re-enabling pre-commit; round 8's first commit caught 4 real
drift findings the bypassed gate had been missing.

---

## Principle 12: Every gate has an opt-out, every opt-out has a reason

Hard rules don't survive long. Real systems need escape hatches —
but the escape hatch must be auditable.

Pattern across the substrate:
- `[no-postmortem: <reason>]` for typo-fix commits
- `[meta-fix-not-applicable: <reason>]` for class-less fixes
- `# coverage-opt-out: <reason>` for fields with upstream validation
- `# pragma: no cover` for defensive raise-after-isinstance lines
- `[no-history-bump]` for cosmetic changes

Each opt-out:
1. Has a `<reason>` field (mandatory; placeholder rejected)
2. Names what makes the opt-out legitimate
3. Is grep-able (audit can find every instance)

The kit's validators reject placeholder reasons (`<reason>`,
`TODO`, `N/A`, etc.) — the reason must be real. An audit on the
source project caught a stale opt-out claim referencing a
non-existent validator; the discipline of "every reason is real"
is enforced by the gate.

---

## Principle 13: Substrate-vs-product ratio matters

The substrate is not free. Every gate adds friction. Every postmortem
takes time to write. Every ADR is a small decision-cost tax.

The substrate is **proportional to risk**. A throwaway script doesn't
need ADRs. A 10-person team with code review doesn't need a four-
field commit-msg protocol.

The substrate is **for**: codebases being built by LLM agents, with
operator oversight, intended for production, where mistakes compound.

**The substrate-to-product ratio is a real metric.** If 95% of your
codebase is gates-protecting-gates and 5% is product, you've inverted.
The substrate exists to protect the product; without product, it's
just process for its own sake.

The source project's substrate is at the high end of useful because
the product is high-stakes (operator-trusted dashboard with real
money attached). For lower-stakes projects, omit the heavier gates
(calibration, DIY ultrareview, postmortem-gates cross-ref).

---

## What this kit does NOT defend against

- **Wrong product decisions.** ADRs document decisions; they don't
  validate them. A wrong tech-stack ADR is wrong from day 1; the
  substrate just keeps it visible.

- **Bugs in the product domain.** Domain-specific validators
  (codegen drift, schema cross-ref, etc.) are not in this kit
  because they're project-specific. Build them on top.

- **Operator skipping rules.** `--no-verify` is always available
  in git. Branch protection is the structural defense. Without it,
  the operator can ship anything.

- **LLM hallucination.** The validators catch drift and structural
  errors. They don't catch the AI inventing a function that doesn't
  exist (mypy strict catches some; runtime testing catches more).

- **Undisciplined human contributors.** A new engineer can `git
  push --force` and bypass the substrate. The defense is branch
  protection + code review. Substrate is for the AI's blind spots,
  not the team's.

---

## When the substrate fights you

Some changes will trip multiple gates simultaneously. This is normal
when the substrate has wide reach. Patterns:

- **HISTORY append + manifest auto-regen race**: the manifest hook
  auto-regenerates `docs/manifest.json`, which races with pre-
  commit's stash mechanism on cloud-sync filesystems. Workaround:
  run `update_manifest.py` manually first, stage, then commit.

- **Knowledge-doc drift on every code edit**: covered files trigger
  drift detection. If you're editing fast, batch the date bumps —
  one commit at end of feature work to bump all touched docs'
  dates.

- **Postmortem-gates resolved fires on every postmortem edit**:
  the validator runs `pytest --collect-only` (slow). If you're
  iterating on a postmortem, expect ~30s gate time per commit.

The substrate is a tax. The tax pays for itself when (a) the LLM
makes mistakes and (b) the operator can't spot all of them by
review alone. Both conditions are usually true.

---

## Principle 14: Hooks, not honor systems

Any discipline that can be enforced by a lifecycle hook must be.
Advisory instructions degrade as context fills; hooks fire identically
on session 1 and session 200.

The v3 hook layer:
- PostToolUse(Edit|Write) -> lint_on_write.py — errors feed back at
  write time, not commit time.
- PostToolUse(TodoWrite) -> todo_state_hook.py — todo state mirrored
  to disk on every change.
- PreCompact / SessionEnd -> session_handoff.py capture — compaction
  handoff written without anyone remembering to.
- SessionStart -> session_handoff.py restore — handoff re-injected,
  verified against git before being trusted.

Two design rules for substrate hooks:
1. **Fail open.** A hook that can block compaction or interrupt the
   agent on an environment error does more harm than the discipline
   it enforces. capture/mirror hooks always exit 0; only lint errors
   (real findings) use the blocking exit code.
2. **Stdlib only.** Hooks run outside the project venv. A hook that
   needs `uv sync` to have happened is a hook that silently never ran.

What remains honor-system after v3: date-bumps on knowledge docs
(reading the diff cannot be mechanically verified) and the startup
protocol itself. Everything else moved to mechanism.
