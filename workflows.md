# Agent Substrate Kit — Workflows

The disciplines the substrate enforces. Each workflow has a forcing
function (a hook, a validator, or an explicit doc rule).

---

## Workflow 1: Session startup

**When:** Any new AI session opens the repo.

**Steps:**

```
1. Read AGENTS.md (the keystone).
2. Check for docs/CURRENT_SESSION.md.
   - If exists: this is mid-task recovery; read it for state.
   - If absent: fresh session; will need a new snapshot before stopping.
3. Read docs/README.md (doc index).
4. Read last 5 entries of docs/HISTORY.md.
5. Read your active execution playbook (BUILD_INSTRUCTIONS.md or equivalent).
6. Read relevant docs/knowledge/*.md for the area being worked.
7. Read relevant docs/decisions/*.md for decisions touching that area.
```

**Forcing function:** The keystone documents this order. If a session
skips it, the AI is operating on incomplete context — that's an
error class to flag in the next audit.

---

## Workflow 2: Pre-commit self-audit (three layers)

**When:** Before composing any non-trivial commit message.

**Layer 1 — Domain blind-spot checklist** (~3 min):

```
1. Identify the domain(s) the diff touches.
   - regex / yaml-parsing / commit-msg-hooks / ast-parsing / etc.
2. Spawn the checklist-auditor subagent per domain (do NOT read the
   checklist into the main context):
     "Domain: <domain>. Diff: <range>. Walk every bug class in
      docs/blind-spot-checklists/<domain>.md. PASS/WARN/BLOCK,
      <=500 tokens, file:line per finding."
3. Treat WARN/BLOCK findings as inputs to the finding-response skill.
```

**Layer 2 — Steelman review** (~5 min):

```
1. Write down: "Imagine an external reviewer is about to review
   this diff. What three objections would it raise?"
2. Check each:
   - Is the objection real?
   - Does the diff need to change?
   - Or is it a genuine non-issue (document why)?
```

**Layer 3 — DIY ultrareview** (~10 min, for non-trivial commits only):

```
1. scripts/diy_ultrareview.sh HEAD~3..HEAD
2. Spawn 6 specialist sub-agent reviews IN PARALLEL (one message,
   six Agent tool calls):
   - lens-1: adversarial-input
   - lens-2: sibling-cluster
   - lens-3: doc-drift
   - lens-4: verbatim-shape
   - lens-5: forcing-function-gameability
   - lens-6: external-CWE-corpus (WebFetch)
3. After all 6 return, spawn lens-7 (synthesizer) sequentially with
   the 6 reports as input.
4. Treat the synthesizer's output as a pre-commit review. Address
   real findings before committing.
```

**Forcing function:** No mechanical gate, but the patterns that
appear in postmortems (rule 13 sibling-parity, rule 15 verbatim-shape)
make Layer 1 essentially required for compliance with the four-field
commit-msg protocol.

---

## Workflow 3: Bug-fix protocol (four fields)

**When:** Fixing a bug, regardless of who/what found it.

**Steps:**

```
1. Read the entire finding. Identify the bug CLASS in one line.
   Examples:
     "yaml-field used without isinstance guard"
     "stale-phrase regex misses multiline form"
     "validator silent-pass on null input"

2. Grep the whole file for siblings of the same class.
   Note the grep + result count.

3. Grep the whole repo for instances of the same class.
   Note the grep + result count.

4. Identify the LOCK-DOWN mechanism that prevents recurrence:
   - New stale-phrase entry?
   - New validator?
   - New test?
   - New opt-out comment with reason?
   You CANNOT commit without one.

5. If the lock-down is a stale-phrase regex, use the VERBATIM bug
   shape in the negative test (don't paraphrase to a same-line
   minimal example).

6. Empirically verify the lock-down catches the original bug.
   Run re.search() / pytest / whatever proves it.

7. Compose the commit message with the four required fields:
```

```
<subject — describes what was fixed>

<body explaining the change>

Bug class:           <one-line summary — NOT the symptom>
Cluster searched:    <grep command + result count>
Lock-down:           <mechanism + path>
Verbatim-shape verified: <yes — confirmed via X / no — opt-out>

Co-Authored-By: <you>
```

**Forcing function:** `scripts/check_finding_response.py` is a
commit-msg hook that fires when the subject matches a bug-fix shape.
Missing fields = blocked commit.

**Opt-out:** `[meta-fix-not-applicable: <reason>]` in commit body.
Use only for genuinely class-less fixes (typo, doc-only follow-up,
rename).

---

## Workflow 4: Postmortem-on-bug-fix

**When:** Any bug, near-miss, or stale-claim drift you (or an audit)
catches.

**Steps:**

```
1. Copy the template:
   cp docs/postmortems/_template.md \
      docs/postmortems/$(date -u +%Y-%m-%d)-<slug>.md

2. Fill in all 5 required sections:
   - What happened
   - Why it happened
   - Why our tooling didn't catch it
   - Preventative gate added
   - Carry-forward rule

3. The Carry-forward rule MUST be specific.
   Bad: "be careful with allowlists"
   Good: "grep `<pattern>` in the whole repo before committing"

4. Frontmatter has gates_added: list the test/script that pins
   this regression.

5. Cross-link from docs/AUDIT_REGRESSIONS.yaml (if maintained):
     lessons:
       - postmortem: "docs/postmortems/YYYY-MM-DD-slug.md"
         section: "carry-forward-rule"

6. Commit the postmortem in the same commit as the fix (or just
   before).

7. Reference the postmortem in the commit message body:
     Postmortem: docs/postmortems/YYYY-MM-DD-slug.md
```

**Forcing function:** `scripts/check_postmortem_for_bug_fix.py` is a
commit-msg hook that fires when the subject is a bug-fix shape. Body
must contain either a postmortem reference OR
`[no-postmortem: <reason>]` for genuinely typo/rename/refactor commits.

**Validator:** `scripts/check_postmortem_gates_resolved.py` runs at
pre-commit and asserts every postmortem's `gates_added` references
resolve to real files. A renamed test = stale postmortem claim,
caught here.

---

## Workflow 5: HISTORY append

**When:** After every meaningful commit.

**Recommended: commit first, then append HISTORY.**

```sh
# Step 1: commit your change.
git add -A && git commit -m "<message>"

# Step 2: append HISTORY entry. The --commit-hash flag is critical.
python scripts/append_history.py \
  --summary "<one line>" \
  --files "<comma,separated,paths>" \
  --intent "<why>" \
  --knowledge "<what future sessions need to know>" \
  --commit-hash "$(git rev-parse --short HEAD)"

# Step 3: commit the HISTORY edit.
git add docs/HISTORY.md docs/manifest.json
git commit -m "docs: HISTORY for <prev-commit-sha>"
```

**Why --commit-hash explicitly:** without it, append_history.py falls
back to `git rev-parse HEAD` AT THE TIME OF SCRIPT INVOCATION. If
called BEFORE the actual commit, HEAD is the parent of the impending
commit — produces an off-by-one. The guard refuses the
fallback when the working tree is dirty (forces explicit
`--commit-hash` in that case).

**A "meaningful change":**
- Bug fix → entry
- New feature → entry
- Refactor → entry
- Tweaking comments → not necessarily

**The four fields:**
- `Summary` — one-line, just the index
- `Files` — comma-separated paths
- `Intent` — why this change happened
- `Knowledge` — what future sessions need to know

`Intent` and `Knowledge` are load-bearing. `Summary` is just for
greppable text.

**Forcing function:** No hard gate (HISTORY isn't required by pre-
commit). The discipline is documented in AGENTS.md as a hard rule.
The drift detector (`check_history_sha.py`) catches invented SHAs.

---

## Workflow 6: ADR authoring

**When:** Any change involves picking one approach over alternatives.

**Steps:**

```sh
# Find next ADR number
NEXT=$(printf '%04d' \
  $(($(ls docs/decisions/ | grep -E '^[0-9]{4}-' | sort -r | head -1 | cut -d- -f1) + 1)))

# Create from template
cp docs/decisions/0000-template.md "docs/decisions/${NEXT}-<slug>.md"
```

**Required sections:**
- Status (Proposed | Accepted | Superseded by NNNN | Deprecated)
- Date (ISO)
- Deciders
- Related (links to other ADRs)
- Context
- Decision
- Consequences (positive / negative / neutral)
- **Alternatives Considered** (REQUIRED — without it, the ADR is a
  summary, not a decision record)

**Once Accepted, immutable.** Changes = a new ADR that references
the old.

**Numbering:** sequential. Don't reuse numbers. The numbers are
permanent identifiers used in cross-references.

**Forcing function:** No mechanical gate (would require parsing
prose). The discipline is documented in AGENTS.md. Stale-phrase
regexes can be configured to fire on common forms of "decision
without alternatives" if you find this is recurring.

---

## Workflow 7: Knowledge-doc maintenance

**When:** When you touch a file that's covered by a knowledge doc.

**Drift catches:** `scripts/check_doc_drift.py` runs at pre-commit
and fires when a covered file has been modified after the doc's
`last_human_reviewed` date.

**Resolution:**

```
Option 1 — Bump the date (the file was edited but the doc still
describes reality):
   1. Read the diff to verify the doc still matches code.
   2. Edit the doc's frontmatter: last_human_reviewed: <today>
   3. Commit.

Option 2 — Update the doc (the file was edited and the doc no
longer matches):
   1. Update the doc body to reflect the new reality.
   2. Bump last_human_reviewed: <today>
   3. Commit.

Option 3 — Add the file to a different doc (the file was edited but
isn't really part of this subsystem):
   1. Remove the file from the wrong doc's covers: list.
   2. Add it to the right doc's covers: list.
   3. Bump that doc's last_human_reviewed: <today>
   4. Commit.

Option 4 — Coverage gap (the file is new and no doc covers it):
   1. Add the file to an existing doc's covers: list, OR
   2. Create a new doc.
   3. Bump dates as appropriate.
   4. Commit.
```

**Forcing function:** Pre-commit hook `check-doc-drift`. Blocks
commits with stale-doc / phantom-doc / coverage-gap.

**Hard rule:** NEVER bump the date without actually reading the
diffs. The discipline is honor-system; if you bump dates blindly,
the substrate's drift signal becomes noise.

---

## Workflow 8: Compaction recovery

**When:** Any time you might lose context (long session, before risky
operation, after major decision, end-of-turn if mid-task).

**Snapshot:**

```sh
./manage.sh handoff   # runs scripts/session_handoff.py capture (hooks also fire this automatically on PreCompact/SessionEnd)
```

This writes `docs/CURRENT_SESSION.md` with:
- Current TODO state (from `docs/.todo_state.json`)
- Last 5 commits
- Active branch
- Open files (best-effort)
- Optional notes

**Recovery:**

```
1. Read docs/CURRENT_SESSION.md (the bridge).
2. git log -5 --oneline (verify the recorded commits match HEAD).
3. Read last 5 HISTORY entries (cross-reference what landed).
4. Read AGENTS.md (refresh on the workflow rules).
5. Resume from the recorded TODO state.
```

**Snapshot cadence: automated.** Hooks fire the capture on
PreCompact and SessionEnd; TodoWrite state is mirrored on every call
by todo_state_hook.py. Manual `./manage.sh handoff` remains for
"before a risky operation" moments.

**Forcing function:** No hard gate. The discipline is in AGENTS.md
hard rules. If a session loses state without snapshotting, the
recovery is harder — the substrate's response is to make snapshotting
cheap (one command) so it happens routinely.

---

## Workflow 9: Validator addition

**When:** You catch a bug class that should have a structural defense.

**Steps:**

```
1. Write the validator: scripts/check_<thing>.py
   - Top-of-file docstring explains what it catches
   - main(argv) -> int returns 0/1/2 (ok/drift/env-error)
   - Errors print to stderr with actionable messages

2. Write the paired test: tests/test_validator_<thing>.py
   - At least one positive test (live config passes)
   - Adversarial tests (each YAML field set to wrong types)
   - Use parametrize for systematic coverage

3. Add the pre-commit hook entry in .pre-commit-config.yaml:
     - id: check-<thing>
       name: <Human-readable name>
       entry: .venv/bin/python scripts/check_<thing>.py
       language: system
       files: ^<file-pattern>$    # only fire on relevant changes
       pass_filenames: true       # or false depending on the validator

4. Run the validator-input-coverage gate to confirm the new validator
   is properly coupled to its tests:
     uv run python scripts/check_validator_input_coverage.py --all

5. Add the validator file to docs/knowledge/06_prevention_and_audit.md
   (or equivalent) covers: list. Bump last_human_reviewed.

6. Commit. The pre-commit will fire on the new validator's pattern
   and the validator-input-coverage gate will confirm it's tested.
```

**Forcing function:** `scripts/check_validator_input_coverage.py`
runs at pre-commit and blocks any commit that adds a `scripts/
check_*.py` reading YAML fields without a paired test.

---

## Workflow 10: Audit round

**When:** Periodically (after major work, after a postmortem, when
substrate work feels stale).

**Steps:**

```sh
# 1. Run all the gates.
uv run pre-commit run --all-files

# 2. Run the meta-validators specifically.
uv run python scripts/check_doc_drift.py --strict
uv run python scripts/check_validator_input_coverage.py --all
uv run python scripts/check_postmortem_gates_resolved.py
uv run python scripts/calibrate_diy_ultrareview.py --strict   # strict profile only (extras/)
uv run python scripts/check_history_sha.py
uv run python scripts/check_bandit_skip_baseline.py

# 3. Run coverage.
uv run pytest tests/ --cov=<your-modules> --cov-report=json
uv run python scripts/check_coverage_floors.py

# 4. Run mypy strict.
uv run mypy <your-modules>

# 5. Run ruff.
uv run ruff check .

# 6. Run bandit at high+high.
uv run bandit -lll -iii -r <your-modules>
```

For each finding: classify (real bug? per-file-ignore candidate?
genuine drift?). Real bugs get the bug-fix workflow. Per-file-ignores
get a justification. Drift gets the doc bump or validator update.

**Cadence:** Whenever you've done substantial substrate work, run
the audit. Yields decay across rounds (4-8 typical for the first
audit; 0-2 by round 5+ if discipline is intact).

**The decay is non-monotonic.** If a hook has been bypassed
(`--no-verify`), the next un-bypassed commit will surface accumulated
drift. That's not a substrate failure; it's the discipline working.

---

## Workflow 11: Substrate retirement

**When:** A validator hasn't fired in 12+ months OR the bug class is
provably impossible OR a more general validator subsumes it.

**Steps:**

```
1. Write a brief postmortem-style note: "Retiring check_<X>.py because <reason>."

2. Remove:
   - scripts/check_<X>.py
   - tests/test_validator_<X>.py
   - .pre-commit-config.yaml entry
   - docs/knowledge/<NN>_<topic>.md covers: line for the script

3. Bump knowledge-doc last_human_reviewed.

4. uv run python scripts/update_manifest.py
   git add docs/manifest.json

5. Commit:
   - Subject: "retire: scripts/check_<X>.py (no fires in 12mo)"
   - Body explains the rationale.

6. HISTORY entry documents the retirement.
```

**Why retire:** A validator that never fires AND can't fire is dead
weight. Worse, it implies a defense that doesn't actually exist.

**When NOT to retire:** A validator that hasn't fired in 12 months
but COULD fire under some configuration. The defense is real even if
the trigger is rare.

---

## Workflow 12: First-time install on a new repo

**When:** Bootstrapping a new project with this kit.

**Steps:**

```sh
# 1. Empty/new git repo.
git init

# 2. Drop the kit.
bash path/to/Agent Substrate Kit/bootstrap.sh

# 3. Customize AGENTS.md.
$EDITOR AGENTS.md   # bottom 'Project-specific instructions' section

# 4. Set up dep manager.
$EDITOR pyproject.toml   # add the dev-group deps from customization.md

# 5. Install.
uv sync --group dev
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg

# 6. First ADR.
cp docs/decisions/0000-template.md docs/decisions/0001-tech-stack.md
$EDITOR docs/decisions/0001-tech-stack.md

# 7. First knowledge doc.
$EDITOR docs/knowledge/00_repo_layout.md   # cover the meta-system files

# 8. Verify clean baseline.
uv run pre-commit run --all-files

# 9. First commit.
git add -A
git commit -m "Bootstrap: Agent Substrate Kit installed"

# 10. First HISTORY entry.
uv run python scripts/append_history.py \
  --summary "Bootstrap meta-system: kit installed, first ADR + knowledge doc" \
  --files "AGENTS.md,scripts/,docs/decisions/0001-tech-stack.md,docs/knowledge/00_repo_layout.md,.pre-commit-config.yaml" \
  --intent "Establish the substrate before any product code lands. AGENTS.md customized for this project, first ADR documents tech stack, first knowledge doc covers the meta-system." \
  --knowledge "Agent Substrate Kit bootstrap is complete. Next step: write BUILD_INSTRUCTIONS.md (or equivalent execution playbook) and start product work." \
  --commit-hash "$(git rev-parse --short HEAD)"

git add docs/HISTORY.md docs/manifest.json
git commit -m "docs: HISTORY for $(git log -1 --format=%h HEAD~1)"
```

**Forcing function:** None for bootstrap (you have to do it). After
this, the substrate is self-enforcing.

---

## What each workflow protects against

| Workflow | Protects against |
|---|---|
| Session startup | Operating without context (drift, re-derivation, missed rules) |
| Pre-commit self-audit | Symptom-only fixes, missed bug classes, missed sibling sites |
| Bug-fix four-field | Symptom-only fixes (forces class-of-bug) |
| Postmortem-on-bug-fix | Recurrence (forces gate creation) |
| HISTORY append | Lost intent, AI-invented SHAs |
| ADR authoring | Re-litigated decisions |
| Knowledge-doc maintenance | Stale documentation claims |
| Compaction recovery | Lost mid-task state |
| Validator addition | Validators without tests |
| Audit round | Cumulative substrate drift |
| Substrate retirement | Dead-weight validators implying false defense |
| First-time install | Bootstrapping discipline before product work |

Each workflow has a clear forcing function or doc rule. Skipping a
workflow has a documented cost in the postmortem trail.
