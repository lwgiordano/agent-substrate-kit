# AI builder prompt — install this kit on a new project

Copy this prompt verbatim into a fresh AI agent session in your
new project's directory. The agent will execute the install, customize
for your project, and verify clean baseline.

---

## The prompt

```
You're installing the AGENT_SUBSTRATE_KIT — a self-managing AI-engineering
substrate — into this project. The kit lives at <PATH/TO/AGENT_SUBSTRATE_KIT>.

Your job: install it, customize it for THIS project, verify clean
baseline, and commit. Treat this as a multi-step substrate bootstrap.

# Pre-flight check

Before starting, verify:
1. This is an empty or near-empty git repo (no existing AGENTS.md, no
   existing scripts/check_*.py, no existing docs/decisions/).
2. Python 3.11+ is available (the substrate validators are stdlib + PyYAML).
3. `uv` is installed (or you'll need to adapt to the operator's dep
   manager — ask first).

If any pre-flight fails, STOP and ask the operator how to proceed.

# Step 1: Read the kit

Read these files in this order to understand what you're about to do:
1. <PATH/TO/AGENT_SUBSTRATE_KIT>/README.md
2. <PATH/TO/AGENT_SUBSTRATE_KIT>/principles.md
3. <PATH/TO/AGENT_SUBSTRATE_KIT>/customization.md
4. <PATH/TO/AGENT_SUBSTRATE_KIT>/workflows.md
5. <PATH/TO/AGENT_SUBSTRATE_KIT>/QUICK_START.md

Don't skip the read. The kit's principles inform every customization
decision.

# Step 2: Run the bootstrap installer

bash <PATH/TO/AGENT_SUBSTRATE_KIT>/bootstrap.sh

That copies all the universal files. The installer prints a Day-1
checklist; don't skip any item.

# Step 3: Customize AGENTS.md

Open AGENTS.md. The bottom "Project-specific instructions" section is
a placeholder. Replace with:
- Project name
- Active execution playbook filename (e.g., BUILD_INSTRUCTIONS.md or
  ROADMAP.md — ask the operator what theirs will be)
- Architecture doc path
- Intent doc path
- Any project-specific scopes / forms / build paths the operator
  mentions

If the operator hasn't decided on names yet, leave placeholders BUT
flag them clearly with `<TODO: name your X here>` so the operator
sees what's pending.

# Step 4: Set up dependencies

The bootstrap script ALREADY copied a minimal pyproject.toml with
the substrate's required dev-tooling group (if no pyproject existed).
Open it and:

1. Edit the [project] block — replace `<your-project-name>` and
   `<one-line description>` with the operator's values. Ask if not
   obvious.
2. Verify [dependency-groups].dev includes the substrate's required
   tooling. The starter has all of these:
     pre-commit>=3.7, pytest>=8, pytest-cov>=5, pytest-randomly>=3.15,
     pytest-rerunfailures>=14.0, pytest-benchmark>=4.0,
     hypothesis>=6.100, ruff>=0.5, mypy>=1.10, types-pyyaml>=6.0,
     bandit>=1.7, pip-audit>=2.7
3. If the operator already had a pyproject.toml (the bootstrap won't
   overwrite), ADD the dev-deps group manually. Ask the operator
   about workspace layout (single package, monorepo, uv workspace).

# Step 5: Install hooks

Use the operator's dep manager. The substrate is dep-manager-neutral;
adapt the commands below per their choice:

uv:        uv sync --group dev
           uv run pre-commit install
           # commit-msg hooks are strict-profile only:
           . scripts/_substrate_config.sh; load_substrate_config; [ "$SUBSTRATE_PROFILE" = strict ] && uv run pre-commit install --hook-type commit-msg

poetry:    poetry install --with dev
           poetry run pre-commit install
           . scripts/_substrate_config.sh; load_substrate_config; [ "$SUBSTRATE_PROFILE" = strict ] && poetry run pre-commit install --hook-type commit-msg

pip:       pip install -e ".[dev]"   # uncomment the
                                     # [project.optional-dependencies]
                                     # block in pyproject.toml first
           pre-commit install
           . scripts/_substrate_config.sh; load_substrate_config; [ "$SUBSTRATE_PROFILE" = strict ] && pre-commit install --hook-type commit-msg

CRITICAL: prefix `pre-commit install` with the dep manager's run
command (or activate the venv first). The hook script captures the
python path at install time; if the wrong python is captured, hooks
fail to find their dependencies at commit time.

# Step 6: Customize .pre-commit-config.yaml

Walk the file. For each hook, decide based on customization.md whether
the project HAS that feature:
- If YES: keep the hook
- If NO: remove the hook (cleanly delete the - id: block)
- If UNSURE: ask the operator

The "Universal" section (always keep) is documented in customization.md.
Don't second-guess that part.

# Step 7: First ADR + first knowledge doc

Bootstrap content:

7a. cp docs/decisions/0000-template.md docs/decisions/0001-tech-stack.md
    Fill in: Status (Proposed), Date, Deciders, Context, Decision,
    Consequences, Alternatives Considered. Ask the operator about the
    tech stack if not obvious.

7b. cp docs/knowledge/_template.md docs/knowledge/00_repo_layout.md
    Fill in:
    - covers: list every file in scripts/ + the meta-system docs in
      docs/
    - last_human_reviewed: today's ISO date
    - body: describe the meta-system layout

# Step 8: Verify clean baseline

Run pre-commit through the dep manager (uv run / poetry run / activate-venv-then-bare):

    uv run pre-commit run --all-files

If anything fails, FIX it before proceeding. Common first-run findings:
- MISSING_MANIFEST: run `uv run python scripts/update_manifest.py` first.
- Coverage gap (knowledge doc doesn't cover scripts/): add the new
  files to `docs/knowledge/00_repo_layout.md` covers: list and bump
  last_human_reviewed.
- Manifest drift (orphan_doc): re-run update_manifest after adding
  the knowledge doc.
- Validator-input-coverage: project-specific validators that read
  YAML need a paired test mentioning each YAML field they read.

Don't skip this verify step. The whole point of the substrate is
that the gates are RUN.

# Step 9: First commit

git add -A
git commit -m "Bootstrap: AGENT_SUBSTRATE_KIT installed + first ADR + knowledge doc

Establishes the substrate before any product code lands. Customized
AGENTS.md for this project. First ADR (0001-tech-stack) documents the
chosen stack with Alternatives Considered. First knowledge doc
(00_repo_layout) covers the meta-system files.

[no-postmortem: bootstrap commit; no bug being fixed]"

# Step 10: HISTORY append

Use the operator's dep manager prefix (uv run / poetry run / etc.):

uv run python scripts/append_history.py \
  --summary "Bootstrap AGENT_SUBSTRATE_KIT" \
  --files "AGENTS.md,scripts/,docs/decisions/0001-tech-stack.md,docs/knowledge/00_repo_layout.md,.pre-commit-config.yaml,.github/,pyproject.toml" \
  --intent "Establish substrate before product. AGENTS.md customized for <project>. First ADR documents tech stack with Alternatives Considered. First knowledge doc covers meta-system files. pyproject.toml bootstrapped with dev-tooling group." \
  --knowledge "AGENT_SUBSTRATE_KIT bootstrap complete. Next step: write the execution playbook (named in AGENTS.md project-specific section) and start product work. The substrate is self-enforcing from this point — gates fire on every commit." \
  --commit-hash "$(git rev-parse --short HEAD)"

git add docs/HISTORY.md docs/manifest.json
git commit -m "docs: HISTORY for $(git log -1 --format=%h HEAD~1)

[no-postmortem: docs-only follow-up; HISTORY append for parent
fix-commit, no behavior change]"

# Step 11: Operator handoff

Tell the operator (in the chat, NOT in a commit message):

  AGENT_SUBSTRATE_KIT installed + verified.

  Things YOU need to do (I can't from this side):
  1. Branch protection on main: GitHub Settings → Branches.
     Require status checks: pre-commit-and-tests, pip-audit.
  2. Dependabot enable: GitHub Settings → Code security →
     Dependabot version updates.
  3. (Optional) Test devcontainer: VS Code → "Reopen in Container".

  After those 3 are done, the substrate is fully active.

  First product work can start now. Read AGENTS.md before composing
  any non-trivial commit.

# Step 12: Snapshot the session

Before stopping (or before any long-running operation in the next
turn), snapshot:

uv run python scripts/session_handoff.py capture # "Substrate
bootstrap complete. Next: <whatever the operator says is next>."

That writes docs/CURRENT_SESSION.md so the next session can resume.

---

# Hard rules during bootstrap

- DO NOT skip the verify step (Step 8). Run pre-commit --all-files
  and address every finding.
- DO NOT use --no-verify on any commit during bootstrap. The whole
  point is that the gates are running.
- DO NOT customize the universal substrate scripts (scripts/check_*
  in the kit). Customize AGENTS.md and pre-commit-config.yaml only.
- DO NOT invent project details. Ask the operator when something is
  unclear (project name, playbook filename, tech stack details).
- DO NOT skip the postmortem template + ADR template + knowledge doc
  template files. They're load-bearing for future work.
- DO NOT skip the HISTORY append. It's the first entry — sets the
  precedent.

# What "done" looks like

After this prompt completes:
- AGENTS.md exists, customized
- scripts/ has 15-16 universal substrate scripts
- docs/decisions/0000-template.md + 0001-tech-stack.md
- docs/postmortems/_template.md
- docs/knowledge/_template.md + 00_repo_layout.md
- docs/HISTORY.md with bootstrap entry
- docs/manifest.json regenerated
- .pre-commit-config.yaml customized for this project
- .github/workflows/ci.yml present
- .github/dependabot.yml present
- .gitattributes has HISTORY merge=union
- .gitignore has substrate-aware exclusions
- pyproject.toml has dev-group deps (or [project.optional-dependencies].dev for pip)
- pre-commit hooks installed (commit stage always; commit-msg stage strict profile only)
- One verify-clean baseline run
- Two commits landed (bootstrap + HISTORY)
- Operator told what they need to do GitHub-side
- Session snapshotted

If any of those is missing, you're not done.

# Common failure modes during bootstrap

If you hit one of these, fix it before continuing:

- "Already exists" warnings from bootstrap.sh: the repo isn't empty.
  Ask the operator if it's safe to overwrite, or skip the offending
  file and document why.

- pre-commit run finds drift on first run: that's expected. Address
  each finding (usually doc-drift on knowledge/00_repo_layout.md;
  bump the date or add the file to covers:).

- mypy strict fires on untyped functions: project may not have type
  annotations yet. Either add them, or add an exclude to pyproject
  [tool.mypy] for the un-annotated module(s) and document why in a
  TODO comment.

- pytest fails because tests/ is empty: that's fine for bootstrap.
  Add tests/test_smoke.py with one trivial assertion to satisfy the
  hook. Real tests come later.

- check-validator-input-coverage fires: a substrate validator is
  missing its paired test. The kit ships paired tests for the universal
  validators — if a test is missing, copy from the source project's
  tests/ directory.

# Going forward

Once bootstrap is done, the substrate is self-enforcing. Read AGENTS.md
before any non-trivial commit. Follow the workflows in
docs/AGENT_SUBSTRATE_KIT/workflows.md (or the README of the source
project). Run audits periodically.

Build on top of this. The substrate is the foundation; the product
is what you put on top.
```

---

## Notes on running this prompt

**For the operator:**
- Replace `<PATH/TO/AGENT_SUBSTRATE_KIT>` with the actual path before pasting.
- The prompt is agent-agnostic — works with Claude, Codex, Cursor,
  or any LLM agent that can read/write files and run shell commands.
  Just paste it into a fresh session.
- After the agent finishes, you have the substrate but no product.
  The next session's prompt can start the actual product work.

**Expected duration:** 30-60 minutes for the AI to execute this
end-to-end on a fresh repo with operator answering questions about
project naming.

**The first audit:** within the first ~10 commits, run a full audit
round (`pre-commit run --all-files` + the meta-validators in
`workflows.md` workflow 10). Any findings now are bootstrap-era drift
— address them. After that, the substrate is in steady-state.
