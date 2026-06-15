# Contributing

This project uses the Agent Substrate Kit substrate. Read [`AGENTS.md`](AGENTS.md)
before any non-trivial commit — it's the keystone that explains the
repo's discipline.

## Quick start

```sh
git clone <repo-url>
cd <repo>
uv sync --group dev          # or: poetry install --with dev / pip install -e ".[dev]"
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg
```

After installing hooks, every `git commit` runs the substrate's
profile-dependent gates (starter ~6, standard ~10, strict ~13). The first commit may need a re-run after auto-fixers
modify files (this is normal pre-commit behavior).

## What lives where

- `AGENTS.md` — instructions for AI agents (read first, every session)
- `docs/HISTORY.md` — append-only project changelog (use `scripts/append_history.py`)
- `docs/decisions/` — Architecture Decision Records (ADRs)
- `docs/postmortems/` — bug/incident postmortems
- `docs/knowledge/` — subsystem documentation with `covers:` lists
- `scripts/` — substrate validators + helpers
- `tests/` — unit + integration tests

## Workflow

1. **Branch**. `git checkout -b <username>/<short-description>`.
2. **Read AGENTS.md** if this is a non-trivial change.
3. **Write the change**. The substrate enforces:
   - Knowledge-doc coverage for new modules
   - ADR for any decision picking one approach over alternatives
   - Postmortem for any bug fix (or `[no-postmortem: <reason>]` opt-out)
   - Four-field bug-fix protocol on commit messages
4. **Commit**. `git commit -m "<conventional-commit-style message>"`.
   Prefix with `fix:`, `feat:`, `bug:`, `docs:`, `refactor:`, etc.
5. **Append HISTORY** after the commit lands:
   ```sh
   uv run python scripts/append_history.py \
     --summary "<one line>" \
     --files "<paths>" \
     --intent "<why>" \
     --knowledge "<what future sessions need>" \
     --commit-hash "$(git rev-parse --short HEAD)"
   git add docs/HISTORY.md docs/manifest.json
   git commit -m "docs: HISTORY for $(git log -1 --format=%h HEAD~1)"
   ```
6. **Push + PR**. CI will re-run all gates. Branch protection requires
   green CI + Code Owner approval before merge.

## Bug fixes

When you fix a bug, the commit-msg hook will require four fields:

```
fix(<area>): <one-line summary>

Bug class:           <one-line — the GENERAL pattern, not the symptom>
Cluster searched:    <grep command + result count>
Lock-down:           <mechanism + path>
Verbatim-shape verified: <yes/no with evidence>
```

See [`docs/templates/finding_response.md`](docs/templates/finding_response.md)
for the full template.

## Code style

- **Python**: ruff (lint + format), mypy strict, line-length 100.
- **Tests**: pytest, hypothesis for property-based tests.
- **Commits**: conventional-commit-style subjects.
- **Documentation**: every subsystem has a `docs/knowledge/<area>.md`
  with `covers:` listing the files it documents.

## Reporting bugs

- **Security vulnerabilities**: see [`SECURITY.md`](SECURITY.md). Do
  NOT use public issues for security reports.
- **Other bugs**: open a GitHub issue with reproduction steps,
  expected vs actual behavior, environment info.

## Reviewing

- Be specific: cite file:line, propose alternatives.
- Block-on-merge: anything that would degrade the substrate's
  discipline (skipping a postmortem, weakening a validator).
- Approve quickly when the substrate has done the heavy lifting
  (gates passed, knowledge doc updated, postmortem written).

## Code of conduct

Be kind. Assume good faith. When in doubt, escalate to maintainers.

---

*Customize this template for your project's specific tooling,
branch model, and review SLAs.*
