# Beginner Start Here

This kit installs a self-auditing AI engineering substrate into a Git repo.
It gives Claude Code, Codex, and humans the same rules, plus deterministic
scripts that run locally, in pre-commit, and in CI.

## Fast install

```bash
unzip agent_substrate_kit_v3.zip -d ~/ai-kits
mkdir -p ~/projects/my-project
cd ~/projects/my-project
bash ~/ai-kits/agent_substrate_kit_v3/bootstrap.sh --runner auto --workflow superpowers --ui no
./manage.sh setup
./manage.sh doctor
./manage.sh check
```

For UI-heavy projects:

```bash
bash ~/ai-kits/agent_substrate_kit_v3/bootstrap.sh --runner auto --workflow superpowers --ui yes
```

## Daily commands

```bash
./manage.sh doctor        # verify substrate wiring
./manage.sh check         # run normal local checks
./manage.sh audit         # write quick audit report
./manage.sh release       # run the full release gate
./manage.sh check         # run substrate + language gates
```

## What gets installed

- `AGENTS.md` — canonical instructions for Codex and other agents.
- `CLAUDE.md` — tiny Claude Code wrapper that imports `AGENTS.md`.
- `.agents/skills/` and `.claude/skills/` — reusable audit workflows.
- `.claude/agents/` and `.codex/agents/` — read-only auditor agents.
- `scripts/` — deterministic validators, doctor, audit, and release gate.
- `docs/` — HISTORY, ADRs, postmortems, knowledge docs, templates.
- `.github/workflows/` — CI, scheduled audit, and agent-config audit.
- `manage.sh` — one command center.

Use Superpowers as the default engineering workflow unless you specifically want GSD's phase/milestone project manager. Do not run both as competing primary controllers.
