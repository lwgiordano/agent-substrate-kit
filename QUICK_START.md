# Agent Substrate Kit v3 — Quick start

The 5-minute version. Read `README.md` for the full guide and
`CHANGES_V3.md` for why v3 differs from v2.

---

## Install (5 minutes)

```sh
cd <your-repo>
bash path/to/agent_substrate_kit_v3/bootstrap.sh          # standard profile, lang auto-detect
./manage.sh setup
```

That installs:

- `AGENTS.md` keystone (byte-stable; customize bottom section only)
- `.claude/settings.json` with lifecycle hooks: lint-on-write, todo
  mirror, compaction handoff capture/restore
- Core validators in `scripts/` + pre-commit config filtered to your
  profile and language
- 9 skills (`.claude/skills/`, `.agents/skills/`) + 7 read-only
  auditor agents for Claude and Codex
- `docs/` scaffolding: HISTORY (append-only), ADR + postmortem +
  knowledge templates, blind-spot checklists
- CI + scheduled-audit + agent-config-audit GitHub workflows

## What runs without you doing anything

| Event | What happens |
|---|---|
| Agent edits a file | `lint_on_write.py` lints it; errors feed back immediately |
| Agent updates todos | `todo_state_hook.py` mirrors to `docs/.todo_state.json` |
| Context compaction / session end | `session_handoff.py` captures state to `docs/CURRENT_SESSION.md` |
| New session starts | Handoff re-injected as additionalContext (verified against git) |
| `git commit` | Profile-filtered pre-commit gates (drift, secrets, harness, SHA, lint, tests) |
| Merge to main | CI re-runs all gates |

## Token economics (why v3 is shaped like this)

- Keystone byte-stable → prompt-cache hits (cache reads = 0.1x input price).
- Startup reads: keystone + last 5 HISTORY entries. Everything else
  just-in-time.
- Checklists (~26KB) and review prompts (~23KB) cost zero until a
  subagent reads them — never load them into the main context.
- Auditors return ≤500-token verdicts; exploration burns subagent
  context, not yours.

## First commits (10 minutes)

```sh
cp docs/decisions/0000-template.md docs/decisions/0001-tech-stack.md
$EDITOR docs/decisions/0001-tech-stack.md          # all 4 sections, esp. Alternatives Considered
$EDITOR AGENTS.md                                   # bottom project-specific section
git add -A && git commit -m "Bootstrap: agent substrate v3 installed"
python3 scripts/append_history.py \
  --summary "Bootstrap substrate v3" \
  --files "AGENTS.md,scripts/,docs/" \
  --intent "Establish substrate before product work." \
  --knowledge "Substrate v3 installed at profile <X>. Hooks handle lint/todo/handoff automatically." \
  --commit-hash "$(git rev-parse --short HEAD)"
git add docs/HISTORY.md docs/manifest.json && git commit -m "docs: HISTORY for bootstrap"
```

## Operator side (GitHub)

1. Branch protection on `main`: require CI green before merge.
2. Enable Dependabot version updates.

## When NOT to use this kit

Throwaway scripts, spikes, pre-product hobby projects. The kit is for
codebases built by LLM agents, with operator oversight, intended for
production, where mistakes compound. Start at `--profile starter` if
unsure; ratchet up when postmortems justify it.
