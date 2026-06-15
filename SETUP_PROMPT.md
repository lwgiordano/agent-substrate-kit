# Setup prompt — drop this substrate into a repo

Paste ONE block below to your AI agent (Claude Code / Codex) from inside your
target project. The agent runs a fixed, deterministic install. After that the
substrate's hooks self-manage (Bash exfil guard, lint-on-write, session
handoff) and `manage.sh check` / CI gate every commit.

## A. From a local copy of the kit (no network)

> Run `bash /ABSOLUTE/PATH/TO/agent-substrate-kit/bootstrap.sh --target . --install-tools`,
> then `./manage.sh check && ./manage.sh evals`, and report the results.

## B. From GitHub (this repo; uses your `gh` auth — works while the repo is private)

> Run `gh repo clone lwgiordano/agent-substrate-kit /tmp/ask && bash /tmp/ask/bootstrap.sh --target . --install-tools && ./manage.sh check && ./manage.sh evals`,
> then report the results.

## What it installs

- `scripts/` (validators + hooks), `.substrate/config`, `AGENTS.md` + per-agent
  wiring (Claude `.claude/`, Codex `.codex/`, Gemini `GEMINI.md`, Copilot
  `.github/`), CI workflows, and a `docs/` scaffold.
- Profiles: `--profile starter|standard|strict` (default `standard`).

## After install

- `./manage.sh go-live` — readiness report (repo-local vs production-hardened);
  `./manage.sh go-live --json` for machine-readable output.
- `./manage.sh evals` — prove the policy BEHAVES (block-rate / false-positive-rate).
- `./manage.sh check` — full validator chain + lint/typecheck/test + pre-commit.

## Honest scope

Today the agent runs `bootstrap.sh` (the existing installer). The fully
automatic *signed one-command* flow (`uvx`-style, minisign-verified profile,
Copier upgrades) is the `DESIGN.md` target — not yet built. Runtime containment
(the `strict+sandbox` profile) is the next capability (v3.4.x); until then the
exfil guard is a tripwire, not a sandbox.
