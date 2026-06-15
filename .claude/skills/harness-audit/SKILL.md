---
name: harness-audit
description: Audit the AI-agent substrate itself — AGENTS.md, Claude/Codex configs, skills, hooks, MCP wiring. Use after editing any agent-facing config, when onboarding a new MCP server, or on a periodic schedule.
---

# harness-audit

The substrate is attack surface: prompt-injection phrases, leaked
secrets, and dangerous commands can hide in agent configs the same
way bugs hide in code.

## Mechanical pass

```bash
python scripts/check_agent_harness.py
```

Scans AGENTS.md, CLAUDE.md, `.claude/**`, `.codex/**`, `.agents/**`,
`.mcp.json`, workflows for: secret patterns, the permission-bypass
flag, curl/wget-pipe-shell, destructive rm, prompt-injection phrases.

## Manual pass (the regexes are shallow — this part matters)

Spawn the `harness-auditor` subagent for substantial config changes.
Things the regexes cannot catch:

1. New MCP servers: who publishes it? what scopes does it get?
2. Hook commands: do they run only project-local scripts? Any hook
   invoking a network fetch or non-pinned binary is a finding.
3. Skill instructions that weaken hard rules ("you may skip checks
   when...") — instruction-level privilege escalation.
4. settings.json permission widening (new allow rules, removed denies).

## Cadence

- After every agent-config edit (pre-commit covers the mechanical pass).
- `.github/workflows/agent-config-audit.yml` re-runs it on push.
- Full manual pass quarterly or after adding any external MCP server.
