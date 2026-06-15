@AGENTS.md

## Claude Code specific

- Hooks already lint every write, mirror TodoWrite state, and capture
  session handoffs — trust them; do not re-implement their work.
- Use project skills for repeatable procedures instead of expanding
  this file. Skills are progressive-disclosure: their reference files
  load only on demand.
- Use read-only auditor subagents for audit passes; require compact
  (≤500 token) verdicts back.
- Do not claim completion until relevant deterministic checks pass.
- For substantial changes, run the self-audit skill before the final
  response.
