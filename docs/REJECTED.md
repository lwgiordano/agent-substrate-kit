# REJECTED.md — Append-only log of rejected approaches

**DO NOT EDIT prior entries.** Append only via `./manage.sh reject`
(`scripts/append_rejected.py`). The newest entries are injected at SessionStart
so a future session does not re-propose something already ruled out.

This file is `merge=union` in `.gitattributes` — concurrent branches' entries
combine without conflicts.

For a decision that needs full context and consequences, write an ADR in
`docs/decisions/` instead; this file is for one-liners.

- [2026-07-29T19:41:23Z] Raising ABSOLUTE_MAX_CONTEXT_CHARS to fit a new injected block — rejected because operator review of PR #4 chose separate per-block budgets instead; a new block must take existing headroom
- [2026-07-29T19:41:24Z] Executing commands declared in knowledge-doc front-matter — rejected because it makes agent-writable repo prose executable, which this threat model refuses; use declarative assertions
- [2026-07-29T19:41:24Z] LLM-judged checks anywhere in the gate chain — rejected because gates must be deterministic and re-runnable; a model verdict is not reproducible evidence
- [2026-08-09T15:33:43Z] O_APPEND direct write for the append-only logs — rejected because an O_APPEND fd writes through a hard-linked leaf, regressing the v3.8.25 no-write-through-links invariant; serialize writers with a parent-directory flock around the existing replace instead
- [2026-07-30T12:09:16Z] Split the substrate knowledge document into chronological version-range files — rejected because It preserves release-note narration instead of subsystem contracts, so progressive disclosure remains poor and future growth repeats the same problem
- [2026-07-30T17:07:35Z] Keep one substrate knowledge document and only trim duplicated release paragraphs — rejected because The document would still couple unrelated subsystems and would exceed the context budget again as those subsystems evolve
- [2026-08-10T11:49:33Z] Put project-authored docs/superpowers under substrate OPTIONAL_DIRS — rejected because write_install_json consumes OPTIONAL_DIRS as install ownership, so normal plan edits would enter provenance and falsely block upgrades; use GOVERNED_OPTIONAL_DIRS to require scanning, CODEOWNERS, and CI review without install drift ownership
- [2026-08-10T12:17:02Z] Treat every docs/knowledge sibling as substrate install-owned — rejected because Project-authored knowledge would enter install provenance, so ordinary knowledge edits would falsely block later upgrades. Govern the directory recursively, but baseline only the generated 00_substrate.md and installed _template.md.
- [2026-08-10T12:46:55Z] Make a pre-v3.8.32 target upgrader transparently apply the future knowledge-ownership migration — rejected because The target manage.sh dispatches its already-installed old substrate_upgrade.py before new code is installed, so it cannot know a future baseline rule. The boundary crossing must run the verified new kit's engine against the old target; later steady-state upgrades may use the target CLI normally.
- [2026-08-28T03:16:05Z] timestamp-wide AGENT_BUS evidence carve-out — rejected because It trusts a line's claimed date or surrounding context; the accepted design pins only exact already-published line-number plus content-hash pairs, so new backdated, duplicated, or continuation text still scans verbatim.
