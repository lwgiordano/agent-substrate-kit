# 0003: Record what the hooks decide, and let people judge it

**Status:** Accepted
**Date:** 2026-10-31
**Deciders:** operator, claude
**Related:** [Policy and governance](../knowledge/04_policy_governance.md),
[Memory and sessions](../knowledge/03_memory_sessions.md)

## Context

The kit proves its rules in two ways. Evals measure block and false-positive
rates on fixtures, and `prove` shows that each guard's tests fail without it.
Neither says what the rules do in real sessions: which exfil rules block real
commands, which ones operators override, how often lint finds something, how
large the injected session context is, and which lessons are ever injected.

Without that, gardening runs on opinion. A rule that keeps blocking legitimate
work looks the same as one that never fires, and a lesson whose trigger points
at a renamed path keeps its place in the file. A 2026 survey of public agent
harnesses found few repositories that record harness usage at all. Its advice
is that scripts should measure and never judge, and that the agent or operator
should judge and never measure.

## Decision

1. Four hooks record one event per decision: exfil guard, lint-on-write,
   completion gate and session start. The log is `.substrate/usage/events.jsonl`.
   Each event holds the hook, its outcome, the fixed rule name, small integer
   counts and injected lesson ids. It never holds the command, a path, findings,
   prompt text or environment values. The writer keeps only those fields and
   strips the rule name to a fixed character set.
2. Recording happens after the verdict is fixed, never raises and never prints.
   An unsafe log (a linked directory or leaf, a hard link, or a non-directory)
   is skipped and the verdict stands. `SUBSTRATE_USAGE_LOG=0` turns it off.
3. The log is local runtime state. It is Git-ignored and left out of receipts
   and release packages. It rotates once at 2 MiB. The test suite, evals and
   hook smoke turn it off, so the log holds only real agent work.
4. `./manage.sh usage` reports. Blocks and overrides are counted per rule
   separately: an override where a rule would have blocked is an operator
   calling that block a false positive. Lessons count as never injected only
   once at least five session starts are in the window. The log is a local
   file anything can append to, and an agent may read the report, so the
   report re-checks every field. It shows only rule names a hook writes;
   anything else reads as unrecognized. The report changes no rule, threshold
   or lesson; any prune is a reviewed change like any other.

## Consequences

- Gardening has evidence. A rule overridden often is a false-positive
  candidate, and a lesson never injected is a stale-trigger candidate.
- Exfil rules that never fire are expected to stay silent. The report does
  not list them as prune candidates.
- A rotation race between two hooks can drop the older file. The log is
  evidence for a person to weigh, so it may be incomplete; nothing depends on it.
- The Copilot adapter decides in-process and does not record yet. "ok" from
  lint-on-write includes a linter that is not installed.

## Alternatives Considered

- **Auto-prune or auto-tune rules from usage:** rejected. A script that judges
  would turn a measurement bug into a weakened guard, the failure the kit
  exists to prevent.
- **Log commands or paths for richer analysis:** rejected. The log would become
  a second copy of what the exfil guard keeps in place.
- **Store usage in the memory chain:** rejected. Usage is high-volume and
  loss-tolerant, while the chain is append-only evidence that is verified and
  anchored. Mixing them would make the chain noisy and its verification slower.
