# Intent

The Agent Substrate Kit is a **deterministic governance substrate for
AI-agent-driven repositories**. It installs the process discipline an agent
host does not provide for itself: tamper-evident memory, fail-closed policy
gates, docs/code parity, behavioral security evals, and verified release and
upgrade paths. It is designed to be dropped into a project, upgraded in
place, and trusted to say *no* deterministically.

## What it is

- **A governance layer around external agent hosts** (Claude Code, Codex,
  Copilot, Gemini). The host runs the agent loop; the substrate constrains
  and records what happens in the repository.
- **Deterministic.** Every gate is re-runnable code with a stable verdict.
  No model judgment sits anywhere in the enforcement chain — a rejected
  design (`docs/REJECTED.md`), not an omission.
- **Offline-complete at its base.** Memory, hooks, validators, evals, and
  the release bundle need no network, token, or remote service. Remote
  governance and deep scanners are explicit opt-in tiers above the base.
- **Fail-closed at trust anchors.** A missing capability is reported as
  missing; a present-but-unreadable or invalid trust input (a lock, a
  provenance baseline, a verifier) is refused, never treated as absent.
- **Progressive-disclosure.** The always-loaded surface stays small
  (AGENTS.md as a concise map); knowledge, skills, and auditor references
  load on demand and carry per-doc size budgets.

## What it is not

- **Not an agent runtime.** It does not schedule model calls, broker every
  tool, or manage run state. Hosts own their tool surfaces; the substrate
  mediates exactly what each host's hook API exposes (see the
  host-capability matrix in `docs/ARCHITECTURE.md`) and documents honestly
  what it cannot reach.
- **Not a sandbox.** The exfil guard is a tripwire for obvious patterns.
  Real containment is the sandbox tier (`SUBSTRATE_SANDBOX`) backed by an
  OS-level backend, or a contained host environment the operator attests.
- **Not a cryptographic authority by itself.** Local manifests, baselines,
  and knowledge text are deterministic evidence. The stronger anchors are
  the signed release artifact and the remote trusted-base freeze.

## Objectives, in priority order

1. An agent cannot silently turn a failed or inconsistent state into a
   claimed success.
2. Repository knowledge stays truthful: docs are drift-checked against the
   code they claim to cover, and claims can be asserted declaratively.
3. Sessions survive compaction, crashes, and handoffs between different
   agents with state that is verified against git, never trusted blindly.
4. Every hardening claim is proven by a behavioral eval or regression, not
   asserted in prose.

## Design principles the code enforces

- Verify what you **use**, not what you wrote (read-side sanitization,
  execute-the-bytes-you-verified).
- A trust anchor may not fail open; absence and unreadability are different
  states with different verdicts.
- Fix classes, not instances: mirrored code inherits defects, so shared
  implementations replace copies.
- Warn-only first for advisory signals; blocking is an explicit opt-in
  after dogfooding.
- The repository is the system of record. Anything durable lives in git;
  chat context on any host is disposable.
