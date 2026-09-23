# 0002: Freeze local anchor hardening at a declared threat-model boundary

**Status:** Accepted
**Date:** 2026-09-23
**Deciders:** operator, claude
**Related:** [The memory trust anchor](../knowledge/08_memory_anchor.md),
[postmortem: write-through links recurrence](../postmortems/2026-08-24-write-through-links-recurrence.md)

## Context

Codex rounds 34–39 each found real defects in how the release gate and
`memory_log.py` establish that the memory chain is the one that was anchored.
Every finding was fixed, with a discriminating regression. But the findings
per round went 2, 3, 3, 1, 4, 7 — diverging, not converging — and almost all of
them share one shape: a process running as the same OS user, concurrently with
the gate, rewrites a file the gate is reading (config, loader, log, note) in the
window between two reads.

No local control can close that class. The attacker can write every byte the
verifier can read, including the verifier. Each fix moved the window; none can
remove it. Continuing to chase it spends release cycles on a guarantee the
architecture cannot give, while the controls that DO bound it (publishing the
anchor off-machine, branch protection, CODEOWNERS) stayed unconfigured.

## Decision

1. **In scope for local controls:** accidental and sequential tampering —
   an agent or human editing memory, config, HISTORY, or the note between
   runs; malformed, duplicate, non-regular, or symlinked inputs; a gate that
   certifies a state other than the one it checked; fail-open on absence;
   readers of one file that disagree; user/system git config redirecting
   which server answers. Findings here are still taken and fixed.
2. **Out of scope for local controls:** a same-user process that rewrites the
   repository, the substrate scripts, or the git objects WHILE a gate runs,
   with timing chosen against it. The mitigation is off-machine: publish the
   anchor (`refs/notes/substrate-memory` on origin), protect the branch, and
   require CODEOWNER review of `scripts/` and `.substrate/`. The local check
   reports honestly which tier it reached (`verified against origin` vs
   `LOCAL-ONLY`) and never claims more.
3. **Findings that cross the boundary are still taken** when they show a
   sequential attack, a false positive claim of remote verification, or a
   gate that reports success over a state it did not check. A finding that
   requires mid-run concurrent rewriting is logged as accepted-out-of-scope
   with a pointer to this ADR, not remediated.
4. **The effort freed goes to the remote controls** and to lesson delivery
   (the substrate's retrieval and memory gaps), which is where the operator's
   production-readiness gaps are.

## Consequences

- **Positive:** release cycles stop on a non-converging class; the threat
  model is written down, so a finding can be triaged against it in one step;
  production hardening moves to the controls that actually bound the risk.
- **Negative:** a concurrent same-user rewrite of the repo during a release
  can still produce a green local gate. That was always true; now it is
  stated. An unpublished anchor gives no protection against a patient
  same-user attacker.
- **Neutral:** no code changes. Existing snapshot, pin, and re-verify logic
  stays — it closes the sequential cases and costs little.

## Alternatives Considered

- **Keep hardening every reported window.** **Rejected because:** the class
  is unbounded locally; six rounds of data show the finding count rising, and
  each fix is a new surface for the next round.
- **Sign the chain with a local key.** **Rejected because:** a same-user
  attacker can read the key; it moves the secret, not the boundary.
- **Run the gate under a separate OS user or container.** **Rejected for the
  base tier because:** it breaks offline-complete, zero-infra installs. It
  remains the right answer for a consumer who needs it, via the sandbox
  backend, and can be revisited as an opt-in.
- **Require publication at every tier.** **Rejected because:** the base tier
  promises offline-complete operation; strict already requires publication.
