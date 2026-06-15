# Substrate — Target Architecture & Locked Decisions

**Status:** Design direction for the next major version (post-v3.3.x). NOT yet
implemented. The current shipped kit is the internal-plumbing era; this document
defines the **compose-don't-build** re-architecture it migrates toward.
Authoritative record of the architecture decisions; supersedes prior roadmap notes.

Decisions locked via an adversarial design interview (gsd-grill) on 2026-06-13,
grounded in three adversarially-verified web-research passes (landscape →
quantitative benchmarks → architectural solutions).

## Goal

A public, drop-in tool: someone adds it to a repo (new project first), tells
their AI agent to run one command, and the repo is set up with an optimized,
secure, resilient, eval-proven governance process — automatically, and
upgradable over time. Cross-agent (Claude Code + Codex + Gemini), git-synced,
auditable by a stranger.

## Core principle

**Compose boring, audited primitives; build nothing new.** The only thing we
author and must keep excellent is the **governance profile (curation)** and the
**eval harness that proves it**. Everything else is deliberately-boring,
externally-audited delivery plumbing.

## The 7 locked decisions

1. **Trust model — sealed floor, agent verify-only.** The governance profile/
   validator bundle is signed by the maintainer's private key at release time;
   the user's environment and the AI agent get the **public key only (verify
   only)**. The agent can `verify → apply` but can never produce a valid
   signature, so it is **structurally incapable of authoring or forging config**.
   Bring-your-own-key (org re-signs a customized floor) is a later advanced
   feature, not v1.

2. **Sealed floor vs user zone.** The **sealed floor** (command policy,
   verify-apply bootstrap, deny rules, eval harness) changes only via a signed
   release. The **user zone** (project conventions, profile tier, egress
   allowlist, lint/test commands) is freely editable — it is **data the floor
   reads and validates**, never the trust root. `AGENTS.md` = a tool-owned
   managed governance block (generated from the signed floor, re-emitted on
   upgrade) **+** a user-owned free-text region. The block is a consistency/UX
   device, NOT a security control — all enforcement is execution-time
   hooks/policy/sandbox, so a poisoned instruction still dies at the policy hook.

3. **Sandbox — tiered, graceful-degrade (compose, never build isolation).**
   Deterministic command-policy + egress allowlist run always, everywhere. The
   OS sandbox (Anthropic `sandbox-runtime`: Seatbelt on macOS, bubblewrap+seccomp
   on Linux) runs where supported, else warn + degrade. Hard containment is the
   `strict+sandbox` profile and the CI tier (microVM/gVisor or hosted sandbox).
   The laptop sandbox is defense-in-depth (raises exfil cost), NOT containment.
   No Windows (WSL2 fallback).

4. **Invocation — agent invokes a trusted published one-command.** Entry point
   is a single published command (`uvx substrate-init` / `copier copy
   gh:<org>/substrate@vN`). Trust lives in the command's composition (copier +
   minisign + signed profile), not in who types it. The minisign **verify key
   ships inside the published installer package (PyPI/npm), NOT in the fetched
   repo**, so a malicious fork's profile fails verification (fork-proof,
   fail-closed).

5. **Cross-agent scope — Claude + Codex + Gemini at v1.** One source (`AGENTS.md`)
   fans out to per-agent files (`CLAUDE.md`, `AGENTS.md`/Codex, `GEMINI.md`) via
   managed BEGIN/END blocks. Generator stays extensible for Cursor/Aider later.

6. **Upgrade boundary — v1 upgrades substrate-created repos.** v1 ships
   new-project install **plus** safe in-place upgrade of substrate-created repos
   (`copier update` 3-way merge on a version-pinned `.copier-answers.yml` + a
   drift-check CI gate). Only the retrofit of pre-existing repos is deferred to
   v2. The upgrade channel is the realistic form of "self-reinforcing" — improved
   signed profiles propagate, and the eval harness guarantees they can't regress.

7. **Product value — the eval harness (proof) is the moat.** All plumbing is
   commodity. The defensible value is eval-proven governance: not config someone
   *thinks* is good, but governance *measured* to block what it claims, re-proven
   every release. Value = eval harness × profile quality. Pitch: *"eval-proven
   governance any agent applies in one command."*

## Integrated reference architecture (compose these named layers)

| Layer | Compose | Role |
|---|---|---|
| Distribute + apply + upgrade | **Copier** (`.copier-answers.yml`, 3-way merge, migration scripts) | init + safe in-place upgrade of substrate-created repos |
| Trust root | **minisign** (Ed25519 detached sig), key embedded in installer package | verify-before-apply, fail-closed; replaces AST/hash/base64 self-integrity |
| Proof | **eval harness** (KEEP — the moat) | prove governance behavior post-apply + as a release gate |
| Sandbox (laptop) | **Anthropic `sandbox-runtime`** + default-deny egress allowlist | defense-in-depth where supported |
| Sandbox (CI) | microVM/gVisor or e2b/Daytona | real containment for untrusted execution |
| Cross-agent | **thin in-house generator**: AGENTS.md → per-agent managed blocks | flawless Claude/Codex/Gemini; no heavy dependency |

**The subtractive win:** a minisign signature answers "were our validators
tampered with?" in ~50 auditable lines, so the current self-integrity machinery
(whole-module AST pins, hash-pinned regex, base64'd danger strings) is **deleted**,
not ported. Trusted core collapses to: *verify signature → apply via Copier →
prove with evals.*

## v1 scope vs deferred

- **v1:** new-project install via trusted one-command; signed profile
  (verify-then-apply, fail-closed); eval harness as proof + release gate;
  AGENTS.md→CLAUDE.md/Codex/Gemini managed-block generator; tiered sandbox;
  upgrade of substrate-created repos; profiles starter/standard/strict(+sandbox).
- **Deferred → v2:** retrofit of pre-existing repos; bring-your-own-key org
  signing; Cursor/Aider targets; MCP intake layer; GEPA-style profile
  self-optimization (needs a real-world quality signal first).
- **Defer / frontier (do not promise):** autonomous self-re-architecting;
  agentic-OS / portable-identity interop ("dial-up era"); knowledge-graph memory
  (file-based structured-JSON memory is settled — graph benchmarks failed
  independent reproduction).

## Honest flags

- **Composition risk:** every primitive is individually proven (primary
  sources), but the full stack has never been observed running together. Wire it
  on a branch and test the seams before claiming it works.
- **Sandbox is defense-in-depth, not a wall.** Documented escapes exist; never
  market the laptop tier as containment.
- **`sandbox-runtime` is experimental + macOS/Linux only.** Pin a version;
  Windows needs WSL2.
- **Validate with real repos.** The substrate has been validated against an
  adversarial AI reviewer, not real users. Before scaling effort, put v1 in 2–3
  real repos (Claude + Codex) and replace the AI-judge signal with real usage.

## First build (sequence)

The spine, not the sandbox: **minisign trust root + Copier skeleton, with the
existing governance core + eval harness as the signed profile.** That is what
lets the clever self-integrity code be deleted and gives every other layer a
verifiable backbone. Sandbox is layer 4.
