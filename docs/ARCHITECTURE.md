# Architecture

Component map, data flow, trust boundaries, threat model, and the
host-capability matrix. Contracts live in `docs/knowledge/01–07`; this file
is the system-level view that connects them.

## Components

| Component | Entry points | Role |
|---|---|---|
| Gate chain | `manage.sh check`, pre-commit, CI `checks` | Deterministic validators: config-as-data, doc drift, manifest, harness scan, policy integrity, secrets, HISTORY SHA resolution, lint/typecheck/test |
| Hook layer | host hook configs → `scripts/*.py` | Per-event mediation: Bash tripwire + containment gate, lint-on-write, todo mirror, session capture/restore, completion nudge |
| Memory | `scripts/memory_log.py`, `scripts/session_handoff.py` | Hash-chained event journal (tamper-evident), structured session snapshot (sanitized on read), SessionStart injection under fixed budgets |
| Knowledge layer | `docs/knowledge/`, `scripts/check_doc_drift.py`, `scripts/context_report.py` | Functional contract docs with coverage, declarative `asserts`, review dates, and warn-only size budgets |
| Policy | `scripts/command_policy.py`, `scripts/harness_patterns.json` | Single shared detection source used by both the Bash hook and the config-value validator |
| Evals | `scripts/run_substrate_evals.py` | Behavioral proof: malicious tasks must be blocked, benign tasks must pass, in kit and installed layouts |
| Release / upgrade | `package_release.sh`, `scripts/release_gate.sh`, `scripts/substrate_upgrade.py` | Artifact packaged (signed when a maintainer key is present, else honestly unsigned), gate re-run from the built artifact, verified in-place upgrade with ownership migration |
| Coordination | `AGENT_BUS.md`, `docs/HISTORY.md`, `docs/REJECTED.md` | Append-only, git-carried records for multi-agent claims, history, and rejected designs |

## Data flow

1. **Session start**: host fires SessionStart → `session_handoff.py restore`
   rebuilds context from the structured snapshot plus sanitized HISTORY and
   REJECTED tails, all under fixed character budgets, all sanitized at read
   time.
2. **During work**: PreToolUse guards Bash; PostToolUse lints writes and
   mirrors todo state; every durable change lands in git-tracked files.
3. **Compaction / session end**: capture writes the structured snapshot and
   appends a hash-chained memory event.
4. **Commit**: pre-commit runs the full gate chain; commits that fail any
   deterministic check do not land.
5. **Release**: the artifact is packaged and the gates re-run from the built
   artifact before a release is claimed. Signing is CONDITIONAL — with a
   maintainer key (`SUBSTRATE_RELEASE_SECKEY` + minisign) the artifact is
   signed and self-verified against the committed trust pubkey, and a claimed
   signature that fails that check aborts the build; without a key the package
   is honestly reported as UNSIGNED rather than blocked. Signature is the
   consumer's authenticity anchor at upgrade time, not a packaging gate.

## Trust boundaries

- **Trusted**: the verified release artifact; the remote trusted-base freeze
  (when the remote tier is on); frozen `.substrate/required_*` locks —
  readable content only. A present lock that cannot be read or parsed is
  treated as tampering and refused at every reader.
- **Deterministic evidence, not authority**: local manifests, drift
  baselines, `docs/manifest.json`, knowledge text, install provenance.
  These make tampering detectable and inconsistency fatal; they do not
  survive an attacker who can rewrite all of them plus the code together.
- **Untrusted**: agent/tool output, repo prose (including this file),
  `.substrate/memory/**` (untracked, agent-writable — sanitized at read),
  anything fetched from outside. Repo prose is never executable: knowledge
  `asserts:` are declarative substring checks, and no gate takes
  instructions from documents.
- **Known limit**: a process with concurrent write and execute access can
  force operations to abort. The substrate's claim is that such a process
  cannot convert a failed state into a *claimed success* that survives the
  gates, the signed release, and (when enabled) the remote freeze.

## Threat model

Adversary: an agent session (or compromised tool output steering one) with
full write access to the working tree, able to run commands the hooks
allow, but unable to alter the remote trusted base or the signed release.

| Threat class | Primary defense |
|---|---|
| Prompt injection via repo text (HISTORY, todos, handoff snapshot, plan files) | Read-side sanitization chain; harness scanner over all agent-read context globs; injection evals |
| Disabling or weakening gates (edit hooks, config, policy) | AST-pinned policy integrity checks, behavioral hook-deny evals, trusted-base freeze, CODEOWNERS on the remote tier |
| Trust-anchor erosion (locks, baselines, provenance) | Fail-closed reads (absent ≠ unreadable), authority snapshots re-compared before writes, content vouching at bootstrap |
| Verify/execute gaps (bytecode caches, symlinks, hard links, TOCTOU) | Execute-the-bytes-you-verified loaders, lstat-based signatures, exact-parent writes, replace-inside-lock appends |
| Exfiltration via shell | Pattern tripwire (shared policy) + containment requirement under the sandbox tier |
| Memory forgery (fake history, forged snapshots) | SHA-resolved HISTORY entries, hash-chained event log, read-side field sanitization |
| Supply chain (upgrade source, release artifact) | Signature verification with a pinned verifier closure, drift gate before render, fail-closed baseline oracle |

Out of scope: a malicious operator, a compromised host binary, kernel-level
attackers, and network egress by tools the host does not route through
hooks (see the matrix below).

## Host-capability matrix

What each host actually lets the substrate mediate. Everything else is
governed only by the host's own permission model — an honest boundary, not
a substrate feature.

| Capability | Claude Code | Codex | Copilot agent | Gemini |
|---|---|---|---|---|
| Bash pre-execution guard | yes (PreToolUse, exit 2 blocks) | yes (PreToolUse via hooks.json, trusted-hash gated) | yes (preToolUse → permissionDecision via adapter) | no hook API — instructions only |
| Lint on every write | yes (PostToolUse Edit/Write) | no (edits arrive as patches; run `./manage.sh check`) | no | no |
| Todo-state mirror | yes (PostToolUse TodoWrite) | no | no | no |
| Session capture/restore | yes (SessionStart restore + PreCompact/SessionEnd capture) | yes (SessionStart restore + Stop capture, via hooks.json) | yes (sessionStart restore + sessionEnd capture, via .github/hooks/exfil-guard.json) | no |
| Completion nudge (Stop) | yes (opt-in gate) | Stop wired to capture (no completion-gate nudge) | no | no |
| Non-Bash tools (Read/Edit/MCP/web) | host permission rules, not substrate hooks | host approval model | host approval model | host model |

Row source of truth: the host hook-config files themselves —
`.claude/settings.json`, `.codex/hooks.json` (SessionStart, PreToolUse, Stop),
and `.github/hooks/exfil-guard.json` (sessionStart, sessionEnd, preToolUse).
Codex and Copilot capture/restore the SAME session_handoff.py state Claude
does; what Claude alone has is per-edit lint/todo hooks and the opt-in
completion-gate nudge. This table is drift-checked against those configs.

Consequences the substrate accepts and documents rather than papers over:
non-Bash tool calls are not command-policy-mediated on any host; Codex and
Copilot lack the per-EDIT lint/todo hooks Claude has and must rely on the gate
chain (commit-time) for that coverage; and an unknown host gets fail-closed
treatment wherever a proof is host-bound (containment proofs do not transfer
between hosts).
