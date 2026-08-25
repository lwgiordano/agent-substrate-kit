---
purpose: Command policy, hooks, sandboxing, and local or remote governance.
asserts:
  - scripts/command_policy.py::looks_dangerous_command
last_human_reviewed: 2026-08-25
covers:
  - manage.sh
  - scripts/_substrate_config.sh
  - scripts/_substrate_surfaces.py
  - scripts/_text_safety.py
  - scripts/check_dep_cooldown.py
  - scripts/check_exfil_guard.py
  - scripts/check_github_governance.py
  - scripts/check_hook_smoke.py
  - scripts/check_policy_code_integrity.py
  - scripts/check_substrate_config.py
  - scripts/check_validator_input_coverage.py
  - scripts/command_policy.py
  - scripts/copilot_hook_adapter.py
  - scripts/lang_gate.sh
  - scripts/remote_detect.py
  - scripts/sandbox_detect.py
  - scripts/sandbox_exec.sh
  - scripts/setup_branch_protection.sh
  - scripts/substrate_profile.py
---

# Policy and governance

[Back to the substrate map](00_substrate.md).

The substrate evaluates command and configuration data through deterministic
parsers. `.substrate/config` is never sourced. Invalid keys, malformed lines,
dangerous configured commands, and attempts to lower frozen capability floors
stop the gate before project commands run.

## Command and hook policy

`command_policy.looks_dangerous_command` is the shared policy seam for configured
and interactive shell checks. The policy blocks destructive filesystem forms,
credential or environment disclosure, dangerous Git history changes, upload or
exfiltration patterns, and command constructions the strict profile cannot prove
safe. Structural integrity checks pin the policy's regex and AST shape so a
compile-clean allow-all replacement does not pass.

Claude, Codex, and Copilot adapters normalize their host payloads into the same
decision. Malformed or missing shell payloads fail closed when containment is
required. Hook smoke tests exercise denial behavior rather than checking only
that a script parses.

## Sandbox and exfiltration

Sandbox detection resolves an available backend from configuration and host
capability. Execution uses a secretless allow-listed environment and marks the
contained child. Language gates, configured lint/typecheck/test commands, and
release tests route through `sandbox_exec.sh` when sandbox mode is enabled.

When `.substrate/required_sandbox=1`, interactive commands require a host-bound
containment proof: a routed sandbox marker, a supported Claude strict-sandbox
configuration for a Claude invocation, or an explicit operator attestation.
Claude settings do not prove containment for Codex, Copilot, or an unknown host.
Codex-native host detection remains unavailable; routing and attestation cover
that case. Missing proof blocks rather than downgrading.

## Local and remote governance

Strict local mode requires operational and security checks but does not require a
GitHub-only CODEOWNERS file. Remote governance is an orthogonal capability locked
by `.substrate/required_remote_governance`. Enabling it requires CODEOWNERS
coverage and the trusted-base workflow. Offline detection reads Git config only
and never claims live branch protection is active; `enable remote --check` is the
operator path for live verification.

The canonical surface inventory feeds harness scanning, strict ownership, and CI
audit triggers. It distinguishes substrate-owned install surfaces from governed
project-authored context such as knowledge siblings and execution plans: both
require review, but only generated or install-supplied knowledge files enter the
install drift baseline. Deterministic parity tests pin the critical cross-list
mappings and the doctor's fail-safe fallback.

Dependency cooldown and security scanner tiers are explicit. Offline or missing
backend states report skipped or unavailable instead of false success, and a
required tier blocks when its evidence cannot be produced.

Frozen `.substrate/required_*` locks fail closed at every reader: an absent
lock means no lock was pinned, but a present lock that is a symlink, a
**hard link** (`st_nlink > 1`), a directory, a FIFO/special file, unreadable,
undecodable, out-of-domain, or padded beyond a few bytes fails the config gate,
and the exfil guard treats such a sandbox lock as containment-required. The
reader opens with `O_NOFOLLOW | O_NONBLOCK` (a symlinked lock is never followed
to an attacker-controlled value; a FIFO fails fast instead of hanging the hook),
checks `st_nlink > 1` on the fstat result (a hard link IS a regular file, so
`O_NOFOLLOW`+`S_ISREG` alone would read a shared outside inode's value), and
reads the whole small-bounded content (a `0`-then-padding-then-`1` file cannot
be truncated into a lowering value). Permission flips are not content drift, so
a malformed lock must never be cheaper than a governed edit. An absent
`.substrate/config` does not bypass the locks either — every pinned minimum
above a default fails the gate rather than vanishing with the file.
