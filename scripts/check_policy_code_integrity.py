#!/usr/bin/env python3
"""Pin the ENTIRE policy/scanner module SOURCE — not just selected definitions.

Pinning named functions and regex assignments was still bypassable: an
attacker can append arbitrary top-level code AFTER the pinned nodes that
mutates the live globals — `globals()["_NET_UPLOAD_FILE"] = <fake>` where the
fake preserves `.pattern` (so the hash check passes) but overfits `.search()`,
or `INJECTION = [(label, <fake>)]` reassigning the scanner's pattern list
(the v3.2.18 findings). Per-node pins don't see the extra top-level code.

So this validator pins the WHOLE SOURCE of the security-critical policy code:
  - command_policy.py      (the shared command-danger detection)
  - check_agent_harness.py (the agent-context scanner)

ANY byte change — a new statement, a reassignment, a fake object, a reordering,
even a comment or whitespace edit — moves the hash and BLOCKS. There is no
top-level code (nor a hidden-in-a-comment trick) these files can carry that the
pin does not cover. Weakening requires an explicit, reviewed pin update in this
CODEOWNED file.

Hash: SHA-256 of the raw UTF-8 source bytes. This is VERSION-PORTABLE — the
same on every CPython — which the prior `ast.unparse` normalization was NOT:
`ast.unparse` formatting differs across minor versions (e.g. 3.11 vs 3.13), so
a pin generated on one interpreter FALSELY BLOCKED on another (CI runs 3.11
against a 3.13-generated pin → spurious "module changed"; the v3.4.3 fix).
Hashing raw bytes is also STRICTER (a comment-channel weakening cannot slip
through); the only cost — a comment/whitespace edit now needs a reviewed
re-pin — is the intended posture for these CODEOWNED files, and the strict
trusted-base audit already freezes all of `scripts/` against the base branch.

--root DIR: validate the policy code under DIR/scripts instead of this
script's own directory. PINS always come from THIS (trusted) file, so a CI
job can run the base-branch validator against a PR workspace.

Run BEFORE check_harness_smoke / check_hook_smoke.
Exit: 0 ok | 1 module changed / unreadable. Stdlib only.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Canonical SHA-256 of the raw UTF-8 source bytes of the shipped policy code.
# Regenerate with:
#   shasum -a 256 scripts/command_policy.py scripts/check_agent_harness.py
# (identical on every Python — see the module docstring on why raw bytes, not AST).
MODULE_SOURCE_SHA256 = {
    "command_policy.py": "f60c5f5a47ffe5567edbb0241a57f696a5f7b5b9393173c087068079bc924809",
    "check_agent_harness.py": "07caeba1123e2fc12f56d94669c8e6812d27d754138b10b43f8c1b477bf9f3e1",
}


def _target_scripts(argv: list[str]) -> Path:
    if "--root" in argv:
        return Path(argv[argv.index("--root") + 1]).resolve() / "scripts"
    return Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    scripts = _target_scripts(argv)
    failures = []
    for rel, want in MODULE_SOURCE_SHA256.items():
        src = scripts / rel
        try:
            got = hashlib.sha256(src.read_bytes()).hexdigest()
        except Exception as e:
            print(f"check-policy-code-integrity: BLOCK: {rel}: {e}", file=sys.stderr)
            return 1
        if got != want:
            failures.append(
                f"{rel}: source hash mismatch — the policy/scanner code changed "
                f"(any edit to this CODEOWNED file, including comments/whitespace; "
                f"update MODULE_SOURCE_SHA256 in check_policy_code_integrity.py if intended)")
    if failures:
        print("check-policy-code-integrity: BLOCK", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("check-policy-code-integrity: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
