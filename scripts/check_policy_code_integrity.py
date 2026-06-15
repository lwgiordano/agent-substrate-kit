#!/usr/bin/env python3
"""Pin the ENTIRE policy/scanner module — not just selected definitions.

Pinning named functions and regex assignments was still bypassable: an
attacker can append arbitrary top-level code AFTER the pinned nodes that
mutates the live globals — `globals()["_NET_UPLOAD_FILE"] = <fake>` where the
fake preserves `.pattern` (so the hash check passes) but overfits `.search()`,
or `INJECTION = [(label, <fake>)]` reassigning the scanner's pattern list
(the v3.2.18 findings). Per-node pins don't see the extra top-level code.

So this validator pins the WHOLE normalized-module AST of the security-
critical policy code:
  - command_policy.py     (the shared command-danger detection)
  - check_agent_harness.py (the agent-context scanner)

ANY change — a new statement, a reassignment, a fake object, a reordering —
changes the module AST hash and BLOCKS. There is no top-level code these
files can carry that the pin doesn't cover. Weakening requires an explicit,
reviewed pin update in this CODEOWNED file.

Normalization: ast.unparse of the module with the module docstring stripped.
Version-stable across 3.11+ (unlike ast.dump); comments and whitespace don't
affect it, so only real code/string changes move the hash.

--root DIR: validate the policy code under DIR/scripts instead of this
script's own directory. PINS always come from THIS (trusted) file, so a CI
job can run the base-branch validator against a PR workspace.

Run BEFORE check_harness_smoke / check_hook_smoke.
Exit: 0 ok | 1 module changed / unreadable. Stdlib only.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Canonical normalized whole-module SHA-256 of the shipped policy code.
MODULE_AST_SHA256 = {
    "command_policy.py": "ee33e0464427ae74631f2d4f9bbcfb623745c3c189524bd7ad38996daa81582f",
    "check_agent_harness.py": "02c4acffd73ea399c6de18742bd12d0162dc060aa8684c1ead8655bc86927aff",
}


def _target_scripts(argv: list[str]) -> Path:
    if "--root" in argv:
        return Path(argv[argv.index("--root") + 1]).resolve() / "scripts"
    return Path(__file__).resolve().parent


def _norm_module(src: str) -> str:
    tree = copy.deepcopy(ast.parse(src))
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(getattr(tree.body[0], "value", None), ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        tree.body = tree.body[1:]  # drop module docstring
    return ast.unparse(tree)


def main(argv: list[str]) -> int:
    scripts = _target_scripts(argv)
    failures = []
    for rel, want in MODULE_AST_SHA256.items():
        src = scripts / rel
        try:
            got = hashlib.sha256(_norm_module(src.read_text(encoding="utf-8")).encode("utf-8")).hexdigest()
        except Exception as e:
            print(f"check-policy-code-integrity: BLOCK: {rel}: {e}", file=sys.stderr)
            return 1
        if got != want:
            failures.append(
                f"{rel}: module AST hash mismatch — the policy/scanner code changed "
                f"(any added top-level code, reassignment, or logic edit; update "
                f"MODULE_AST_SHA256 in check_policy_code_integrity.py if intended)")
    if failures:
        print("check-policy-code-integrity: BLOCK", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("check-policy-code-integrity: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
