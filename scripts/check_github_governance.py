#!/usr/bin/env python3
"""Prove the GitHub-side root of trust is actually configured.

The local validators and the trusted-base freeze guard are only the strict
root of trust IF GitHub enforces them: the trusted-base + CI checks must be
REQUIRED, code-owner review must be REQUIRED, and the protected branch must
disallow force-push/deletion. Those are repository settings, not properties
of a workflow file — a kit cannot assert them, only an API query can.

This validator queries the GitHub REST API (stdlib urllib; GITHUB_TOKEN +
GITHUB_REPOSITORY from the runner env) and reports whether the protected
branch requires:
  - the trusted-base policy audit as a status check,
  - pull requests with CODE-OWNER review,
  - and blocks force-push / deletion.

It is intentionally best-effort about AUTHORIZATION: a default GITHUB_TOKEN
often cannot read branch protection (needs admin). When the API is
unreachable, unauthorized (401/403), or the branch is unprotected-and-
unreadable, this SKIPS with a clear warning (exit 0) rather than failing a
PR for a permissions reason. When it CAN read protection and finds it
MISCONFIGURED, it BLOCKS (exit 1). Run it in the trusted-base workflow.

Flags: --branch NAME (default $GITHUB_BASE_REF or 'main'),
       --require (treat an unreadable/unprotected branch as a failure).
Exit: 0 ok / skipped | 1 misconfigured (or unreadable with --require).
Stdlib only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"


def _arg(argv, name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default


def _get(path, token):
    req = urllib.request.Request(
        API + path,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "substrate-governance-check"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (fixed host)
        return r.status, json.loads(r.read().decode("utf-8"))


def _skip(msg: str, require: bool) -> int:
    stream = sys.stderr if require else sys.stdout
    tag = "BLOCK" if require else "SKIP"
    print(f"check-github-governance: {tag} ({msg})", file=stream)
    return 1 if require else 0


def main(argv) -> int:
    require = "--require" in argv
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    branch = _arg(argv, "--branch") or os.environ.get("GITHUB_BASE_REF") or "main"
    if not repo or not token:
        return _skip("no GITHUB_REPOSITORY/GITHUB_TOKEN (run in CI to enforce)", require)
    try:
        status, prot = _get(f"/repos/{repo}/branches/{branch}/protection", token)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return _skip(f"token cannot read branch protection for {branch!r} "
                         "(needs admin) — verify manually", require)
        if e.code == 404:
            return _skip(f"branch {branch!r} is not protected, or no access", require)
        return _skip(f"GitHub API error {e.code}", require)
    except Exception as e:
        return _skip(f"GitHub API unreachable: {e}", require)

    failures = []
    checks = (((prot.get("required_status_checks") or {}).get("checks")) or [])
    names = {c.get("context", "") for c in checks}
    if not any("trusted-base" in n.lower() or "policy audit" in n.lower() for n in names):
        failures.append("the trusted-base policy audit is not a REQUIRED status check")
    # Ordinary CI must also be required, else a PR can merge without project
    # tests/lint passing even though the policy audit is green.
    if not any(n.lower() in ("ci", "checks") or "ci" == n.lower() or "build" in n.lower()
               or "test" in n.lower() for n in names):
        failures.append("ordinary CI (tests/lint) is not a REQUIRED status check")
    pr = prot.get("required_pull_request_reviews") or {}
    if not pr:
        failures.append("pull request reviews are not required")
    elif not pr.get("require_code_owner_reviews"):
        failures.append("CODE-OWNER review is not required")
    if (prot.get("allow_force_pushes") or {}).get("enabled"):
        failures.append("force pushes are allowed on the protected branch")
    if (prot.get("allow_deletions") or {}).get("enabled"):
        failures.append("deletion of the protected branch is allowed")

    if failures:
        print(f"check-github-governance: BLOCK (branch {branch!r} protection insufficient)",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"check-github-governance: ok (branch {branch!r} protection enforces the root of trust)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
