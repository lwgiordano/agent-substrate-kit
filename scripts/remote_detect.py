#!/usr/bin/env python3
"""Detect the git remote — OFFLINE ONLY. (v3.6.0)

Answers "is there a remote, and is it GitHub?" so go-live + `manage.sh enable
remote` can show the remote-expansion tier. This NEVER touches the network or a
token: it reads the local `remote.origin.url` (or the first remote) from
.git/config via `git config --get`. LIVE branch-protection state needs an API
call and lives behind `setup_branch_protection.sh --check` / `enable remote
--check`, not here — keeping go-live side-effect-light.

Usage:
  remote_detect.py [--root PATH] [--json | --provider | --has-remote]

Exit: 0 always (detection is informational; absence of a remote is a state, not
an error). --has-remote exits 0 if a remote exists, 1 otherwise (script-friendly).
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()

_PROVIDER_HOSTS = {
    "github.com": "github", "www.github.com": "github",
    "gitlab.com": "gitlab", "bitbucket.org": "bitbucket",
}


def _git(root: Path, *args: str):
    """Run a LOCAL git command; return stdout stripped, or None on failure."""
    try:
        p = subprocess.run(["git", "-C", str(root), *args],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    return p.stdout.strip()


def _parse_remote_url(url: str):
    """(provider, owner, repo, host) from a remote URL. Handles:
      git@github.com:owner/repo.git        (scp-like)
      ssh://git@github.com/owner/repo.git  (ssh url)
      https://github.com/owner/repo.git    (https)
      https://user@github.com/owner/repo   (https with userinfo)
    provider is 'github'/'gitlab'/'bitbucket' by host, else 'other'."""
    host = owner = repo = None
    u = url.strip()
    # scp-like: [user@]host:owner/repo(.git)
    m = re.match(r"^(?:[^@/]+@)?([^/:]+):(.+)$", u) if "://" not in u else None
    if m:
        host, path = m.group(1), m.group(2)
    else:
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^@/]+@)?([^/:]+)(?::\d+)?/(.+)$", u)
        if m:
            host, path = m.group(1), m.group(2)
        else:
            return ("other", None, None, None)
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2:
        owner, repo = parts[0], parts[-1]
    provider = _PROVIDER_HOSTS.get((host or "").lower(), "other")
    return (provider, owner, repo, host)


def detect(root: Path) -> dict:
    inside = _git(root, "rev-parse", "--is-inside-work-tree") == "true"
    out = {"inside_git_repo": inside, "has_remote": False, "remote_name": None,
           "remote_url": None, "provider": "none", "owner": None, "repo": None,
           "host": None, "can_check_live_governance": False,
           "reason": "offline detection only; run `./scripts/setup_branch_protection.sh --check` for live GitHub enforcement"}
    if not inside:
        out["reason"] = "not inside a git work tree"
        return out
    url = _git(root, "config", "--get", "remote.origin.url")
    name = "origin"
    if not url:
        remotes = (_git(root, "remote") or "").split()
        if remotes:
            name = remotes[0]
            url = _git(root, "config", "--get", f"remote.{name}.url")
    if not url:
        out["reason"] = "no git remote configured (offline-complete; add a GitHub remote to unlock remote governance)"
        return out
    provider, owner, repo, host = _parse_remote_url(url)
    out.update(has_remote=True, remote_name=name, remote_url=url,
               provider=provider, owner=owner, repo=repo, host=host,
               can_check_live_governance=(provider == "github"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--provider", action="store_true")
    ap.add_argument("--has-remote", dest="has_remote", action="store_true")
    a = ap.parse_args()
    d = detect(Path(a.root))
    if a.provider:
        print(d["provider"])
    elif a.has_remote:
        print("yes" if d["has_remote"] else "no")
        return 0 if d["has_remote"] else 1
    else:
        print(json.dumps(d, indent=2) if a.json else json.dumps(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
