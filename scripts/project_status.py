#!/usr/bin/env python3
"""Read-only status for projects you name: installed kit, Git state, hook wiring,
latest receipt, local governance config. Remote controls are not checked.

Every target is inspected with THIS kit's code and treated as untrusted data: no
target Python is imported, no target script, hook or manage.sh is run, its config
is parsed as data and never sourced, Git runs with filters, fsmonitor, optional
locks, user config and lazy fetch disabled, and nothing is written. Roots are
explicit: no home-directory scan and no saved registry. Hook files that exist are
reported as configured, never as proof that the host runs them. Branch
protection, rulesets and memory-anchor publication need a network check this
command does not make, so they read `not checked`, never absent or secure.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import open_dir_chain, read_lock, safe_read_bytes, substrate_profile
from _task_evidence import (clip_bytes, git, git_facts, harden_path, json_text, now, safe_text,
                            sanitize_report)

SCHEMA = 1
MAX_ROOTS = 100
JSON_LIMIT = 1 << 20
MAX_DIAGNOSTICS = 50
MAX_HOOK_EVENTS, MAX_HOOK_REF = 30, 300
_LOCKS = {"required_profile": {"starter", "standard", "strict"},
          "required_sandbox": {"0", "1"}, "required_remote_governance": {"0", "1"}}
_GIT_HOOKS = ("pre-commit", "pre-push", "commit-msg")


def _diag(code: str, path: str = ".", **extra) -> dict:
    return {"code": code, "path": path, **extra}


def _read_json(root: Path, rel: str, limit: int, diags: list) -> dict | None:
    raw = safe_read_bytes(root / rel, root, max_bytes=limit)
    if raw is None:
        if os.path.lexists(root / rel):
            diags.append(_diag("unsafe-or-unreadable", rel))
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        diags.append(_diag("malformed-json", rel))
        return None
    if not isinstance(data, dict):
        diags.append(_diag("malformed-json", rel))
        return None
    return data


def _kit(root: Path, diags: list) -> dict:
    data = _read_json(root, ".substrate/install.json", 1 << 20, diags)
    if data is None:
        installed = os.path.lexists(root / ".substrate/install.json")
        return {"installed": "unknown" if installed else "no", "version": None,
                "provenance": "unavailable"}
    owned = data.get("owned_file_sha256")
    return {"installed": "yes", "version": _short(data.get("kit_version")),
            "installed_at": _short(data.get("installed_at")),
            "provenance": "baseline-present" if isinstance(owned, dict) and owned else "unavailable"}


def _short(value) -> str | None:
    """A version or timestamp from the target: short text or nothing."""
    return safe_text(value, 40) if isinstance(value, str) and 0 < len(value) <= 40 else None


def _config(root: Path, diags: list) -> dict:
    out = {"status": "absent"}
    rel = ".substrate/config"
    raw = safe_read_bytes(root / rel, root, max_bytes=1 << 20)
    if raw is None:
        if os.path.lexists(root / rel):
            diags.append(_diag("unsafe-or-unreadable", rel))
            out["status"] = "unsafe"
    else:
        from check_substrate_config import parse_config_text
        try:
            values, error = parse_config_text(raw.decode("utf-8"))
        except UnicodeError:
            values, error = {}, "undecodable"
        if error:
            diags.append(_diag("invalid-config", rel, reason=error[:200]))
            out["status"] = "invalid"
        else:
            out = {"status": "ok",
                   "profile": substrate_profile(raw.decode("utf-8")) or "standard",
                   "lang": values.get("SUBSTRATE_LANG"),
                   "sandbox": values.get("SUBSTRATE_SANDBOX", "0"),
                   "remote_governance": values.get("SUBSTRATE_REMOTE_GOVERNANCE", "0")}
    locks = {}
    for name, allowed in _LOCKS.items():
        state, value, _ = read_lock(root / ".substrate" / name, allowed, root=root)
        locks[name] = value if state == "ok" else state
        if state == "bad":
            diags.append(_diag("unsafe-lock", f".substrate/{name}"))
    out["locks"] = locks
    return out


def _is_regular(root: Path, rel: str) -> str:
    if "\0" in rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
        return "unsafe"
    path = root / rel
    try:
        fd = open_dir_chain(root, path.parent)
    except (OSError, ValueError):
        try:
            return "missing" if not os.path.lexists(path.parent) else "unknown"
        except ValueError:
            return "unknown"
    try:
        st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return "missing"
    except (OSError, ValueError):
        return "unknown"
    finally:
        os.close(fd)
    if stat.S_ISREG(st.st_mode):
        return "present-executable" if st.st_mode & stat.S_IXUSR else "present"
    return "unsafe"


def _hooks(root: Path, diags: list) -> dict:
    settings = _read_json(root, ".claude/settings.json", 1 << 20, diags)
    declared = {}
    if settings is not None and isinstance(settings.get("hooks"), dict):
        for event, groups in list(settings["hooks"].items())[:MAX_HOOK_EVENTS]:
            scripts = set()
            for group in groups if isinstance(groups, list) else []:
                hooks = group.get("hooks") if isinstance(group, dict) else None
                for hook in hooks if isinstance(hooks, list) else []:
                    cmd = hook.get("command") if isinstance(hook, dict) else None
                    if isinstance(cmd, str):
                        for word in cmd.replace('"', " ").split():
                            if ("/scripts/" in word and word.endswith(".py")
                                    and len(word) <= MAX_HOOK_REF):
                                scripts.add("scripts/" + word.rsplit("/scripts/", 1)[1])
            # Keys are target text too: sanitized here, since the report
            # sanitizer only cleans values.
            declared[safe_text(str(event), 40)] = {
                safe_text(ref, MAX_HOOK_REF): _is_regular(root, ref)
                for ref in sorted(scripts)[:20]}
    git_hooks, location = {}, "unknown"
    try:
        hooks_dir = os.fsdecode(git(root, "rev-parse", "--git-path", "hooks")).strip()
        # Never resolve(): a symlink loop raises RuntimeError there. The target
        # repo's core.hooksPath picks this directory, so say where it is.
        hooks_path = Path(hooks_dir) if os.path.isabs(hooks_dir) else root / hooks_dir
        real, base = os.path.realpath(hooks_path), os.path.realpath(root)
        location = "inside-root" if os.path.commonpath([real, base]) == base else "outside-root"
        for name in _GIT_HOOKS:
            try:
                mode = os.lstat(hooks_path / name).st_mode
            except FileNotFoundError:
                git_hooks[name] = "missing"
                continue
            except OSError:
                git_hooks[name] = "unknown"
                continue
            if not stat.S_ISREG(mode):
                git_hooks[name] = "unsafe"
            else:
                git_hooks[name] = "present-executable" if mode & stat.S_IXUSR else "present"
    except (OSError, ValueError, RuntimeError):
        diags.append(_diag("git-hooks-unavailable"))
        git_hooks = {name: "unknown" for name in _GIT_HOOKS}
    return {"claude_settings": "absent" if settings is None else "configured",
            "declared": declared, "git_hooks": git_hooks, "git_hooks_location": location,
            "meaning": "files present and wired; not proof that the host runs them"}


def _receipt(root: Path, diags: list, facts: dict) -> dict | None:
    from task_receipt import latest_tasks
    try:
        shown, problems = latest_tasks(root, limit=1, current=facts)
    except (OSError, ValueError) as exc:
        diags.append(_diag("receipts-unreadable", ".substrate/receipts", reason=type(exc).__name__))
        return None
    for p in problems:
        diags.append(_diag(p["code"], ".substrate/receipts/" + p["task_id"]))
    if not shown:
        return None
    r = shown[0]
    return {"task_id": r["task_id"], "task": clip_bytes(r["task"] or "", 200),
            "created_at": r["created_at"], "completion": r["summary"]["completion"],
            "checks": r["summary"]["checks"],
            "authentication": "unsigned, recorded by the inspected project itself"}


def inspect(root: Path) -> dict:
    """One project's row. Any failure stays inside this row: one hostile or
    broken project never aborts, or hides, the report on the others."""
    row = {"root": str(root), "collected_at": now(), "status": "error", "diagnostics": []}
    try:
        _inspect(root, row)
    except Exception as exc:  # noqa: BLE001 - per-root isolation is the contract
        # A half-built row would read as a partial report: keep only what is known.
        row = {k: row[k] for k in ("root", "collected_at", "diagnostics")}
        row["status"] = "error"
        row["diagnostics"].append(_diag("inspection-failed", reason=type(exc).__name__))
    extra = len(row["diagnostics"]) - MAX_DIAGNOSTICS
    if extra > 0:
        row["diagnostics"] = row["diagnostics"][:MAX_DIAGNOSTICS]
        row["diagnostics_omitted"] = extra
    return row


def _inspect(root: Path, row: dict) -> None:
    diags = row["diagnostics"]
    if not root.is_dir() or root.is_symlink():
        diags.append(_diag("missing-root" if not os.path.lexists(root) else "not-a-directory"))
        return
    dot_git = root / ".git"
    row["worktree"] = ("linked" if dot_git.is_file() else "main" if dot_git.is_dir() else "none")
    facts = git_facts(root)
    row["git"] = {k: facts.get(k) for k in ("status", "head", "branch", "dirty")}
    diags.extend(facts.get("diagnostics", []))
    row["kit"] = _kit(root, diags)
    row["config"] = _config(root, diags)
    row["hooks"] = _hooks(root, diags)
    row["latest_receipt"] = _receipt(root, diags, facts) if facts.get("status") == "ok" else None
    row["remote"] = {"branch_protection": "not checked", "rulesets": "not checked",
                     "memory_anchor_publication": "not checked"}
    row["status"] = "error" if facts.get("status") != "ok" else "ok"


def report(roots: list[Path]) -> dict:
    harden_path()
    if not roots:
        raise ValueError("at least one --root is required")
    if len(roots) > MAX_ROOTS:
        raise ValueError(f"at most {MAX_ROOTS} roots")
    seen, rows = set(), []
    for raw in roots:
        root = Path(os.path.abspath(os.path.expanduser(str(raw))))
        try:
            canonical = root.resolve() if root.exists() else root
        except (OSError, RuntimeError, ValueError):
            canonical = root
        if canonical in seen:
            continue
        seen.add(canonical)
        rows.append(inspect(canonical))
    kit_version = (Path(__file__).resolve().parents[1] / "VERSION")
    raw = safe_read_bytes(kit_version, kit_version.parent, max_bytes=64)
    out = {"schema_version": SCHEMA, "collected_at": now(),
           "inspector": {"kit_version": raw.decode("utf-8", "replace").strip() if raw else None,
                         "network": "off"},
           "projects": rows, "errors": sum(r["status"] == "error" for r in rows)}
    clean, _ = sanitize_report(out)
    return clean


def render_text(rep: dict) -> str:
    lines = [f"Projects: {len(rep['projects'])} inspected, {rep['errors']} with errors "
             f"(inspector kit {rep['inspector']['kit_version']}, network off) at {rep['collected_at']}"]
    for r in rep["projects"]:
        lines.append(f"\n{clip_bytes(r['root'], 120)}  [{r['status']}]")
        if "git" in r:
            g = r["git"]
            lines.append(f"  git: {g['status']} {(g['head'] or '')[:12]} {g['branch'] or ''} {g['dirty']}"
                         f" ({r.get('worktree')} worktree)")
            k = r["kit"]
            lines.append(f"  kit: installed {k['installed']} version {k['version']} provenance {k['provenance']}")
            c = r["config"]
            lines.append(f"  config: {c['status']} profile {c.get('profile')} sandbox {c.get('sandbox')} "
                         f"remote-governance {c.get('remote_governance')} locks {c['locks']}")
            h = r["hooks"]
            declared = sum(len(v) for v in h["declared"].values())
            missing = sum(1 for v in h["declared"].values() for s in v.values() if s != "present"
                          and s != "present-executable")
            lines.append(f"  hooks: claude settings {h['claude_settings']} ({declared} script refs, "
                         f"{missing} missing/unsafe); git {h['git_hooks']} "
                         f"({h['git_hooks_location']}) — wired, not proven to run")
            rec = r["latest_receipt"]
            if not rec:
                lines.append("  receipt: none")
            else:
                checks = "; ".join(f"{k2} {v['latest_outcome']} (applies: {v['applies_to_current_state']})"
                                   for k2, v in rec["checks"].items()) or "no checks run"
                lines.append(f"  receipt: {rec['task_id'][:8]} completion {rec['completion']}; "
                             f"{checks} (unsigned, recorded by that project)")
            lines.append("  remote: branch protection, rulesets, anchor publication — not checked")
        for d in r["diagnostics"][:5]:
            lines.append(f"  diagnostic: {d['code']} {d.get('path', '')}")
        more = len(r["diagnostics"]) - 5 + r.get("diagnostics_omitted", 0)
        if more > 0:
            lines.append(f"  … {more} more diagnostics (see --json)")
    return "\n".join(lines)


def render_json(rep: dict) -> str:
    """At most JSON_LIMIT bytes. Projects that do not fit are dropped from the end
    and counted in `truncated_projects`; a truncated report is an error (exit 2)."""
    text = json_text(rep)
    while len(text.encode()) > JSON_LIMIT and rep["projects"]:
        rep["projects"].pop()
        rep["truncated_projects"] = rep.get("truncated_projects", 0) + 1
        text = json_text(rep)
    return text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="./manage.sh projects", description=__doc__.split("\n")[0])
    parser.add_argument("--root", action="append", default=[], required=True,
                        help="project folder to inspect (repeat; at most 100)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        rep = report([Path(r) for r in args.root])
    except (OSError, ValueError) as exc:
        print(f"projects: {safe_text(str(exc), 200)}", file=sys.stderr)
        return 2
    print(render_json(rep) if args.json else render_text(rep))
    return 2 if rep["errors"] or rep.get("truncated_projects") else 0


if __name__ == "__main__":
    raise SystemExit(main())
