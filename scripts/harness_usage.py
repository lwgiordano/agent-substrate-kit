#!/usr/bin/env python3
"""What the harness actually does, recorded where it runs (v3.11.0).

The hooks append one line per decision to `.substrate/usage/events.jsonl`: which
hook ran, its outcome, the fixed name of the rule that decided, and a few counts.
Nothing else is stored. Never a command, a file path or its content, prompt text,
or an environment value: a usage log that kept them would be a second copy of
everything the exfil guard exists to keep in place.

Recording never changes a hook's result. A missing, linked or unwritable log is
skipped silently, and `SUBSTRATE_USAGE_LOG=0` turns recording off. The log is
local runtime state, Git-ignored like the receipt store, and capped: past 2 MiB
it rotates to `events.1.jsonl`, so at most two files are kept. Two hooks that
rotate at the same moment can lose the older file; the log is evidence for a
person to weigh, not a record anything else depends on.

`./manage.sh usage [--days N] [--json]` reports what the log holds. Scripts
measure; the operator or agent judges: a rule that blocks often, or is
overridden, is a false-positive candidate, and a lesson that is never injected
may have a stale trigger. The report changes nothing.

Exit codes (report): 0 report printed | 2 the log is unsafe to read or bad args.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

USAGE_DIR = Path(".substrate") / "usage"
LOG, ROTATED = "events.jsonl", "events.1.jsonl"
LIMIT = 2 << 20
HOOKS = ("exfil-guard", "lint-on-write", "completion-gate", "session-start")
OUTCOMES = ("allow", "deny", "override", "ok", "findings", "nudge", "silent", "injected")
HOSTS = ("claude", "codex", "copilot")
_RULE = re.compile(r"[^A-Za-z0-9 ._:/()+,'<-]")
# [0-9], not \d: \d matches every Unicode digit, and a forged timestamp in other
# digits sorts above every real one, so it would stay in any --days window.
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_COUNT_KEY = re.compile(r"[a-z][a-z_]{0,23}")
_LESSON_ID = re.compile(r"L[0-9]{1,5}")
# Too few events to call a lesson "never injected": every lesson would qualify.
MIN_SESSIONS = 5
# A written line is a few hundred bytes; a longer one is forged, and deep nesting
# would make json.loads raise RecursionError.
_LINE_MAX = 4096
# The rule names the hooks write, besides the policy's own reasons (read from
# command_policy.py). The report shows any other as unrecognized: the log is a
# local file anything can append to, and an agent may read the report, so no
# free text from it reaches the output.
RULES = {
    "exfil-guard": frozenset({
        "command policy unavailable",
        "containment required: hook input was malformed",
        "containment required: the Bash payload was missing or malformed",
        "containment required: no command was provided",
        "containment required: not provably sandboxed"}),
    "lint-on-write": frozenset({"ruff", "eslint", "gofmt", "unlinted"}),
    "completion-gate": frozenset({
        "gate off", "no project change", "verified self-audit after the change",
        "no verified self-audit after the change"}),
    "session-start": frozenset(),
}
UNRECOGNIZED = "(unrecognized rule)"


def _disabled() -> bool:
    return os.environ.get("SUBSTRATE_USAGE_LOG", "").strip().lower() in ("0", "off", "false", "no")


def _host() -> str:
    host = os.environ.get("SUBSTRATE_HOOK_HOST", "").strip().lower()
    if host in HOSTS:
        return host
    return "claude" if os.environ.get("CLAUDE_PROJECT_DIR") else "unknown"


def _event(hook: str, outcome: str, rule: str | None, ids, counts: dict) -> dict | None:
    """The line to store, built only from fixed vocabularies and small integers."""
    if hook not in HOOKS or outcome not in OUTCOMES:
        return None
    event: dict = {"v": 1, "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "hook": hook, "host": _host(), "outcome": outcome}
    if isinstance(rule, str) and rule.strip():
        event["rule"] = _RULE.sub("", " ".join(rule.split()))[:120]
    n = {k: int(v) for k, v in counts.items()
         if isinstance(k, str) and _COUNT_KEY.fullmatch(k) and isinstance(v, (int, bool))
         and 0 <= int(v) < 10 ** 9}
    if n:
        event["n"] = n
    kept = [i for i in (ids or []) if isinstance(i, str) and _LESSON_ID.fullmatch(i)][:60]
    if kept:
        event["ids"] = kept
    return event


def record(hook: str, outcome: str, rule: str | None = None, *, root=None, ids=None,
           **counts) -> None:
    """Append one event. Never raises and never prints: a hook's verdict must not
    depend on whether its usage could be written."""
    try:
        if _disabled():
            return
        event = _event(hook, outcome, rule, ids, counts)
        if event is None:
            return
        if root is None:
            from _substrate_root import substrate_root
            root = substrate_root()
        _append(Path(root), (json.dumps(event, separators=(",", ":")) + "\n").encode())
    except Exception:  # noqa: BLE001 - recording is best-effort by contract
        return


def _append(root: Path, data: bytes) -> None:
    """O_APPEND through the guarded directory walk: no symlinked ancestor, no
    symlinked leaf, nothing but a regular file with one link is written to."""
    from _doc_common import open_dir_chain
    dir_fd = open_dir_chain(root, root / USAGE_DIR, create=True)
    try:
        try:
            st = os.stat(LOG, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size > LIMIT:
                os.replace(LOG, ROTATED, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(LOG, flags | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
        try:
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                os.write(fd, data)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


# --- report -------------------------------------------------------------------

class UsageUnreadable(RuntimeError):
    pass


def _read_events(root: Path) -> tuple[list[dict], int]:
    """Events from both files, oldest first, and how many lines did not parse."""
    from _doc_common import safe_read_text
    events, malformed = [], 0
    for name in (ROTATED, LOG):
        path = root / USAGE_DIR / name
        if not os.path.lexists(path):
            continue
        text = safe_read_text(path, root, max_bytes=2 * LIMIT)
        if text is None:
            raise UsageUnreadable(f"{USAGE_DIR / name} is linked, special, outside the repo or "
                                  "oversized; not reading it")
        for line in text.splitlines():
            if not line.strip():
                continue
            if len(line) > _LINE_MAX:
                malformed += 1
                continue
            try:
                ev = json.loads(line)
            except (ValueError, RecursionError):
                malformed += 1
                continue
            ev = _normalized(ev)
            if ev is None:
                malformed += 1
            else:
                events.append(ev)
    return events, malformed


def _normalized(ev) -> dict | None:
    """A read line in the shape `_event` writes, or None. The log is a local file
    anything can append to, so the report trusts no field it did not check."""
    if not (isinstance(ev, dict) and ev.get("hook") in HOOKS and ev.get("outcome") in OUTCOMES
            and isinstance(ev.get("ts"), str) and _TS.fullmatch(ev["ts"])):
        return None
    out = {"ts": ev["ts"], "hook": ev["hook"], "outcome": ev["outcome"]}
    if isinstance(ev.get("rule"), str):
        out["rule"] = _RULE.sub("", ev["rule"])[:120]
    n = ev.get("n") if isinstance(ev.get("n"), dict) else {}
    out["n"] = {k: v for k, v in n.items() if isinstance(k, str) and _COUNT_KEY.fullmatch(k)
                and type(v) is int and 0 <= v < 10 ** 9}
    ids = ev.get("ids") if isinstance(ev.get("ids"), list) else []
    out["ids"] = [i for i in ids if isinstance(i, str) and _LESSON_ID.fullmatch(i)][:60]
    return out


def _lesson_inventory(root: Path) -> list[str] | None:
    from _doc_common import safe_read_text
    text = safe_read_text(root / "docs" / "lessons.jsonl", root, max_bytes=4 << 20)
    if text is None:
        return None
    ids = []
    for line in text.splitlines():
        try:
            d = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(d, dict) and isinstance(d.get("id"), str) and _LESSON_ID.fullmatch(d["id"]) \
                and not d.get("superseded_by"):
            ids.append(d["id"])
    return ids


def _policy_reasons() -> frozenset:
    """The fixed reasons command_policy.looks_dangerous_command returns, read from
    the policy's own source next to this file, so they are written in one place."""
    import ast
    from _doc_common import safe_read_text
    text = safe_read_text(Path(__file__).resolve().parent / "command_policy.py", None,
                          max_bytes=1 << 20)
    try:
        tree = ast.parse(text or "")
    except (SyntaxError, ValueError, RecursionError):
        return frozenset()
    reasons = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "looks_dangerous_command":
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Return) and isinstance(sub.value, ast.Constant)
                        and isinstance(sub.value.value, str)):
                    reasons.add(sub.value.value)
    return frozenset(reasons)


def _rule_name(rule: str, known: frozenset) -> str:
    return rule if not rule or rule in known else UNRECOGNIZED


def _pct(values: list[int], q: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def _count(items) -> list[list]:
    tally: dict = {}
    for item in items:
        tally[item] = tally.get(item, 0) + 1
    return [[k, v] for k, v in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))]


def summarize(root: Path, days: int = 30, now: datetime | None = None) -> dict:
    root = Path(root)
    now = now or datetime.now(UTC)
    since = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events, malformed = _read_events(root)
    window = [e for e in events if e["ts"] >= since]
    by_hook = {h: [e for e in window if e["hook"] == h] for h in HOOKS}
    policy = _policy_reasons()
    hooks = {}
    for hook, evs in by_hook.items():
        known = RULES[hook] | policy if hook == "exfil-guard" else RULES[hook]
        ms = [e["n"]["ms"] for e in evs if "ms" in e["n"]]
        hooks[hook] = {
            "events": len(evs),
            "outcomes": dict(_count(e["outcome"] for e in evs)),
            # Per outcome: how often a rule blocks, and how often an operator
            # overrode it, are different evidence and must not be summed.
            "rules": [[o, r, n] for (o, r), n in _count(
                (e["outcome"], _rule_name(e.get("rule", ""), known)) for e in evs
                if e["outcome"] in ("deny", "override", "findings"))],
            "ms_p50": _pct(ms, 0.5), "ms_p95": _pct(ms, 0.95),
        }
    starts = by_hook["session-start"]
    chars = [e["n"]["chars"] for e in starts if "chars" in e["n"]]
    injected = [i for e in starts for i in e["ids"]]
    inventory = _lesson_inventory(root)
    never = None
    if inventory is not None and len(starts) >= MIN_SESSIONS:
        seen = set(injected)
        never = [i for i in inventory if i not in seen]
    return {
        "schema_version": 1, "days": days, "since": since,
        "first": min(e["ts"] for e in window) if window else None,
        "last": max(e["ts"] for e in window) if window else None,
        "events": len(window), "malformed_lines": malformed,
        "hooks": hooks,
        "context": {"sessions": len(starts), "chars_p50": _pct(chars, 0.5),
                    "chars_max": max(chars) if chars else None,
                    "truncated": sum(1 for e in starts if e["n"].get("truncated"))},
        "lessons": {"injected": _count(injected), "never_injected": never,
                    "inventory": len(inventory) if inventory is not None else None,
                    "min_sessions": MIN_SESSIONS},
        "note": "Scripts measure; you judge. Nothing here changes a rule.",
    }


def render(s: dict) -> str:
    if not s["events"]:
        lines = [f"Harness usage: no events in the last {s['days']} days (.substrate/usage/ "
                 "is empty, off via SUBSTRATE_USAGE_LOG=0, or the hooks are not wired)."]
        if s["malformed_lines"]:
            lines.append(f"  {s['malformed_lines']} log line(s) did not parse")
        return "\n".join(lines)
    out = [f"Harness usage, {s['first'][:10]}..{s['last'][:10]} ({s['events']} events in the last "
           f"{s['days']} days; local log, never shared)"]
    if s["malformed_lines"]:
        out.append(f"  {s['malformed_lines']} log line(s) did not parse and are not counted")
    for hook in HOOKS:
        h = s["hooks"][hook]
        if not h["events"]:
            out.append(f"{hook:<16} no events")
            continue
        outcomes = ", ".join(f"{v} {k}" for k, v in h["outcomes"].items())
        # Time inside the hook's main(), not interpreter start-up: the cost of the
        # decision itself, which is what a rule change can move.
        timing = (f"; in-hook p50 {h['ms_p50']} ms, p95 {h['ms_p95']} ms"
                  if h["ms_p50"] is not None else "")
        noun = "event" if h["events"] == 1 else "events"
        out.append(f"{hook:<16} {h['events']} {noun}: {outcomes}{timing}")
        if h["rules"]:
            out.append("  by rule: " + "; ".join(f"{o} {r or '(no rule matched)'} x{n}"
                                                 for o, r, n in h["rules"][:8]))
    c = s["context"]
    if c["sessions"]:
        out.append(f"session context: median {c['chars_p50']} chars, max {c['chars_max']}; "
                   f"truncated {c['truncated']} of {c['sessions']}")
    les = s["lessons"]
    if les["injected"]:
        out.append("lessons injected: " + ", ".join(f"{i} x{n}" for i, n in les["injected"][:12]))
    if les["never_injected"] is None:
        out.append(f"lessons never injected: not judged (needs {les['min_sessions']} session "
                   "starts in the window and a readable docs/lessons.jsonl)")
    elif les["never_injected"]:
        out.append(f"lessons never injected ({len(les['never_injected'])} of {les['inventory']}): "
                   + " ".join(les["never_injected"][:40]) + " - check their triggers still match "
                   "real paths")
    out.append("Review candidates, not verdicts: a rule that blocks often or is overridden may "
               "be a false positive; a lesson never injected may have a stale trigger. "
               + s["note"])
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="./manage.sh usage", description=__doc__.split("\n")[0])
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default=None)
    args = ap.parse_args(argv)
    if not 1 <= args.days <= 3650:
        print("usage: --days must be 1..3650", file=sys.stderr)
        return 2
    if args.root:
        root = Path(args.root).resolve()
    else:
        from _substrate_root import substrate_root
        root = substrate_root()
    try:
        s = summarize(root, args.days)
    except UsageUnreadable as exc:
        print(f"usage: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(s, indent=2) if args.json else render(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
