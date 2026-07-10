#!/usr/bin/env python3
"""Append-only, hash-chained substrate memory.

An INTEGRITY TRIPWIRE, not adversarial tamper-proofing. The durable
memory is an append-only event log with a SHA-256 hash chain. It
reliably detects accidental corruption, truncation, reordering, and
naive single-event edits. It does NOT prove history was never
rewritten: anyone with write access can edit an old event AND recompute
every subsequent hash. For that guarantee you need an anchor OUTSIDE
the agent's write scope — `memory_log.py anchor` writes the current head
hash to a git note (refs/notes/substrate-memory), outside events.jsonl;
`verify --anchor` checks the head against it. For strong assurance push
that note to a protected remote or anchor in CI.

CURRENT_SESSION.md is a derived, disposable VIEW — never authoritative.

Layout:
  .substrate/memory/events.jsonl   append-only; one JSON event per line

Each event:
  {"seq": N, "ts": "...", "type": "...", "prev": "<hash N-1>",
   "hash": "<sha256(prev + canonical payload)>", "data": {...redacted...}}

The chain root (seq 0) uses prev = 64 zeros. Appends take an exclusive
file lock (flock where available) so concurrent hooks/subagents don't
race the sequence number. The events file should be COMMITTED.

Stdlib only (runs from hooks). Secrets redacted on write.

Usage:
  memory_log.py append --type <t> --json '<data>'   # or --message TEXT
  memory_log.py verify [--anchor]   # walk chain; --anchor checks head note
  memory_log.py anchor              # write head hash to a git note
  memory_log.py tail [N]
  memory_log.py tasks

Exit codes: 0 ok | 1 chain broken / anchor mismatch / error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

try:
    import fcntl  # unix; absent on Windows
except Exception:  # pragma: no cover
    fcntl = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
try:
    from _substrate_root import git_output as _git_output
except Exception:
    def _git_output(root, *args, timeout=15):
        try:
            p = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout)
            return p.stdout.strip() if p.returncode == 0 else ""
        except Exception:
            return ""
try:
    import _text_safety  # confusable/leet-fold for the note danger scan
except Exception:  # pragma: no cover - fail open to un-folded text
    _text_safety = None
MEM = ROOT / ".substrate" / "memory"
EVENTS = MEM / "events.jsonl"
ZERO = "0" * 64

_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9._\-/+]{8,}['\"]?"
    ),
]


def _redact(obj):
    if isinstance(obj, str):
        out = obj
        for rx in _SECRET_PATTERNS:
            out = rx.sub("[REDACTED-SECRET]", out)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items()}
    return obj


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _event_hash(prev: str, seq: int, ts: str, etype: str, data) -> str:
    payload = _canonical({"seq": seq, "ts": ts, "type": etype, "prev": prev, "data": data})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_events() -> list[dict]:
    if not EVENTS.exists():
        return []
    out = []
    for line in EVENTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"_corrupt": line})
    return out


def append(etype: str, data) -> int:
    try:
        MEM.mkdir(parents=True, exist_ok=True)
        lock = MEM / ".lock"
        with lock.open("w") as lf:
            # Exclusive lock so concurrent hooks/subagents can't race the
            # sequence number (read-tail-then-append must be atomic).
            if fcntl is not None:
                with suppress(Exception):
                    fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            events = _read_events()
            prev = events[-1].get("hash", ZERO) if events else ZERO
            seq = len(events)
            ts = datetime.now(UTC).replace(microsecond=0).isoformat()
            data = _redact(data)
            h = _event_hash(prev, seq, ts, etype, data)
            event = {"seq": seq, "ts": ts, "type": etype, "prev": prev, "hash": h, "data": data}
            with EVENTS.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=True) + "\n")
            if fcntl is not None:
                with suppress(Exception):
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"memory-log: append failed: {e}", file=sys.stderr)
        return 1
    return 0


def _git(*args: str) -> str:
    return _git_output(ROOT, *args)


# skill-run free-text fields are agent-authored and durable. Nothing re-injects
# them into model context TODAY (completion_gate reads only type/skill/ts), but
# harden at the write like session_handoff does — future consumers (memory tail
# in a skill, v3.8.4 block reasons) must not inherit a poisoned log.
_INSTRUCTION_PREFIX = re.compile(
    r"(?im)^\s*(?:ignore|disregard|forget|override|system:|developer:|"
    r"you must|you are now|new instructions?|from now on)\b.*$"
)
_ROLE_PREFIX = re.compile(
    r"(?i)\[\s*(?:system|assistant|developer|user|tool)\s*[:\]]"
)


def _safe_note(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    text = _INSTRUCTION_PREFIX.sub("[instruction-line stripped]", text)
    # Scan confusable/leet-folded variants too, so homoglyph ("[SYSTEM…" with a
    # Cyrillic S) / leet evasion can't smuggle a directive past the ASCII regex.
    variants = [text]
    if _text_safety is not None:
        try:
            variants = _text_safety.scan_variants(text)
        except Exception:
            variants = [text]
    if any(_ROLE_PREFIX.search(v) or _INSTRUCTION_PREFIX.search(v) for v in variants):
        return "[note stripped: role-prefix directive]"
    return _redact(text)[:limit]


def _run_deterministic_check() -> tuple[int, str]:
    """Run the in-process static validator chain and return (rc, output). This
    is a REAL deterministic signal (not a self-report) that `--verify` records,
    so the recorded result can't claim 'pass' while the checks are red. Uses
    run_smoke_verification.py — fast, stdlib, no venv required."""
    tool = ROOT / "scripts" / "run_smoke_verification.py"
    if not tool.is_file():
        return 2, "run_smoke_verification.py not found"
    try:
        p = subprocess.run([sys.executable, "-I", str(tool)], cwd=ROOT,
                           capture_output=True, text=True, timeout=120)
        return p.returncode, (p.stdout + p.stderr)
    except Exception as e:
        return 2, f"verification failed to run: {e}"


def skill_run(name: str, result: str, note: str, verify: bool = False) -> int:
    """Record tamper-evident evidence that a skill ran. Git state (head,
    branch, dirty, changed files) is captured HERE at append time, so the
    caller cannot record a wrong SHA or hide dirty files. The completion
    gate (v3.8.3) looks for `skill-run` events with skill == self-audit.

    With verify=True the recorded result is NOT self-asserted: the static
    validator chain is run and its real exit status + an output hash are
    stored (`verified`/`verify_rc`/`verify_hash`), and `result` is overridden
    to reflect it. Block mode (deferred) will require a verified event — an
    unverified `--result pass` is a nudge, not evidence."""
    def _porcelain():
        # UNSTRIPPED lines — status paths are position-encoded and a global
        # strip() would eat the first line's leading status space.
        try:
            st = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                capture_output=True, text=True, timeout=15)
            return st.stdout.splitlines() if st.returncode == 0 else []
        except Exception:
            return []

    status_lines = _porcelain()
    head_before = _git("rev-parse", "--short", "HEAD") or "none"
    changed = [line[3:].strip() for line in status_lines if len(line) > 3][:50]
    data = {
        "skill": _safe_note(name, 80),
        "head": head_before,
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "none",
        "dirty": bool(status_lines),
        "changed_files": changed,
        "result": result,
        "note": _safe_note(note, 200),
        "verified": False,
    }
    verify_ok = True
    if verify:
        rc, out = _run_deterministic_check()
        # TOCTOU guard (v3.8.5): the working tree can move DURING the up-to-120s
        # check. Re-read git state afterward; if HEAD or the porcelain status
        # changed, the result cannot be trusted to describe the current tree, so
        # do NOT claim verified — record the drift instead of a stale pass.
        status_after = _porcelain()
        head_after = _git("rev-parse", "--short", "HEAD") or "none"
        moved = (status_after != status_lines) or (head_after != head_before)
        verify_ok = (rc == 0) and not moved
        data["verified"] = verify_ok
        data["verify_rc"] = rc
        data["verify_tool"] = "run_smoke_verification"
        data["verify_hash"] = hashlib.sha256(out.encode("utf-8", "replace")).hexdigest()[:16]
        if moved:
            data["verify_stale"] = True
            # file the event against the tree it ACTUALLY ended on
            data["changed_files"] = [ln[3:].strip() for ln in status_after if len(ln) > 3][:50]
            data["result"] = "unverified-tree-changed-during-check"
        else:
            # A real check result overrides a self-asserted one — evidence, not a claim.
            data["result"] = "pass" if rc == 0 else "issues-found"
        print(f"memory-log: skill-run verified rc={rc} "
              f"({'pass' if verify_ok else 'FAILED/STALE'})", file=sys.stderr)
    appended = append("skill-run", data)
    if appended != 0:
        return appended
    # Surface a failed/stale verification as a NONZERO exit (v3.8.5) so shell and
    # automation cannot read "verification ran but did not pass" as success. The
    # event is recorded above regardless — evidence first, then the honest code.
    return 0 if (not verify or verify_ok) else 1


def _head_hash() -> str:
    events = _read_events()
    return events[-1].get("hash", ZERO) if events else ZERO


def anchor() -> int:
    """Write the current head hash to a git note outside events.jsonl."""
    head = _head_hash()
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10)
        if sha.returncode != 0:
            print("memory-log: anchor needs a git repo with at least one commit", file=sys.stderr)
            return 1
        r = subprocess.run(
            ["git", "notes", "--ref", "substrate-memory", "add", "-f",
             "-m", f"substrate-memory-head:{head}", sha.stdout.strip()],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            print(f"memory-log: anchor failed: {r.stderr.strip()[:160]}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"memory-log: anchor error: {e}", file=sys.stderr)
        return 1
    print(f"memory-log: anchored head {head[:12]} to git note (refs/notes/substrate-memory)")
    return 0


def _anchored_head() -> str | None:
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10)
        if sha.returncode != 0:
            return None
        r = subprocess.run(["git", "notes", "--ref", "substrate-memory", "show", sha.stdout.strip()],
                          cwd=ROOT, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        for line in r.stdout.splitlines():
            if line.startswith("substrate-memory-head:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        return None
    return None


def verify(check_anchor: bool = False) -> int:
    events = _read_events()
    prev = ZERO
    for i, ev in enumerate(events):
        if "_corrupt" in ev:
            print(f"memory-log: BREAK at line {i + 1}: not valid JSON", file=sys.stderr)
            return 1
        if ev.get("seq") != i:
            print(f"memory-log: BREAK at seq {i}: out-of-order/missing seq", file=sys.stderr)
            return 1
        if ev.get("prev") != prev:
            print(f"memory-log: BREAK at seq {i}: prev-hash mismatch", file=sys.stderr)
            return 1
        expect = _event_hash(prev, ev["seq"], ev["ts"], ev["type"], ev.get("data"))
        if ev.get("hash") != expect:
            print(f"memory-log: BREAK at seq {i}: content hash mismatch (tampered)", file=sys.stderr)
            return 1
        prev = ev["hash"]
    if check_anchor:
        anchored = _anchored_head()
        if anchored is None:
            print("memory-log: no anchor note for HEAD (run `memory_log.py anchor`)", file=sys.stderr)
            return 1
        if anchored != prev:
            print("memory-log: ANCHOR MISMATCH — head hash differs from the git-note "
                  "anchor; history was rewritten since the last anchor", file=sys.stderr)
            return 1
        print(f"memory-log: chain OK + anchor verified ({len(events)} events)")
        return 0
    print(f"memory-log: chain OK ({len(events)} events)")
    return 0


def tail(n: int) -> int:
    events = _read_events()
    for ev in events[-n:]:
        if "_corrupt" in ev:
            print("CORRUPT LINE")
            continue
        print(f"[{ev.get('seq')}] {ev.get('ts')} {ev.get('type')}: "
              f"{_canonical(ev.get('data'))[:120]}")
    return 0


def tasks() -> int:
    events = _read_events()
    latest: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") == "task" and isinstance(ev.get("data"), dict):
            tid = str(ev["data"].get("id", ev.get("seq")))
            latest[tid] = ev["data"]
    if not latest:
        print("memory-log: no task events")
        return 0
    for tid, d in latest.items():
        print(f"- {tid}: {d.get('status', '?')} — {d.get('content', '')[:80]}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    ap_app = sub.add_parser("append")
    ap_app.add_argument("--type", default="note")
    ap_app.add_argument("--json", default="")
    ap_app.add_argument("--message", default="")
    ap_ver = sub.add_parser("verify")
    ap_ver.add_argument("--anchor", action="store_true")
    sub.add_parser("anchor")
    ap_tail = sub.add_parser("tail")
    ap_tail.add_argument("n", nargs="?", type=int, default=10)
    sub.add_parser("tasks")
    ap_sk = sub.add_parser("skill-run")
    ap_sk.add_argument("name")
    ap_sk.add_argument("--note", default="")
    ap_sk.add_argument("--result", default="unknown",
                       choices=("pass", "issues-found", "unknown"))
    ap_sk.add_argument("--verify", action="store_true",
                       help="run the deterministic validator chain and record its REAL "
                            "result (not self-asserted); required for block-mode evidence")
    a = ap.parse_args(argv)
    if a.cmd == "append":
        if a.json:
            try:
                data = json.loads(a.json)
            except Exception:
                print("memory-log: --json is not valid JSON", file=sys.stderr)
                return 1
        else:
            data = {"message": a.message}
        return append(a.type, data)
    if a.cmd == "skill-run":
        return skill_run(a.name, a.result, a.note, verify=a.verify)
    if a.cmd == "verify":
        return verify(check_anchor=a.anchor)
    if a.cmd == "anchor":
        return anchor()
    if a.cmd == "tail":
        return tail(a.n)
    if a.cmd == "tasks":
        return tasks()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
