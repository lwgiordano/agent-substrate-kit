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
import os
import re
import stat
import subprocess
import sys
import tempfile
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
# Realpath of the repo root, for the symlinked-ancestor containment check in _raw_tracked_hash
# (v3.8.23 / memory:244). Computed once; ROOT itself may legitimately be reached via a symlink.
_ROOT_REAL = os.path.realpath(ROOT)
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


_GIT_ROUTING_VARS = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_COMMON_DIR", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
)


def _clean_env() -> dict:
    """os.environ minus git REPO-ROUTING and CONFIG-INJECTION vars (v3.8.10/v3.8.11): a
    snapshot command that inherited GIT_INDEX_FILE / GIT_DIR / GIT_WORK_TREE could be
    pointed at a DIFFERENT index/repo, and GIT_CONFIG* (GIT_CONFIG_COUNT/KEY_n/VALUE_n,
    GIT_CONFIG_GLOBAL/SYSTEM) could inject config (e.g. a lying core.fsmonitor) that makes
    git under-report changes. Stripping them forces git to discover the repo from cwd
    (ROOT) with only its own on-disk config."""
    e = dict(os.environ)
    for k in _GIT_ROUTING_VARS:
        e.pop(k, None)
    for k in [k for k in e if k.startswith("GIT_CONFIG")]:
        e.pop(k, None)
    return e


def _git_s(*args: str) -> str:
    """git in ROOT under the SANITIZED env with fsmonitor DISABLED (v3.8.11 — a lying
    fsmonitor hook must not shape a snapshot); stripped stdout, "" on any failure."""
    try:
        p = subprocess.run(["git", "-c", "core.fsmonitor=false", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=15, env=_clean_env())
        return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
        return ""


def _git(*args: str) -> str:
    return _git_output(ROOT, *args)


def _write_tree_oid():
    """Content-addressed OID of the FULL dirty+untracked worktree, via `git write-tree` over
    a TEMPORARY index (the user's real index is untouched). `add -A` stages every non-ignored
    path (git blobs content, records modes, stores symlinks as blobs — no following); write-tree
    then yields an immutable, collision-resistant tree OID. Sanitized env + fsmonitor off so
    mutable git config can't steer it; core.fileMode=true so a mode flip is recorded. Returns
    the OID string, or None on any failure (fail closed). (v3.8.16 — delegates canonicalization
    to git instead of hand-rolling a worktree signature.)"""
    try:
        with tempfile.TemporaryDirectory(prefix="substrate-verify-") as td:
            env = _clean_env()
            env["GIT_INDEX_FILE"] = os.path.join(td, "index")
            add = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "-c", "core.fileMode=true", "add", "-A"],
                cwd=ROOT, capture_output=True, timeout=120, env=env)
            if add.returncode != 0:
                return None
            wt = subprocess.run(["git", "-c", "core.fsmonitor=false", "write-tree"],
                                cwd=ROOT, capture_output=True, text=True, timeout=30, env=env)
            if wt.returncode != 0:
                return None
            return wt.stdout.strip() or None
    except Exception:
        return None


def _raw_tracked_hash():
    """SHA-256 over the RAW worktree bytes of every TRACKED path (`git ls-files -z`), read
    directly from disk. `git write-tree` stores git's OBJECT model, which (a) applies `clean`
    filters — so a `filter.*.clean` that canonicalizes differing raw bytes to one blob hides a
    real content change — and (b) is fed by a fresh temp index whose `add -A` DROPS gitignored
    paths, so a tracked-but-ignored file's raw change vanishes from the tree OID. The checker
    reads RAW bytes, so the signature must too. This folds in the literal on-disk bytes,
    symlink targets, and regular-file permission bits (v3.8.20 / memory:255 — a mode flip on a
    tracked-but-ignored path is invisible to both the temp-index tree and a bytes-only hash).
    Length-prefixed (path, then content) so it is injective / collision-resistant. None on any
    failure (fail closed). v3.8.18 (memory:209)."""
    try:
        ls = subprocess.run(["git", "-c", "core.fsmonitor=false", "ls-files", "-z"],
                            cwd=ROOT, capture_output=True, timeout=60, env=_clean_env())
        if ls.returncode != 0:
            return None
        h = hashlib.sha256()
        for path in sorted(p for p in ls.stdout.split(b"\0") if p):
            h.update(f"{len(path)}:".encode())
            h.update(path)
            fp = os.path.join(ROOT, os.fsdecode(path))
            # FAIL CLOSED if the tracked path escapes the repo through a symlinked ANCESTOR
            # (v3.8.23 / memory:244): os.lstat does not follow the FINAL component, but it does
            # follow every parent — so replacing `tracked/` with a symlink to an outside directory
            # made this hash the OUTSIDE file's bytes while still recording verified=true. Resolve
            # the parent and require it to stay inside the repo; anything else is unverifiable.
            _par = os.path.realpath(os.path.dirname(fp))
            if _par != _ROOT_REAL and not _par.startswith(_ROOT_REAL + os.sep):
                return None
            try:
                lst = os.lstat(fp)
            except FileNotFoundError:
                h.update(b"|absent|")   # genuinely gone (ENOENT) — a real, recordable state
                continue
            # Any OTHER lstat error (EACCES/ELOOP/…) is NOT "absent": let it propagate to the
            # outer handler so the signature is None (fail closed), never a stable hash that
            # could match across a content change we couldn't actually read (v3.8.18 auditor).
            if stat.S_ISLNK(lst.st_mode):
                # FAIL CLOSED on a tracked symlink LEAF whose target escapes the repo (v3.8.24 /
                # memory:264): recording just the link TEXT let the outside file change (or be
                # executed — e.g. a tracked `scripts/run_smoke_verification.py` symlinked to an
                # outside script) while the signature stayed identical and verified=true was
                # recorded. The v3.8.23 check covered escaping ANCESTORS; the leaf needs it too.
                _rl = os.path.realpath(fp)
                if _rl != _ROOT_REAL and not _rl.startswith(_ROOT_REAL + os.sep):
                    return None
                target = os.readlink(fp).encode("utf-8", "surrogateescape")
                h.update(f"|link:{len(target)}:".encode())
                h.update(target)
            elif stat.S_ISREG(lst.st_mode):
                with open(fp, "rb") as fh:
                    content = fh.read()
                # Fold the PERMISSION BITS in too (v3.8.20 / memory:255): a 0644->0755 flip on a
                # tracked-but-ignored path is invisible to the temp-index write-tree (add -A skips
                # ignored paths) and to a bytes-only raw hash; and under core.filemode=false the
                # real index never re-records it either. lstat is the checker's-eye view.
                h.update(f"|file:{stat.S_IMODE(lst.st_mode):o}:{len(content)}:".encode())
                h.update(content)
            else:
                h.update(f"|other:{lst.st_mode}|".encode())   # fifo/socket/etc. — record the type
        return h.hexdigest()
    except Exception:
        return None


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
    # Refuse to EXECUTE a check tool that resolves outside the repo (v3.8.24 / memory:264): a
    # tracked path replaced by a symlink to an outside script would otherwise be run as the
    # "deterministic check" whose result --verify records. The signature guard fails closed on the
    # same condition; this refuses the execution itself rather than relying on that alone.
    _tr = os.path.realpath(tool)
    if _tr != _ROOT_REAL and not _tr.startswith(_ROOT_REAL + os.sep):
        return 2, "run_smoke_verification.py resolves outside the repo — refusing to execute it"
    try:
        p = subprocess.run([sys.executable, "-I", str(tool)], cwd=ROOT,
                           capture_output=True, text=True, timeout=120, env=_clean_env())
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
    def _worktree_state():
        """Return (status_lines, signature). `status_lines` feeds the human-facing
        changed_files/dirty fields. `signature` folds three git-derived views of the worktree:
        (1) a CONTENT-ADDRESSED tree OID from `git write-tree` over a TEMPORARY index (the real
        index is untouched) — git canonicalizes content, modes, symlinks and renames, replacing
        the v3.8.7–v3.8.15 hand-rolled lstat/inode/flag signature (v3.8.16); (2) a hash of the
        real index (`ls-files -s`) so a staged-blob swap is caught; and (3) a RAW-byte hash of
        every tracked path (`_raw_tracked_hash`). (3) exists because the tree OID is git's OBJECT
        model — it applies `clean` filters and its fresh temp index drops gitignored paths — so
        the OID alone is NOT faithful to the raw bytes the checker reads (v3.8.18 / memory:209).
        signature is None on any failure (fail closed). A tracked GITLINK (submodule, index
        mode 160000) is not integrity-verifiable from the superproject tree, so we FAIL CLOSED
        whenever one is present in the INDEX — even if its worktree path is absent/removed."""
        # Human-facing status (also confirms git is readable); fsmonitor off + sanitized env.
        try:
            st = subprocess.run(["git", "-c", "core.fsmonitor=false", "status",
                                 "--porcelain", "-z", "-uall"],
                                cwd=ROOT, capture_output=True, timeout=15, env=_clean_env())
            if st.returncode != 0:
                return None, None
        except Exception:
            return None, None
        lines, records, i = [], [r for r in st.stdout.split(b"\0") if r], 0
        while i < len(records):
            rec = records[i]
            xy = rec[:2].decode("ascii", "replace")
            lines.append(xy + " " + rec[3:].decode("utf-8", "surrogateescape"))
            if xy and (xy[0] in "RC" or xy[1] in "RC"):
                i += 1   # a rename/copy record is followed by the OLD-name field — skip it
            i += 1
        # Fail closed on any tracked GITLINK, detected in the INDEX (mode 160000) so a
        # deinitialized/removed submodule worktree still fails closed (round-11 finding).
        try:
            idx = subprocess.run(["git", "-c", "core.fsmonitor=false", "ls-files", "-s", "-z"],
                                cwd=ROOT, capture_output=True, timeout=15, env=_clean_env())
        except Exception:
            return lines, None
        if idx.returncode != 0:
            return lines, None
        for entry in idx.stdout.split(b"\0"):
            if entry[:6] == b"160000":
                return lines, None   # gitlink present -> unverifiable -> fail closed
        # Signature = the worktree tree OID (content/mode/symlink, canonicalized by git) folded
        # with a hash of the real index (`ls-files -s`, so a staged-blob swap that leaves the
        # worktree unchanged is still flagged) AND a RAW-byte hash of every tracked path. The
        # raw hash is what makes the signature faithful to what the CHECKER reads: the tree OID
        # is git's object model, which applies `clean` filters and drops gitignored paths, so
        # neither the OID nor the index hash alone reflects a filtered / tracked-ignored raw
        # change (v3.8.18 / memory:209). All three come from git's tracked set + the real files.
        oid = _write_tree_oid()
        raw = _raw_tracked_hash()
        if oid is None or raw is None:
            return lines, None
        return lines, oid + ":" + hashlib.sha256(idx.stdout).hexdigest() + ":" + raw

    def _identity():
        # success-aware full HEAD OID + symbolic ref, under the sanitized env; "" -> None
        # so an unborn / unreadable HEAD fails closed, and a same-commit branch switch
        # (refs/heads/main -> refs/heads/other) is caught by the ref (v3.8.10).
        return (_git_s("rev-parse", "HEAD") or None,
                _git_s("rev-parse", "--symbolic-full-name", "HEAD") or None)

    status_lines, sig_before = _worktree_state()
    id_before = _identity()
    _sl = status_lines or []
    changed = [line[3:].strip() for line in _sl if len(line) > 3][:50]
    data = {
        "skill": _safe_note(name, 80),
        "head": id_before[0] or "none",
        "branch": _git_s("rev-parse", "--abbrev-ref", "HEAD") or "none",
        "dirty": bool(_sl),
        "changed_files": changed,
        "result": result,
        "note": _safe_note(note, 200),
        "verified": False,
    }
    verify_ok = True
    if verify:
        rc, out = _run_deterministic_check()
        # TOCTOU guard (v3.8.6/v3.8.10): the working tree can move DURING the up-to-120s
        # check. Re-read state afterward and compare the CONTENT signature AND the git
        # identity. Fail closed if the signature is unreadable either side, if the
        # signature or identity changed, or if HEAD is unborn/unreadable (no committed
        # anchor can back a verified=true claim).
        status_after, sig_after = _worktree_state()
        id_after = _identity()
        moved = (sig_before is None or sig_after is None or sig_after != sig_before
                 or id_before != id_after
                 or id_before[0] is None or id_after[0] is None)
        verify_ok = (rc == 0) and not moved
        data["verified"] = verify_ok
        data["verify_rc"] = rc
        data["verify_tool"] = "run_smoke_verification"
        data["verify_hash"] = hashlib.sha256(out.encode("utf-8", "replace")).hexdigest()[:16]
        if moved:
            data["verify_stale"] = True
            if status_after is not None:
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
