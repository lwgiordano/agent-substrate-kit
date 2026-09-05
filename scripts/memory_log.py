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
`verify --anchor` finds the nearest annotated ancestor of HEAD and requires
that anchored hash to be PRESENT in the current chain. Growth after the
anchor passes; a chain replaced wholesale or truncated past the anchor
fails; no anchor anywhere in the ancestry fails closed. A rewrite of the
suffix after the anchor point is undetectable by any unkeyed hash chain —
anchor at every release and push that note to a protected remote or anchor
in CI; that is the documented limit, not a gap.

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

# v3.8.46 (round-29 P1, found by the gate once os.path.join(ROOT, ...) was
# classified as repo-derived): the signature hasher below read every tracked
# file with a bare open(fp, "rb") after an lstat said S_ISREG — stat-then-open,
# so a hard link passes both and an ancestor can be swapped between them. This
# is the MEMORY CHAIN's own signature; a hash taken over bytes the guard never
# approved is the one thing it must not produce.
try:
    from _doc_common import safe_read_bytes as _safe_read_bytes
except Exception:  # pragma: no cover - stripped install
    def _safe_read_bytes(path, root=None, max_bytes=None, tail_bytes=None):
        return None

try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    # v3.8.51 (self-audit, architecture P3): this used to be a ~40-line
    # "same algorithm" mirror of _doc_common.safe_read_text — the v3.8.42
    # algorithm. The canonical primitive then gained component-walk descent
    # (v3.8.44) and post-op liveness (v3.8.45) and the mirror did not: a copy
    # of a security primitive that silently stayed two fixes behind, in a
    # fallback path that _doc_common is never actually stripped from. A
    # fallback that runs an OLDER guard is the same fail-open shape as one
    # that drops the guard, only slower to notice. Refuse instead — and refuse
    # LOUDLY: _read_events turns a None read into "no events", so a None stub
    # here would let a stripped install verify an unreadable chain as empty and
    # OK. A raise propagates to a nonzero exit; a stripped install cannot
    # claim the chain verified.
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        raise OSError("safe_read_text unavailable — refusing an unguarded read of the memory chain")

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


class MemoryLogUnsafe(RuntimeError):
    """events.jsonl is PRESENT but not safe to read (linked/non-regular/routed).

    Distinct from absent: an absent log is a legitimately empty chain, while a
    present-but-unsafe one is tampering and must never verify as OK (v3.8.42)."""


def _events_unsafe_reason() -> str | None:
    """Reason string if EVENTS exists but must not be read, else None.
    lstat-based, so it never follows the link it is judging."""
    try:
        st = os.lstat(str(EVENTS))
    except (OSError, ValueError):
        return None  # absent — a legitimately empty chain
    if stat.S_ISLNK(st.st_mode):
        return "events.jsonl is a symlink"
    if not stat.S_ISREG(st.st_mode):
        return "events.jsonl is not a regular file (fifo/socket/device)"
    if st.st_nlink > 1:
        return "events.jsonl is a hard link (shared inode)"
    return None


def _read_events() -> list[dict]:
    # v3.8.42 (round-25 P2): the READ side had no guard at all — append() was
    # hardened through rounds 23/24 while this bypassed containment entirely, so
    # a symlinked/hard-linked events.jsonl made `verify` report an OUTSIDE chain
    # as OK and `tail`/`tasks` print outside content, and a FIFO hung them.
    # max_bytes=None is deliberate: a truncated read would FAIL OPEN here (a
    # short/empty read verifies as a clean chain), so this read is unbounded.
    # PRESENT-but-unsafe must not degrade to "empty chain" — that would let a
    # symlinked/FIFO events.jsonl verify as OK, trading a hang for a fail-open.
    _unsafe = _events_unsafe_reason()
    if _unsafe is not None:
        raise MemoryLogUnsafe(_unsafe)
    text = _safe_read_text(EVENTS, ROOT, max_bytes=None)
    if text is None:
        if EVENTS.is_symlink() or os.path.lexists(str(EVENTS)):
            # containment refused it (routed parent) though the leaf looked fine
            raise MemoryLogUnsafe("events.jsonl is outside the repo (routed parent)")
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"_corrupt": line})
    return out


def append(etype: str, data) -> int:
    return _append_returning_head(etype, data)[0]


def _append_returning_head(etype: str, data) -> tuple[int, str | None]:
    """append(), plus the hash it actually wrote.

    v3.8.54 (round-36 P2): `anchor --force` checked this append's return code
    and then RE-READ events.jsonl to choose the note payload. The lock is
    released when the append returns, so a writer in that gap got a green
    anchor over a chain containing no `anchor-forced` event at all — the
    evidence precondition was satisfied and the thing it authorized was bound
    to a different read. Returning the hash makes the anchored value the one
    this append produced, so there is nothing to race.
    """
    h = None
    try:
        # v3.8.40 (round-23 P1): the tamper-evident log must never be routed
        # outside the repo. A symlinked `.substrate`/`.substrate/memory`
        # ancestor would send .lock + events.jsonl to an outside inode; the
        # structured-handoff writer had this guard but memory_log did not.
        # STRICT containment (no escaping OR in-repo-aliasing ancestor) BEFORE
        # the mkdir so a refused write creates no outside directory, and refuse
        # a symlinked leaf so the append never writes through a link.
        try:
            from _doc_common import within_root as _within_root
            contained = _within_root(EVENTS, ROOT)
        except Exception:
            # Fallback mirrors _doc_common.within_root STRICTLY and fails
            # CLOSED: the EVENTS parent (MEM) must resolve to its EXACT lexical
            # location under realpath(ROOT). A prior version compared
            # realpath(MEM) to realpath(ROOT/".substrate"/"memory") — the same
            # expression on both sides, an always-True tautology that fails
            # OPEN through any symlinked ancestor (round-23 auditor P1).
            try:
                _root_real = os.path.realpath(str(ROOT))
                _rel = os.path.relpath(str(EVENTS.parent), str(ROOT))
                if _rel == os.pardir or _rel.startswith(os.pardir + os.sep) or os.path.isabs(_rel):
                    contained = False
                else:
                    _expected = os.path.normpath(os.path.join(_root_real, _rel))
                    contained = os.path.realpath(str(EVENTS.parent)) == _expected
            except (OSError, ValueError):
                contained = False
        if not contained:
            print("memory-log: refusing append — memory dir escapes the repo "
                  "(symlinked ancestor)", file=sys.stderr)
            return 1, None
        # v3.8.41 (round-24 P1): refuse a symlinked OR hard-linked leaf. Round-23
        # checked only is_symlink(), but a hard-linked events.jsonl/.lock is a
        # regular file that shares an outside inode, so EVENTS.open("a") appends
        # and lock.open("w") truncates the shared bytes. Route both leaves through
        # the centralized _doc_common.refuse_linked_leaf (symlink OR st_nlink>1),
        # with an inline lstat fallback if the import is unavailable.
        for _leaf in (EVENTS, MEM / ".lock"):
            try:
                from _doc_common import refuse_linked_leaf as _rll
                _reason = _rll(_leaf)
            except Exception:
                try:
                    _lst = os.lstat(str(_leaf))
                    # v3.8.42 (round-25 P2): non-regular too — a FIFO .lock or
                    # events.jsonl passed both link checks and then HUNG the
                    # append on open() instead of failing closed.
                    _reason = ("is a symlink" if stat.S_ISLNK(_lst.st_mode)
                               else "is not a regular file (fifo/socket/device)"
                               if not stat.S_ISREG(_lst.st_mode)
                               else "is a hard link (shared inode)" if _lst.st_nlink > 1 else None)
                except (OSError, ValueError):
                    _reason = None
            if _reason is not None:
                print(f"memory-log: refusing append — {_leaf.name} {_reason}", file=sys.stderr)
                return 1, None
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
        return 1, None
    return 0, h


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


_EVIDENCE_GIT_OK: bool | None = None


def _git_isolates_user_config() -> bool:
    """Can this git be told to IGNORE user/system config files (>= 2.32)?

    GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM landed in Git 2.32. On anything older
    there is no way to keep `$HOME/.gitconfig` out of a subprocess without also
    moving HOME, which would take `~/.ssh` with it and break every ssh remote.
    So on older git we do not weaken the check and we do not pretend: remote
    confirmation is simply not available, which strict treats as unpublished.
    """
    global _EVIDENCE_GIT_OK
    if _EVIDENCE_GIT_OK is None:
        _EVIDENCE_GIT_OK = False
        try:
            p = subprocess.run(["git", "--version"], cwd=ROOT, capture_output=True,
                               text=True, timeout=10, env=_clean_env())
            m = re.search(r"(\d+)\.(\d+)", p.stdout) if p.returncode == 0 else None
            if m:
                _EVIDENCE_GIT_OK = (int(m.group(1)), int(m.group(2))) >= (2, 32)
        except Exception:
            _EVIDENCE_GIT_OK = False
    return _EVIDENCE_GIT_OK


def _evidence_env() -> dict:
    """_clean_env() PLUS isolation from user/system git CONFIG FILES.

    v3.8.54 (round-36 P1a). `_clean_env` was a denylist of the env vars that
    redirect which REPOSITORY git reads, written in v3.8.10 when every call in
    this module was local. v3.8.52 added calls where the answer comes from a
    SERVER, and the denylist was never re-derived for them: `XDG_CONFIG_HOME`
    (and, symmetrically, `HOME`) still selected the user config file, so a
    `url.<attacker>.insteadOf` entry rewrote the origin URL and a genuine
    ANCHOR CONFLICT was reported as `anchor verified against origin`.
    Reproduced through both variables before this fix.

    Config files are therefore taken out of the loop for the calls whose verdict
    the remote decides, rather than one variable being deleted: point
    GIT_CONFIG_GLOBAL/SYSTEM at /dev/null (which supersedes both `$HOME` and
    XDG lookups), refuse system config, drop XDG_CONFIG_HOME anyway, and forbid
    a credential prompt so an unauthenticated remote fails fast instead of
    hanging. What survives is the repository's OWN config — the same trust
    boundary as the working tree itself.

    NOT applied to the purely local reads and to the note write: user config
    cannot change which repository those reach once the routing vars are gone
    (the git dir comes from cwd), the note write needs `user.email` and would
    break on most machines without it, and the local note is never treated as
    authority anyway — that is precisely why remote confirmation exists.
    """
    e = _clean_env()
    e.pop("XDG_CONFIG_HOME", None)
    e["GIT_CONFIG_GLOBAL"] = os.devnull
    e["GIT_CONFIG_SYSTEM"] = os.devnull
    e["GIT_CONFIG_NOSYSTEM"] = "1"
    e["GIT_TERMINAL_PROMPT"] = "0"
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
        _paths = sorted(p for p in ls.stdout.split(b"\0") if p)
        # Realpaths of every TRACKED file, so a tracked SYMLINK leaf can be required to resolve to
        # another TRACKED path (v3.8.25 / memory:264). A link to an in-repo but UNTRACKED/ignored
        # file resolves inside the repo — passing the v3.8.24 escape test — yet its bytes are in no
        # part of the signature, so they can change (or be executed) with the signature unmoved.
        _tracked_real = set()
        for _p in _paths:
            with suppress(Exception):
                _tracked_real.add(os.path.realpath(os.path.join(ROOT, os.fsdecode(_p))))
        for path in _paths:
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
                # ...and, inside the repo, the target must itself be TRACKED — otherwise its
                # content is outside the signature entirely (v3.8.25 / memory:264). `_tracked_real`
                # holds tracked BLOB paths only, so a link to a tracked DIRECTORY also fails closed
                # (unverifiable here); a DANGLING link is allowed — there is no content to cover,
                # and the link text itself is already hashed above.
                if os.path.exists(_rl) and _rl not in _tracked_real:
                    return None
                target = os.readlink(fp).encode("utf-8", "surrogateescape")
                h.update(f"|link:{len(target)}:".encode())
                h.update(target)
            elif stat.S_ISREG(lst.st_mode):
                # Guarded read (v3.8.46): O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG
                # and st_nlink == 1 on the OPENED fd, and a live-parent check —
                # the lstat above proves nothing about what open() would get.
                # None means unreadable or unsafe; the outer handler turns that
                # into a None signature, which is the fail-closed contract.
                content = _safe_read_bytes(fp, ROOT, max_bytes=None)
                if content is None:
                    # Fail closed — but SAY SO. The outer handler turns this
                    # into a None signature, and a chain that goes None without
                    # explanation is indistinguishable from a bug (in-release
                    # auditor WARN). A tracked file with st_nlink > 1 is the
                    # likely cause and it is not obvious from the outside.
                    print("memory-log: refusing to hash a tracked file that is "
                          f"not a private regular file (symlink/hard link/FIFO): {fp}",
                          file=sys.stderr)
                    raise OSError(f"unsafe or unreadable tracked file: {fp}")
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
    # v3.8.25 (memory:264): refuse a SYMLINKED check tool outright, not just an escaping one. A
    # link to an in-repo but UNTRACKED/gitignored script (e.g. scripts/ignored/evil.py) resolves
    # inside the repo, so the escape test passed, yet the executed bytes are covered by NO part of
    # the signature — `git status` stays clean and verified=true was recorded after running it.
    # The kit always installs this tool as a regular file, so refusing links costs nothing.
    if tool.is_symlink():
        return 2, "run_smoke_verification.py is a symlink — refusing to execute it"
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


def anchor(force: bool = False) -> int:
    """Write the current head hash to a git note outside events.jsonl.

    MONOTONIC (v3.8.52, round-34 P1). A git note lives in the same writable
    repo state as the log it vouches for, so the detection added in v3.8.51
    was one command away from being undone: replace `events.jsonl` with a
    different valid chain, re-run this command, and `verify --anchor` went
    green over the replacement. Reproduced end to end before this fix.

    Advancing the anchor is therefore only allowed ALONG the chain it already
    vouches for: if a previous anchor exists, its recorded hash must still be
    a member of the current chain. Growth satisfies that on every legitimate
    release; replace-then-re-anchor does not, which is exactly the laundering
    step. A real operator-intended reset (a wiped log, a new machine) uses
    --force, and that is not a silent escape hatch: the break is APPENDED to
    the new chain as a `anchor-forced` event naming the abandoned hash, so
    the discontinuity is in the record instead of erased from it.

    This closes the local move. It does not make a mutable local note a
    cryptographic authority — see the module docstring and `verify --anchor`,
    which reports a local-only anchor as local-only and requires remote
    confirmation under strict.
    """
    # ONE snapshot of the chain (v3.8.54, round-36 P2). This used to take the
    # head from one read of events.jsonl and the membership set from another,
    # so the hash that got anchored need not have come from the chain the
    # monotonicity check approved. Read once; decide and act on that read.
    events = _read_events()
    head = events[-1].get("hash", ZERO) if events else ZERO
    seen = {ZERO} | {ev.get("hash") for ev in events}
    prior = _nearest_anchor()
    if prior is not None and not force:
        commit, anchored = prior
        if anchored not in seen:
            print(
                f"memory-log: REFUSING to re-anchor — the hash anchored at commit "
                f"{commit[:12]} ({anchored[:12]}) is NOT in the current chain, so this "
                "would move the anchor onto a chain that does not descend from the "
                "anchored state. That is the shape of a replaced or truncated log. If "
                "the log was legitimately reset, re-run with --force, which records the "
                "break as an event in the new chain rather than hiding it.",
                file=sys.stderr,
            )
            return 1
    forced_break = None
    if prior is not None and force:
        commit, anchored = prior
        if anchored not in seen:
            forced_break = (commit, anchored)
    if forced_break is not None:
        # Append BEFORE anchoring so the anchor covers the record of its own
        # discontinuity, and anchor THE HASH THAT APPEND PRODUCED.
        #
        # v3.8.54 (round-36 P2): re-reading events.jsonl here instead was a
        # gap a writer could stand in. append() releases its lock when it
        # returns, so replacing the file between the rc check and the re-read
        # produced rc 0, a note over a chain with no `anchor-forced` event in
        # it, and verify --anchor green. The precondition held and the thing
        # it authorized was bound to a different read of a mutable file.
        #
        # The append rc is a PRECONDITION, not a formality (round-35 P2). v3.8.52
        # ignored it, so making .substrate/memory/.lock a FIFO stopped the event
        # from being written while the note was rewritten anyway — the recorded
        # discontinuity is the entire justification for allowing --force, and it
        # was optional. If the evidence cannot be written, the override does not
        # happen: abort with the note untouched, leaving the mismatch standing.
        commit, anchored = forced_break
        rc, appended = _append_returning_head("anchor-forced", {
            "abandoned_anchor_commit": commit,
            "abandoned_anchor_head": anchored,
            "reason": "operator-forced anchor over a chain that does not contain the "
                      "previously anchored head",
        })
        if rc != 0 or not appended:
            print(
                "memory-log: REFUSING --force — could not append the `anchor-forced` "
                "evidence event (see the error above), so the discontinuity would go "
                "unrecorded. The note is UNCHANGED and the anchor mismatch still "
                "stands. Fix the memory log, then re-run.",
                file=sys.stderr,
            )
            return 1
        head = appended
    # POST-CONDITION, and it can only REFUSE (v3.8.54). Binding `head` to the
    # snapshot above is what makes the payload unraceable; this re-read never
    # chooses a value, it only asks whether the chain still contains the hash
    # about to be certified. A writer that replaced events.jsonl while this ran
    # is then a refusal here rather than a note that verifies against a chain
    # nothing validated.
    if head != ZERO and head not in {ev.get("hash") for ev in _read_events()}:
        print("memory-log: REFUSING to anchor — events.jsonl changed while this "
              "anchor ran and no longer contains the hash being anchored. The note "
              "is UNCHANGED. Re-run once the log is quiescent.", file=sys.stderr)
        return 1
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10,
                             env=_clean_env())
        if sha.returncode != 0:
            print("memory-log: anchor needs a git repo with at least one commit", file=sys.stderr)
            return 1
        r = subprocess.run(
            ["git", "notes", "--ref", "substrate-memory", "add", "-f",
             "-m", f"substrate-memory-head:{head}", sha.stdout.strip()],
            cwd=ROOT, capture_output=True, text=True, timeout=10, env=_clean_env(),
        )
        if r.returncode != 0:
            print(f"memory-log: anchor failed: {r.stderr.strip()[:160]}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"memory-log: anchor error: {e}", file=sys.stderr)
        return 1
    print(f"memory-log: anchored head {head[:12]} to git note (refs/notes/substrate-memory)")
    return 0


def _nearest_anchor() -> tuple[str, str] | None:
    """(commit, anchored_chain_head) for the nearest ancestor of HEAD that
    carries a substrate-memory note, HEAD itself included; None if no ancestor
    does.

    v3.8.51 (self-audit P1): the previous lookup consulted ONLY the note on
    HEAD, so an anchor was invisible from the very next commit and "no anchor"
    became the normal state everywhere except the instant of anchoring. The
    release gate hedged around that by requiring the anchor only when a note
    happened to exist — a trust anchor that fails open on absence, which
    INTENT.md forbids. Walking to the nearest annotated ancestor makes the
    anchor durable across ordinary commits, so absence can mean what it should:
    nobody ever anchored, refuse.
    """
    try:
        listed = subprocess.run(["git", "notes", "--ref", "substrate-memory", "list"],
                                cwd=ROOT, capture_output=True, text=True, timeout=10,
                                env=_clean_env())
        if listed.returncode != 0 or not listed.stdout.strip():
            return None
        annotated = {ln.split()[1] for ln in listed.stdout.splitlines() if len(ln.split()) == 2}
        # Bounded walk: a repo with thousands of commits since its last anchor
        # is not a repo whose anchor we should quietly accept anyway.
        walk = subprocess.run(["git", "rev-list", "--max-count=5000", "HEAD"],
                              cwd=ROOT, capture_output=True, text=True, timeout=20,
                              env=_clean_env())
        if walk.returncode != 0:
            return None
        for commit in walk.stdout.split():
            if commit not in annotated:
                continue
            r = subprocess.run(["git", "notes", "--ref", "substrate-memory", "show", commit],
                               cwd=ROOT, capture_output=True, text=True, timeout=10,
                               env=_clean_env())
            if r.returncode != 0:
                return None
            for line in r.stdout.splitlines():
                if line.startswith("substrate-memory-head:"):
                    return commit, line.split(":", 1)[1].strip()
            return None
    except Exception:
        return None
    return None


def _require_published_anchor() -> bool:
    """Strict demands the anchor be on the protected remote, not just local.

    Read from `.substrate/config` through the guarded reader; an unreadable or
    absent config is NOT "standard" — a trust decision must not be softened by
    failing to read the file that sets it, so absence here means "do not
    demand publication" only when the file genuinely says a weaker profile,
    and an unreadable file is treated as strict.
    """
    cfg = ROOT / ".substrate" / "config"
    raw = _safe_read_text(cfg, ROOT, max_bytes=1 << 20)
    if raw is None:
        return cfg.exists()  # present-but-unreadable => strict; absent => not strict
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SUBSTRATE_PROFILE"):
            return "strict" in line.split("=", 1)[-1]
    return False


def _has_origin() -> bool:
    """Is there an 'origin' remote at all?

    Load-bearing for honesty, not cosmetics: INTENT.md promises the base tier is
    OFFLINE-COMPLETE, so in a repo with no remote a local-only anchor is the
    strongest anchor that can exist and must not be reported as a deficiency.
    Where an origin DOES exist, publishing is achievable and not doing it is
    worth saying. Same shape as the profile tiers, where a strict-LOCAL repo is
    not called broken for lacking a GitHub-only CODEOWNERS.
    """
    try:
        r = subprocess.run(["git", "remote"], cwd=ROOT, capture_output=True,
                           text=True, timeout=10, env=_evidence_env())
        return r.returncode == 0 and "origin" in r.stdout.split()
    except Exception:
        return False


def _diagnose_unreachable_remote() -> None:
    """Say WHY the remote could not be reached when user config is the reason.

    Isolating the evidence calls from user git config (v3.8.54) takes a
    globally-configured credential helper or `safe.directory` with it. That is
    the right trade — a remote reachable only through a file outside the
    repository is not evidence about that repository — but it must not present
    as an unexplained "local-only". So: retry once under the ordinary sanitized
    env purely to CLASSIFY the failure. This retry never contributes to a
    verdict; its only output is the message below.
    """
    try:
        again = subprocess.run(
            ["git", "ls-remote", "origin", "refs/notes/substrate-memory"],
            cwd=ROOT, capture_output=True, text=True, timeout=30, env=_clean_env(),
        )
    except Exception:
        return
    if again.returncode == 0:
        print("memory-log: origin is reachable ONLY with user/system git config in "
              "play (a global credential helper, url rewrite, proxy, or "
              "safe.directory). Config outside this repository chooses which server "
              "answers, so it cannot be the evidence that the anchor is published. "
              "Put what the fetch needs in the repository's own config or in the "
              "environment. Reporting the anchor as unconfirmed.", file=sys.stderr)


def _remote_anchor(commit: str) -> str | None:
    """The anchored head that ORIGIN publishes for `commit`, or None.

    Offline-safe and never fatal: no remote, no note on the remote, or no
    network all return None, and the caller decides what that means (strict
    refuses; otherwise it is reported as local-only). Confirmation is taken ONLY
    from the remote in this process — an existence check against origin, then a
    forced fetch whose return code is checked — never from a pre-existing local
    tracking ref, which is writable by the same party the check defends against.

    Every call here runs under `_evidence_env()` (v3.8.54, round-36 P1a): the
    remote decides this verdict, so nothing outside the repository may choose
    WHICH remote answers. A user git config selected by `XDG_CONFIG_HOME` or
    `HOME` could rewrite the origin URL and did.
    """
    if not _git_isolates_user_config():
        print("memory-log: cannot confirm the anchor against origin — this git is "
              "older than 2.32, so user/system config cannot be kept out of the "
              "subprocess and the remote that answers could be chosen by a file "
              "outside the repository. Treating the anchor as unconfirmed.",
              file=sys.stderr)
        return None
    try:
        remotes = subprocess.run(["git", "remote"], cwd=ROOT, capture_output=True,
                                 text=True, timeout=10, env=_evidence_env())
        if remotes.returncode != 0 or "origin" not in remotes.stdout.split():
            return None
        # 1. Does ORIGIN actually publish the ref? Asking the remote directly means
        #    "absent upstream" can never be mistaken for anything else.
        lsr = subprocess.run(
            ["git", "ls-remote", "origin", "refs/notes/substrate-memory"],
            cwd=ROOT, capture_output=True, text=True, timeout=30, env=_evidence_env(),
        )
        if lsr.returncode != 0:
            _diagnose_unreachable_remote()
            return None
        if not lsr.stdout.strip():
            return None
        # 2. Fetch it, and REQUIRE the fetch to succeed. v3.8.52 ignored this rc and
        #    then read refs/notes/origin-substrate-memory — a LOCAL ref anyone with
        #    write access can create. `git notes --ref=origin-substrate-memory add`
        #    forged a full "verified against origin" pass against an origin with no
        #    note at all (round-35 P1). `--force` overwrites any pre-planted ref, so
        #    what is read below is what this fetch just wrote, not what was lying
        #    there. A trust layer must not be built on an input its adversary writes.
        fetched = subprocess.run(
            ["git", "fetch", "--quiet", "--force", "origin",
             "refs/notes/substrate-memory:refs/notes/origin-substrate-memory"],
            cwd=ROOT, capture_output=True, text=True, timeout=30, env=_evidence_env(),
        )
        if fetched.returncode != 0:
            return None
        r = subprocess.run(
            ["git", "notes", "--ref", "origin-substrate-memory", "show", commit],
            cwd=ROOT, capture_output=True, text=True, timeout=10, env=_evidence_env(),
        )
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
        # MEMBERSHIP, not equality (v3.8.51). The old check required the
        # current head to EQUAL the anchored hash, so every legitimate append
        # after anchoring reported "history was rewritten" — a false positive
        # that made the anchor unusable past the instant it was written and
        # never tested the real threat. The threat is a chain that was
        # REPLACED wholesale (a different valid chain swapped in — observed
        # live during the v3.8.50 self-audit) or TRUNCATED past the anchor.
        # Both leave the anchored hash absent from the chain; growth keeps it
        # present. The chain walk above already proved every link from the
        # genesis, so "present" means "this chain descends from the anchored
        # state". What no unkeyed hash chain can detect is a rewrite of the
        # suffix AFTER the anchor point — anchor often (every release) and
        # push the note to a protected remote; that is the documented limit.
        found = _nearest_anchor()
        if found is None:
            print("memory-log: NO ANCHOR in the ancestry of HEAD — the chain cannot be "
                  "tied to any known-good state. Establish one with "
                  "`memory_log.py anchor` (a release does this after its gate passes).",
                  file=sys.stderr)
            return 1
        commit, anchored = found
        seen = {ZERO} | {ev.get("hash") for ev in events}
        if anchored not in seen:
            print(f"memory-log: ANCHOR MISMATCH — the head anchored at commit {commit[:12]} "
                  f"({anchored[:12]}) is not in the current chain: history was replaced "
                  "or truncated past the anchor", file=sys.stderr)
            return 1
        at = next((ev.get("seq") for ev in events if ev.get("hash") == anchored), "genesis")
        # LOCAL-ONLY vs REMOTE-CONFIRMED (v3.8.52, round-34 P1). A git note is
        # mutable local state in the same writable repo as the log, so "a note
        # exists and agrees" is evidence, not authority. `anchor` is monotonic
        # now, which blocks the replace-then-re-anchor move, but an adversary
        # who can also rewrite refs/notes/ directly is still only bounded by a
        # copy kept somewhere it cannot write. Say which one we actually have
        # instead of printing the same confident line for both.
        published = _remote_anchor(commit)
        if published == anchored:
            print(f"memory-log: chain OK + anchor verified against origin "
                  f"({len(events)} events; anchored at commit {commit[:12]}, "
                  f"chain seq {at})")
            return 0
        # CONFLICT means the PUBLISHED anchor does not describe this chain — not
        # merely that the two notes differ (v3.8.54, found by the round-36 P1b
        # repro rather than reported). A release whose note push is refused
        # leaves a local note legitimately AHEAD of the published one, and
        # calling that "the local note was rewritten" accuses the operator of
        # tampering for a failure the tooling itself reported. The tamper
        # signal is membership: if what origin publishes is still in this
        # chain, the chain descends from the published anchor and the only
        # thing missing is publication. Reaching such a chain requires genuine
        # descent, and re-anchoring onto it is still gated by monotonicity and
        # the --force evidence event, so this narrows the message, not the check.
        if published is not None and published not in seen:
            print(f"memory-log: ANCHOR CONFLICT — the note at commit {commit[:12]} "
                  f"records {anchored[:12]} locally, but what origin publishes "
                  f"({published[:12]}) is NOT in this chain: the published anchor "
                  "does not describe this log", file=sys.stderr)
            return 1
        ahead = published is not None
        if _require_published_anchor():
            print(f"memory-log: ANCHOR NOT PUBLISHED — the note at commit {commit[:12]} "
                  + (f"has advanced past the published one ({published[:12]}) and the "
                     "new head was never pushed. " if ahead else
                     "exists only locally, where whatever can rewrite the log can "
                     "rewrite it too. ")
                  + "Strict requires the anchor to be on the protected remote: "
                  "`git push origin refs/notes/substrate-memory` FROM THIS CLONE (a "
                  "normal push/clone does not carry refs/notes/*, so no other clone "
                  "can publish it for you).", file=sys.stderr)
            return 1
        if ahead:
            print(f"memory-log: chain OK + anchor LOCAL AHEAD of origin ({len(events)} "
                  f"events; anchored at commit {commit[:12]}, chain seq {at}) — origin "
                  f"still publishes {published[:12]}, which IS in this chain, so the "
                  "log descends from the published anchor; the newer note was not "
                  "pushed. Publish FROM THIS CLONE: `git push origin "
                  "refs/notes/substrate-memory`")
            return 0
        if _has_origin():
            print(f"memory-log: chain OK + anchor present LOCAL-ONLY ({len(events)} "
                  f"events; anchored at commit {commit[:12]}, chain seq {at}) — an "
                  "origin exists but does not publish it, so it bounds accident and a "
                  "single re-anchor, not an adversary with write access to "
                  "refs/notes/. Publish FROM THIS CLONE: `git push origin "
                  "refs/notes/substrate-memory`")
            return 0
        print(f"memory-log: chain OK + anchor verified LOCAL (no remote) ({len(events)} "
              f"events; anchored at commit {commit[:12]}, chain seq {at}) — local is "
              "the strongest anchor an offline repo can hold; it bounds accident and a "
              "single re-anchor, not an adversary with write access to refs/notes/")
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
    ap_anc = sub.add_parser("anchor")
    ap_anc.add_argument(
        "--force", action="store_true",
        help="advance the anchor even though the previously anchored head is no "
             "longer in the chain (a legitimate log reset). The break is APPENDED "
             "to the new chain as an `anchor-forced` event, never hidden.")
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
        return anchor(force=a.force)
    if a.cmd == "tail":
        return tail(a.n)
    if a.cmd == "tasks":
        return tasks()
    ap.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except MemoryLogUnsafe as e:
        # v3.8.42: tampering with the log's leaf is a BREAK, not an empty chain.
        print(f"memory-log: BREAK: {e} — refusing to read", file=sys.stderr)
        sys.exit(1)
