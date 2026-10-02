"""Read-only, bounded observations for opt-in task reports (not trust anchors)."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from _doc_common import open_dir_chain, safe_read_bytes

GIT_LIMIT = 16 << 20
FILE_LIMIT = 8 << 20
TOTAL_LIMIT = 128 << 20
EXCLUSIONS = [".substrate/receipts/", "Git-ignored untracked files"]


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
               GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="")
    return env


def git(root: Path, *args: str, limit: int = GIT_LIMIT) -> bytes:
    """No target helpers, shell, optional writes, user config, or unbounded output."""
    argv = ["git", "--no-pager", "-c", "core.fsmonitor=false", *args]
    end = time.monotonic() + 10
    with subprocess.Popen(argv, cwd=root, env=clean_env(), stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as proc:
        chunks, size = [], 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    left = end - time.monotonic()
                    if left <= 0:
                        raise ValueError("git observation timed out")
                    for key, _ in selector.select(min(left, 1)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > limit:
                            raise ValueError("git observation exceeds output limit")
                        chunks.append(chunk)
                if proc.wait(timeout=max(0.01, end - time.monotonic())) != 0:
                    raise ValueError("git observation failed: " + args[0])
            return b"".join(chunks)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def _blob_hash(raw: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def git_facts(root: Path) -> dict:
    """Raw bytes are compared, never Git worktree conversions or status helpers.

    Converted text may conservatively read as dirty. Unsupported/missing reads
    are unknown, never clean. Collection is an observation, not a concurrent
    same-user rewrite defense (ADR 0002).
    """
    root = Path(root).resolve()
    facts = dict(schema_version=1, root=str(root), head=None, branch=None,
                 dirty="unknown", status="error", collected_at=now(), diagnostics=[],
                 changed_paths=[], exclusions=EXCLUSIONS, fingerprint=None)
    try:
        top = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve()
        if top != root:
            raise ValueError("requested root is not the worktree root")
        refs = git(root, "for-each-ref", "--format=%(refname)", "refs/heads/")
        try:
            facts["branch"] = git(root, "symbolic-ref", "-q", "HEAD").decode().strip()
        except ValueError:
            facts["branch"] = "detached"
        try:
            head = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        except ValueError:
            if facts["branch"] != "detached" and facts["branch"].encode() not in refs.splitlines():
                facts["status"] = "unborn"
                facts["diagnostics"].append({"code": "unborn", "path": "HEAD"})
                return facts
            raise
        facts["head"] = head
        algorithm = git(root, "rev-parse", "--show-object-format").decode().strip()
        if algorithm not in ("sha1", "sha256"):
            raise ValueError("unsupported Git object format")
        index = git(root, "ls-files", "--stage", "-z")
        tree_raw = git(root, "ls-tree", "-r", "-z", head)
        untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z")
        tree, entries = {}, {}
        for item in tree_raw.split(b"\0"):
            if item:
                meta, name = item.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                tree[os.fsdecode(name)] = (mode, oid)
        for item in index.split(b"\0"):
            if item:
                meta, name = item.split(b"\t", 1)
                mode, oid, stage = meta.decode().split()
                if stage != "0":
                    raise ValueError("unmerged index")
                entries[os.fsdecode(name)] = (mode, oid)
        changed = {p for p in set(tree) | set(entries) if tree.get(p) != entries.get(p)}
        loose = {os.fsdecode(p) for p in untracked.split(b"\0") if p}
        loose = {p for p in loose if not p.startswith(".substrate/receipts/")}
        changed |= loose
        digest = hashlib.sha256()

        def field(data):
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)

        for value in (head.encode(), facts["branch"].encode(), index):
            field(value)
        total, unknown = 0, False
        for rel in sorted(set(entries) | loose):
            if rel.startswith(".substrate/receipts/"):
                raise ValueError("receipt store must not contain tracked files")
            path = root / rel
            field(os.fsencode(rel))
            try:
                if Path(rel).is_absolute() or ".." in Path(rel).parts:
                    raise ValueError("unsafe input path")
                parent = open_dir_chain(root, path.parent)
                try:
                    mode = os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_mode
                finally:
                    os.close(parent)
                if not stat.S_ISREG(mode):
                    raise ValueError("unsupported input type")
                raw = safe_read_bytes(path, root, max_bytes=FILE_LIMIT)
                if raw is None:
                    raise ValueError("unsafe, unreadable, or oversized input")
                total += len(raw)
                if total > TOTAL_LIMIT:
                    raise ValueError("total input byte limit exceeded")
                observed_mode = "100755" if mode & stat.S_IXUSR else "100644"
                field(observed_mode.encode())
                field(stat.S_IMODE(mode).to_bytes(4, "big"))
                field(raw)
                if entries.get(rel) != (observed_mode, _blob_hash(raw, algorithm)):
                    changed.add(rel)
            except FileNotFoundError:
                field(b"missing")
                changed.add(rel)
            except (OSError, ValueError):
                unknown = True
                facts["diagnostics"].append({"code": "unsupported-input", "path": rel})
                if total > TOTAL_LIMIT:
                    break
        facts.update(status="ok", dirty="unknown" if unknown else "dirty" if changed else "clean",
                     changed_paths=sorted(changed), fingerprint=None if unknown else digest.hexdigest())
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        facts["diagnostics"].append({"code": "git-error", "path": ".", "reason": type(exc).__name__})
    return facts


def safe_text(value: str, limit: int = 2000) -> str:
    from bus_claims import _shown
    from session_handoff import _safe_history_line
    # Context sanitization is not terminal sanitization. Reuse the bus's
    # printable-control policy after the context/credential filter.
    return _shown(_safe_history_line(value, limit, discard_secrets=True))


def clip_bytes(value: str, limit: int) -> str:
    raw = value.encode("utf-8")
    return value if len(raw) <= limit else raw[:max(0, limit - 3)].decode("utf-8", "ignore") + "…"


def sanitize_report(value) -> tuple[object, int]:
    """Display strings only; never mutate source bytes or authentication inputs.

    Fields are schema-owned; user text only appears in values, not dictionary
    keys. Known-pattern redaction is not universal credential detection.
    """
    if isinstance(value, str):
        clean = safe_text(value, len(value) + 1)
        return clean, int(clean != value)
    if isinstance(value, dict):
        out, changed = {}, 0
        for key, item in value.items():
            out[key], count = sanitize_report(item)
            changed += count
        return out, changed
    if isinstance(value, list):
        out, changed = [], 0
        for item in value:
            cleaned, count = sanitize_report(item)
            out.append(cleaned)
            changed += count
        return out, changed
    return value, 0


def read_source(root: Path, rel: str, head: str | None = None,
                provenance: bool = True) -> tuple[dict | None, dict | None]:
    """Hash the exact bytes parsed; never reopen for metadata provenance."""
    raw = safe_read_bytes(root / rel, root, max_bytes=4 << 20)
    if raw is None:
        return None, {"code": "missing-or-unsafe-source", "path": rel}
    try:
        body = raw.decode("utf-8")
    except UnicodeError:
        return None, {"code": "undecodable-source", "path": rel}
    result = dict(path=rel, content_hash=hashlib.sha256(raw).hexdigest(),
                  source_state="unverified-local", source_revision=None,
                  collected_at=now(), text=body)
    if not provenance:
        return result, None
    try:
        head = head or git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        listing = git(root, "ls-tree", "-z", head, "--", rel)
        if not listing:
            result["source_state"] = "untracked"
        else:
            meta, _ = listing.rstrip(b"\0").split(b"\t", 1)
            mode, kind, oid = meta.decode().split()
            algorithm = "sha1" if len(oid) == 40 else "sha256"
            same = mode in ("100644", "100755") and kind == "blob" and _blob_hash(raw, algorithm) == oid
            result.update(source_state="committed" if same else "modified", source_revision=head)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return result, {"code": "source-provenance-unavailable", "path": rel}
    return result, None


def json_text(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def committed_source(root: Path, rel: str, head: str) -> tuple[dict | None, dict | None]:
    try:
        listing = git(root, "ls-tree", "-z", head, "--", rel)
        if not listing:
            return None, {"code": "missing-committed-source", "path": rel}
        meta, _ = listing.rstrip(b"\0").split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError("unsupported committed source")
        raw = git(root, "cat-file", "blob", oid, limit=4 << 20)
        return dict(path=rel, text=raw.decode("utf-8"), content_hash=hashlib.sha256(raw).hexdigest(),
                    source_revision=head, source_state="committed", collected_at=now()), None
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None, {"code": "unreadable-committed-source", "path": rel}
