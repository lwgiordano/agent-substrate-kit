#!/usr/bin/env python3
"""Single source of truth for "is this shell command dangerous?".

This module OWNS the detection (the regexes and the decision logic). It is
used by BOTH:
  - the agent Bash exfil guard (check_exfil_guard.py — a thin stdin/exit
    adapter that calls into here)
  - the .substrate/config command-value validator (check_substrate_config.py)

so a command the agent's Bash hook would block (e.g. a local-file upload)
cannot pass config validation and then execute in CI via LINT_CMD/
TYPECHECK_CMD/TEST_CMD. Detection lives HERE, not in the hook adapter, so
editing the hook adapter cannot silently change config command validation
(the v3.2.15 finding: an overfit `_looks_dangerous` in the hook file
weakened both paths at once).

A TRIPWIRE, NOT A SANDBOX — pattern matching, not shell parsing. A
determined attacker can mutate command shape to evade. The integrity of the
critical regexes is hash-pinned in check_hook_smoke.py so a silent
weakening (overfit to a canary) is caught by the gate.

Stdlib only.
"""
from __future__ import annotations

import errno
import os
import re
import shlex
import stat
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    _ROOT = _sr()
except Exception:
    _ROOT = Path.cwd()


class CommandPolicyUnavailable(RuntimeError):
    """The command policy could not load — callers must fail closed."""


_VALID_PROFILES = {"starter", "standard", "strict"}


# Sensitive file shapes. Kept broad on purpose: matching the path is
# necessary but not sufficient — it must co-occur with a read/transfer
# verb (see _READ_VERBS / _EXFIL) for a block.
_SENSITIVE = re.compile(
    r"(?i)(?:^|[\s=@'\"/])(?:\.env(?:\.[\w.-]+)?|"
    r"[\w./-]*(?:secret|credential|password|passwd|private[_-]?key)[\w./-]*|"
    r"id_rsa|id_ed25519|\.pem|\.p12|\.pfx|\.keystore|"
    r"\.aws/credentials|\.ssh/id_|\.netrc|\.npmrc|\.pypirc|"
    r"service[_-]?account.*\.json|gcloud.*credentials)"
)
_READ_VERBS = re.compile(
    r"(?i)\b(?:cat|bat|less|more|head|tail|nl|xxd|od|strings|"
    r"grep|egrep|rg|ag|ack|awk|sed|sort|uniq|cut|"
    r"base64|openssl|gpg|python3?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e)\b"
)
_EXFIL = re.compile(
    r"(?i)\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|"
    r"telnet|socat)\b"
)
_GREP_TOOL = re.compile(r"(?i)\b(?:grep|egrep|rg|ag|ack)\b")
_RECURSIVE_FLAG = re.compile(r"(?i)(?:^|\s)--?[a-z]*r[a-z]*(?:\s|$)|--recursive\b")
_SECRET_KEYWORD = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|bearer)"
)
_MOVE_TO_PUBLIC = re.compile(
    r"(?i)\b(?:cp|mv|install|tee)\b[^\n]*(?:/tmp/|/var/tmp/|/dev/shm/|"
    r"/public/|~/public|\.\./)"
)
# --- standard-tier additions ---
_ENV_DUMP = re.compile(
    r"(?i)(?:^|[;&|]|\s)(?:printenv\b\s*$|printenv\b\s*[|>]|"
    r"env\b\s*$|env\b\s*[|>]|set\b\s*[|>])"
)
_PY_ENVIRON = re.compile(r"(?i)os\.environ|import\s+os[^\n]*environ")
_GIT_GREP_SECRET = re.compile(
    r"(?i)\bgit\s+grep\b[^\n]*"
    r"(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|bearer)"
)
_ARCHIVE_EXFIL = re.compile(
    r"(?i)\b(?:tar|zip|7z|gzip)\b[^\n]*(?:/tmp/|/var/tmp/|/dev/shm/|/public/)"
)
_FIND_EXEC_SECRET = re.compile(
    r"(?i)\bfind\b[^\n]*(?:\.env|secret|credential|private[_-]?key|id_rsa)"
    r"[^\n]*-exec"
)
_HEREDOC_SECRET = re.compile(
    r"(?is)\b(?:python3?|node|ruby|perl)\b[^\n]*<<.*?"
    r"(?:\.env\b|secret|credential|private[_-]?key|id_rsa|\.pem|os\.environ|\.ssh/)"
)
_ARCHIVE_PIPE_NET = re.compile(
    r"(?i)\b(?:tar|zip|7z|gzip|cat|dd)\b[^\n|]*\|[^\n]*"
    r"\b(?:curl|wget|nc|ncat|socat)\b"
)
_RSYNC_URL_PUSH = re.compile(r"(?i)\brsync\b[^\n]*\srsync://[^\n]*")
_GH_GIST = re.compile(r"(?i)\bgh\s+gist\s+create\b[^\n]*\s[\w./~-]+\.[\w]")
_NET_UPLOAD_FILE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]*"
    r"(?:"
    r"(?:-F|--form(?:-string)?|-d|--data(?:-binary|-raw|-urlencode)?)\s*\S*[@<][\w./~-]"
    r"|(?:-T|--upload-file)\s+\S"
    r"|--(?:post|body)-file[=\s]\S"
    r"|--body-data\s*@"
    r")"
)
_HTTPIE_UPLOAD = re.compile(
    r"(?i)(?:^|\s|;|&&)\s*(?:http|https|httpie)\b[^\n]*"
    r"\s[\w.-]+(?::=)?@[\w./~-]+"
)
_SCP_RSYNC_TOOL = re.compile(r"(?i)\b(?:scp|rsync|sftp)\b")
_REMOTE_DEST = re.compile(r"^[\w.@-]+:")  # host:path, not a URL (no //)
_STDIN_NET = re.compile(
    r"(?i)\b(?:nc|ncat|netcat|socat|curl|wget|telnet|http|https|httpie|ftp|sftp)\b[^\n]*<\s*[\w./~-]"
)
_INTERP_NET = re.compile(
    r"(?is)\b(?:python3?|node|ruby|perl)\b.*?"
    r"(?:requests\.(?:post|put|patch)|urlopen|urllib|http\.client|"
    r"fetch\(|net/http|httparty|XMLHttpRequest|LWP::UserAgent|"
    r"socket\.|\.connect\(|\.send\(|\.request\(|require\(['\"]https?['\"])"
)
_INTERP_OPEN = re.compile(
    r"(?is)\b(?:python3?|node|ruby|perl)\b.*?"
    r"(?:open\(|\bopen\s+my\b|open\s+['\"<]|read_text|readFileSync|"
    r"File\.read|IO\.read|Path\(|<\s*['\"][\w./~-]+['\"])"
)

# ReDoS / pathological-input guard: cap the bytes we run regexes over.
_MAX_CMD_LEN = 16_000

# Critical regexes whose integrity is hash-pinned by check_hook_smoke.py.
# Weakening any of these (e.g. overfitting it to a canary) changes the SHA
# and BLOCKS the gate — silent weakening is impossible. Order-stable.
INTEGRITY_REGEXES = {
    "SENSITIVE": _SENSITIVE.pattern,
    "READ_VERBS": _READ_VERBS.pattern,
    "EXFIL": _EXFIL.pattern,
    "NET_UPLOAD_FILE": _NET_UPLOAD_FILE.pattern,
    "HTTPIE_UPLOAD": _HTTPIE_UPLOAD.pattern,
    "STDIN_NET": _STDIN_NET.pattern,
    "ARCHIVE_PIPE_NET": _ARCHIVE_PIPE_NET.pattern,
    "ENV_DUMP": _ENV_DUMP.pattern,
    "MOVE_TO_PUBLIC": _MOVE_TO_PUBLIC.pattern,
    "INTERP_NET": _INTERP_NET.pattern,
    "INTERP_OPEN": _INTERP_OPEN.pattern,
}


def _is_scp_push(cmd: str) -> bool:
    if not _SCP_RSYNC_TOOL.search(cmd):
        return False
    try:
        toks = shlex.split(cmd)
    except Exception:
        toks = cmd.split()
    if len(toks) < 2:
        return False
    last = toks[-1].strip("'\"")
    return bool(_REMOTE_DEST.match(last)) and "//" not in last


def profile() -> str:
    # MUST resolve repo root, not cwd — else a hook launched from a
    # subdirectory can't find .substrate/config and silently downgrades
    # strict policy to standard (the v3.2.1 subdir-bypass bug).
    #
    # FAIL CLOSED on an INVALID profile value. The gate validators reject a
    # bad enum, but this runtime hook can fire while the tree is dirty or
    # before checks run — a typo'd SUBSTRATE_PROFILE="stirct" must NOT
    # silently downgrade strict to standard here. Raise so the hook blocks.
    cfg = _ROOT / ".substrate" / "config"
    configured = "standard"
    if cfg.exists():
        try:
            lines = cfg.read_text(encoding="utf-8").splitlines()
        except Exception as e:
            raise CommandPolicyUnavailable(f"could not read .substrate/config: {e}")
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("SUBSTRATE_PROFILE="):
                val = s.split("=", 1)[1].strip().strip("\"'")
                if val not in _VALID_PROFILES:
                    raise CommandPolicyUnavailable(
                        f"invalid SUBSTRATE_PROFILE in .substrate/config: {val!r}")
                configured = val
                break
    # PROFILE LOCK: never run BELOW the pinned minimum, even at the runtime hook
    # boundary (before the gate runs). A downgraded config can't disable strict.
    # v3.8.36 FAIL CLOSED (Codex round-19): the old read ignored the lock on ANY
    # error, so undecodable bytes in required_profile silently downgraded the
    # live hook policy to the config value. A lock that is PRESENT but is a
    # symlink, a non-regular file, unreadable, undecodable, or out-of-domain now
    # raises CommandPolicyUnavailable so the hook BLOCKS. Inline (not shared
    # _doc_common.read_lock): this module is AST-pinned and dependency-light —
    # the semantics are the same contract by construction, covered by tests.
    req = _ROOT / ".substrate" / "required_profile"
    order = {"starter": 0, "standard": 1, "strict": 2}
    # v3.8.37: O_NONBLOCK so a FIFO lock fails fast (not hangs), and a WHOLE
    # small-bounded read so a padded `b"strict"+spaces+b"starter"` cannot be
    # truncated into a lowering value (round-20 P1/P2) — same contract as
    # _doc_common.read_lock, kept inline because this module is AST-pinned.
    _LOCK_MAX = 64
    try:
        fd = os.open(str(req),
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return configured  # genuinely absent — no lock was pinned
        raise CommandPolicyUnavailable(
            f"required_profile lock unreadable ({e.__class__.__name__}) — failing closed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CommandPolicyUnavailable(
                "required_profile lock is not a regular file — failing closed")
        try:
            raw = os.read(fd, _LOCK_MAX + 1)
        except (OSError, BlockingIOError) as e:
            raise CommandPolicyUnavailable(
                f"required_profile lock unreadable ({e.__class__.__name__}) — failing closed")
    finally:
        os.close(fd)
    if len(raw) > _LOCK_MAX:
        raise CommandPolicyUnavailable(
            "required_profile lock exceeds 64 bytes — refusing a padded value")
    try:
        r = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise CommandPolicyUnavailable(
            "required_profile lock is not valid UTF-8 — failing closed") from None
    if r not in order:
        raise CommandPolicyUnavailable(
            f"required_profile lock holds invalid value {r[:40]!r} — failing closed")
    if order[r] > order.get(configured, 0):
        return r
    return configured


def looks_dangerous_command(cmd: str, profile_name: str | None = None) -> str | None:
    """Reason string if `cmd` is dangerous (exfil/secret-read/destructive),
    else None. The detection — owned here, shared by the hook and config."""
    if not cmd:
        return None
    prof = profile_name or profile()
    if len(cmd) > _MAX_CMD_LEN:
        if prof == "strict":
            return "command exceeds length cap (strict: denied)"
        cmd = cmd[:_MAX_CMD_LEN]
    has_sensitive = bool(_SENSITIVE.search(cmd))
    # --- base tier (all profiles) ---
    if (_GREP_TOOL.search(cmd) and _RECURSIVE_FLAG.search(cmd)
            and _SECRET_KEYWORD.search(cmd)):
        return "recursive grep for secret/token/key patterns"
    if _HEREDOC_SECRET.search(cmd):
        return "inline interpreter heredoc reading a sensitive file"
    if has_sensitive and _EXFIL.search(cmd):
        return "network/transfer command referencing a sensitive file"
    if has_sensitive and _READ_VERBS.search(cmd):
        return "read of a sensitive file (.env / credential / key)"
    if has_sensitive and _MOVE_TO_PUBLIC.search(cmd):
        return "copy/move of a sensitive file to a public/tmp/parent path"
    if _ARCHIVE_PIPE_NET.search(cmd):
        return "archive/cat piped to a network upload (exfil)"
    if _NET_UPLOAD_FILE.search(cmd):
        return "network upload of a local file (curl/wget upload form)"
    if _HTTPIE_UPLOAD.search(cmd):
        return "httpie field upload of a local file"
    if _STDIN_NET.search(cmd):
        return "local file redirected into a network sender (nc/socat/curl <file)"
    if _is_scp_push(cmd):
        return "scp/rsync/sftp push of a local file to a remote host"
    if _RSYNC_URL_PUSH.search(cmd):
        return "rsync:// protocol push to a remote module"
    if _GH_GIST.search(cmd):
        return "gh gist create of a local file (publishes contents)"
    if _INTERP_NET.search(cmd) and _INTERP_OPEN.search(cmd):
        return "inline interpreter reading a file and making a network call"
    if prof == "starter":
        return None
    # --- standard + strict tiers ---
    if _ENV_DUMP.search(cmd):
        return "whole-environment dump (env/printenv/set)"
    if _PY_ENVIRON.search(cmd):
        return "reading os.environ from an inline interpreter"
    if _GIT_GREP_SECRET.search(cmd):
        return "git grep for secret/token/key patterns"
    if _ARCHIVE_EXFIL.search(cmd):
        return "archiving files to a public/tmp path (exfil staging)"
    if _FIND_EXEC_SECRET.search(cmd):
        return "find -exec over secret-looking paths"
    if prof != "strict":
        return None
    # --- strict tier ---
    if _EXFIL.search(cmd) and re.search(r"(?i)(?:-d\s*@|--data\s*@|-T\s|--upload-file)", cmd):
        return "network upload of a local file (strict: denied)"
    if re.search(r"(?i)\bcurl\b[^\n]*\s(?:--config|-K)\b", cmd):
        return "curl --config can hide upload flags in a config file (strict: denied)"
    return None


# Back-compat aliases for callers/tests that referenced the old private names
# when the detection lived in check_exfil_guard.py.
_looks_dangerous = looks_dangerous_command
_profile = profile
