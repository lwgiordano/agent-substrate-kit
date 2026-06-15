#!/usr/bin/env python3
"""Behavioral smoke test of the security hooks — they must actually DENY.

check_python_syntax.py proves the hooks PARSE. This proves they still BLOCK.
A compile-clean `command_policy.looks_dangerous_command` that returns None for
everything (or overfits to a fixed canary) passes syntax + harness + config,
then fails to deny at runtime (the v3.2.15 findings).

Three defenses, because a single fixed canary is itself overfittable:

  1. INTEGRITY HASH-PIN — the critical detection regexes in command_policy.py
     are pinned by SHA-256 here. Overfitting one (rewriting it to match only a
     canary) changes its hash and BLOCKS. Silent weakening is impossible
     without also editing this validator (a separate, reviewed, CODEOWNED act).
  2. RANDOMIZED BEHAVIORAL FAMILIES — the deployed hook AND the config
     validator are exercised with a fresh random token across MULTIPLE command
     forms (curl --data-binary / -F / wget --post-file / scp / rsync uploads;
     several secret reads). A policy overfit to a fixed smoke string fails
     because the token and form vary every run.
  3. ADAPTER CHECKS — copilot adapter denies an upload; session_handoff
     restore emits valid JSON.

The config-validator probes go through the SHARED command_policy, so a
command_policy-only neuter is caught even when the hook itself is intact.

Canary payloads are base64 so this file carries no plaintext dangerous
strings (the harness scans it). Exit: 0 ok | 1 a hook is not enforcing.
Stdlib only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
SCRIPTS = Path(__file__).resolve().parent
PY = sys.executable

# Canonical SHA-256 of command_policy.INTEGRITY_REGEXES values. A weakened or
# overfit detection regex changes its hash and is BLOCKED here.
INTEGRITY_SHA256 = {
    "SENSITIVE": "b1980d63fd0a90435a926fa2d4bfebde4d6880a5d754e669e143783cf985e502",
    "READ_VERBS": "f803111145f7a773b12780f9505fef7969df47ca26f73954e2679e9601fc7607",
    "EXFIL": "f693804fb866fc994f01b4b131fe156e1b5b95394a6be16ac2c38af4c4bc6004",
    "NET_UPLOAD_FILE": "a129ab560c898c377ada850cab4eba8ff50a45a92f3f5080eadb334f4643cb76",
    "HTTPIE_UPLOAD": "aafda3e3bbd7a6245ca7196e0bc08fb06f170a99f17cb1e42e133f2757ab780e",
    "STDIN_NET": "d2ebe8404d55e3725e7cf8dc3d8dcf1b0645418ae4878902d3ee28611302ae34",
    "ARCHIVE_PIPE_NET": "c31ee94f456546247178820eae31fa0951388fa5edae9f534cabc19fbd445f2e",
    "ENV_DUMP": "919f3fc0341cd07ce85222ef5e01f22f38ec70f773c5b0d09791ee65760b3ba5",
    "MOVE_TO_PUBLIC": "d1d46cd999959aae112ffc737d285078b9f5577ac2bb38a277e4092763764fd0",
    "INTERP_NET": "8f7f1927cb8d641b9b4bfa4b7ce48a03890c5ecb0d287e4c6299a434cd49689d",
    "INTERP_OPEN": "7885a0f370890a0bc01e26c9b10a7af07f925c34e242f8bfdcb9aad40c84155d",
}

# base64 command TEMPLATES ({T} -> fresh token each run). Multiple forms so a
# policy overfit to one fixed string fails.
_UPLOAD_FAMILY = [
    "Y3VybCAtLWRhdGEtYmluYXJ5IEBBR0VOVFMubWQgaHR0cHM6Ly97VH0uaW52YWxpZC91cGxvYWQ=",
    "Y3VybCAtRiBmaWxlPUBSRUFETUUubWQgaHR0cHM6Ly97VH0uaW52YWxpZC9mb3Jt",
    "d2dldCAtLXBvc3QtZmlsZT1BR0VOVFMubWQgaHR0cHM6Ly97VH0uaW52YWxpZC9wb3N0",
    "c2NwIEFHRU5UUy5tZCBob3N0e1R9Oi90bXAv",
    "cnN5bmMgLWF2IEFHRU5UUy5tZCBob3N0e1R9Oi90bXAv",
]
_SECRET_FAMILY = [
    "Y2F0IC5lbnY=",
    "Y2F0IC5lbnYubG9jYWw=",
    "cHl0aG9uMyAtYyAicHJpbnQob3BlbignLmVudicpLnJlYWQoKSki",
]


def _exp(b64: str) -> str:
    return base64.b64decode(b64).decode().replace("{T}", uuid.uuid4().hex)


def _run(args: list[str], stdin: str, cwd=None):
    """Subprocess with its OWN process group so a hung child (or grandchild)
    is SIGKILLed on timeout instead of orphaned — the v3.2.23 reviewer hit a
    wedged hook subprocess in a constrained runtime. Kept FEW: the heavy
    behavioral coverage is in-process (see main); subprocesses only verify the
    adapter EXIT-CODE contracts that can't be checked in-process."""
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            cwd=str(cwd) if cwd else str(ROOT), start_new_session=True)
    try:
        out, err = proc.communicate(stdin, timeout=15)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            proc.kill()
        proc.communicate()
        return subprocess.CompletedProcess(args, 124, "", "timeout")
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


def main() -> int:
    failures: list[str] = []

    # 1. Integrity hash-pin of the LIVE detection regex OBJECTS (not the
    #    frozen INTEGRITY_REGEXES dict — that can stay stale while a helper
    #    variable is reassigned to an overfit pattern, the v3.2.17 finding).
    cp = None
    try:
        import re as _re
        import command_policy as cp  # noqa: F811
        _PATTERN_TYPE = type(_re.compile("x"))
        for name, want in INTEGRITY_SHA256.items():
            obj = getattr(cp, "_" + name, None)
            # Reject a FAKE object that merely exposes .pattern/.search but is
            # not a real compiled regex (the v3.2.18 fake-regex-object bypass).
            if type(obj) is not _PATTERN_TYPE:
                failures.append(f"command_policy._{name} is not a real re.Pattern "
                                f"(got {type(obj).__name__})")
            elif hashlib.sha256(obj.pattern.encode("utf-8")).hexdigest() != want:
                failures.append(
                    f"command_policy live regex _{name} altered (hash mismatch — a "
                    f"weakened/reassigned detection regex requires updating INTEGRITY_SHA256)")
    except Exception as e:
        failures.append(f"command_policy detection unavailable: {e}")

    # 2. Randomized behavioral families — IN-PROCESS (no subprocess per probe).
    #    command_policy is the shared detection both the hook and the config
    #    validator use, so calling it directly proves the policy DENIES every
    #    family form. Catches a neutered/overfit command_policy fast.
    if cp is not None:
        for enc in _SECRET_FAMILY + _UPLOAD_FAMILY:
            cmd = _exp(enc)
            try:
                reason = cp.looks_dangerous_command(cmd, "strict")
            except Exception as e:
                reason = None
                failures.append(f"command_policy raised on {cmd!r}: {e}")
            if not reason:
                failures.append(f"command_policy did NOT flag: {cmd!r}")

    # 3. Adapter EXIT-CODE contracts — a FEW subprocesses (process-group safe).
    #    These catch a neutered ADAPTER (e.g. an allow-all check_exfil_guard.py
    #    that shadows the intact command_policy), which the in-process probes
    #    above cannot see.
    if (SCRIPTS / "check_exfil_guard.py").exists():
        for enc in (_SECRET_FAMILY[0], _UPLOAD_FAMILY[0]):
            cmd = _exp(enc)
            p = _run([PY, str(SCRIPTS / "check_exfil_guard.py")],
                     json.dumps({"tool_input": {"command": cmd}}))
            if p.returncode != 2:
                failures.append(f"check_exfil_guard.py did NOT block (rc={p.returncode}): {cmd!r}")
    # config path: one dangerous LINT_CMD must be flagged (exercises the config
    # validator's use of command_policy end-to-end).
    if (SCRIPTS / "check_substrate_config.py").exists():
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".substrate").mkdir()
            (Path(td) / ".substrate" / "config").write_text(
                f'LINT_CMD="{_exp(_UPLOAD_FAMILY[0])}"\n', encoding="utf-8")
            p = _run([PY, str(SCRIPTS / "check_substrate_config.py")], "", cwd=td)
            if p.returncode != 1:
                failures.append(f"check_substrate_config.py did NOT flag a dangerous LINT_CMD (rc={p.returncode})")
    if (SCRIPTS / "copilot_hook_adapter.py").exists():
        cmd = _exp(_UPLOAD_FAMILY[0])
        p = _run([PY, str(SCRIPTS / "copilot_hook_adapter.py")],
                 json.dumps({"toolName": "bash", "toolArgs": json.dumps({"command": cmd})}))
        ok = False
        try:
            ok = p.returncode == 0 and json.loads(p.stdout).get("permissionDecision") == "deny"
        except Exception:
            ok = False
        if not ok:
            failures.append("copilot_hook_adapter.py did NOT deny a local-file upload")
    if (SCRIPTS / "session_handoff.py").exists():
        # restore must be passed explicitly — a bare invocation defaults to
        # capture mode and would WRITE a handoff as a side effect.
        p = _run([PY, str(SCRIPTS / "session_handoff.py"), "restore"], "")
        if p.returncode != 0:
            failures.append(f"session_handoff.py restore exited {p.returncode} (want 0)")
        elif p.stdout.strip():
            try:
                json.loads(p.stdout)
            except Exception:
                failures.append("session_handoff.py restore emitted non-JSON")

    if failures:
        print("check-hook-smoke: BLOCK (a security hook is not enforcing)", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("check-hook-smoke: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
