#!/usr/bin/env python3
"""Validate .substrate/config as DATA and reject dangerous command values.

Two jobs:
  1. Enforce the same data grammar as the shell parser
     (_substrate_config.sh): KEY=VALUE only, fixed key allowlist, no
     command substitution / backticks. Invalid → exit 2.
  2. Apply the SHARED command policy (command_policy.looks_dangerous_command,
     the exact policy the agent Bash exfil guard uses) to the command
     fields LINT_CMD/TYPECHECK_CMD/TEST_CMD, so a config that encodes a
     local-file upload (`curl --data-binary @AGENTS.md ...`) is blocked
     BEFORE any gate executes it. Dangerous → exit 1.

Run by `manage.sh check` and `release_gate.sh` before the lang gates.

Exit codes: 0 ok | 1 dangerous value | 2 invalid config syntax.
"""
from __future__ import annotations
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
import json

from _doc_common import read_lock as _dc_read_lock
# Detection is owned by command_policy.py. FAIL CLOSED: if it cannot import
# (broken/neutered policy module), looks_dangerous_command raises and main()
# converts that to exit 2 — never silently allow a command value.
try:
    from command_policy import CommandPolicyUnavailable, looks_dangerous_command
    _POLICY_IMPORT_ERROR = None
except Exception as _e:  # pragma: no cover - exercised via staged broken module
    _POLICY_IMPORT_ERROR = _e

    class CommandPolicyUnavailable(RuntimeError):
        pass

    def looks_dangerous_command(cmd, profile=None):
        raise CommandPolicyUnavailable(
            f"command_policy.py failed to import: {_POLICY_IMPORT_ERROR}")

_ALLOWED_KEYS = {"SUBSTRATE_PROFILE", "SUBSTRATE_LANG", "SUBSTRATE_RUNNER",
                 "LINT_CMD", "TYPECHECK_CMD", "TEST_CMD", "SUBSTRATE_CODE_SUFFIXES",
                 "SUBSTRATE_SANDBOX", "SUBSTRATE_REMOTE_GOVERNANCE", "SUBSTRATE_DEP_COOLDOWN",
                 "SUBSTRATE_SECURITY_SCANNERS", "SUBSTRATE_RELEASE_BACKEND"}
# Non-negative-integer keys (validated numerically, not against a fixed enum domain).
# SUBSTRATE_DEP_COOLDOWN=N opts into the dependency-cooldown tier — flag direct deps
# whose resolved version published < N days ago (a fresh-version risk signal). 0 = off. v3.7.2.
_INT_KEYS = {"SUBSTRATE_DEP_COOLDOWN"}
_ENUMS = {
    "SUBSTRATE_PROFILE": {"starter", "standard", "strict"},
    "SUBSTRATE_LANG": {"python", "node", "go", "none"},
    "SUBSTRATE_RUNNER": {"auto", "uv", "python", "poetry"},
    # SUBSTRATE_SANDBOX=1 opts into the egress-containment tier (sandbox_exec.sh).
    "SUBSTRATE_SANDBOX": {"0", "1"},
    # SUBSTRATE_REMOTE_GOVERNANCE=1 opts into the remote-governance tier (CODEOWNERS
    # coverage, trusted-base authority) — orthogonal to the governance PROFILE so a
    # repo can be strict-LOCAL (no remote) or standard+remote. v3.6.0.
    "SUBSTRATE_REMOTE_GOVERNANCE": {"0", "1"},
    # SUBSTRATE_SECURITY_SCANNERS=1 opts into the DEEP scanner tier (gitleaks/trivy/osv,
    # composed + skip-honest). Networked (vuln DBs) — never part of the offline base. v3.7.17.
    "SUBSTRATE_SECURITY_SCANNERS": {"0", "1"},
    # SUBSTRATE_RELEASE_BACKEND declares HOW releases are signed/published — a scale rung, not a
    # runtime gate: local (laptop minisign) → ci-minisign (key in CI) → keyless (Sigstore/OIDC).
    # go-live maps the ladder; `enable release <tier>` installs the matching workflow. v3.7.18.
    "SUBSTRATE_RELEASE_BACKEND": {"local", "ci-minisign", "keyless"},
}


class HarnessPatternsUnavailable(RuntimeError):
    """harness_patterns.json could not load — callers must fail closed."""


def _shell_danger_patterns():
    """harness_patterns.json shell-danger (curl|bash, rm -rf, bypass flags) —
    complements the exfil policy (uploads), which doesn't cover pipe-to-shell.

    FAIL CLOSED: if the data file is missing/corrupt or the group is gone,
    raise instead of returning [] — otherwise a corrupted policy file would
    silently disable the pipe-to-shell check and let a curl|bash LINT_CMD
    pass validation and run in `check`/CI. (Semantic weakening of an intact
    file is caught earlier by check_harness_patterns.py.)"""
    try:
        p = Path(__file__).resolve().parent / "harness_patterns.json"
        data = json.loads(p.read_text(encoding="utf-8"))
        entries = data["shell_danger"]
        return [(label, re.compile(rx)) for label, rx in entries]
    except Exception as e:
        raise HarnessPatternsUnavailable(
            f"harness_patterns.json unavailable or invalid: {e}"
        ) from e


def _command_is_dangerous(val, profile, shell_danger):
    """Reason if a config command value is dangerous: exfil policy OR
    harness shell-danger. Both, because they cover different threats."""
    reason = looks_dangerous_command(val, profile)
    if reason:
        return reason
    for label, rx in shell_danger:
        if rx.search(val):
            return label
    return None
_COMMAND_KEYS = ("LINT_CMD", "TYPECHECK_CMD", "TEST_CMD")
_KV = re.compile(r"^([A-Za-z][A-Za-z0-9_ ]*?)\s*=(.*)$")


_LOCK_ERRORS: list[str] = []


def _read_lock(name: str, allowed: set) -> str | None:
    """Read a frozen `.substrate/<name>` lock. ABSENT file → None (no lock was
    ever pinned — bootstrap never wrote one). PRESENT but unreadable, or holding
    a value outside `allowed`, → recorded in _LOCK_ERRORS so main() FAILS THE
    GATE (v3.8.33). A present lock proves operator intent, and flipping its
    permission bits is not content drift (the freeze/CODEOWNERS see edits, not
    chmod), so an unreadable lock must never be cheaper than a governed edit —
    the v3.8.25 'a trust anchor may not fail open' class."""
    # v3.8.36: delegate to the canonical fail-closed reader (O_NOFOLLOW +
    # fstat S_ISREG + explicit UTF-8 decode) — a SYMLINKED lock is an error,
    # never read through, and a DIRECTORY lock is an error, never "absent"
    # (is_file() got both wrong; Codex round-19).
    state, val, reason = _dc_read_lock(ROOT / ".substrate" / name, allowed, root=ROOT)
    if state == "bad":
        _LOCK_ERRORS.append(f".substrate/{name}: {reason} — refusing to treat it as absent")
        return None
    return val  # "ok" → value; "absent" → None


def _required_profile():
    """The pinned minimum profile (.substrate/required_profile), or None.
    Written by bootstrap; frozen by the trusted-base guard + CODEOWNERS."""
    return _read_lock("required_profile", {"starter", "standard", "strict"})


def _required_sandbox():
    """The pinned sandbox requirement (.substrate/required_sandbox): '0'/'1' or None.
    Written by bootstrap when the sandbox tier is selected (→ '1'); frozen by the
    trusted-base guard + CODEOWNERS, exactly like .substrate/required_profile."""
    return _read_lock("required_sandbox", {"0", "1"})


def _required_remote_governance():
    """The pinned remote-governance requirement (.substrate/required_remote_governance):
    '0'/'1' or None. Written by bootstrap when the remote tier is selected (→ '1');
    frozen by the trusted-base guard + CODEOWNERS, exactly like .substrate/required_sandbox.
    v3.6.0."""
    return _read_lock("required_remote_governance", {"0", "1"})


def _required_dep_cooldown():
    """The pinned dependency-cooldown requirement (.substrate/required_dep_cooldown):
    '0'/'1' or None. When '1', the cooldown tier may not be disabled (flag set to 0).
    Frozen by the trusted-base guard, like the other locks. v3.7.2."""
    return _read_lock("required_dep_cooldown", {"0", "1"})


def _required_security_scanners():
    """The pinned security-scanner requirement (.substrate/required_security_scanners):
    '0'/'1' or None. When '1', the scanner tier may not be disabled. Frozen by the
    trusted-base guard, like the other locks. v3.7.17."""
    return _read_lock("required_security_scanners", {"0", "1"})


def _strip_quotes_checked(raw: str, key: str):
    """Returns (value, error). Rejects unbalanced quotes."""
    v = raw.strip()
    if v[:1] in ('"', "'"):
        q = v[0]
        if len(v) < 2 or v[-1] != q:
            return "", f"unbalanced quotes in {key}"
        return v[1:-1], None
    if v[-1:] in ('"', "'"):
        return "", f"unbalanced quotes in {key}"
    return v, None


def main() -> int:
    cfg = ROOT / ".substrate" / "config"
    # In-process repeat calls must not inherit a previous run's lock errors
    # (module-level state; audit finding).
    _LOCK_ERRORS.clear()
    # Evaluate every frozen lock FIRST (v3.8.33). Two fail-closed rules:
    # (1) a lock that exists but cannot be read/parsed fails the gate — an
    #     unreadable lock must not be cheaper than a governed edit;
    # (2) an ABSENT config does not bypass the locks — every flag then sits at
    #     its default, so any pinned minimum above the default is violated.
    #     Deleting config must not be cheaper than editing it.
    req = _required_profile()
    req_sb = _required_sandbox()
    req_rg = _required_remote_governance()
    req_dc = _required_dep_cooldown()
    req_ss = _required_security_scanners()
    if _LOCK_ERRORS:
        for e in _LOCK_ERRORS:
            print(f"check-substrate-config: LOCK ERROR — {e}", file=sys.stderr)
        print("check-substrate-config: refusing (a present lock that cannot be read is "
              "treated as tampering, never as 'no lock'); fix the file's contents/permissions",
              file=sys.stderr)
        return 2
    if not cfg.is_file():
        violated = []
        if req == "strict":
            violated.append("required_profile=strict (default profile is standard)")
        for lock_val, name in ((req_sb, "required_sandbox"),
                               (req_rg, "required_remote_governance"),
                               (req_dc, "required_dep_cooldown"),
                               (req_ss, "required_security_scanners")):
            if lock_val == "1":
                violated.append(f"{name}=1 (the tier defaults to off without config)")
        if violated:
            print("check-substrate-config: .substrate/config is MISSING but pinned "
                  "minimums exist: " + "; ".join(violated), file=sys.stderr)
            return 2
        return 0
    vals: dict[str, str] = {}
    for raw in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw
        # drop full-line comments / blanks
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.split("  #", 1)[0].rstrip()
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if not line:
            continue
        # strict KEY=VALUE: uppercase key, no leading `export`, no space before `=`
        if not re.match(r"^[A-Z][A-Z0-9_]*=", line):
            print(f"check-substrate-config: invalid line (only KEY=VALUE allowed): {line}", file=sys.stderr)
            return 2
        key, raw_val = line.split("=", 1)
        if key not in _ALLOWED_KEYS:
            print(f"check-substrate-config: unknown key: {key}", file=sys.stderr)
            return 2
        # command substitution / backticks / ${...} forbidden (data, not code)
        if "$(" in raw_val or "`" in raw_val or "${" in raw_val:
            print(f"check-substrate-config: command substitution forbidden in {key}", file=sys.stderr)
            return 2
        val, err = _strip_quotes_checked(raw_val, key)
        if err:
            print(f"check-substrate-config: {err}", file=sys.stderr)
            return 2
        # enum values must be in their fixed domain (a typo like "stirct"
        # would otherwise silently disable strict governance).
        if key in _ENUMS and val not in _ENUMS[key]:
            print(f"check-substrate-config: invalid {key}: {val}", file=sys.stderr)
            return 2
        # integer-valued keys (e.g. cooldown days) must be non-negative ints.
        if key in _INT_KEYS and not val.isdigit():
            print(f"check-substrate-config: invalid {key}: {val} (want non-negative integer)", file=sys.stderr)
            return 2
        vals[key] = val
    profile = vals.get("SUBSTRATE_PROFILE", "standard")
    # PROFILE LOCK: a repo may RAISE its profile but never silently LOWER it.
    # `.substrate/required_profile` (written by bootstrap, CODEOWNED + frozen by
    # the trusted-base guard) pins the minimum. A PR flipping strict→standard
    # to disable strict-only hook behavior is blocked here — the gate, the
    # runtime hook profile, and CI all read this same file. (v3.2.20 finding.)
    # (req/req_sb/req_rg/req_dc/req_ss were read before the config parse — v3.8.33.)
    if req is not None:
        order = {"starter": 0, "standard": 1, "strict": 2}
        if order.get(profile, 0) < order.get(req, 0):
            print(f"check-substrate-config: SUBSTRATE_PROFILE={profile!r} is below the "
                  f"required minimum profile {req!r} (.substrate/required_profile)", file=sys.stderr)
            return 2
    # SANDBOX LOCK + POLICY (v3.5.1 — closes the v3.5.0-audit P1s). Mirror the
    # profile lock for the egress-containment tier. `.substrate/required_sandbox=1`
    # (written by bootstrap when the sandbox tier is selected, CODEOWNED + trusted-
    # base frozen) makes containment a REQUIRED minimum — a PR cannot flip
    # SUBSTRATE_SANDBOX to 0. And the sandbox POLICY (.substrate/sandbox.json) is
    # SECURITY data, so a malformed policy must FAIL THE GATE here — not only when
    # something happens to invoke the sandbox at runtime.
    sandbox_on = vals.get("SUBSTRATE_SANDBOX", "0")
    if req_sb == "1" and sandbox_on != "1":
        print('check-substrate-config: SUBSTRATE_SANDBOX must be "1" — containment is a '
              "required minimum (.substrate/required_sandbox=1); a PR may not disable it",
              file=sys.stderr)
        return 2
    # REMOTE-GOVERNANCE LOCK (v3.6.0). Mirror the profile + sandbox locks for the
    # remote-governance tier. Once a repo pins .substrate/required_remote_governance=1
    # (written by bootstrap --profile *+remote, CODEOWNED + trusted-base frozen), a PR
    # may not flip SUBSTRATE_REMOTE_GOVERNANCE to 0 to silently drop CODEOWNERS coverage
    # / trusted-base authority. Only enforced when the lock is "1".
    remote_gov_on = vals.get("SUBSTRATE_REMOTE_GOVERNANCE", "0")
    if req_rg == "1" and remote_gov_on != "1":
        print('check-substrate-config: SUBSTRATE_REMOTE_GOVERNANCE must be "1" — remote '
              "governance is a required minimum (.substrate/required_remote_governance=1); "
              "a PR may not disable it", file=sys.stderr)
        return 2
    # DEPENDENCY-COOLDOWN LOCK (v3.7.2). When .substrate/required_dep_cooldown=1, the
    # cooldown tier may not be silently disabled — SUBSTRATE_DEP_COOLDOWN must be > 0.
    if req_dc == "1" and vals.get("SUBSTRATE_DEP_COOLDOWN", "0") == "0":
        print('check-substrate-config: SUBSTRATE_DEP_COOLDOWN must be > 0 — the dependency-'
              "cooldown tier is a required minimum (.substrate/required_dep_cooldown=1); "
              "a PR may not disable it", file=sys.stderr)
        return 2
    # SECURITY-SCANNER LOCK (v3.7.17). When .substrate/required_security_scanners=1, the
    # scanner tier may not be silently disabled — SUBSTRATE_SECURITY_SCANNERS must be "1".
    if req_ss == "1" and vals.get("SUBSTRATE_SECURITY_SCANNERS", "0") != "1":
        print('check-substrate-config: SUBSTRATE_SECURITY_SCANNERS must be "1" — the scanner '
              "tier is a required minimum (.substrate/required_security_scanners=1); "
              "a PR may not disable it", file=sys.stderr)
        return 2
    sbx_det = Path(__file__).resolve().parent / "sandbox_detect.py"
    if sbx_det.is_file() and ((ROOT / ".substrate" / "sandbox.json").is_file() or req_sb == "1"):
        import subprocess
        r = subprocess.run([sys.executable, "-I", str(sbx_det), "--root", str(ROOT), "--json"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 2:  # invalid sandbox.json (bad enum / shape / not JSON)
            print(f"check-substrate-config: invalid sandbox policy — {r.stderr.strip()}", file=sys.stderr)
            return 2
        if req_sb == "1" and r.returncode == 3:  # containment required but no backend present
            print("check-substrate-config: SUBSTRATE_SANDBOX required but no sandbox backend is "
                  "available (install @anthropic-ai/sandbox-runtime, or bubblewrap / sandbox-exec)",
                  file=sys.stderr)
            return 2
    findings = []
    shell_danger = None
    for key in _COMMAND_KEYS:
        v = vals.get(key, "")
        if not v:
            continue
        try:
            if shell_danger is None:
                # load lazily so an empty-command config never depends on it,
                # but a command-valued config FAILS CLOSED on a broken policy
                shell_danger = _shell_danger_patterns()
            reason = _command_is_dangerous(v, profile, shell_danger)
        except (CommandPolicyUnavailable, HarnessPatternsUnavailable) as e:
            print(f"check-substrate-config: {e}", file=sys.stderr)
            return 2
        if reason:
            findings.append((key, reason))
    if findings:
        print("check-substrate-config: dangerous command value(s):", file=sys.stderr)
        for key, reason in findings:
            print(f"  - {key}: {reason}", file=sys.stderr)
        return 1
    print("check-substrate-config: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
