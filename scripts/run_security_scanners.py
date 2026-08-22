#!/usr/bin/env python3
"""Security-scanner tier — composes best-in-class scanners behind the substrate's opt-in
profile/lock/skip-honest discipline. The substrate is the JUDGE; scanners are INPUTS, never
a new root of trust (a scanner that fails/skips never silently passes a required tier). (v3.7.17)

Opt-in: SUBSTRATE_SECURITY_SCANNERS=1 (`./manage.sh enable security`). trivy/osv pull vuln
databases (NETWORK) → this is a DEEP-tier gate, never part of the offline base. `manage.sh
check` runs it only when the flag is on; `./manage.sh security scan` runs it on demand.

Composed scanners (a finding = nonzero exit → BLOCK):
  gitleaks    — secrets, including git history        (no network)
  trivy       — filesystem deps/vulns/misconfig        (--exit-code 1 so findings fail)
  osv-scanner — dependency CVEs against the OSV database

SKIP-HONEST: a scanner whose binary is ABSENT is SKIPPED with a reason — never silently
passed, never assumed clean. In REQUIRED mode (--require / .substrate/required_security_scanners=1)
a skipped/missing scanner BLOCKS: you asked for the tier, so an unavailable scanner is a fail.

Sandbox note: trivy/osv REQUIRE network for their vuln DBs, which conflicts with the default
deny-egress sandbox; scanners therefore run OUTSIDE containment even when SUBSTRATE_SANDBOX=1,
and the runner says so plainly rather than silently failing them. (Honest caveat, not a bypass.)

Results are recorded under .substrate/audits/security/<run>/ (advisory artifact).
CLI: run_security_scanners.py [--root DIR] [--require] [--json] [--scan]
Exit: 0 clean (or only skips, non-required) | 1 findings (or skip while required) | 2 config/internal error.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import read_lock as _dc_read_lock  # noqa: E402
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()

# name → (binary, argv-template, human description). argv runs with cwd=root.
SCANNERS = [
    ("gitleaks", "gitleaks", ["gitleaks", "detect", "--no-banner", "--redact", "--source", "."],
     "secrets (incl. git history)"),
    ("trivy", "trivy", ["trivy", "fs", "--quiet", "--exit-code", "1", "."],
     "filesystem deps/vulns/misconfig"),
    ("osv-scanner", "osv-scanner", ["osv-scanner", "--recursive", "."],
     "dependency CVEs (OSV database)"),
]


def _cfg(root: Path, key: str, default: str = "0") -> str:
    cfg = root / ".substrate" / "config"
    if cfg.is_file():
        for ln in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.split("#", 1)[0].strip()
            if ln.startswith(key + "="):
                return ln.split("=", 1)[1].strip().strip("\"'")
    return default


def _required(root: Path, argv) -> bool:
    if "--require" in argv:
        return True
    # v3.8.36: canonical fail-closed lock read (Codex round-19) — the old
    # `except OSError` both failed OPEN on I/O errors and CRASHED on
    # undecodable bytes (UnicodeDecodeError is a ValueError). A malformed
    # present lock now means the tier IS required.
    state, val, _reason = _dc_read_lock(
        root / ".substrate" / "required_security_scanners", {"0", "1"})
    if state == "bad":
        return True
    return state == "ok" and val == "1"


def _run_scanner(cmd, root: Path) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=600)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # tool crash / not executable
        return 2, f"scanner invocation error: {e}"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(description="Composed security-scanner tier (skip-honest, fail-closed when required).")
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--require", action="store_true", help="treat missing/skipped scanners as a failure")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--scan", action="store_true", help="run even when SUBSTRATE_SECURITY_SCANNERS=0 (on-demand)")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()

    enabled = _cfg(root, "SUBSTRATE_SECURITY_SCANNERS", "0") == "1"
    required = _required(root, argv)
    if not enabled and not a.scan and not required:
        msg = "security-scanners: not enabled (SUBSTRATE_SECURITY_SCANNERS=0) — skipping"
        print(json.dumps({"enabled": False, "results": []}) if a.json else msg)
        return 0

    results = []
    findings = 0
    skipped = 0
    for name, binary, cmd, desc in SCANNERS:
        if shutil.which(binary) is None:
            results.append({"scanner": name, "status": "skipped", "reason": f"{binary} not installed", "desc": desc})
            skipped += 1
            continue
        rc, out = _run_scanner(cmd, root)
        status = "clean" if rc == 0 else ("findings" if rc == 1 else "error")
        if status != "clean":
            findings += 1
        results.append({"scanner": name, "status": status, "rc": rc, "desc": desc,
                        "output_tail": out[-2000:] if status != "clean" else ""})

    # advisory artifact
    try:
        import hashlib
        run_id = hashlib.sha256(json.dumps(results, sort_keys=True).encode()).hexdigest()[:12]
        outdir = root / ".substrate" / "audits" / "security" / run_id
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass

    blocked = findings > 0 or (required and skipped > 0)
    if a.json:
        print(json.dumps({"enabled": enabled, "required": required, "findings": findings,
                          "skipped": skipped, "blocked": blocked, "results": results}, indent=2))
    else:
        print(f"security-scanners: {len(results)} scanner(s) — {findings} with findings/errors, {skipped} skipped"
              + (" [REQUIRED]" if required else ""))
        for r in results:
            mark = {"clean": "ok", "findings": "!!", "error": "ER", "skipped": "--"}.get(r["status"], "??")
            print(f"  [{mark}] {r['scanner']:<12} {r['status']:<8} {r.get('reason', r['desc'])}")
        if required and skipped:
            print("  REQUIRED tier: a skipped/missing scanner is a failure — install it or disable the tier.")
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
