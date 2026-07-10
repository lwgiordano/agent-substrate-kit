#!/usr/bin/env python3
"""In-place profile ratchet: starter -> standard -> strict, no re-bootstrap.

Before v3.8.2 the only way to raise the governance profile was re-running
bootstrap.sh --force from a kit checkout (bootstrap is not copied into the
target repo). This script performs the raise IN PLACE from the templates
bootstrap stages under .substrate/:

  --plan  TARGET   enumerate exactly what --write would do (default)
  --write TARGET   apply the ratchet (RAISE-only; refuses to lower)
  --check TARGET   verify the repo is at/above TARGET and consistent

What --write does, in order. Nothing is edited until the staged template is
confirmed readable and every refusal condition passes, so a REFUSAL never
half-applies. The apply steps themselves are sequential, not transactional:
an interrupt mid-apply can leave them inconsistent — `--check` detects that
state and re-running `--write` repairs it.
  1. re-renders .pre-commit-config.yaml from
     .substrate/pre-commit-config.yaml.template at TARGET profile
     (drift-guarded against install.json's recorded hash; --force overrides)
  2. sets SUBSTRATE_PROFILE in .substrate/config
  3. RAISES .substrate/required_profile (other required_* locks untouched)
  4. strict: copies staged .substrate/extras/*.py into scripts/ (skip-if-exists)
  5. re-records install.json so the next upgrade sees no false drift

Exit codes: 0 ok / 1 check found inconsistency / 2 refusal or env error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

RANK = {"starter": 0, "standard": 1, "strict": 2}
_KV = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"]*)"')
STAGED_TEMPLATE = ".substrate/pre-commit-config.yaml.template"
_MARKER = re.compile(r"^\s*# (>>>|<<<) (standard|strict|python-only)$")


def _read_config(root: Path) -> dict[str, str]:
    cfg: dict[str, str] = {}
    path = root / ".substrate" / "config"
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _KV.match(line.strip())
            if m:
                cfg[m.group(1)] = m.group(2)
    except Exception:
        pass
    return cfg


def _run_prefix(cfg: dict[str, str]) -> str:
    """Same derivation as bootstrap.sh: explicit runner wins; auto+python
    prefers uv, then poetry; otherwise empty."""
    runner = cfg.get("SUBSTRATE_RUNNER", "auto")
    lang = cfg.get("SUBSTRATE_LANG", "python")
    if runner == "uv":
        return "uv run"
    if runner == "poetry":
        return "poetry run"
    if runner == "auto" and lang == "python":
        import shutil
        if shutil.which("uv"):
            return "uv run"
        if shutil.which("poetry"):
            return "poetry run"
    return ""


def render_precommit(template_text: str, profile: str, lang: str, run_prefix: str) -> str:
    """Python port of bootstrap.sh render_precommit: placeholder substitution
    plus profile/lang marker-block stripping."""
    text = template_text.replace("{{RUN_PREFIX}}", run_prefix)
    text = text.replace("{{PY}}", ".substrate/venv/bin/python")  # bootstrap.sh parity
    strip: set[str] = set()
    if profile == "starter":
        strip |= {"standard", "strict"}
    elif profile == "standard":
        strip.add("strict")
    if lang != "python":
        strip.add("python-only")
    out: list[str] = []
    skipping: str | None = None
    for line in text.splitlines():
        m = _MARKER.match(line)
        if m:
            kind, block = m.groups()
            if kind == ">>>" and skipping is None and block in strip:
                skipping = block
            elif kind == "<<<" and skipping == block:
                skipping = None
            continue  # marker lines never reach the output (kept or stripped)
        if skipping is None:
            out.append(line)
    return "\n".join(out) + "\n"


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _install_json(root: Path) -> dict | None:
    p = root / ".substrate" / "install.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _precommit_drifted(root: Path, baseline: dict | None) -> bool:
    """True when .pre-commit-config.yaml no longer matches the install
    baseline (hand-edited) — overwriting it then needs --force."""
    pc = root / ".pre-commit-config.yaml"
    if not pc.is_file():
        return False
    recorded = ((baseline or {}).get("owned_file_sha256") or {}).get(".pre-commit-config.yaml")
    if recorded is None:
        return baseline is None  # no baseline at all -> treat as unknown/drifted
    return recorded != _sha256(pc)


def _plan(target: str, cfg: dict[str, str]) -> None:
    current = cfg.get("SUBSTRATE_PROFILE", "?")
    print(f"`enable profile {target}` ratchets the governance profile IN PLACE "
          f"(current: {current}). --write will:")
    print(f"  1. re-render .pre-commit-config.yaml from {STAGED_TEMPLATE} at profile={target}")
    if target == "strict":
        print("     (adds the strict-only gates: check-postmortem-for-bug-fix, "
              "check-finding-response, check-validator-input-coverage)")
    print(f'  2. set SUBSTRATE_PROFILE="{target}" in .substrate/config')
    print(f"  3. RAISE .substrate/required_profile to {target} (raise-only; "
          "a PR may not lower it back)")
    if target == "strict":
        print("  4. copy staged .substrate/extras/*.py into scripts/ (skip-if-exists)")
    print("  5. re-record .substrate/install.json (so the next upgrade sees no false drift)")
    print("It will NOT touch: AGENTS.md, required_sandbox, required_remote_governance,")
    print("docs/, or any project file. A hand-edited .pre-commit-config.yaml is refused")
    print("without --force. Lowering the profile is always refused.")
    print(f"Apply with:  ./manage.sh enable profile {target} --write")


def _write(root: Path, target: str, cfg: dict[str, str], force: bool) -> int:
    current = cfg.get("SUBSTRATE_PROFILE", "standard")
    if RANK.get(current) is None:
        print(f"substrate-profile: invalid current profile {current!r} in .substrate/config",
              file=sys.stderr)
        return 2
    # The floor is max(config, required_profile lock): config can be stale BELOW
    # the lock, and a raise must clear the true floor, not just the config value
    # (v3.8.4 defense-in-depth alongside the upgrade-path floor fix).
    req = root / ".substrate" / "required_profile"
    try:
        lock = req.read_text(encoding="utf-8").strip()
    except Exception:
        lock = ""
    floor = max(RANK[current], RANK.get(lock, -1))
    if RANK[target] <= floor:
        floor_name = {0: "starter", 1: "standard", 2: "strict"}[floor]
        print(f"substrate-profile: refusing {current} -> {target} — not above the floor "
              f"({floor_name}, = max of config/required_profile). The ratchet is RAISE-only; "
              "lowering is a deliberate, reviewed act outside this command.", file=sys.stderr)
        return 2
    tpl = root / STAGED_TEMPLATE
    if not tpl.is_file():
        print(f"substrate-profile: {STAGED_TEMPLATE} is missing — this install predates "
              "staged profile templates. Run `./manage.sh upgrade` (or re-bootstrap) first; "
              "nothing was changed.", file=sys.stderr)
        return 2
    try:
        template_text = tpl.read_text(encoding="utf-8")
    except Exception as e:
        print(f"substrate-profile: cannot read {STAGED_TEMPLATE}: {e}; nothing was changed.",
              file=sys.stderr)
        return 2
    baseline = _install_json(root)
    if _precommit_drifted(root, baseline) and not force:
        print("substrate-profile: .pre-commit-config.yaml differs from the install.json "
              "baseline (locally edited?). Re-rendering would clobber those edits — review "
              "them, then re-run with --force.", file=sys.stderr)
        return 2

    # ---- all preconditions pass; apply (template confirmed readable) ----
    rendered = render_precommit(template_text, target, cfg.get("SUBSTRATE_LANG", "python"),
                                _run_prefix(cfg))
    (root / ".pre-commit-config.yaml").write_text(rendered, encoding="utf-8")
    print("substrate-profile: re-rendered .pre-commit-config.yaml")

    cfg_path = root / ".substrate" / "config"
    lines = cfg_path.read_text(encoding="utf-8").splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith("SUBSTRATE_PROFILE="):
            lines[i] = f'SUBSTRATE_PROFILE="{target}"'
            replaced = True
            break
    if not replaced:
        lines.append(f'SUBSTRATE_PROFILE="{target}"')
    cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f'substrate-profile: SUBSTRATE_PROFILE="{target}"')

    req = root / ".substrate" / "required_profile"
    prev_req = req.read_text(encoding="utf-8").strip() if req.is_file() else ""
    if RANK.get(prev_req, -1) < RANK[target]:  # raise-only; never lower the lock
        req.write_text(target + "\n", encoding="utf-8")
        print(f"substrate-profile: required_profile -> {target}")

    if target == "strict":
        staged = sorted((root / ".substrate" / "extras").glob("*.py"))
        for f in staged:
            dest = root / "scripts" / f.name
            if dest.exists():
                print(f"substrate-profile: SKIP scripts/{f.name} (exists)")
                continue
            dest.write_bytes(f.read_bytes())
            dest.chmod(dest.stat().st_mode | 0o755)
            print(f"substrate-profile: + scripts/{f.name}")
        if not staged:
            print("substrate-profile: WARNING no staged extras (.substrate/extras/) — "
                  "strict extras not installed; run `./manage.sh upgrade` to stage them.")

    # Re-record install.json so upgrade drift stays clean. Reuse the recorded
    # answers/provenance; only the profile (and the file hashes) change.
    if baseline is not None:
        answers = baseline.get("answers") or {}
        answers["profile"] = target
        subprocess.run(
            [sys.executable, "-I", str(root / "scripts" / "write_install_json.py"),
             "--root", str(root), "--version", str(baseline.get("kit_version", "unknown")),
             "--commit", str(baseline.get("kit_commit", "none")),
             "--source", str(baseline.get("source", "")),
             "--installed-at", datetime.now(timezone.utc).isoformat(),
             "--profile", target, "--lang", answers.get("lang", ""),
             "--runner", answers.get("runner", ""), "--ui", answers.get("ui", ""),
             "--workflow", answers.get("workflow", ""),
             "--sandbox", str(answers.get("sandbox", "")),
             "--remote-governance", str(answers.get("remote_governance", ""))],
            cwd=root, capture_output=True, text=True, timeout=60)
        print("substrate-profile: re-recorded .substrate/install.json")
    else:
        print("substrate-profile: WARNING no install.json baseline to re-record — the next "
              "`upgrade` will need --force (pre-provenance install).")
    print(f"substrate-profile: ratcheted {current} -> {target}. Next: `./manage.sh check`.")
    return 0


def _check(root: Path, target: str, cfg: dict[str, str]) -> int:
    problems: list[str] = []
    current = cfg.get("SUBSTRATE_PROFILE", "")
    if RANK.get(current, -1) < RANK[target]:
        problems.append(f"SUBSTRATE_PROFILE={current!r} is below {target}")
    req = root / ".substrate" / "required_profile"
    req_val = req.read_text(encoding="utf-8").strip() if req.is_file() else ""
    if RANK.get(req_val, -1) < RANK[target]:
        problems.append(f"required_profile={req_val!r} is below {target}")
    tpl = root / STAGED_TEMPLATE
    if not tpl.is_file():
        problems.append(f"{STAGED_TEMPLATE} not staged (run ./manage.sh upgrade)")
    elif current in RANK:
        want = render_precommit(tpl.read_text(encoding="utf-8"), current,
                                cfg.get("SUBSTRATE_LANG", "python"), _run_prefix(cfg))
        pc = root / ".pre-commit-config.yaml"
        if pc.is_file() and pc.read_text(encoding="utf-8") != want:
            problems.append(".pre-commit-config.yaml does not match a fresh render at the "
                            "current profile (locally edited or stale template)")
    for p in problems:
        print(f"substrate-profile: FAIL {p}")
    if not problems:
        print(f"substrate-profile: ok (profile >= {target}, lock in place, render consistent)")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--plan", metavar="TARGET", choices=("standard", "strict"))
    g.add_argument("--write", metavar="TARGET", choices=("standard", "strict"))
    g.add_argument("--check", metavar="TARGET", choices=("standard", "strict"))
    ap.add_argument("--force", action="store_true",
                    help="overwrite a locally-edited .pre-commit-config.yaml")
    a = ap.parse_args(argv)
    cfg = _read_config(ROOT)
    if not cfg:
        print("substrate-profile: no readable .substrate/config — run bootstrap first",
              file=sys.stderr)
        return 2
    if a.write:
        return _write(ROOT, a.write, cfg, a.force)
    if a.check:
        return _check(ROOT, a.check, cfg)
    _plan(a.plan or "strict", cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
