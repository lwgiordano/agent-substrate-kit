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

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import safe_atomic_write as _safe_atomic_write
except Exception:  # pragma: no cover - stripped install
    def _safe_atomic_write(*a, **k):
        raise OSError("safe_atomic_write unavailable — refusing an unguarded write")

# v3.8.43 (round-26 P2): the canonical guarded reader. The fallback returns None
# ("no usable config") rather than an unguarded read, so a stripped install
# degrades to the caller's fail-closed default instead of blocking on a FIFO.
try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None

# v3.8.44 (round-27, found by the gate's new interprocedural pass): _sha256()
# read its argument with a raw read_bytes(), so a governed path handed to it
# was hashed through whatever the leaf happened to be.
try:
    from _doc_common import safe_read_bytes as _safe_read_bytes
except Exception:  # pragma: no cover - stripped install
    def _safe_read_bytes(path, root=None, max_bytes=None, tail_bytes=None):
        return None

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
    # v3.8.43 (round-26 P2): guarded read — a FIFO config must not block a gate.
    try:
        for line in (_safe_read_text(path, root, max_bytes=1 << 20) or "").splitlines():
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


def _sha256(p: Path, root: Path | None = None) -> str | None:
    """Guarded hash: None when the leaf is absent or unsafe (link/FIFO/escape).

    A drift check that hashes through a symlinked or hard-linked
    .pre-commit-config.yaml compares OUTSIDE bytes to the baseline, so a
    planted link could make a tampered config read as clean.
    """
    raw = _safe_read_bytes(p, root, max_bytes=None)
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _install_json(root: Path) -> dict | None:
    p = root / ".substrate" / "install.json"
    try:
        return json.loads(_safe_read_text(p, root, max_bytes=8 << 20) or "null")
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
    got = _sha256(pc, root)
    # An unhashable leaf is not "unchanged": treat it as drift so the overwrite
    # requires --force rather than silently proceeding.
    return got is None or recorded != got


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
    req = root / ".substrate" / "required_profile"
    try:
        lock = (_safe_read_text(req, root, max_bytes=1 << 16) or "").strip()
    except Exception:
        lock = ""
    # Two INDEPENDENT constraints (v3.8.5). The v3.8.4 single max()-floor with `<=`
    # trapped the documented repair path: a config stale BELOW a strict lock made
    # strict — the ceiling — unreachable (target == floor was refused), so the config
    # could never be brought back up to its own lock. Separate the concerns:
    #   (a) never BELOW the required_profile lock -> refuse target < lock
    #   (b) RAISE-only vs the LIVE config         -> refuse target <= current
    # Repairing a stale config UP to the lock (target == lock > current) is a raise
    # that clears the floor, so it is allowed; lowering and no-ops are still refused.
    names = {0: "starter", 1: "standard", 2: "strict"}
    lock_rank = RANK.get(lock, -1)
    if RANK[target] < lock_rank:
        print(f"substrate-profile: refusing {current} -> {target} — below the "
              f"required_profile lock ({names[lock_rank]}). The lock is a hard floor; "
              "lowering it is a deliberate, reviewed act outside this command.",
              file=sys.stderr)
        return 2
    if RANK[target] <= RANK[current]:
        print(f"substrate-profile: refusing {current} -> {target} — not a raise. The "
              "ratchet is RAISE-only; lowering is a deliberate, reviewed act outside "
              "this command.", file=sys.stderr)
        return 2
    tpl = root / STAGED_TEMPLATE
    if not tpl.is_file():
        print(f"substrate-profile: {STAGED_TEMPLATE} is missing — this install predates "
              "staged profile templates. Run `./manage.sh upgrade` (or re-bootstrap) first; "
              "nothing was changed.", file=sys.stderr)
        return 2
    try:
        template_text = _safe_read_text(tpl, root, max_bytes=8 << 20) or ""
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
    _safe_atomic_write(root / ".pre-commit-config.yaml", rendered, root=root)
    print("substrate-profile: re-rendered .pre-commit-config.yaml")

    cfg_path = root / ".substrate" / "config"
    lines = (_safe_read_text(cfg_path, root, max_bytes=1 << 20) or "").splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith("SUBSTRATE_PROFILE="):
            lines[i] = f'SUBSTRATE_PROFILE="{target}"'
            replaced = True
            break
    if not replaced:
        lines.append(f'SUBSTRATE_PROFILE="{target}"')
    _safe_atomic_write(cfg_path, "\n".join(lines) + "\n", root=root)
    print(f'substrate-profile: SUBSTRATE_PROFILE="{target}"')

    req = root / ".substrate" / "required_profile"
    prev_req = (_safe_read_text(req, root, max_bytes=1 << 16) or "").strip()
    if RANK.get(prev_req, -1) < RANK[target]:  # raise-only; never lower the lock
        _safe_atomic_write(req, target + "\n", root=root)
        print(f"substrate-profile: required_profile -> {target}")

    if target == "strict":
        staged = sorted((root / ".substrate" / "extras").glob("*.py"))
        for f in staged:
            dest = root / "scripts" / f.name
            if dest.exists():
                print(f"substrate-profile: SKIP scripts/{f.name} (exists)")
                continue
            # v3.8.43: dest.exists() is FALSE for a BROKEN symlink, so the
            # skip above did not protect this write — it followed the link
            # and created the outside file. Anchored write instead.
            _safe_atomic_write(dest, f.read_bytes(), root=root,
                               mode=(f.stat().st_mode & 0o777) | 0o755)
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
    req_val = (_safe_read_text(req, root, max_bytes=1 << 16) or "").strip()
    if RANK.get(req_val, -1) < RANK[target]:
        problems.append(f"required_profile={req_val!r} is below {target}")
    tpl = root / STAGED_TEMPLATE
    if not tpl.is_file():
        problems.append(f"{STAGED_TEMPLATE} not staged (run ./manage.sh upgrade)")
    elif current in RANK:
        want = render_precommit(_safe_read_text(tpl, root, max_bytes=8 << 20) or "", current,
                                cfg.get("SUBSTRATE_LANG", "python"), _run_prefix(cfg))
        pc = root / ".pre-commit-config.yaml"
        if pc.is_file() and (_safe_read_text(pc, root, max_bytes=8 << 20) or "") != want:
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
