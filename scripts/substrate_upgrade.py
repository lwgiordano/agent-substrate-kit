#!/usr/bin/env python3
"""In-place substrate upgrade engine (v3.7.14, installer/upgrade Phase 1b).

`./manage.sh upgrade --from <signed-zip|dir> [--plan|--write] [--force] [--allow-unverified]`

Flow (fail-closed):
  1. VERIFY the source. A .zip is verified with scripts/verify_release.py against the repo's
     trusted minisign key BEFORE anything is read from it (skip only with --allow-unverified,
     which warns loudly — for a local dir or a deliberately unsigned build).
  2. DRIFT-GATE. Machinery files whose local hash no longer matches the .substrate/install.json
     baseline are "drifted" (someone edited a substrate-owned file). --write refuses to clobber
     them unless --force.
  3. APPLY (via the NEW kit's own bootstrap.sh --force — the real, correct renderer) wrapped in
     BACKUP -> force -> RESTORE of the user-content set, so machinery refreshes while AGENTS.md,
     CLAUDE.md, pyproject.toml, .substrate/config, the required_* LOCKS, sandbox.json and the docs
     narrative are never clobbered. Project (non-substrate) files are never touched at all.
  4. RE-RECORD .substrate/install.json (new version/commit + fresh hashes).

--plan (default) mutates nothing: it verifies, shows the version delta, drift, and the
preserve list. Managed-region merge of AGENTS.md/CLAUDE.md is deferred to Phase 3 (Copier);
1b preserves those files whole.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _verify_backends import verify  # noqa: E402  (shared multi-backend verifier — same policy everywhere)

# User-content / operator-owned surfaces: NEVER overwritten by an upgrade (backed up
# then restored around the bootstrap --force). Includes the required_* LOCKS so an
# upgrade can never silently lower a profile/sandbox/remote requirement.
PRESERVE_FILES = [
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "pyproject.toml",
    ".substrate/config", ".substrate/required_profile", ".substrate/required_sandbox",
    ".substrate/required_remote_governance", ".substrate/sandbox.json",
    ".github/dependabot.yml",
    "docs/ARCHITECTURE.md", "docs/INTENT.md", "docs/HISTORY.md", "docs/README.md",
]
PRESERVE_DIRS = ["design-system", "docs/decisions", "docs/postmortems"]

# Never drift-check the provenance file itself — it is rewritten every upgrade and is
# excluded from its own baseline (see write_install_json._BASELINE_EXCLUDE). v3.7.16 P1.
_DRIFT_EXCLUDE = {".substrate/install.json"}


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _load_install_json(root: Path) -> dict | None:
    p = root / ".substrate" / "install.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _parse_config(root: Path) -> dict:
    """Comment-aware, quote-aware parse of .substrate/config, mirroring
    check_substrate_config (v3.8.9): strips bootstrap's inline `# ...` comments and ONE
    layer of surrounding quotes. The old `.strip('"')` left the comment IN the value, so
    `SUBSTRATE_REMOTE_GOVERNANCE="1"   # ...` parsed to `1"   # ...` and was treated as
    OFF — dropping the trusted-base workflow once live config became the render authority."""
    vals: dict[str, str] = {}
    try:
        text = (root / ".substrate" / "config").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return vals
    for raw in text.splitlines():
        line = raw
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.split("  #", 1)[0].rstrip()
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if not line.startswith("SUBSTRATE_") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        vals[k] = v
    return vals


def _answers_from_config(root: Path) -> dict:
    """Answers derived from live .substrate/config (the render authority for every
    config-backed tier). Uses the comment-aware parser above."""
    vals = _parse_config(root)
    return {
        "profile": vals.get("SUBSTRATE_PROFILE", "standard"),
        "lang": vals.get("SUBSTRATE_LANG", "auto"),
        "runner": vals.get("SUBSTRATE_RUNNER", "auto"),
        "ui": "no", "workflow": "superpowers",
        "sandbox": vals.get("SUBSTRATE_SANDBOX", "0"),
        "remote_governance": vals.get("SUBSTRATE_REMOTE_GOVERNANCE", "0"),
    }


def _profile_alias(ans: dict) -> str:
    base = ans.get("profile") or "standard"
    if str(ans.get("sandbox", "0")) == "1":
        base += "+sandbox"
    if str(ans.get("remote_governance", "0")) == "1":
        base += "+remote"
    return base


def _sha256(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _resolve_kit(src: Path, root: Path, allow_unverified: bool, tmp: Path) -> tuple[Path, str, str | None]:
    """Return (kit_dir, verify_note, verified_commit). Verifies a .zip against the trusted
    key first; the commit is parsed from the VERIFIED trusted comment (tamper-evident) so a
    .zip install/upgrade records exact provenance even with no .git tree (v3.7.16 P2b)."""
    if src.is_dir():
        if not allow_unverified:
            raise SystemExit("upgrade: a directory source is unverified — pass --allow-unverified "
                             "to use it (a signed .zip is the trusted path).")
        kit = src if (src / "bootstrap.sh").is_file() else None
        if kit is None:
            for d in src.iterdir():
                if (d / "bootstrap.sh").is_file():
                    kit = d
                    break
        if kit is None:
            raise SystemExit(f"upgrade: no bootstrap.sh found under {src}")
        return kit, "UNVERIFIED (directory source)", None
    # a file → treat as a release zip
    commit = None
    if not allow_unverified:
        # Multi-backend, fail-closed — same policy as verify_release / substrate-init (v3.7.19),
        # so the upgrade engine verifies FOR ITSELF (the auto-upgrade workflow no longer needs
        # --allow-unverified). minisign yields a commit from the trusted comment; keyless doesn't.
        pub = root / ".substrate" / "trust" / "minisign.pub"
        r = verify(src, minisign_pub=pub, root=root, require=True)
        if r.rc != 0:
            raise SystemExit(f"upgrade: signature verification FAILED (fail-closed): {r.detail}")
        commit = r.commit
        note = f"verified ({r.backend})"
    else:
        note = "UNVERIFIED (--allow-unverified)"
    ex = tmp / "extract"
    ex.mkdir(parents=True, exist_ok=True)
    shutil.unpack_archive(str(src), str(ex))
    for d in ex.rglob("bootstrap.sh"):
        return d.parent, note, commit
    raise SystemExit("upgrade: extracted archive has no bootstrap.sh")


def _drifted(root: Path, baseline: dict | None) -> list[str]:
    """Machinery files whose local hash differs from the baseline (user edited a substrate
    file). Preserve-set files are excluded — they are expected to differ."""
    if not baseline:
        return []
    preserve = set(PRESERVE_FILES)
    out = []
    for rel, want in baseline.get("owned_file_sha256", {}).items():
        if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(d + "/") for d in PRESERVE_DIRS):
            continue
        p = root / rel
        if p.is_file() and _sha256(p) != want:
            out.append(rel)
    return sorted(out)


def _backup(root: Path, dest: Path) -> list[str]:
    saved = []
    for rel in PRESERVE_FILES:
        src = root / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
            saved.append(rel)
    for d in PRESERVE_DIRS:
        src = root / d
        if src.is_dir():
            shutil.copytree(src, dest / d, dirs_exist_ok=True)
            saved.append(d + "/")
    return saved


def _restore(root: Path, backup: Path, saved: list[str]) -> None:
    for rel in PRESERVE_FILES:
        b = backup / rel
        if b.is_file():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(b, root / rel)
    for d in PRESERVE_DIRS:
        b = backup / d
        if b.is_dir():
            shutil.copytree(b, root / d, dirs_exist_ok=True)


_PROF_RANK = {"starter": 0, "standard": 1, "strict": 2}


def _read_cfg_profile(root: Path) -> str:
    # comment-aware parse (v3.8.9) — an inline `# ...` on the profile line previously
    # leaked into the value via `.strip('"')`.
    return _parse_config(root).get("SUBSTRATE_PROFILE", "standard")


def _read_required_profile(root: Path) -> str:
    try:
        v = (root / ".substrate" / "required_profile").read_text(encoding="utf-8").strip()
        return v if v in _PROF_RANK else "starter"
    except Exception:
        return "starter"


def _read_required_remote_governance(root: Path) -> str:
    """The frozen remote-governance lock. "1" means the repo REQUIRES remote
    governance (the trusted-base workflow), so the render must never turn it off
    regardless of what the agent-writable install.json/config claims (v3.8.7)."""
    try:
        return (root / ".substrate" / "required_remote_governance").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _read_required_sandbox(root: Path) -> str:
    """The frozen egress-containment lock. "1" means the repo REQUIRES the sandbox,
    so the render must never turn it off regardless of provenance/config (v3.8.8)."""
    try:
        return (root / ".substrate" / "required_sandbox").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _apply_profile_ratchet(root: Path, target: str) -> None:
    """Re-apply the profile raise AFTER _restore(): .substrate/config and
    required_profile are in PRESERVE_FILES, so the bootstrap's fresh values
    get overwritten by the preserved (old-profile) copies. RAISE-only: the
    required_profile lock is written to max(existing, target), never lowered
    (v3.8.4 — an unconditional write let a stale-provenance upgrade lower a
    strict lock)."""
    cfg = root / ".substrate" / "config"
    try:
        lines = cfg.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.startswith("SUBSTRATE_PROFILE="):
                lines[i] = f'SUBSTRATE_PROFILE="{target}"'
                break
        else:
            lines.append(f'SUBSTRATE_PROFILE="{target}"')
        cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
        req = root / ".substrate" / "required_profile"
        prev = _read_required_profile(root)
        locked = target if _PROF_RANK[target] >= _PROF_RANK.get(prev, 0) else prev
        req.write_text(locked + "\n", encoding="utf-8")
        print(f"upgrade: profile ratcheted to {target} (required_profile lock={locked})")
    except Exception as e:
        print(f"upgrade: WARNING could not apply the profile ratchet: {e}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="In-place substrate upgrade (fail-closed).")
    ap.add_argument("--from", dest="src", required=True, help="signed release .zip (trusted) or a kit directory (needs --allow-unverified)")
    ap.add_argument("--root", default=".")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--plan", action="store_true", help="show what would change; mutate nothing (default)")
    g.add_argument("--write", action="store_true", help="apply the upgrade")
    ap.add_argument("--force", action="store_true", help="overwrite locally-modified machinery files")
    ap.add_argument("--allow-unverified", action="store_true", help="skip signature verification (dir/unsigned source)")
    ap.add_argument("--profile", choices=["standard", "strict"],
                    help="RAISE the governance profile during the upgrade (raise-only)")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    src = Path(a.src).resolve()
    if not src.exists():
        print(f"upgrade: source not found: {src}", file=sys.stderr)
        return 2

    baseline = _load_install_json(root)
    # Render authority for SECURITY tiers is the LIVE CONFIG, never the agent-writable
    # install.json provenance (v3.8.7 / P2): forged provenance must not change what gets
    # rendered. install.json still supplies cosmetic answers config does not carry
    # (ui/workflow). profile + remote_governance are additionally floored to their frozen
    # required_* locks below. (The v3.8.6 patch only floored profile DOWNWARD and still
    # trusted provenance for remote_governance and an inconsistent HIGH profile.)
    prov = dict((baseline or {}).get("answers") or {})
    _cfg_answers = _answers_from_config(root)
    answers = dict(prov)
    # EVERY config-backed render tier comes from LIVE CONFIG, never agent-writable
    # provenance (v3.8.8 — v3.8.7 only did profile+remote_governance, so a forged
    # lang/runner/sandbox still dropped the matching hooks, e.g. lang=none removing the
    # python ruff/pytest gates). These are exactly the keys _answers_from_config reads
    # from .substrate/config. ui/workflow are NOT stored in config, so provenance
    # supplies them (config default is only a fallback). required_* tiers floored below.
    for _k in ("profile", "lang", "runner", "sandbox", "remote_governance"):
        answers[_k] = _cfg_answers[_k]
    for _k in ("ui", "workflow"):
        answers.setdefault(_k, _cfg_answers[_k])
    cur_ver = (baseline or {}).get("kit_version", "unknown")
    if a.profile:
        _rank = {"starter": 0, "standard": 1, "strict": 2}
        _names = {0: "starter", 1: "standard", 2: "strict"}
        # SECURITY (v3.8.4/v3.8.5): two INDEPENDENT constraints. The hard FLOOR is the
        # on-disk required_profile LOCK — owned + frozen, NOT the agent/attacker-writable
        # install.json — so a mutated provenance file still cannot lower it. The RAISE
        # baseline is the live config + provenance answers. Anchoring "below" on the lock
        # (not on a single max()-floor with `<=`) fixes the v3.8.5 equality trap: a config
        # stale BELOW the lock can now be repaired UP to it, while lowering stays refused.
        #   (a) refuse target < required_profile lock   (never below the floor)
        #   (b) refuse target <= current live profile   (raise-only)
        lock_rank = _rank.get(_read_required_profile(root), -1)
        # Raise baseline is the LIVE config only — install.json answers are
        # agent-writable, so forged-HIGH provenance must not block a legitimate
        # repair up to the lock (v3.8.6). The lock handles the below-floor case.
        current_rank = _rank.get(_read_cfg_profile(root), 1)
        target_rank = _rank[a.profile]
        if target_rank < lock_rank:
            print(f"upgrade: --profile {a.profile} is below the required_profile lock "
                  f"({_names[lock_rank]}) — the ratchet never lowers a lock.", file=sys.stderr)
            return 2
        if target_rank <= current_rank:
            print(f"upgrade: --profile {a.profile} would not RAISE above the current profile "
                  f"({_names[current_rank]}) — the ratchet is raise-only.", file=sys.stderr)
            return 2
        answers["profile"] = a.profile

    # Never RENDER below the required_profile lock, even on a plain upgrade with no
    # --profile: answers["profile"] comes from the agent-writable install.json, so a
    # forged LOW profile must not drop the strict pre-commit hooks the frozen lock
    # promises (v3.8.6 — P1: the v3.8.5 floor only guarded the --profile branch, so a
    # plain `upgrade --write` rendered whatever provenance claimed).
    _rk = {"starter": 0, "standard": 1, "strict": 2}
    _lock_profile = _read_required_profile(root)
    if _lock_profile and _rk.get(_lock_profile, -1) > _rk.get(answers.get("profile") or "standard", 1):
        answers["profile"] = _lock_profile
    # remote_governance is a SEPARATE required_* tier: a repo whose frozen lock says "1"
    # must never render with it OFF, no matter what config/provenance claims — else a
    # forged value drops the trusted-base workflow the lock promises (v3.8.7 / P2).
    if _read_required_remote_governance(root) == "1":
        answers["remote_governance"] = "1"
    if _read_required_sandbox(root) == "1":
        answers["sandbox"] = "1"

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        try:
            kit, vnote, verified_commit = _resolve_kit(src, root, a.allow_unverified, tmp)
        except SystemExit as e:
            print(str(e), file=sys.stderr)
            return 2
        new_ver = (kit / "VERSION").read_text(encoding="utf-8").strip() if (kit / "VERSION").is_file() else "unknown"
        drift = _drifted(root, baseline)

        print(f"substrate upgrade: {cur_ver} -> {new_ver}  [source: {vnote}]")
        if not baseline:
            print("  note: no .substrate/install.json baseline (pre-1b install) — drift cannot be "
                  "checked; --write requires --force.")
        if drift:
            print(f"  DRIFT: {len(drift)} locally-modified machinery file(s) would be overwritten:")
            for d in drift:
                print(f"    ~ {d}")
        print(f"  preserved (never overwritten): {', '.join(PRESERVE_FILES)} + {', '.join(d + '/' for d in PRESERVE_DIRS)}")

        if not a.write:
            print("  (plan only — nothing changed; re-run with --write to apply)")
            return 0

        # --write from here
        if drift and not a.force:
            print("upgrade: refusing to overwrite locally-modified machinery files without --force "
                  "(review them, or pass --force).", file=sys.stderr)
            return 2
        if not baseline and not a.force:
            print("upgrade: no install.json baseline — re-run with --force to apply without drift "
                  "protection.", file=sys.stderr)
            return 2

        backup = tmp / "preserve"
        saved = _backup(root, backup)
        alias = _profile_alias(answers)
        cmd = ["bash", str(kit / "bootstrap.sh"), "--target", str(root), "--force", "--no-doctor",
               "--profile", alias, "--lang", answers.get("lang", "auto"),
               "--runner", answers.get("runner", "auto"), "--workflow", answers.get("workflow", "superpowers"),
               "--ui", answers.get("ui", "no")]
        r = _run(cmd)
        if r.returncode != 0:
            _restore(root, backup, saved)
            print(f"upgrade: bootstrap --force FAILED; restored preserved files.\n{r.stderr[-1500:]}",
                  file=sys.stderr)
            return 2
        _restore(root, backup, saved)
        if a.profile:
            _apply_profile_ratchet(root, a.profile)

        # consistency + fresh provenance
        _run([sys.executable, "-I", str(root / "scripts" / "update_manifest.py"), "--fix"], cwd=root)
        # Prefer the commit parsed from the VERIFIED trusted comment (a .zip extract has no
        # .git, so git rev-parse would record 'none' — v3.7.16 P2b). Fall back to git for a
        # directory source that IS a checkout.
        commit = verified_commit or "none"
        if commit == "none":
            gc = _run(["git", "rev-parse", "--short", "HEAD"], cwd=kit)
            if gc.returncode == 0:
                commit = gc.stdout.strip()
        _run([sys.executable, "-I", str(root / "scripts" / "write_install_json.py"),
              "--root", str(root), "--version", new_ver, "--commit", commit,
              "--source", str(src), "--installed-at", datetime.now(timezone.utc).isoformat(),
              "--profile", answers.get("profile", "standard"), "--lang", answers.get("lang", "auto"),
              "--runner", answers.get("runner", "auto"), "--ui", answers.get("ui", "no"),
              "--workflow", answers.get("workflow", "superpowers"),
              "--sandbox", str(answers.get("sandbox", "0")),
              "--remote-governance", str(answers.get("remote_governance", "0"))], cwd=root)
        print(f"substrate upgrade: applied {new_ver}. Review `git diff`, run `./manage.sh check`, then commit.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
