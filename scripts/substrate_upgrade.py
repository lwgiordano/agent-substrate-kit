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
from _minisign import VerifyError, commit_from_trusted_comment, verify_file  # noqa: E402

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


def _answers_from_config(root: Path) -> dict:
    """Fallback answers when install.json is absent (pre-1b repo): read .substrate/config."""
    cfg = root / ".substrate" / "config"
    vals = {}
    if cfg.is_file():
        for ln in cfg.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if ln.startswith("SUBSTRATE_") and "=" in ln:
                k, v = ln.split("=", 1)
                vals[k.strip()] = v.strip().strip('"')
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
        pub = root / ".substrate" / "trust" / "minisign.pub"
        if not pub.is_file():
            raise SystemExit("upgrade: no .substrate/trust/minisign.pub to verify against (fail-closed).")
        try:
            tc = verify_file(pub, src)
        except VerifyError as e:
            raise SystemExit(f"upgrade: signature verification FAILED (fail-closed): {e}")
        commit = commit_from_trusted_comment(tc)
        note = "verified (minisign)"
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="In-place substrate upgrade (fail-closed).")
    ap.add_argument("--from", dest="src", required=True, help="signed release .zip (trusted) or a kit directory (needs --allow-unverified)")
    ap.add_argument("--root", default=".")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--plan", action="store_true", help="show what would change; mutate nothing (default)")
    g.add_argument("--write", action="store_true", help="apply the upgrade")
    ap.add_argument("--force", action="store_true", help="overwrite locally-modified machinery files")
    ap.add_argument("--allow-unverified", action="store_true", help="skip signature verification (dir/unsigned source)")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    src = Path(a.src).resolve()
    if not src.exists():
        print(f"upgrade: source not found: {src}", file=sys.stderr)
        return 2

    baseline = _load_install_json(root)
    answers = (baseline or {}).get("answers") or _answers_from_config(root)
    cur_ver = (baseline or {}).get("kit_version", "unknown")

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
