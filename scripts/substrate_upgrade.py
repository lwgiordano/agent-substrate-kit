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
import os
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
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        # install.json is agent-writable and drift-EXCLUDED, so a hostile/garbled shape
        # (e.g. a bare JSON string) must not crash the upgrade with an AttributeError when
        # `.get()`/`dict()` are called on it — treat any non-mapping as absent (v3.8.10).
        if not isinstance(data, dict):
            return None
        # A malformed drift map (non-dict owned_file_sha256) must be treated as an UNTRUSTED /
        # ABSENT baseline — so --write requires --force — NOT as proof of zero drift, which
        # would let a forged `owned_file_sha256: []` silently overwrite locally-modified owned
        # files (v3.8.13 / P2). Drift protection can only be trusted with a valid drift map.
        owned = data.get("owned_file_sha256")
        if owned is not None and not isinstance(owned, dict):
            return None
        return data
    return None


def _parse_config_text(text: str) -> dict:
    """Comment-aware, quote-aware parse of .substrate/config TEXT, mirroring
    check_substrate_config (v3.8.9): strips bootstrap's inline `# ...` comments and ONE
    layer of surrounding quotes. The old `.strip('"')` left the comment IN the value, so
    `SUBSTRATE_REMOTE_GOVERNANCE="1"   # ...` parsed to `1"   # ...` and was treated as
    OFF — dropping the trusted-base workflow once live config became the render authority."""
    vals: dict[str, str] = {}
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


def _parse_config(root: Path) -> dict:
    try:
        return _parse_config_text(
            (root / ".substrate" / "config").read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _answers_from_vals(vals: dict) -> dict:
    return {
        "profile": vals.get("SUBSTRATE_PROFILE", "standard"),
        "lang": vals.get("SUBSTRATE_LANG", "auto"),
        "runner": vals.get("SUBSTRATE_RUNNER", "auto"),
        "ui": "no", "workflow": "superpowers",
        "sandbox": vals.get("SUBSTRATE_SANDBOX", "0"),
        "remote_governance": vals.get("SUBSTRATE_REMOTE_GOVERNANCE", "0"),
    }


def _answers_from_config(root: Path) -> dict:
    """Answers derived from live .substrate/config (the render authority for every
    config-backed tier). Uses the comment-aware parser above."""
    return _answers_from_vals(_parse_config(root))


def _answers_from_snapshot(auth: dict) -> dict:
    """Answers derived EXCLUSIVELY from an authority snapshot's config bytes (v3.8.13):
    deriving from the SAME snapshot the abort-check compares against closes the gap where
    a concurrent config/lock change between derive-time and snapshot-time yielded stale
    answers accepted as fresh."""
    text = (auth.get("config") or b"").decode("utf-8", "replace")
    return _answers_from_vals(_parse_config_text(text))


def _lock_from_snapshot(auth: dict, name: str) -> str:
    b = auth.get(name)
    return b.decode("utf-8", "replace").strip() if isinstance(b, (bytes, bytearray)) else ""


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
    owned = baseline.get("owned_file_sha256", {})
    if not isinstance(owned, dict):
        return []   # malformed agent-writable provenance -> no drift claims (v3.8.11 P2:
                    # the old `.items()` crashed on a list/scalar owned_file_sha256)
    preserve = set(PRESERVE_FILES)
    out = []
    for rel, want in owned.items():
        if not isinstance(rel, str) or not isinstance(want, str):
            continue
        if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(d + "/") for d in PRESERVE_DIRS):
            continue
        p = root / rel
        # is_file()/_sha256 follow symlinks — but a symlinked owned dest is a hard tamper
        # condition handled by _unsafe_owned_dests (abort), so here we only compare regular
        # files' content.
        if p.is_file() and not p.is_symlink() and _sha256(p) != want:
            out.append(rel)
    return sorted(out)


_SYMLINK_SCAN_SKIP = {".git", "venv", ".venv", "node_modules", "__pycache__",
                      ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _unsafe_owned_dests(root: Path, baseline: dict | None) -> list[str]:
    """Destinations a render `cp`/`sed >` would FOLLOW to write outside the repo (P1).
    bootstrap's copy()/render() follow a symlinked destination, and they write to EVERY
    rendered path — not just the ones the OLD baseline recorded — so a v3.8.11 check of
    only the baseline+preserve set missed a symlink planted at a NEW-version path. This
    now does TWO things (v3.8.12):
      1. Flag any SYMLINK at a baseline-owned / preserve path (even one pointing in-repo).
      2. Whole-tree scan: flag ANY symlink anywhere under root whose target ESCAPES root —
         the external-write vector, regardless of whether the path is in the baseline.
    Hard tamper condition — refused even with --force."""
    rootr = root.resolve()
    bad, seen = [], set()

    def _flag(rel):
        if rel not in seen:
            seen.add(rel)
            bad.append(rel)

    owned = baseline.get("owned_file_sha256", {}) if isinstance(baseline, dict) else {}
    for rel in [r for r in owned if isinstance(r, str)] + list(PRESERVE_FILES):
        p = root / rel
        try:
            if p.is_symlink():
                _flag(rel)
            elif p.exists():
                rp = p.resolve()
                if rp != rootr and rootr not in rp.parents:
                    _flag(rel)   # a path component escapes root
        except Exception:
            _flag(rel)           # unresolvable -> unsafe, fail closed
    # Whole-tree escaping-symlink scan (followlinks=False so we never descend a link).
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SYMLINK_SCAN_SKIP]
        for name in list(dirnames) + filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            rel = os.path.relpath(p, root)
            try:
                rp = p.resolve()
                if rp != rootr and rootr not in rp.parents:
                    _flag(rel)
            except Exception:
                _flag(rel)       # dangling / unresolvable link -> unsafe, fail closed
    return sorted(bad)


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


def _authority_snapshot(root: Path) -> dict:
    """Byte-snapshot of the render AUTHORITY — live config + every frozen required_*
    lock. The render answers are derived from these BEFORE source resolution
    (_resolve_kit can be slow / involve verification), so re-comparing this snapshot
    just before the write catches a lock/config change mid-run that would otherwise
    render a stale, inconsistent state (v3.8.10 / P1 TOCTOU)."""
    snap = {}
    for rel in ("config", "required_profile", "required_remote_governance", "required_sandbox"):
        try:
            snap[rel] = (root / ".substrate" / rel).read_bytes()
        except Exception:
            snap[rel] = None
    return snap


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
    # Snapshot the render AUTHORITY (live config + frozen locks) FIRST, then derive ALL
    # answers EXCLUSIVELY from that snapshot (v3.8.13 / P1): deriving from the same bytes
    # the pre-write abort-check compares against closes the gap where a concurrent
    # config/lock change between derive-time and snapshot-time yielded stale answers then
    # accepted as fresh. required_* locks are also read from the snapshot, not fresh disk.
    _auth0 = _authority_snapshot(root)
    _cfg_answers = _answers_from_snapshot(_auth0)
    _raw_ans = (baseline or {}).get("answers")
    prov = dict(_raw_ans) if isinstance(_raw_ans, dict) else {}   # answers shape is agent-writable
    answers = dict(prov)
    # EVERY config-backed render tier comes from LIVE CONFIG (the snapshot), never agent-
    # writable provenance (v3.8.7/v3.8.8 — a forged profile/lang/runner/sandbox/remote would
    # else drop the matching hooks/workflow). ui/workflow are NOT in config, so provenance
    # supplies them, coerced to a STRING (a forged ui=[] would else reach subprocess argv).
    for _k in ("profile", "lang", "runner", "sandbox", "remote_governance"):
        answers[_k] = _cfg_answers[_k]
    for _k in ("ui", "workflow"):
        _v = answers.get(_k, _cfg_answers[_k])
        answers[_k] = _v if isinstance(_v, str) else _cfg_answers[_k]
    cur_ver = (baseline or {}).get("kit_version", "unknown")
    _rk = {"starter": 0, "standard": 1, "strict": 2}
    _names = {0: "starter", 1: "standard", 2: "strict"}
    _lock_profile = _lock_from_snapshot(_auth0, "required_profile")
    if a.profile:
        # Two INDEPENDENT constraints, both anchored on the SNAPSHOT (v3.8.4/v3.8.5/v3.8.13):
        #   (a) refuse target < required_profile lock   (never below the floor)
        #   (b) refuse target <= current live profile   (raise-only)
        lock_rank = _rk.get(_lock_profile, -1)
        current_rank = _rk.get(_cfg_answers["profile"], 1)   # live config, from the snapshot
        target_rank = _rk[a.profile]
        if target_rank < lock_rank:
            print(f"upgrade: --profile {a.profile} is below the required_profile lock "
                  f"({_names[lock_rank]}) — the ratchet never lowers a lock.", file=sys.stderr)
            return 2
        if target_rank <= current_rank:
            print(f"upgrade: --profile {a.profile} would not RAISE above the current profile "
                  f"({_names[current_rank]}) — the ratchet is raise-only.", file=sys.stderr)
            return 2
        answers["profile"] = a.profile

    # Never RENDER below the frozen required_* locks (all from the SNAPSHOT), even on a plain
    # upgrade — forged provenance/config must not drop the hooks/workflow the locks promise.
    if _lock_profile and _rk.get(_lock_profile, -1) > _rk.get(answers.get("profile") or "standard", 1):
        answers["profile"] = _lock_profile
    if _lock_from_snapshot(_auth0, "required_remote_governance") == "1":
        answers["remote_governance"] = "1"
    if _lock_from_snapshot(_auth0, "required_sandbox") == "1":
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

        # Authority TOCTOU guard (v3.8.10 / P1): if .substrate config or any frozen
        # required_* lock changed since we derived `answers` (e.g. during _resolve_kit),
        # those answers are stale — abort BEFORE any mutation rather than render an
        # inconsistent state (e.g. a raised lock with the old config).
        if _authority_snapshot(root) != _auth0:
            print("upgrade: .substrate authority (config / required_* locks) changed during "
                  "source resolution — aborting to avoid rendering a stale, inconsistent state. "
                  "Nothing was changed; re-run.", file=sys.stderr)
            return 2

        # External-write guard (v3.8.11 / P1): refuse if any owned destination is a symlink
        # or resolves outside root — the render's `cp` would FOLLOW it and overwrite a file
        # outside the repo. Hard tamper condition: refused even with --force.
        unsafe = _unsafe_owned_dests(root, baseline)
        if unsafe:
            print("upgrade: refusing — owned destination(s) are symlinks or resolve outside "
                  f"the repo (a render would write outside root): {', '.join(unsafe[:8])}"
                  + (" …" if len(unsafe) > 8 else "") + ". Restore them to regular in-repo "
                  "files and re-run.", file=sys.stderr)
            return 2

        backup = tmp / "preserve"
        saved = _backup(root, backup)
        # Final authority re-check immediately before the mutating render (v3.8.13 / P1):
        # root is still UNMUTATED here (_backup only COPIED it), so if the authority changed
        # since _auth0 we simply abort — no stale render, and no lock is ever lowered. The
        # backup was captured with authority == _auth0 (just verified), so the post-render
        # _restore reconstitutes exactly the state the answers were derived from. (This
        # replaces the v3.8.12 transactional overwrite, which could LOWER a concurrently
        # raised lock — violating raise-only.)
        if _authority_snapshot(root) != _auth0:
            print("upgrade: .substrate authority (config / required_* locks) changed before "
                  "the render — aborting; nothing was mutated. Re-run.", file=sys.stderr)
            return 2
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
        mf = _run([sys.executable, "-I", str(root / "scripts" / "update_manifest.py"), "--fix"], cwd=root)
        # Prefer the commit parsed from the VERIFIED trusted comment (a .zip extract has no
        # .git, so git rev-parse would record 'none' — v3.7.16 P2b). Fall back to git for a
        # directory source that IS a checkout.
        commit = verified_commit or "none"
        if commit == "none":
            gc = _run(["git", "rev-parse", "--short", "HEAD"], cwd=kit)
            if gc.returncode == 0:
                commit = gc.stdout.strip()
        wj = _run([sys.executable, "-I", str(root / "scripts" / "write_install_json.py"),
              "--root", str(root), "--version", new_ver, "--commit", commit,
              "--source", str(src), "--installed-at", datetime.now(timezone.utc).isoformat(),
              "--profile", answers.get("profile", "standard"), "--lang", answers.get("lang", "auto"),
              "--runner", answers.get("runner", "auto"), "--ui", answers.get("ui", "no"),
              "--workflow", answers.get("workflow", "superpowers"),
              "--sandbox", str(answers.get("sandbox", "0")),
              "--remote-governance", str(answers.get("remote_governance", "0"))], cwd=root)
        # Do NOT claim success if a finalizer failed (v3.8.10 / P2): a failed
        # write_install_json (e.g. install.json is a directory) leaves drift protection /
        # fresh provenance absent, yet the kit files were already applied — surface it.
        # Trust the RESULT on disk, not just the finalizer rc (v3.8.11 / P2): write_install_json
        # can exit 0 yet not have written (e.g. .substrate/install.json is a DIRECTORY), leaving
        # provenance/drift-protection silently absent. Verify install.json is now a regular file
        # carrying the new version.
        prov_ok = False
        ij = root / ".substrate" / "install.json"
        try:
            if ij.is_file() and not ij.is_symlink():
                _pj = json.loads(ij.read_text(encoding="utf-8"))
                prov_ok = isinstance(_pj, dict) and _pj.get("kit_version") == new_ver
        except Exception:
            prov_ok = False
        if mf.returncode != 0 or wj.returncode != 0 or not prov_ok:
            print(f"upgrade: kit files applied, but a FINALIZER FAILED (manifest rc={mf.returncode}, "
                  f"provenance rc={wj.returncode}, provenance_written={prov_ok}) — drift protection / "
                  f"fresh provenance may be incomplete. Review and re-run.\n"
                  f"{((wj.stderr or '') + (mf.stderr or ''))[-800:]}", file=sys.stderr)
            return 2
        print(f"substrate upgrade: applied {new_ver}. Review `git diff`, run `./manage.sh check`, then commit.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
