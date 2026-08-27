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
import types
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None

try:
    from _doc_common import safe_atomic_write as _safe_atomic_write
except Exception:  # pragma: no cover - stripped install
    def _safe_atomic_write(*a, **k):
        raise OSError("safe_atomic_write unavailable — refusing an unguarded write")

try:
    from _doc_common import refuse_linked_leaf as _refuse_linked_leaf
except Exception:  # pragma: no cover - stripped install
    def _refuse_linked_leaf(path):
        return "guard unavailable"

try:
    from _doc_common import safe_read_bytes as _safe_read_bytes
except Exception:  # pragma: no cover - stripped install
    def _safe_read_bytes(path, root=None, max_bytes=None, tail_bytes=None):
        return None
from _doc_common import read_lock as _dc_read_lock  # noqa: E402


def _load_verify(root: Path | None = None):
    """Import the multi-backend verifier LAZILY, only when a source is actually being verified
    (v3.8.23 / upgrade:32). A module-level `from _verify_backends import verify` executed that
    sibling at interpreter start — before argument parsing, before source verification, and before
    the drift gate could refuse — so `upgrade --plan` on a repo with a locally-modified
    `_verify_backends.py` ran the modification even when the source was then REJECTED. Deferring it
    means the rejection paths (unverified directory source, bad args, drift refusal in --plan) never
    execute it.

    v3.8.24 (upgrade:209): deferral alone still let a MODIFIED verifier approve an unsigned zip —
    a `verify()` stubbed to return rc=0 made an unsigned source print "verified". Verification is
    the trust anchor for the source, so before importing it we require the helper to match the drift
    baseline whenever the engine is running FROM the target tree (the only case where the baseline
    describes this file) and the baseline vouches for it. A mismatch aborts instead of trusting a
    tampered verifier. Honest limits: the baseline is itself agent-writable (see the documented
    limitation for upgrade:220), and running the TARGET's `scripts/substrate_upgrade.py` is already
    trusted-by-execution — an attacker who edits BOTH the helper and the baseline (or the engine
    itself) is outside what any in-process check can catch; the real anchors are the signed release
    and the remote trusted-base freeze."""
    eng = Path(__file__).resolve().parent
    if root is not None:
        try:
            same_tree = eng == (root / "scripts").resolve()
        except Exception:
            same_tree = False
        if same_tree:
            # v3.8.25 (upgrade:63 + _verify_backends:29): pin the verifier's whole DEPENDENCY
            # CLOSURE, and FAIL CLOSED when the baseline cannot vouch for it. v3.8.24 pinned only
            # the wrapper and skipped the check whenever the owned-map entry was missing/non-string
            # — so deleting one entry (or poisoning `_minisign.py`, which the wrapper imports)
            # restored a fully-trusted forged verification. A trust anchor may not fail open.
            _b = _load_install_json(root)
            _owned = (_b.get("owned_file_sha256") or {}) if _b else {}
            for _name in _VERIFIER_CLOSURE:
                _rel = f"scripts/{_name}"
                _want = _owned.get(_rel)
                if not isinstance(_want, str):
                    raise SystemExit(
                        f"upgrade: refusing — the drift baseline does not vouch for {_rel}, so "
                        "source verification cannot be trusted (a missing/!str owned-map entry is "
                        "NOT a pass). Re-install the kit to rebuild the baseline, or re-run with "
                        "--allow-unverified to skip verification explicitly.")
                try:
                    _got = _sha256(eng / _name)
                except Exception as e:
                    raise SystemExit(f"upgrade: refusing — cannot hash {_rel} to check it against "
                                     f"the drift baseline: {e}")
                if _got is None:
                    raise SystemExit(
                        f"upgrade: refusing — {_rel} is missing or is an unsafe leaf "
                        "(symlink/hard link/FIFO), so it cannot be checked against the "
                        "drift baseline.")
                if _got != _want:
                    raise SystemExit(
                        f"upgrade: refusing — {_rel} does not match the drift baseline, so source "
                        "verification cannot be trusted. Restore it (re-install the kit) or, if "
                        "you intend to skip verification entirely, re-run with --allow-unverified.")
    # Execute the EXACT BYTES we just hashed (v3.8.25 / upgrade:79). A normal `import` consults
    # `__pycache__`, and a PEP 552 UNCHECKED hash-based .pyc is used WITHOUT validating it against
    # the source — so hash-pinning the .py while importing normally verified bytes Python never
    # ran. `__pycache__` is gitignored, so neither the drift gate nor the memory signature covered
    # it. Compiling the source ourselves closes the gap: hash-then-execute the same bytes.
    # `_minisign` is pre-loaded the same way so the wrapper's `from _minisign import ...` binds our
    # trusted module instead of re-entering the import machinery (and its pyc).
    _saved = list(sys.path)
    _saved_mods = {n: sys.modules.get(n) for n in ("_minisign", "_verify_backends")}
    try:
        sys.path.insert(0, str(eng))
        mod = None
        for _name in _VERIFIER_CLOSURE:
            mod = _exec_module_from_source(eng / _name)
        return mod.verify
    finally:
        sys.path[:] = _saved
        # Restore sys.modules so these trusted-but-privately-loaded modules do not linger under
        # common names for a later in-process importer (v3.8.25 auditor). The returned `verify`
        # keeps working: its globals reference the still-live module dict.
        for _n, _prev in _saved_mods.items():
            if _prev is None:
                sys.modules.pop(_n, None)
            else:
                sys.modules[_n] = _prev


# The verifier's dependency closure, in import order: `_minisign` first so it is already in
# sys.modules when `_verify_backends` does `from _minisign import ...`.
_VERIFIER_CLOSURE = ("_minisign.py", "_verify_backends.py")


def _exec_module_from_source(path: Path):
    """Compile and execute a module from its SOURCE BYTES, bypassing the bytecode cache entirely,
    and register it in sys.modules under its stem so sibling imports bind to it (v3.8.25)."""
    name = path.stem
    # v3.8.47 (round-30 P2, found by the sweep): this COMPILES AND EXECUTES
    # the bytes it reads. Reading code to run through an unguarded path is
    # the highest-value instance of this class in the kit — a symlinked or
    # hard-linked engine module would execute outside bytes with the
    # upgrader's privileges.
    _src = _safe_read_bytes(path, max_bytes=None)
    if _src is None:
        raise OSError(f"refusing to execute a module from an unsafe or "
                      f"unreadable source: {path}")
    code = compile(_src, str(path), "exec")
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    sys.modules[name] = mod
    exec(code, mod.__dict__)
    return mod

# User-content / operator-owned surfaces: NEVER overwritten by an upgrade (backed up
# then restored around the bootstrap --force). Includes the required_* LOCKS so an
# upgrade can never silently lower a profile/sandbox/remote requirement.
PRESERVE_FILES = [
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "pyproject.toml",
    ".substrate/config", ".substrate/required_profile", ".substrate/required_sandbox",
    ".substrate/required_remote_governance", ".substrate/sandbox.json",
    ".github/dependabot.yml",
    "docs/ARCHITECTURE.md", "docs/INTENT.md", "docs/HISTORY.md", "docs/REJECTED.md",
    "docs/README.md",
]
PRESERVE_DIRS = ["design-system", "docs/decisions", "docs/postmortems"]

# Never drift-check the provenance file itself — it is rewritten every upgrade and is
# excluded from its own baseline (see write_install_json._BASELINE_EXCLUDE). v3.7.16 P1.
_DRIFT_EXCLUDE = {".substrate/install.json"}

def _retired_knowledge_baseline_entry(rel: str, coverage: set[str] | None) -> bool:
    """Whether NEW-kit ownership retires an old recursive knowledge entry.

    Coverage comes from the selected kit's canonical provenance writer. None is
    fail-closed: if that trusted calculation cannot run, no old entry is retired.
    Restricting migration to the intentionally mixed knowledge directory avoids
    treating unrelated inventory mistakes as authorization to ignore drift.
    """
    return (
        coverage is not None
        and rel.startswith("docs/knowledge/")
        and rel not in coverage
    )


def _run(cmd, cwd=None, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)


def _load_install_json(root: Path) -> dict | None:
    p = root / ".substrate" / "install.json"
    if p.is_file():
        try:
            data = json.loads(_safe_read_text(p, root, max_bytes=8 << 20) or "null")
        except Exception:
            return None
        # install.json is agent-writable and drift-EXCLUDED, so a hostile/garbled shape
        # (e.g. a bare JSON string) must not crash the upgrade with an AttributeError when
        # `.get()`/`dict()` are called on it — treat any non-mapping as absent (v3.8.10).
        if not isinstance(data, dict):
            return None
        # Drift protection can only be trusted with a VALID drift map. A MISSING or non-dict
        # owned_file_sha256 makes the baseline UNTRUSTED / ABSENT — so --write requires --force
        # — never a proof of zero drift that would silently overwrite locally-modified owned
        # files (v3.8.13 non-dict; v3.8.14 also the missing/incomplete-key case / P2).
        if not isinstance(data.get("owned_file_sha256"), dict):
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
            _safe_read_text(root / ".substrate" / "config", root, max_bytes=1 << 20) or "")
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


def _lock_ge(a: str, b: str) -> str:
    """RAISE-only max of two lock values — profile ranks for required_profile, else the
    binary '1' wins over '0'/anything (v3.8.14). Used to reconcile a concurrent raise that
    landed just before the render so the upgrade never LOWERS it."""
    if a in _PROF_RANK and b in _PROF_RANK:
        return a if _PROF_RANK[a] >= _PROF_RANK[b] else b
    if a == "1" or b == "1":
        return "1"
    return a or b


def _profile_alias(ans: dict) -> str:
    base = ans.get("profile") or "standard"
    if str(ans.get("sandbox", "0")) == "1":
        base += "+sandbox"
    if str(ans.get("remote_governance", "0")) == "1":
        base += "+remote"
    return base


def _sha256(p: Path, root: Path | None = None) -> str | None:
    """Guarded hash: None when the leaf is absent or unsafe (link/FIFO/escape).

    v3.8.44 (round-27, surfaced by the gate's new interprocedural pass): this
    was a raw read_bytes() on whatever path it was handed, and every caller
    compares the result to a baseline hash. Hashing OUTSIDE bytes through a
    planted link makes a tampered file compare clean, which is the one thing a
    drift check must not do. None is never equal to a recorded hash, so an
    unreadable leaf now reads as DRIFT rather than as a match.
    """
    import hashlib
    raw = _safe_read_bytes(p, root, max_bytes=None)
    return None if raw is None else hashlib.sha256(raw).hexdigest()


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
        r = _load_verify(root)(src, minisign_pub=pub, root=root, require=True)
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


def _drifted(root: Path, baseline: dict | None, kit: Path,
             coverage: set[str]) -> list[str]:
    """Machinery files whose local hash differs from the baseline (user edited a substrate
    file). Preserve-set files are excluded — they are expected to differ. When `kit` is given,
    completeness is also cross-checked against the NEW kit's exact overwrite set (v3.8.19)."""
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
        if _retired_knowledge_baseline_entry(rel, coverage):
            continue
        if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(d + "/") for d in PRESERVE_DIRS):
            continue
        p = root / rel
        # is_file()/_sha256 follow symlinks — but a symlinked owned dest is a hard tamper
        # condition handled by _unsafe_owned_dests (abort), so here we only compare regular
        # files' content.
        if p.is_file() and not p.is_symlink() and _sha256(p, root) != want:
            out.append(rel)
    # Completeness cross-check (v3.8.15 / P2): the owned map is agent-writable, so an attacker
    # can EDIT an owned file AND DELETE its entry so the hash loop above never sees it. Scan the
    # security-critical managed dir(s): any regular file present that the render would overwrite
    # but that has NO baseline hash is UNVERIFIABLE -> flag as drift (needs --force). (Project
    # files legitimately never live under scripts/ — it is substrate-reserved by the hard rules —
    # so this does not false-flag a well-behaved repo.)
    # Only a well-formed path/hash pair vouches for content. A null/list hash is
    # skipped by the comparison loop above and must stay absent here too; counting
    # its key as vouched lets forged provenance suppress the completeness check.
    ownkeys = {
        rel for rel, want in owned.items()
        if isinstance(rel, str)
        and isinstance(want, str)
        and not _retired_knowledge_baseline_entry(rel, coverage)
    }
    for d in _COMPLETENESS_SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.is_symlink() or p.suffix not in _COMPLETENESS_SCAN_EXTS:
                continue
            rel = p.relative_to(root).as_posix()
            if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(pd + "/") for pd in PRESERVE_DIRS):
                continue
            if rel not in ownkeys:
                out.append(rel)   # present under a managed dir but unvouched by the baseline
    # v3.8.17 (P2, finding upgrade:252): the dir scan above missed RESERVED top-level managed
    # FILES (e.g. `manage.sh`) — an attacker could edit manage.sh AND delete its owned-map entry
    # and the completeness cross-check would never see it (it lives under no scanned dir). Extend
    # to the reserved top-level files a project NEVER authors. This deliberately does NOT scan the
    # whole write_install_json owned set (tests/, .claude/, .github/workflows/, docs/knowledge/):
    # projects legitimately add their own files there, so an unvouched file is expected, not
    # tamper — scanning them would FALSE-FLAG a well-behaved repo (cut functionality). Only
    # substrate-RESERVED surfaces (scripts/ by the hard rules, plus the fixed entrypoints below)
    # are safe to treat "present-but-unvouched" as drift.
    for rel in _COMPLETENESS_SCAN_FILES:
        if rel in preserve or rel in _DRIFT_EXCLUDE:
            continue
        p = root / rel
        if p.is_file() and not p.is_symlink() and rel not in ownkeys:
            out.append(rel)   # a reserved managed entrypoint present but unvouched by the baseline
    # v3.8.19 (P2, finding upgrade:258): cross-check the NEW KIT's EXACT overwrite set. The
    # scans above cover the reserved surfaces (scripts/, manage.sh), but bootstrap --force
    # also overwrites .pre-commit-config.yaml, pytest.ini, .github/workflows/*, agent configs,
    # skills, docs templates, ... — an attacker who edits any of those AND deletes its baseline
    # entry evaded the hash loop AND the reserved-surface scans, and --write without --force
    # silently clobbered the edit. Flag any render target that exists locally, is INSIDE the
    # baseline's vouch surface (write_install_json.owned_files — what hash_owned enumerates),
    # yet has no baseline hash: that combination means a DELETED/FORGED entry or a file added
    # since install, never a legitimate state. Kit dests OUTSIDE the vouch surface (e.g. the
    # dormant .substrate/ staged templates) are NOT flagged — the baseline never hashed those,
    # so "unvouched" is their normal state and flagging them would false-drift every upgrade
    # (a pre-existing coverage gap, documented, not a regression).
    for rel in _kit_overwrite_set(kit):
        if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(pd + "/") for pd in PRESERVE_DIRS):
            continue
        p = root / rel
        if p.is_file() and not p.is_symlink() and rel in coverage and rel not in ownkeys:
            out.append(rel)   # render target the baseline should vouch for, but doesn't
    # v3.8.20/v3.8.21 (P2, findings upgrade:350 + upgrade:296): the leaf set above misses
    # DELETION effects. bootstrap replaces skill dirs WHOLESALE (`rm -rf` + `cp -R`), so
    # ANYTHING under one of those dirs that is not vouched by the baseline is silently
    # destroyed — a local FILE (350) or a local SYMLINK / other non-regular entry (296,
    # which the earlier is_file-only scan skipped even though rm -rf deletes it too). The
    # whole subtree dies, so the rule is not "in the render overwrite set" but simply
    # "present + unvouched": any entry under a replaced dir whose path the baseline does
    # not vouch for is drift (needs --force). After a clean install every kit skill file
    # IS in ownkeys, so a well-behaved repo is not flagged; ephemeral build artifacts are
    # skipped so they never force --force.
    for d in _kit_replaced_dirs(kit):
        base = root / d
        # v3.8.22 (upgrade:298): if the replaced-dir ROOT is itself a symlink, bootstrap's
        # `rm -rf "$dest"` deletes the link and `cp -R` writes a fresh dir — so the operator's
        # symlink is destroyed. The v3.8.21 scan `continue`d on a symlinked base and missed it;
        # flag the root itself as drift (needs --force) unless the baseline already vouches it.
        if base.is_symlink():
            if d not in preserve and d not in ownkeys \
               and not any(d.startswith(pd + "/") for pd in PRESERVE_DIRS):
                out.append(d)
            continue
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_dir() and not p.is_symlink():
                continue   # a real subdir carries no content of its own; its entries are walked
            relp = p.relative_to(root)
            if any(part in _SYMLINK_SCAN_SKIP for part in relp.parts):
                continue   # __pycache__/.pytest_cache/... — build noise, never force --force
            rel = relp.as_posix()
            if rel in preserve or rel in _DRIFT_EXCLUDE or any(rel.startswith(pd + "/") for pd in PRESERVE_DIRS):
                continue
            if rel not in ownkeys:
                out.append(rel)   # present under a wholesale-replaced dir, unvouched -> would be DELETED
    return sorted(set(out))


def _baseline_coverage(root: Path, kit: Path) -> set[str] | None:
    """The baseline's vouch surface: the exact file set hash_owned() would enumerate for this
    root (write_install_json.owned_files). Loaded from the TRUSTED KIT copy, not the target's
    `scripts/write_install_json.py` (v3.8.22 / upgrade:320): a bare `from write_install_json
    import` resolves to the target's (possibly locally-modified) module and RUNS its top-level
    code — during `upgrade --plan`, before drift is even refused. Exec the kit's file in an
    isolated module and restore sys.path so a kit-side `sys.path.insert` has no lasting effect.
    None if unavailable; the caller treats that as a hard pre-render failure."""
    scripts = kit / "scripts"
    surfaces_src = scripts / "_substrate_surfaces.py"
    src = scripts / "write_install_json.py"
    if not surfaces_src.is_file() or not src.is_file():
        return None
    _saved_path = list(sys.path)
    _saved_mods = {
        name: sys.modules.get(name)
        for name in ("_substrate_surfaces", "write_install_json")
    }
    try:
        sys.path.insert(0, str(src.parent))
        # Compile from source rather than importlib (v3.8.25): same bytecode-cache bypass as the
        # verifier loader, so a planted `__pycache__` .pyc can never stand in for the kit's source.
        surfaces = _exec_module_from_source(surfaces_src)
        mod = _exec_module_from_source(src)   # trusted kit code, never the target's
        raw = mod.owned_files(root)
        # Treat this as a security oracle, not an arbitrary iterable. Validate
        # both serialization shape and exact parity with the inventory constants
        # the selected kit's writer imported. Empty, absolute, parent-traversing,
        # duplicate, or irrelevant-only results are unavailable coverage.
        if not isinstance(raw, list) or not raw:
            return None

        def _valid_rel(rel) -> bool:
            if not isinstance(rel, str) or not rel or "\\" in rel:
                return False
            posix = PurePosixPath(rel)
            return not posix.is_absolute() and ".." not in posix.parts \
                and rel == posix.as_posix()

        if not all(_valid_rel(rel) for rel in raw) or raw != sorted(set(raw)):
            return None
        groups = [getattr(mod, name, None) for name in (
            "OWNED_FILES", "OPTIONAL_FILES", "OWNED_DIRS", "OPTIONAL_DIRS",
        )]
        skip = getattr(mod, "COVERAGE_SKIP_PARTS", None)
        canonical_groups = [getattr(surfaces, name, None) for name in (
            "OWNED_FILES", "OPTIONAL_FILES", "OWNED_DIRS", "OPTIONAL_DIRS",
        )]
        canonical_skip = getattr(surfaces, "COVERAGE_SKIP_PARTS", None)
        if groups != canonical_groups or skip != canonical_skip:
            return None
        if any(not isinstance(group, list) or not all(_valid_rel(x) for x in group)
               for group in groups):
            return None
        if not isinstance(skip, set) or not all(isinstance(x, str) for x in skip):
            return None
        expected = {rel for rel in groups[0] + groups[1] if (root / rel).is_file()}
        for rel in groups[2] + groups[3]:
            base = root / rel
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if path.is_file() and not any(part in skip for part in path.parts):
                    expected.add(path.relative_to(root).as_posix())
        coverage = set(raw)
        return coverage if coverage == expected else None
    except Exception:
        return None
    finally:
        sys.path[:] = _saved_path   # undo any sys.path.insert the kit module did at import
        for name, previous in _saved_mods.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


_COMPLETENESS_SCAN_DIRS = ("scripts",)
_COMPLETENESS_SCAN_EXTS = (".py", ".sh")
# Reserved top-level managed files a project never authors (unlike tests/ or .claude/), so a
# present-but-unvouched instance is tamper, not a legitimate project file. `manage.sh` is the
# substrate CLI entrypoint; bootstrap --force overwrites it, so an upgrade must gate on it too.
_COMPLETENESS_SCAN_FILES = ("manage.sh",)


def _kit_overwrite_set(kit: Path) -> set[str]:
    """Repo-relative destinations the NEW kit's `bootstrap.sh --force` MAY overwrite, derived
    from the kit's own contents (v3.8.19 / upgrade:258). This is the correct completeness
    surface: the v3.8.17 scripts/+manage.sh heuristic missed real overwrite targets
    (.pre-commit-config.yaml, pytest.ini, .github/workflows/ci.yml, ...) — a project file the
    render WILL clobber must be baseline-vouched or flagged as drift, REGARDLESS of who authored
    it (the earlier "projects author files there -> never flag" reasoning conflated ownership
    with overwrite risk). Deliberately OVER-inclusive (profile/lang/remote conditionals ignored:
    extras, pyproject.toml, trusted-base always included) — over-inclusion only widens drift
    protection, and preserve-set filtering in _drifted removes the operator-owned surfaces.
    Mirrors bootstrap.sh's dest mapping; test_upgrade_overwrite_set_parity_with_bootstrap runs
    the REAL bootstrap --force and fails if this map ever drifts from it."""
    out: set[str] = set()

    def _names(sub: str, pattern: str = "*"):
        base = kit / sub
        if base.is_dir():
            for p in sorted(base.glob(pattern)):
                if p.is_file():
                    yield p.name

    for n in _names("scripts"):
        out.add(f"scripts/{n}")
    for n in _names("extras", "*.py"):
        out.add(f"scripts/{n}")
        out.add(f".substrate/extras/{n}")
    for n in _names("tests", "*.py"):
        out.add(f"tests/{n}")
    for n in _names("agents/claude"):
        out.add(f".claude/agents/{n}")
    for n in _names("agents/codex"):
        out.add(f".codex/agents/{n}")
    for n in _names("templates/blind-spot-checklists", "*.md"):
        out.add(f"docs/blind-spot-checklists/{n}")
    for n in _names("templates/github", "*.instructions.md"):
        out.add(f".github/instructions/{n}")
    skills = kit / "skills"
    if skills.is_dir():
        for sd in sorted(skills.iterdir()):
            if not sd.is_dir():
                continue
            for p in sorted(sd.rglob("*")):
                if p.is_file():
                    rel = p.relative_to(skills).as_posix()
                    out.add(f".claude/skills/{rel}")
                    out.add(f".agents/skills/{rel}")
    for wf in ("ci.yml", "scheduled-audit.yml", "agent-config-audit.yml", "trusted-base-audit.yml"):
        if (kit / "workflows" / f"{wf}.template").is_file():
            out.add(f".github/workflows/{wf}")
    for rt in ("trusted-base-audit.yml.template", "release-ci-minisign.yml.template",
               "release-keyless.yml.template", "auto-upgrade.yml.template"):
        if (kit / "workflows" / rt).is_file():
            out.add(f".substrate/{rt}")
    # Fixed template-rendered / copied destinations (kit-source -> dest).
    for src, dest in (
        ("templates/AGENTS.md", "AGENTS.md"),
        ("templates/CLAUDE.md", "CLAUDE.md"),
        ("templates/pyproject.toml.template", "pyproject.toml"),
        ("templates/pre-commit-config.yaml.template", ".pre-commit-config.yaml"),
        ("templates/pre-commit-config.yaml.template", ".substrate/pre-commit-config.yaml.template"),
        ("templates/manage.sh.template", "manage.sh"),
        ("templates/pytest.ini.template", "pytest.ini"),
        ("templates/codex/config.toml.template", ".codex/config.toml"),
        ("templates/codex/hooks.json.template", ".codex/hooks.json"),
        ("templates/claude/settings.json.template", ".claude/settings.json"),
        ("templates/0000-adr-template.md", "docs/decisions/0000-template.md"),
        ("templates/postmortem_template.md", "docs/postmortems/_template.md"),
        ("templates/knowledge_doc_template.md", "docs/knowledge/_template.md"),
        ("templates/finding_response.md", "docs/templates/finding_response.md"),
        ("templates/diy_ultrareview_prompts.md", "docs/templates/diy_ultrareview_prompts.md"),
        ("templates/pull_request_template.md", ".github/pull_request_template.md"),
        ("templates/CODEOWNERS.template", ".github/CODEOWNERS.suggested"),
        ("templates/SECURITY.md", "SECURITY.md"),
        ("templates/CONTRIBUTING.md", "CONTRIBUTING.md"),
        ("templates/copilot-instructions.md", ".github/copilot-instructions.md"),
        ("templates/github/exfil-guard.hook.json", ".github/hooks/exfil-guard.json"),
        (".substrate/trust/minisign.pub", ".substrate/trust/minisign.pub"),
    ):
        if (kit / src).is_file():
            out.add(dest)
    # Direct-write regenerated files (force-overwritten by bootstrap's redirection sites).
    out.update((".substrate/config", ".substrate/required_profile", ".substrate/required_sandbox",
                ".substrate/required_remote_governance", ".substrate/sandbox.json",
                "docs/HISTORY.md", "docs/REJECTED.md", "docs/README.md",
                "docs/knowledge/00_substrate.md",
                ".github/dependabot.yml"))
    return out


def _kit_replaced_dirs(kit: Path) -> set[str]:
    """Dirs the new kit's bootstrap --force replaces WHOLESALE (`rm -rf` + `cp -R`) rather than
    file-by-file, so EVERY local file under them is deleted/replaced — not only the new kit's
    leaves (v3.8.20 / upgrade:350). Mirrors bootstrap.sh's skills loop."""
    out: set[str] = set()
    skills = kit / "skills"
    if skills.is_dir():
        for sd in sorted(skills.iterdir()):
            if sd.is_dir():
                out.add(f".claude/skills/{sd.name}")
                out.add(f".agents/skills/{sd.name}")
    return out


_SYMLINK_SCAN_SKIP = {".git", "venv", ".venv", "node_modules", "__pycache__",
                      ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _unsafe_owned_dests(root: Path, baseline: dict | None,
                        coverage: set[str]) -> list[str]:
    """Destinations a render `cp`/`sed >` would FOLLOW to write outside the repo (P1).
    bootstrap's copy()/render() follow a symlinked destination, and they write to EVERY
    rendered path — not just the ones the OLD baseline recorded — so a v3.8.11 check of
    only the baseline+preserve set missed a symlink planted at a NEW-version path. This
    now does THREE things (v3.8.12; 3 added v3.8.20):
      1. Flag any SYMLINK at a baseline-owned / preserve path (even one pointing in-repo).
      2. Whole-tree scan: flag ANY symlink anywhere under root whose target ESCAPES root —
         the external-write vector, regardless of whether the path is in the baseline.
      3. Flag any owned/preserve path whose RESOLVED path differs from its literal path
         (a symlinked ANCESTOR aliasing it, e.g. `.substrate -> .git`) — backup/restore and
         the render would silently read/write through the alias into the aliased target.
    Hard tamper condition — refused even with --force."""
    rootr = root.resolve()
    bad, seen = [], set()

    def _flag(rel):
        if rel not in seen:
            seen.add(rel)
            bad.append(rel)

    owned = baseline.get("owned_file_sha256", {}) if isinstance(baseline, dict) else {}
    for rel in [
        r for r in owned
        if isinstance(r, str) and not _retired_knowledge_baseline_entry(r, coverage)
    ] + list(PRESERVE_FILES):
        p = root / rel
        try:
            if p.is_symlink():
                _flag(rel)
            elif p.exists():
                rp = p.resolve()
                if rp != rootr and rootr not in rp.parents:
                    _flag(rel)   # a path component escapes root
                elif rp != rootr / rel and str(rp).casefold() != str(rootr / rel).casefold():
                    _flag(rel)   # ALIASED path component (e.g. `.substrate -> .git`): resolves
                    #              in-repo but NOT to its literal path, so backup/restore and the
                    #              render would read/write through the alias (v3.8.20, the
                    #              upgrade-side companion to bootstrap's exact-parent _safe_dest).
                    #              casefold: on a case-INSENSITIVE fs (macOS APFS) resolve() may
                    #              return canonical casing for a NON-aliased file — a case-only
                    #              difference is never an alias (aliases differ in components),
                    #              so it must not hard-brick the upgrade (v3.8.20 auditor WARN).
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


def _read_lock_or_refuse(root: Path, name: str, allowed: set, absent: str) -> str:
    """Read a frozen `.substrate/<name>` lock for render authority (v3.8.33).

    ABSENT file → `absent` (no lock was ever pinned). PRESENT but unreadable or
    holding a value outside `allowed` → REFUSE THE UPGRADE. The old readers
    fell back to the LOWEST tier on any error, so an unreadable lock let the
    render silently drop a required tier — the same 'trust anchor may not fail
    open' class as v3.8.25. SystemExit surfaces as a nonzero refusal.

    v3.8.36: delegates to the canonical reader — is_file() treated a DIRECTORY
    lock as absent (Codex reproduced a --plan run sailing past a
    required_sandbox/ directory) and followed symlinked locks; both now refuse."""
    state, val, reason = _dc_read_lock(root / ".substrate" / name, allowed, root=root)
    if state == "absent":
        return absent
    if state == "bad":
        raise SystemExit(
            f"substrate-upgrade: refusing — .substrate/{name}: {reason}; a malformed "
            f"lock must not lower the render authority. Fix the lock and re-run.")
    return val


def _read_required_profile(root: Path) -> str:
    return _read_lock_or_refuse(root, "required_profile", set(_PROF_RANK), "starter")


def _read_required_remote_governance(root: Path) -> str:
    """The frozen remote-governance lock. "1" means the repo REQUIRES remote
    governance (the trusted-base workflow), so the render must never turn it off
    regardless of what the agent-writable install.json/config claims (v3.8.7)."""
    return _read_lock_or_refuse(root, "required_remote_governance", {"0", "1"}, "")


def _read_required_sandbox(root: Path) -> str:
    """The frozen egress-containment lock. "1" means the repo REQUIRES the sandbox,
    so the render must never turn it off regardless of provenance/config (v3.8.8)."""
    return _read_lock_or_refuse(root, "required_sandbox", {"0", "1"}, "")


def _authority_snapshot(root: Path) -> dict:
    """Byte-snapshot of the render AUTHORITY — live config + every frozen required_*
    lock. The render answers are derived from these BEFORE source resolution
    (_resolve_kit can be slow / involve verification), so re-comparing this snapshot
    just before the write catches a lock/config change mid-run that would otherwise
    render a stale, inconsistent state (v3.8.10 / P1 TOCTOU)."""
    # v3.8.36: VALIDATE the locks before snapshotting them (Codex round-19 —
    # the render answers derive from these bytes, and the refusing readers were
    # never on this path, so a directory/symlink/undecodable lock sailed into
    # `--plan`/render as "no lock"). A "bad" lock state refuses the upgrade
    # here, before any derivation; the byte snapshot below is unchanged and
    # still backs the pre-write TOCTOU re-compare.
    _lock_domains = {"required_profile": set(_PROF_RANK),
                     "required_remote_governance": {"0", "1"},
                     "required_sandbox": {"0", "1"}}
    for rel, dom in _lock_domains.items():
        state, _v, reason = _dc_read_lock(root / ".substrate" / rel, dom, root=root)
        if state == "bad":
            raise SystemExit(
                f"substrate-upgrade: refusing — .substrate/{rel}: {reason}; a malformed "
                f"lock must not enter the render authority. Fix the lock and re-run.")
    snap = {}
    for rel in ("config", "required_profile", "required_remote_governance", "required_sandbox"):
        # v3.8.43 (round-26): snapshotting THROUGH a link would capture outside
        # bytes as the pre-render state of a trust anchor. None is the existing
        # "no usable value" path, so an unsafe leaf takes it.
        try:
            if _refuse_linked_leaf(root / ".substrate" / rel) is not None:
                snap[rel] = None
            else:
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
        lines = (_safe_read_text(cfg, root, max_bytes=1 << 20) or "").splitlines()
        for i, line in enumerate(lines):
            if line.startswith("SUBSTRATE_PROFILE="):
                lines[i] = f'SUBSTRATE_PROFILE="{target}"'
                break
        else:
            lines.append(f'SUBSTRATE_PROFILE="{target}"')
        _safe_atomic_write(cfg, "\n".join(lines) + "\n", root=root)
        req = root / ".substrate" / "required_profile"
        prev = _read_required_profile(root)
        locked = target if _PROF_RANK[target] >= _PROF_RANK.get(prev, 0) else prev
        _safe_atomic_write(req, locked + "\n", root=root)
        print(f"upgrade: profile ratcheted to {target} (required_profile lock={locked})")
    except Exception as e:
        print(f"upgrade: WARNING could not apply the profile ratchet: {e}", file=sys.stderr)


def _apply_capability_floor(root: Path) -> None:
    """Raise .substrate/config's SUBSTRATE_REMOTE_GOVERNANCE / SUBSTRATE_SANDBOX to "1" when the
    matching frozen required_* lock is "1" (v3.8.22). config is PRESERVED (restored from the
    pre-upgrade backup), so a repo whose lock=1 but whose preserved config line said 0 ends up
    internally INCONSISTENT — the render honored the lock (workflow/sandbox rendered) but the
    config still claims the capability off, which check_substrate_config rejects. This mirrors
    _apply_profile_ratchet for the two capability flags: RAISE-only (only 0->1 to match a lock the
    render already honored), inline comments preserved, never lowers a value."""
    cfg = root / ".substrate" / "config"
    pairs = (("required_remote_governance", "SUBSTRATE_REMOTE_GOVERNANCE"),
             ("required_sandbox", "SUBSTRATE_SANDBOX"))
    try:
        want = set()
        for lock, key in pairs:
            lp = root / ".substrate" / lock
            if (_safe_read_text(lp, root, max_bytes=1 << 16) or "").strip() == "1":
                want.add(key)
        if not want:
            return
        lines = (_safe_read_text(cfg, root, max_bytes=1 << 20) or "").splitlines()
        seen = set()
        for i, line in enumerate(lines):
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key in want:
                comment = ("   " + line[line.index("#"):]) if "#" in line else ""
                lines[i] = f'{key}="1"{comment}'
                seen.add(key)
        for key in want - seen:
            lines.append(f'{key}="1"')
        _safe_atomic_write(cfg, "\n".join(lines) + "\n", root=root)
    except Exception as e:
        print(f"upgrade: WARNING could not floor capability config lines: {e}", file=sys.stderr)


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
    try:
        return _main_after_args(a)
    except SystemExit as e:
        # v3.8.36: the fail-closed lock readers signal refusal via SystemExit;
        # at the CLI boundary that is exit code 2, never an uncaught traceback,
        # even when a lock is truncated mid-run (TOCTOU) so the refusal fires
        # from a later _authority_snapshot rather than the first read.
        if isinstance(e.code, int):
            return e.code
        print(str(e.code), file=sys.stderr)
        return 2


def _main_after_args(a) -> int:
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
        coverage = _baseline_coverage(root, kit)
        if coverage is None:
            print("upgrade: refusing — the selected kit cannot establish baseline coverage "
                  "from scripts/write_install_json.py. No render was attempted; restore a "
                  "complete kit and re-run.", file=sys.stderr)
            return 2
        drift = _drifted(root, baseline, kit, coverage)

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
        unsafe = _unsafe_owned_dests(root, baseline, coverage)
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
        # Capture the required_* lock values as the LAST read before the mutation (v3.8.14 / P1):
        # a concurrent RAISE landing between the check above and the render would be clobbered by
        # bootstrap+restore, so we reconcile raise-only after restore (never lower it). The
        # residual sub-ms window — a raw non-cooperating writer between this read and bootstrap's
        # first write — is documented, not silently claimed closed (a mandatory lock the substrate
        # cannot impose on arbitrary processes would be required to fully close it).
        _lock_names = ("required_profile", "required_remote_governance", "required_sandbox")
        _snap_pre = _authority_snapshot(root)
        _locks_pre = {_n: _lock_from_snapshot(_snap_pre, _n) for _n in _lock_names}
        # The renderer's process context is the target, not whichever checkout or
        # shell directory launched the engine. `--target` controls bootstrap's
        # intended destinations; cwd=root also contains any relative auxiliary
        # writes made by the selected renderer and matches the finalizer context.
        r = _run(cmd, cwd=root)
        if r.returncode != 0:
            _restore(root, backup, saved)
            print(f"upgrade: bootstrap --force FAILED; restored preserved files.\n{r.stderr[-1500:]}",
                  file=sys.stderr)
            return 2
        _restore(root, backup, saved)
        if a.profile:
            _apply_profile_ratchet(root, a.profile)
        # Floor the config's capability flags to the frozen locks (v3.8.22): the render already
        # honored required_remote_governance/required_sandbox, but the PRESERVED config line may
        # still say 0 — raise it so the end state is consistent (else check_substrate_config, and
        # the v3.8.22 postcondition config-validity gate, correctly reject it).
        _apply_capability_floor(root)
        # Raise-only lock reconciliation (v3.8.14 / P1): never leave a required_* lock LOWER than
        # the value observed just before the render — a concurrent raise that landed in the
        # check->render window must survive (bootstrap+restore would otherwise clobber it down).
        _reconciled = False
        for _n in _lock_names:
            _cur = _lock_from_snapshot(_authority_snapshot(root), _n)
            _want = _lock_ge(_cur or "", _locks_pre.get(_n) or "")
            if _want and _want != _cur:
                try:
                    _safe_atomic_write(root / ".substrate" / _n, _want + "\n", root=root)
                    print(f"upgrade: raise-only reconcile: {_n} {_cur or '(unset)'} -> {_want}",
                          file=sys.stderr)
                    _reconciled = True
                except Exception:
                    pass
        # A reconciliation means a concurrent RAISE landed after our render answers were fixed,
        # so the freshly rendered config/hooks are STALE relative to the now-higher lock (e.g.
        # required_profile=strict but SUBSTRATE_PROFILE="standard" and no strict hook). Do NOT
        # claim success with that internally-inconsistent state — fail so the operator re-runs,
        # which will render consistently against the raised lock (v3.8.15 / P1). The lock is
        # preserved raised (never lowered); only fresh provenance is skipped.
        if _reconciled:
            print("upgrade: a required_* lock was RAISED concurrently during the render — the "
                  "rendered config/hooks are stale relative to the new lock. The raise was "
                  "preserved; re-run `upgrade --write` to render consistently.", file=sys.stderr)
            return 2

        # POST-CONDITION authority check (v3.8.19 / P1, finding upgrade:593): the v3.8.15
        # `_reconciled` failure only fires when the reconcile loop itself had to WRITE a lock
        # back up — a raise landing after _restore but BEFORE the reconcile read leaves
        # _cur == the raised value, _reconciled stays False, and the upgrade claimed success
        # with config/hooks stale vs the lock. Success must be a property of the END STATE,
        # not of how we got there: re-derive the render answers from the CURRENT on-disk
        # authority (config + locks, floored exactly like the pre-render derivation) and
        # compare with the answers actually rendered. Any mismatch means the render is stale
        # relative to the authority as it exists NOW -> fail (rc 2) so a re-run renders
        # consistently. (Residual: a raise between THIS read and process exit remains, as
        # documented — no smaller window exists without OS-level locking.)
        # v3.8.20 (P1, finding upgrade:750): _answers_from_snapshot treats a MISSING config as
        # b"" -> {} -> all-DEFAULT answers, so when the rendered answers equal the defaults
        # (a plain standard install), an authority file DELETED after _restore compared EQUAL
        # ("default-equivalent absence") and the upgrade returned 0 with no config on disk.
        # Success must first require the CONCRETE end state: every authority file present as a
        # regular (non-symlink) file with readable snapshot bytes, config carrying an explicit
        # SUBSTRATE_PROFILE line, and each lock holding a value bootstrap could have written.
        # v3.8.21 (P1, finding upgrade:846): this ran only ONCE, BEFORE the finalizers — a lock
        # raise landing DURING update_manifest/write_install_json still claimed success. It is
        # now a reusable closure re-evaluated AFTER the finalizers too (the last read before exit,
        # shrinking the window to the documented irreducible residual).
        def _authority_postcondition():
            _an = _authority_snapshot(root)
            _bk = []
            for _n in ("config", "required_profile", "required_remote_governance", "required_sandbox"):
                _p = root / ".substrate" / _n
                if _an.get(_n) is None or not _p.is_file() or _p.is_symlink():
                    _bk.append(_n)
            if "SUBSTRATE_PROFILE" not in _parse_config_text(
                    (_an.get("config") or b"").decode("utf-8", "replace")):
                _bk.append("config:SUBSTRATE_PROFILE")
            if _lock_from_snapshot(_an, "required_profile") not in _PROF_RANK:
                _bk.append("required_profile:value")
            for _n in ("required_remote_governance", "required_sandbox"):
                if _lock_from_snapshot(_an, _n) not in ("0", "1"):
                    _bk.append(_n + ":value")
            if _bk:
                return ("upgrade: authority END STATE is invalid — missing/symlinked/unreadable/"
                        f"invalid-value: {', '.join(sorted(set(_bk)))}. Refusing to claim success "
                        "without a concrete on-disk authority; restore .substrate and re-run "
                        "`upgrade --write`.")
            _f = _answers_from_snapshot(_an)
            _flp = _lock_from_snapshot(_an, "required_profile")
            if _flp and _rk.get(_flp, -1) > _rk.get(_f.get("profile") or "standard", 1):
                _f["profile"] = _flp
            if _lock_from_snapshot(_an, "required_remote_governance") == "1":
                _f["remote_governance"] = "1"
            if _lock_from_snapshot(_an, "required_sandbox") == "1":
                _f["sandbox"] = "1"
            _st = [k for k in ("profile", "lang", "runner", "sandbox", "remote_governance")
                   if str(_f.get(k)) != str(answers.get(k))]
            if _st:
                return ("upgrade: the .substrate authority changed during the render "
                        f"(stale render keys: {', '.join(_st)}) — the rendered config/hooks do not "
                        "match the authority as it now stands. Locks were never lowered; re-run "
                        "`upgrade --write` to render consistently.")
            # Canonical config validity (v3.8.22 / upgrade:812): the answer/lock checks above do
            # not catch a config that `check_substrate_config.py` (what `manage.sh check` runs)
            # rejects — e.g. an unknown key or a dangerous command value preserved from the old
            # config. Run the canonical validator (root/scripts/ is the freshly force-rendered kit
            # copy in the upgrade path; ROOT=cwd, so it validates the target's config). Only block
            # on a real validation failure (rc 2), not an execution/env error (traceback), so a
            # missing venv can never false-fail a legitimate upgrade.
            # v3.8.23 (P1, upgrade:916): the v3.8.22 gate ran the TARGET's validator and failed
            # OPEN on a crash (`rc == 2 and "Traceback" not in out`), so a concurrent writer that
            # replaced `scripts/check_substrate_config.py` with a crashing file made the check
            # silently pass — and rc 1 (dangerous command values) was never covered at all. Now:
            # run the KIT's trusted copy (its `__file__`-relative siblings — harness_patterns.json,
            # sandbox_detect.py — resolve inside the kit, and cwd=root keeps the TARGET's config as
            # the subject), and treat ANY nonzero rc as a failure. Trusted stdlib-only code that
            # cannot run is itself a real problem, so there is no fail-open path left.
            _ckit = kit / "scripts" / "check_substrate_config.py"
            _cpath = _ckit if _ckit.is_file() else (root / "scripts" / "check_substrate_config.py")
            # Pin the validator's notion of the repo to THIS root (v3.8.23 auditor): the validator
            # resolves its root via _substrate_root, which honors SUBSTRATE_PROJECT_DIR /
            # CLAUDE_PROJECT_DIR BEFORE cwd — in an agent session whose env points at a different
            # tree, cwd=root alone would validate the WRONG repo's config.
            _cenv = dict(os.environ)
            _cenv["SUBSTRATE_PROJECT_DIR"] = str(root)
            _cenv.pop("CLAUDE_PROJECT_DIR", None)
            _cc = _run([sys.executable, "-I", str(_cpath)], cwd=root, env=_cenv)
            _ccout = ((_cc.stdout or "") + (_cc.stderr or "")).strip()
            if _cc.returncode != 0:
                return ("upgrade: the rendered .substrate/config fails canonical validation "
                        f"(check_substrate_config rc={_cc.returncode}: {_ccout[-300:]}) — the same "
                        "check `manage.sh check` enforces. Fix .substrate/config and re-run.")
            return None

        _pc = _authority_postcondition()
        if _pc:
            print(_pc, file=sys.stderr)
            return 2

        # consistency + fresh provenance — run the KIT's copies (v3.8.24 / upgrade:961): these ran
        # the TARGET's `root/scripts/*.py` AFTER the drift gate, so a concurrent replacement landing
        # in that window executed target code and still produced a "successful" upgrade. The kit is
        # verified/resolved by now, so its copies are the trusted ones; cwd=root (+ the pinned
        # SUBSTRATE_PROJECT_DIR below, and write_install_json's explicit --root) keeps the TARGET as
        # the subject. Falls back to root's copy only if the kit lacks the file.
        def _tool(name: str) -> str:
            kp = kit / "scripts" / name
            return str(kp if kp.is_file() else (root / "scripts" / name))
        _tenv = dict(os.environ)
        _tenv["SUBSTRATE_PROJECT_DIR"] = str(root)
        _tenv.pop("CLAUDE_PROJECT_DIR", None)
        mf = _run([sys.executable, "-I", _tool("update_manifest.py"), "--fix"], cwd=root, env=_tenv)
        # Prefer the commit parsed from the VERIFIED trusted comment (a .zip extract has no
        # .git, so git rev-parse would record 'none' — v3.7.16 P2b). Fall back to git for a
        # directory source that IS a checkout.
        commit = verified_commit or "none"
        if commit == "none":
            gc = _run(["git", "rev-parse", "--short", "HEAD"], cwd=kit)
            if gc.returncode == 0:
                commit = gc.stdout.strip()
        wj = _run([sys.executable, "-I", _tool("write_install_json.py"),
              "--root", str(root), "--version", new_ver, "--commit", commit,
              "--source", str(src), "--installed-at", datetime.now(timezone.utc).isoformat(),
              "--profile", answers.get("profile", "standard"), "--lang", answers.get("lang", "auto"),
              "--runner", answers.get("runner", "auto"), "--ui", answers.get("ui", "no"),
              "--workflow", answers.get("workflow", "superpowers"),
              "--sandbox", str(answers.get("sandbox", "0")),
              "--remote-governance", str(answers.get("remote_governance", "0"))], cwd=root, env=_tenv)
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
                _pj = json.loads(_safe_read_text(ij, root, max_bytes=8 << 20) or "null")
                prov_ok = isinstance(_pj, dict) and _pj.get("kit_version") == new_ver
        except Exception:
            prov_ok = False
        if mf.returncode != 0 or wj.returncode != 0 or not prov_ok:
            print(f"upgrade: kit files applied, but a FINALIZER FAILED (manifest rc={mf.returncode}, "
                  f"provenance rc={wj.returncode}, provenance_written={prov_ok}) — drift protection / "
                  f"fresh provenance may be incomplete. Review and re-run.\n"
                  f"{((wj.stderr or '') + (mf.stderr or ''))[-800:]}", file=sys.stderr)
            return 2
        # Re-check the authority AFTER the finalizers (v3.8.21 / upgrade:846): a lock raise landing
        # during update_manifest/write_install_json would otherwise slip past the pre-finalizer
        # check and claim success with a stale render. This is the last read before exit.
        _pc2 = _authority_postcondition()
        if _pc2:
            print(_pc2, file=sys.stderr)
            return 2
        print(f"substrate upgrade: applied {new_ver}. Review `git diff`, run `./manage.sh check`, then commit.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
