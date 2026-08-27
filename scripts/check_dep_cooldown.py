#!/usr/bin/env python3
"""Dependency-cooldown gate — a FRESH-VERSION RISK SIGNAL, not a malware detector. (v3.7.2)

Opt-in (`SUBSTRATE_DEP_COOLDOWN=N` days, 0=off). Flags DIRECT dependencies whose resolved
version published < N days ago — the timing window a malicious new fork/typosquat exploits
(the satire's foxhole-lz4 was hours old). It does NOT detect malware, maintainer takeover,
or anything shipped after the cooldown elapses; it only buys time before a brand-new
version is trusted.

Determinism + honesty:
- The RULE is a deterministic date comparison. The DATA (publish dates) is registry
  metadata = NETWORK, so this is an opt-in DEEP-tier gate, never part of the offline base.
- SKIP-HONEST: a dep whose publish time can't be determined (offline, uncached, registry
  ambiguous) is SKIPPED with a reason — never silently passed, never assumed young.
- Conservative: if a publish time is unavailable or ambiguous, SKIP — do not infer.

Sources: npm `registry.npmjs.org/<pkg>` (.time[ver]); PyPI `pypi.org/pypi/<pkg>/<ver>/json`
(.urls[].upload_time_iso_8601); Go `proxy.golang.org/<mod>/@v/<ver>.info` (.Time).
Cache: .substrate/dep_cooldown_cache.json (gitignored; publish dates are immutable).

CLI: check_dep_cooldown.py [--root DIR] [--days N] [--offline] [--require] [--json]
Exit: 0 no young deps (or only skips, non-required) | 1 young dep found (or skips while
required) | 2 invalid config / malformed lockfile / internal error.
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

def _repo_root():
    """Repo root for containment checks in functions that take no root param."""
    try:
        from _substrate_root import substrate_root as _sr2
        return _sr2()
    except Exception:
        return Path.cwd()


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
from _doc_common import read_lock as _dc_read_lock  # noqa: E402
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()

_TIMEOUT = 8


def _cfg_int(root: Path, key: str) -> int:
    cfg = root / ".substrate" / "config"
    if cfg.is_file():
        for ln in (_safe_read_text(cfg, root, max_bytes=1 << 20) or "").splitlines():
            ln = ln.split("#", 1)[0].strip()
            if ln.startswith(key + "="):
                v = ln.split("=", 1)[1].strip().strip("\"'")
                return int(v) if v.isdigit() else 0
    return 0


def _required(root: Path, argv) -> bool:
    if "--require" in argv:
        return True
    # v3.8.36: canonical fail-closed lock read (Codex round-19) — a present
    # lock that is malformed (symlink/dir/unreadable/undecodable/garbage)
    # means the tier IS required; only a genuinely absent lock or a valid
    # '0' leaves it optional.
    state, val, _reason = _dc_read_lock(root / ".substrate" / "required_dep_cooldown", {"0", "1"}, root=root)
    if state == "bad":
        return True
    return state == "ok" and val == "1"


# ---- direct-dependency discovery (DIRECT only for v1; transitive is a later mode) ----

def _npm_direct(root: Path):
    """(name, version) for direct npm deps: names from package.json, resolved versions
    from package-lock.json (v2/v3 `packages` map). No lockfile → cannot resolve → []."""
    pj, pl = root / "package.json", root / "package-lock.json"
    if not pj.is_file() or not pl.is_file():
        return []
    try:
        names = set()
        d = json.loads(_safe_read_text(pj, root, max_bytes=64 << 20) or "{}")
        for grp in ("dependencies", "devDependencies"):
            names.update((d.get(grp) or {}).keys())
        lock = json.loads(_safe_read_text(pl, root, max_bytes=256 << 20) or "{}")
        pkgs = lock.get("packages", {})
        out = []
        for n in sorted(names):
            ent = pkgs.get(f"node_modules/{n}")
            if ent and isinstance(ent.get("version"), str):
                out.append((n, ent["version"]))
        return out
    except Exception as e:
        raise ValueError(f"malformed npm lockfile/manifest: {e}") from e


def _py_direct(root: Path):
    """Direct python deps: names from pyproject.toml (PEP 621 project.dependencies +
    poetry), resolved versions from uv.lock. Needs tomllib (3.11+) + uv.lock."""
    pp, ul = root / "pyproject.toml", root / "uv.lock"
    if not pp.is_file() or not ul.is_file():
        return []
    try:
        import tomllib
    except Exception:
        return []  # no TOML parser → skip ecosystem (handled as "no deps found")
    try:
        proj = tomllib.loads(_safe_read_text(pp, root, max_bytes=64 << 20) or "")
        names = set()
        for dep in (proj.get("project", {}).get("dependencies") or []):
            m = re.match(r"^([A-Za-z0-9._-]+)", dep)
            if m:
                names.add(m.group(1).lower().replace("_", "-"))
        poetry = proj.get("tool", {}).get("poetry", {}).get("dependencies", {})
        names.update(k.lower().replace("_", "-") for k in poetry if k.lower() != "python")
        lock = tomllib.loads(_safe_read_text(ul, root, max_bytes=256 << 20) or "")
        out = []
        for pkg in lock.get("package", []):
            nm = str(pkg.get("name", "")).lower().replace("_", "-")
            ver = pkg.get("version")
            if nm in names and isinstance(ver, str):
                out.append((nm, ver))
        return sorted(set(out))
    except Exception as e:
        raise ValueError(f"malformed python lockfile/manifest: {e}") from e


def _go_direct(root: Path):
    """Direct Go deps: go.mod `require` lines NOT marked `// indirect`. go.mod carries
    the resolved version inline."""
    gm = root / "go.mod"
    if not gm.is_file():
        return []
    try:
        out, in_block = [], False
        for ln in (_safe_read_text(gm, root, max_bytes=8 << 20) or "").splitlines():
            s = ln.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block and s == ")":
                in_block = False
                continue
            if "// indirect" in s:
                continue
            m = re.match(r"^(?:require\s+)?([^\s]+)\s+(v[^\s]+)", s) if (in_block or s.startswith("require ")) else None
            if m:
                out.append((m.group(1), m.group(2)))
        return out
    except Exception as e:
        raise ValueError(f"malformed go.mod: {e}") from e


def _discover(root: Path):
    """[(eco, name, version)] across the ecosystems present. DIRECT deps only."""
    deps = []
    for n, v in _npm_direct(root):
        deps.append(("npm", n, v))
    for n, v in _py_direct(root):
        deps.append(("pypi", n, v))
    for n, v in _go_direct(root):
        deps.append(("go", n, v))
    return deps


# ---- publish-date lookup (network, best-effort, conservative) ----

def _http_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "substrate-dep-cooldown"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # noqa: S310 (https registry URLs only)
        return json.loads(r.read().decode("utf-8", "replace"))


def _published(eco: str, name: str, version: str):
    """ISO publish time for a version, or None (conservative — caller SKIPS on None)."""
    try:
        if eco == "npm":
            d = _http_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
            t = (d.get("time") or {}).get(version)
            return t if isinstance(t, str) else None
        if eco == "pypi":
            d = _http_json(f"https://pypi.org/pypi/{name}/{version}/json")
            urls = d.get("urls") or []
            for u in urls:
                t = u.get("upload_time_iso_8601") or u.get("upload_time")
                if isinstance(t, str):
                    return t
            return None
        if eco == "go":
            d = _http_json(f"https://proxy.golang.org/{name.lower()}/@v/{version}.info")
            t = d.get("Time")
            return t if isinstance(t, str) else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return None
    return None


def _parse_iso(s: str):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--require", action="store_true")
    ap.add_argument("--json", action="store_true")
    a, _unknown = ap.parse_known_args(argv)
    root = Path(a.root)
    days = a.days if a.days is not None else _cfg_int(root, "SUBSTRATE_DEP_COOLDOWN")
    required = _required(root, argv)
    if days <= 0:
        if a.json:
            print(json.dumps({"cooldown_days": days, "enabled": False}))
        else:
            print("dep-cooldown: disabled (SUBSTRATE_DEP_COOLDOWN=0)")
        return 0

    try:
        deps = _discover(root)
    except ValueError as e:
        print(f"dep-cooldown: BLOCK — {e}", file=sys.stderr)
        return 2

    cache_path = root / ".substrate" / "dep_cooldown_cache.json"
    cache = {}
    if cache_path.is_file():
        try:
            cache = json.loads(_safe_read_text(cache_path, root, max_bytes=8 << 20) or "{}")
        except Exception:
            cache = {}
    now = datetime.now(timezone.utc)
    young, skipped = [], []
    checked = cache_hits = fetches = 0
    cache_dirty = False
    for eco, name, ver in deps:
        key = f"{eco}:{name}@{ver}"
        published = (cache.get(key) or {}).get("published_at")
        if published:
            cache_hits += 1
        elif a.offline:
            skipped.append({"id": key, "reason": "offline; not cached"})
            continue
        else:
            published = _published(eco, name, ver)
            fetches += 1
            if published:
                cache[key] = {"published_at": published, "fetched_at": now.isoformat(), "source": eco}
                cache_dirty = True
        if not published:
            skipped.append({"id": key, "reason": "publish time unavailable"})
            continue
        dt = _parse_iso(published)
        if dt is None:
            skipped.append({"id": key, "reason": f"unparseable publish time {published!r}"})
            continue
        checked += 1
        age_days = (now - dt).total_seconds() / 86400.0
        if age_days < days:
            young.append({"id": key, "published_at": published, "age_days": round(age_days, 2)})

    if cache_dirty:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            _safe_atomic_write(cache_path,
                               json.dumps(cache, indent=2, sort_keys=True), root=root)
        except Exception:
            pass

    result = {"cooldown_days": days, "enabled": True, "checked": checked,
              "young": young, "skipped": skipped, "cache_hits": cache_hits,
              "network_fetches": fetches, "required": required}
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        for y in young:
            print(f"dep-cooldown: YOUNG {y['id']} published {y['age_days']}d ago (< {days}d)")
        for s in skipped:
            print(f"dep-cooldown: SKIP {s['id']} ({s['reason']})")
        verdict = ("BLOCK" if young else
                   "BLOCK (required + unverifiable)" if (skipped and required) else "ok")
        print(f"dep-cooldown: {verdict} — checked {checked}, young {len(young)}, "
              f"skipped {len(skipped)} (cache {cache_hits}, net {fetches})")
    if young:
        return 1
    # required + ANY unverifiable dep → BLOCK (v3.7.4 audit P1: one verified dep must NOT
    # mask another unverifiable one — you required cooldown but can't prove it for all).
    if skipped and required:
        print(f"dep-cooldown: BLOCK — cooldown REQUIRED but {len(skipped)} dependency "
              "publish time(s) could not be verified (offline/uncached/ambiguous)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
