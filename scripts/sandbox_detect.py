#!/usr/bin/env python3
"""Resolve the sandbox BACKEND for egress/filesystem containment.

The substrate composes OS sandbox primitives — it does NOT hand-roll isolation.
This resolver reads `.substrate/sandbox.json` (DATA, validated fail-closed),
detects which backends are actually available on this host, and picks one:

  backend = auto | anthropic-srt | bubblewrap | seatbelt | none

  auto → prefer anthropic-srt (whole-process, fs-scope + egress allowlist) if the
         `srt` CLI is on PATH; else the OS-native primitive (Linux bubblewrap /
         macOS seatbelt, NETWORK containment only); else none.

Backends are NOT equal — capabilities are reported honestly so `go-live` never
overclaims:
  anthropic-srt : network deny+allowlist, filesystem write-scope, read-deny   (needs Node/npm)
  bubblewrap    : network containment only (private netns)                     (Linux)
  seatbelt      : network containment only (deny network*)                     (macOS)
  none          : NO containment

Optional dependency, never mandatory: a Python/Go/none repo is never forced to
install Node just to use the substrate — `srt` is used only if already present.

CLI:
  sandbox_detect.py --json [--root DIR]      machine-readable resolution (for doctor/go-live)
  sandbox_detect.py --backend [--root DIR]   print the resolved backend id only
  sandbox_detect.py --emit-srt-settings PATH [--root DIR]
                                             translate sandbox.json → an srt-settings.json
Exit: 0 ok | 2 invalid sandbox.json (fail-closed) | 3 requested backend unavailable. Stdlib only.
"""
from __future__ import annotations

import json
import platform
import shutil
import sys
from pathlib import Path

_BACKENDS = {"auto", "anthropic-srt", "bubblewrap", "seatbelt", "none"}
_NETWORK = {"deny", "allowlist"}
_WRITE_SCOPE = {"repo", "cwd", "none"}

# Honest capability map per concrete (resolved) backend.
_CAPS = {
    "anthropic-srt": {"network": True, "egress_allowlist": True, "fs_write_scope": True, "read_deny": True},
    "bubblewrap":    {"network": True, "egress_allowlist": False, "fs_write_scope": False, "read_deny": False},
    "seatbelt":      {"network": True, "egress_allowlist": False, "fs_write_scope": False, "read_deny": False},
    "none":          {"network": False, "egress_allowlist": False, "fs_write_scope": False, "read_deny": False},
}

_DEFAULTS = {
    "backend": "auto",
    "network": "deny",
    "allowed_domains": [],
    "write_scope": "repo",
    "deny_read": ["~/.ssh", "~/.aws", "~/.config/gh", ".env"],
}


def _root(argv: list[str]) -> Path:
    if "--root" in argv:
        return Path(argv[argv.index("--root") + 1]).resolve()
    return Path.cwd()


def _load_config(root: Path) -> dict:
    """Load + VALIDATE .substrate/sandbox.json. Fail-closed (raise) on anything
    that isn't a known key / valid enum — a malformed sandbox policy must not
    silently degrade to 'no containment'."""
    cfg = dict(_DEFAULTS)
    path = root / ".substrate" / "sandbox.json"
    if not path.exists():
        return cfg
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"sandbox.json is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("sandbox.json must be a JSON object")
    for k, v in data.items():
        if k not in _DEFAULTS:
            raise ValueError(f"sandbox.json: unknown key {k!r}")
        cfg[k] = v
    if cfg["backend"] not in _BACKENDS:
        raise ValueError(f"sandbox.json: invalid backend {cfg['backend']!r} (allowed: {sorted(_BACKENDS)})")
    if cfg["network"] not in _NETWORK:
        raise ValueError(f"sandbox.json: invalid network {cfg['network']!r} (allowed: {sorted(_NETWORK)})")
    if cfg["write_scope"] not in _WRITE_SCOPE:
        raise ValueError(f"sandbox.json: invalid write_scope {cfg['write_scope']!r}")
    for key in ("allowed_domains", "deny_read"):
        if not isinstance(cfg[key], list) or not all(isinstance(x, str) for x in cfg[key]):
            raise ValueError(f"sandbox.json: {key} must be a list of strings")
    return cfg


def _available() -> dict:
    sysname = platform.system()
    return {
        "anthropic-srt": shutil.which("srt") is not None,
        "bubblewrap": sysname == "Linux" and shutil.which("bwrap") is not None,
        "seatbelt": sysname == "Darwin" and shutil.which("sandbox-exec") is not None,
        "none": True,
    }


def _resolve(cfg: dict, avail: dict) -> tuple[str, list[str]]:
    """Return (chosen_backend, warnings). Honors an explicit backend (fail-closed
    if unavailable); 'auto' prefers srt → OS-native → none."""
    warns: list[str] = []
    want = cfg["backend"]
    if want == "auto":
        for cand in ("anthropic-srt", "bubblewrap", "seatbelt"):
            if avail.get(cand):
                chosen = cand
                break
        else:
            chosen = "none"
            warns.append("no OS sandbox backend available (install @anthropic-ai/sandbox-runtime, or bubblewrap on Linux / sandbox-exec on macOS)")
    else:
        chosen = want
        if not avail.get(chosen):
            warns.append(f"requested backend {chosen!r} is not available on this host")
    # capability honesty: allowlist egress + fs write-scope only on srt
    if chosen in _CAPS and not _CAPS[chosen]["egress_allowlist"] and cfg["network"] == "allowlist":
        warns.append(f"network=allowlist requested but backend {chosen!r} can only deny-all egress (no per-domain allowlist) — use anthropic-srt for allowlisting")
    if chosen in _CAPS and not _CAPS[chosen]["fs_write_scope"] and cfg["write_scope"] != "none":
        warns.append(f"write_scope={cfg['write_scope']!r} requested but backend {chosen!r} cannot scope filesystem writes (network containment only)")
    return chosen, warns


def _resolution(root: Path) -> dict:
    cfg = _load_config(root)  # raises on invalid → caller turns into exit 2
    avail = _available()
    chosen, warns = _resolve(cfg, avail)
    return {
        "requested": cfg["backend"],
        "backend": chosen,
        "available": bool(avail.get(chosen)) and chosen != "none",
        "capabilities": _CAPS.get(chosen, _CAPS["none"]),
        "config": cfg,
        "availability": avail,
        "warnings": warns,
    }


def _emit_srt_settings(root: Path, out: Path) -> None:
    """Translate .substrate/sandbox.json → an srt-settings.json the `srt` CLI reads.
    srt: network deny-by-default + allowedDomains; filesystem write deny-by-default
    + allowWrite, read allow-by-default + denyRead."""
    cfg = _load_config(root)
    allow_write = [str(root)] if cfg["write_scope"] == "repo" else (["."] if cfg["write_scope"] == "cwd" else [])
    settings = {
        "network": {
            "allowedDomains": cfg["allowed_domains"] if cfg["network"] == "allowlist" else [],
            "deniedDomains": [],
        },
        "filesystem": {
            "allowWrite": allow_write,
            "denyWrite": [".env"],
            "denyRead": cfg["deny_read"],
        },
    }
    out.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def main(argv: list[str]) -> int:
    root = _root(argv)
    try:
        if "--emit-srt-settings" in argv:
            out = Path(argv[argv.index("--emit-srt-settings") + 1])
            _emit_srt_settings(root, out)
            return 0
        res = _resolution(root)
    except ValueError as e:
        print(f"sandbox-detect: BLOCK — {e}", file=sys.stderr)
        return 2
    if "--backend" in argv:
        print(res["backend"])
        return 0 if res["available"] else 3
    if "--json" in argv:
        print(json.dumps(res, indent=2))
        return 0 if res["available"] else 3
    # default: human summary
    cap = res["capabilities"]
    print(f"sandbox-detect: backend={res['backend']} available={res['available']} "
          f"(network={cap['network']} allowlist={cap['egress_allowlist']} fs_write_scope={cap['fs_write_scope']})")
    for w in res["warnings"]:
        print(f"  - warn: {w}")
    return 0 if res["available"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
