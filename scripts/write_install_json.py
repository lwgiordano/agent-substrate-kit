#!/usr/bin/env python3
"""Write .substrate/install.json — the provenance + drift baseline the upgrade engine
reads (v3.7.14, installer/upgrade Phase 1b).

Records: the kit version/commit/source this repo was installed or upgraded from, the FULL
bootstrap answer set (profile/lang/runner/ui/workflow/sandbox/remote — ui+workflow are NOT
in .substrate/config, so a faithful re-render on upgrade needs them here), a SHA-256 of every
substrate-owned file present (the drift baseline: an upgrade refuses to overwrite a machinery
file whose local hash no longer matches, unless --force), and a timestamp.

Called by bootstrap.sh at install and by substrate_upgrade.py after applying an upgrade.
Read-only w.r.t. everything except .substrate/install.json. Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import refuse_linked_leaf as _refuse_linked_leaf
    from _doc_common import safe_atomic_write as _safe_atomic_write
except Exception:  # pragma: no cover - stripped install
    def _refuse_linked_leaf(path):
        return "guard unavailable"

    def _safe_atomic_write(*a, **k):
        raise OSError("safe_atomic_write unavailable — refusing an unguarded write")
try:
    from _substrate_surfaces import (
        COVERAGE_SKIP_PARTS, OPTIONAL_DIRS, OPTIONAL_FILES, OWNED_DIRS, OWNED_FILES,
    )
except Exception:  # fail-soft: a baseline is a safety aid, not a gate
    # Keep this fallback in exact parity with the install-owned inventory in
    # _substrate_surfaces.py. It deliberately does NOT include governed
    # project-authored knowledge directories, which are CODEOWNER-reviewed
    # context but not substrate provenance/drift baseline.
    OWNED_DIRS = ["scripts", "tests", ".claude", ".codex", ".agents",
                  "docs/decisions", "docs/blind-spot-checklists", "docs/templates",
                  ".github/hooks", ".github/instructions", ".github/workflows"]
    OWNED_FILES = ["AGENTS.md", "CLAUDE.md", "DESIGN.md", "AGENT_BUS.md", "manage.sh",
                   "bootstrap.sh", "agentsync.sh", "package_release.sh", "pytest.ini",
                   ".pre-commit-config.yaml", ".gitattributes", ".gitignore",
                   ".github/copilot-instructions.md", ".github/dependabot.yml",
                   ".substrate/config", ".substrate/required_profile",
                   "docs/HISTORY.md", "docs/REJECTED.md", "docs/README.md",
                   "docs/ARCHITECTURE.md", "docs/INTENT.md",
                   "docs/knowledge/00_substrate.md", "docs/knowledge/_template.md"]
    OPTIONAL_FILES = [".mcp.json", ".substrate/trust/minisign.pub",
                      ".substrate/trust/sigstore_identity.json", ".substrate/install.json"]
    OPTIONAL_DIRS = [".github/skills", "docs/postmortems", "design-system", "templates"]
    COVERAGE_SKIP_PARTS = {"__pycache__", "venv", "node_modules", ".pytest_cache",
                           ".ruff_cache", ".mypy_cache"}


def owned_files(root: Path) -> list[str]:
    """Every substrate-owned file present under root (repo-relative, sorted)."""
    out: set[str] = set()
    for f in OWNED_FILES + OPTIONAL_FILES:
        if (root / f).is_file():
            out.add(f)
    for d in OWNED_DIRS + OPTIONAL_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.is_file() and not any(part in COVERAGE_SKIP_PARTS for part in p.parts):
                out.add(str(p.relative_to(root)).replace("\\", "/"))
    return sorted(out)


# install.json must NOT be part of its own baseline: it records the hash map, so hashing
# it would embed a hash-of-itself that can never match after the file is rewritten — every
# subsequent upgrade would then false-report .substrate/install.json as "locally modified"
# (v3.7.16 P1). It stays a governed/owned surface; it is just excluded from the DRIFT baseline.
_BASELINE_EXCLUDE = {".substrate/install.json"}


def hash_owned(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for rel in owned_files(root):
        if rel in _BASELINE_EXCLUDE:
            continue
        # v3.8.43 (round-26): hashing THROUGH a link records the wrong bytes as
        # this repo's provenance — an outside file's hash stored as if it were
        # ours. An owned surface is never legitimately a link, so skip it here
        # (the harness BLOCKs it separately) rather than attest a false hash.
        if _refuse_linked_leaf(root / rel) is not None:
            continue
        try:
            result[rel] = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        except OSError:
            pass
    return result


def build(root: Path, version: str, commit: str, source: str, answers: dict,
          installed_at: str) -> dict:
    return {
        "schema": 1,
        "kit_version": version,
        "kit_commit": commit,
        "source": source,
        "answers": answers,
        "owned_file_sha256": hash_owned(root),
        "installed_at": installed_at,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Write .substrate/install.json provenance.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", default="none")
    ap.add_argument("--source", default="")
    ap.add_argument("--installed-at", required=True, help="ISO-8601 UTC timestamp (caller-supplied)")
    for k in ("profile", "lang", "runner", "ui", "workflow", "sandbox", "remote-governance"):
        ap.add_argument(f"--{k}", default="")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    answers = {
        "profile": a.profile, "lang": a.lang, "runner": a.runner, "ui": a.ui,
        "workflow": a.workflow, "sandbox": a.sandbox,
        "remote_governance": getattr(a, "remote_governance"),
    }
    data = build(root, a.version, a.commit, a.source, answers, a.installed_at)
    dest = root / ".substrate" / "install.json"
    # v3.8.25 fixed the original instance of this class HERE, with a hand-rolled
    # same-dir temp + os.replace: a plain write_text() writes THROUGH the existing
    # inode, so a HARD-LINKED install.json had its outside twin overwritten with
    # provenance while the install reported success. That reasoning was right and
    # is now the shared helper's — but this site kept its own copy for eighteen
    # versions, still resolving dest.parent as a path and chmod'ing by name.
    # v3.8.44 routes the first instance of the class through the centralized
    # primitive: component-walk descent, mode set on the temp fd, atomic replace.
    _safe_atomic_write(dest, json.dumps(data, indent=2, sort_keys=True) + "\n",
                       root=root, tmp_prefix=".install.", make_parents=True, mode=0o644)
    print(f"write_install_json: wrote {dest.relative_to(root)} "
          f"({len(data['owned_file_sha256'])} owned files, kit {a.version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
