#!/usr/bin/env python3
"""Phrase-level supersession check (postmortem 2026-04-29-codex-second-pass).

`check_stale_terminology.py` already catches WORD-level supersession
(`_quarantine` → `_data_quality_issues`, etc.). This script is its
phrase-level companion: scans active code/docs for known-stale
multi-word phrases or descriptive claims that are no longer true.

Why two scripts: the terminology lint targets short tokens in mixed
contexts (SQL, Python, comments) and is heavy on case-insensitive
matching + alias detection. Phrase-level claims are longer, more
context-dependent, and benefit from regex matching with smaller
allowlists. Keeping them split lets each have a clear contract
without one scope accumulating creep.

The list of stale phrases is hand-curated. When the audit tool (or anyone)
catches a stale-claim issue, the OPERATOR adds an entry here as
PART OF THE FIX — converting the one-off catch into a permanent
gate. See `docs/postmortems/2026-04-29-codex-second-pass-meta-failure.md`
for the meta-pattern.

Each entry has:
  - phrase: regex-quoted string OR a regex if `regex: true`. Matched
    case-insensitively unless `case_sensitive: true`.
  - replacement_hint: human-readable note shown on hit ("Update body
    to describe current state").
  - allowlist: list of paths/globs where the phrase is allowed (e.g.
    HISTORY, postmortems, ADRs that legitimately quote the old
    phrase as part of the supersession record).
  - regex: optional bool, default False. When True, `phrase` is
    treated as a Python regex.

Exit codes: 0 ok | 1 stale-phrase hit | 2 env error.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StalePhrase:
    phrase: str
    replacement_hint: str
    allowlist: tuple[str, ...] = field(default_factory=tuple)
    regex: bool = False
    case_sensitive: bool = False


# Initial entries are the descriptive claims the audit tool caught in the
# 2026-04-29 audit passes (1 + 2). Each lived in active docs/code
# WHILE the underlying state had moved on. Adding the phrase here
# blocks future re-introduction.
STALE_PHRASES: tuple[StalePhrase, ...] = (
    # Add entries here when you find descriptive claims in docs that
    # drift from code. Pattern (uncomment + adapt):
    #
    # StalePhrase(
    #     phrase=r"<regex pattern that matches the stale claim>",
    #     regex=True,
    #     replacement_hint=(
    #         "<what the doc should say instead — explain the current state>"
    #     ),
    #     allowlist=(
    #         "docs/HISTORY.md",            # entries legitimately quote old phrasing
    #         "docs/postmortems/",          # postmortems document the drift
    #     ),
    # ),
    #
    # The regex fires whenever the phrase appears OUTSIDE the
    # allowlist. The hint is shown to the operator. Don't add
    # entries pre-emptively — add them after you find real drift.
)


# Globally allowlisted paths: no stale-phrase scanning. Postmortems
# and HISTORY legitimately quote outdated states as part of the
# historical record.
#
# 2026-04-29 pass-6 P3 (lesson 11): `docs/decisions/` was
# REMOVED from this list. The original justification — "ADRs may
# quote old phrasing in Alternatives Considered" — was true but
# over-broad: the same blanket allowlist also suppressed stale
# claims in active Context/Decision sections (pass-5 caught one in
# ADR-0002, pass-6 caught one in ADR-0037 still hidden by this
# prefix even after the r5 fix). ADR sections that legitimately
# quote rejected phrasing now use per-entry allowlists naming the
# specific ADR path; new ADRs that need the same exception add
# themselves explicitly.
_ALLOWLIST_GLOBAL_PREFIXES: tuple[str, ...] = (
    "docs/HISTORY.md",
    "docs/postmortems/",
    "docs/SELF_AUDIT_LOG.md",
    # Audit registry quotes old phrasings in supersession-record
    # entries — closing one finding via doc rewrite means the OLD
    # phrasing legitimately appears in the registry's `summary` field.
    "docs/AUDIT_REGRESSIONS.yaml",
    "data/",             # canonical run artifacts
    "node_modules/",
    ".venv/",
    ".git/",
    # mutmut working directory — copies source + test files (including
    # tests/test_validator_stale_phrases.py with its planted fixtures)
    # into mutants/. Without this skip, every planted phrase fires once
    # per mutant copy. Mutants are gitignored anyway; this is belt-and-
    # suspenders for the scanner.
    "mutants/",
    "scripts/check_stale_phrases.py",  # this file (the regex source)
    # Volatile-doc generators carry self-referential quotes:
    "scripts/regen_volatile_docs.py",
    # Test fixtures may carry phrase strings for negative tests:
    "tests/test_validator_stale_phrases.py",
)


# Active-text file extensions: only scan files that actually carry
# operator-facing claims. Skip parquets, images, lockfiles, etc.
_SCAN_EXTENSIONS: tuple[str, ...] = (
    ".md", ".py", ".ts", ".tsx", ".js", ".jsx",
    ".sql", ".yaml", ".yml", ".toml", ".sh",
)

# 2026-04-29 pass-3 P3 — coverage gap. The original validator
# filtered solely by file suffix, which silently skipped extensionless
# active text files like `Makefile`, `Dockerfile`, `LICENSE`. The
# Makefile header carried a stale "P0b ships ingest hello-world only"
# claim that the validator THEN PASSED OVER, generating false
# confidence — the worst kind of validator gap.
#
# Fix: scan a file if either its suffix is in _SCAN_EXTENSIONS OR its
# basename is in this explicit filename list. New extensionless text
# files added to the repo get one-line additions here.
_SCAN_EXPLICIT_FILENAMES: frozenset[str] = frozenset({
    "Makefile",
    "Dockerfile",
    "Procfile",
    ".gitignore",
    ".gitattributes",
    ".dockerignore",
    ".env.example",
    ".pre-commit-config.yaml",  # already matches via .yaml; keep
                                # explicit so a future rename to
                                # `.pre-commit-config` (no suffix)
                                # still scans.
    "BUILD_INSTRUCTIONS",  # if ever extensionless
    "RUNBOOK",             # same
})


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_allowlisted(rel: str, entry: StalePhrase) -> bool:
    if any(rel.startswith(p) for p in _ALLOWLIST_GLOBAL_PREFIXES):
        return True
    return any(rel.startswith(p) or rel == p for p in entry.allowlist)


def _compile(entry: StalePhrase) -> re.Pattern[str]:
    flags = 0 if entry.case_sensitive else re.IGNORECASE
    pattern = entry.phrase if entry.regex else re.escape(entry.phrase)
    return re.compile(pattern, flags)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--list-scanned-files",
        action="store_true",
        help=(
            "Print every file the validator considered (post-allowlist) "
            "and exit. audit pass-3 audit follow-up: ops can audit the "
            "validator's reach without trusting that suffix/filename "
            "filters cover everything they should."
        ),
    )
    args = parser.parse_args(argv)

    repo = _repo_root()
    findings: list[str] = []
    n_files_scanned = 0
    scanned_paths: list[str] = []

    compiled = [(e, _compile(e)) for e in STALE_PHRASES]

    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        # audit pass-3: scan by suffix OR explicit filename. Without
        # the explicit-name branch, `Makefile`, `Dockerfile`, etc.
        # were silently skipped.
        if (
            path.suffix not in _SCAN_EXTENSIONS
            and path.name not in _SCAN_EXPLICIT_FILENAMES
        ):
            continue
        try:
            rel = path.relative_to(repo).as_posix()
        except ValueError:
            continue
        # Cheap globl skips before reading the file:
        if any(rel.startswith(p) for p in _ALLOWLIST_GLOBAL_PREFIXES):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        n_files_scanned += 1
        if args.list_scanned_files:
            scanned_paths.append(rel)
            continue

        for entry, regex in compiled:
            if _is_allowlisted(rel, entry):
                continue
            for m in regex.finditer(text):
                # Snippet for context: 30 chars on each side.
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                snippet = text[start:end].replace("\n", "\\n")
                # Line number for the operator.
                line_no = text.count("\n", 0, m.start()) + 1
                findings.append(
                    f"{rel}:{line_no}: stale-phrase hit "
                    f"(matched: {m.group(0)!r})\n"
                    f"    context: …{snippet}…\n"
                    f"    hint   : {entry.replacement_hint}"
                )

    if args.list_scanned_files:
        for p in scanned_paths:
            print(p)
        print(
            f"\n--- {len(scanned_paths)} files scanned ---",
            file=sys.stderr,
        )
        return 0

    if findings:
        print("check-stale-phrases: STALE PHRASES FOUND", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        for f in findings:
            print(f, file=sys.stderr)
        print(
            f"\n{len(findings)} stale-phrase hit(s) across "
            f"{n_files_scanned} files.",
            file=sys.stderr,
        )
        print(
            "\nFix by updating the file to describe the CURRENT state, OR "
            "if the phrase is a legitimate historical reference (HISTORY, "
            "postmortem, ADR), move it under one of the allowlisted "
            "directories or add the path to the entry's `allowlist` in "
            "STALE_PHRASES.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-stale-phrases: ok ({n_files_scanned} files scanned, "
        f"{len(STALE_PHRASES)} stale-phrase entries)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
