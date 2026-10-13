#!/usr/bin/env python3
"""Commit-msg forcing function for the "respond to an audit finding"
meta-pattern.

The recurring shape this hook defends against: a fix scopes to the
symptom the audit flagged, not to the CLASS of bugs the symptom is
part of. The structural fix is layered — checklists, postmortem
discipline, and this hook as the at-commit-time forcing function.
At commit time the message must contain four fields that force
class-of-bug thinking BEFORE the commit lands.

Detection (subject-line heuristics — see _BUG_FIX_SUBJECT_PATTERNS):

  - Conventional-commit `fix:`/`bug:`/`bugfix:` prefixes
  - Phase-fix subjects matching `^[A-Z]\\d+...-fix` (e.g. P3c2-fix:)
  - Loose: `fix`/`bug` token followed by colon within 60 chars
  - (Optional) audit-pass subjects — extend the tuple if your team
    uses a fixed agent-name prefix (e.g., `^audit YYYY-MM-DD`).

When detected, the message body must contain ALL four required
fields (or the opt-out tag for genuinely class-less fixes):

  Bug class:           <one-line summary>
  Cluster searched:    <grep command + result count>
  Lock-down:           <mechanism + path>
  Verbatim-shape verified: <yes/no with evidence>

Field-content contract is three-step:
  1. Presence: a same-line value with at least one non-whitespace
     char after the colon.
  2. Non-placeholder: the value must not look like an unfilled
     template — `_looks_like_placeholder` rejects whole-value bracket
     wrappers, bare TODO/FIXME/XXX/TBD markers, and template-prompt
     phrases.
  3. Domain-checklist coverage: the `Cluster searched:` field must
     reference the relevant `docs/blind-spot-checklists/<domain>.md`
     for every domain the STAGED DIFF touches (regex / yaml-parsing /
     commit-msg-hooks / ast-parsing). Per-domain opt-out:
     `(checklist <domain> not applicable: <reason>)` with
     non-placeholder reason.

Failures produce a clear per-field error: `missing or empty` /
`unfilled placeholder` / `diff touches <domain> but field doesn't
reference checklist`.

Opt-out: `[meta-fix-not-applicable: <reason>]` — for docs-only
follow-up commits, typo renames, or genuinely class-less fixes.
Reason gets the same two-step contract (presence + non-placeholder).
The opt-out tag is line-anchored so an inline mention in
commit-body documentation doesn't fire as an actual opt-out — the
tag only counts when it's the whole content of its line.

The hook complements `check_postmortem_for_bug_fix.py` — they
detect the same commit shapes but enforce different requirements.
postmortem-for-bug-fix demands a postmortem reference; this hook
demands the four class-of-bug fields. Both are required for
non-trivial bug-fix commits.

Exit codes: 0 ok | 1 missing required fields | 2 env error.

See:
  - docs/templates/finding_response.md (copy-paste template)
  - AGENTS.md "Responding to an audit finding" section
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

# Bug-fix commit subject heuristics. Mirror check_postmortem_for_bug_fix.py
# so both hooks fire on the same set of commits.
#
# Extension point: if your team uses a fixed agent-name prefix for
# external audit-pass commits (e.g., "Codex 2026-04-30 pass-1",
# "Audit 2026-04-30 pass-2"), prepend a pattern like:
#     re.compile(r"^Codex \d{4}-\d{2}-\d{2}\b", re.IGNORECASE),
# The hook is conservative by default — only the universal shapes
# (conventional commits, phase-fix, loose fix-token) fire.
_BUG_FIX_SUBJECT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Conventional-commit fix:/bug:/bugfix: prefix
    re.compile(r"^(fix|bug|bugfix)(\([^)]+\))?:\s+", re.IGNORECASE),
    # Phase-fix subject (e.g. P3c2-fix:, P3c2-fix-r2:, P3-fix:)
    re.compile(r"^[A-Z]\d+(c\d+)?(-fix(-r\d+)?)\b", re.IGNORECASE),
    # Loose: `fix` or `bug` as a token followed by colon within first 60 chars
    re.compile(r"^.{0,60}\b(fix|bug)(es|ed|ing|fix|fixes)?\b.{0,30}:", re.IGNORECASE),
    # v3.8.38: version-prefixed audit-remediation release (lock-step with
    # check_postmortem_for_bug_fix). Scoped to remediation/finding language so
    # feature releases do not trip.
    re.compile(r"^v?\d+\.\d+\.\d+:.*(\bremediat\w*|\d+\s+findings?\b)", re.IGNORECASE),
)


# Required fields. The two-step contract (a prior round):
#   1. Presence: regex `^\s*<label>\s*:\s*<non-empty>` extracts the
#      value via _field_value_or_none — same-line content only
#      (uses `[ \t]*` not `\s*` to prevent multi-line spillover).
#   2. Non-placeholder: _field_problem calls _looks_like_placeholder
#      to reject bracket-wrapped values, TODO/FIXME markers, and
#      template-prompt phrases.
# Pre-pass-12 the comment said "non-empty" only; that under-
# described the contract and is the same docstring-drift class
# pass-13 caught.
_REQUIRED_FIELDS: tuple[str, ...] = (
    "Bug class",
    "Cluster searched",
    "Lock-down",
    "Verbatim-shape verified",
)


# Opt-out tag for genuinely class-less fixes (docs-only follow-up,
# typo rename, etc.). Reason must be non-empty AND not a placeholder.
#
# Self-found during pass-12 development: regex must be line-anchored
# (`^[ \\t]*...[ \\t]*$` with MULTILINE) so that an INLINE mention of
# `[meta-fix-not-applicable: <reason>]` in a commit message's body
# (e.g., describing the opt-out tag in documentation) doesn't fire as
# an actual opt-out. The opt-out only counts when the tag is the whole
# content of its line.
_OPT_OUT_TAG = re.compile(
    r"^[ \t]*\[meta-fix-not-applicable:[ \t]*([^\n\]]+?)[ \t]*\][ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


# 2026-04-30 pass-12 (a prior round): placeholder detection.
# The pre-pass-12 hook only checked that field values were non-empty,
# letting copy-pasted template placeholders (`<one-line summary>`,
# `<grep command + result count>`, etc.) satisfy the contract without
# the operator/AI doing the class/cluster/lock-down thinking. This
# defends against that gameable case + the same opt-out gap in
# sibling hooks (check_postmortem_for_bug_fix, check_validator_input_coverage).
#
# Reject shapes:
#   - Whole-value bracket wrappers: <...>, [...], {...}
#   - Bare TODO/FIXME/XXX/TBD/??/.../N/A markers
#   - Common template-prompt phrases (case-insensitive substring)
#
# A value with brackets MID-string (e.g., `grep '<dict>.get' scripts/`)
# is legitimate — only entire-value-bracket-wrap is rejected. The
# operator can satisfy the contract with a real grep command that
# happens to contain angle brackets.
_PLACEHOLDER_BRACKET_RE = re.compile(r"^\s*[<\[{].*[>\]}]\s*$")
_PLACEHOLDER_MARKER_RE = re.compile(
    r"^\s*(?:TODO|FIXME|XXX|TBD|\?+|\.{3,}|N/?A)\s*$",
    re.IGNORECASE,
)
_PLACEHOLDER_PHRASES: tuple[str, ...] = (
    "one-line summary",
    "single-line summary",
    "grep command + result count",
    "mechanism + path",
    "yes/no with evidence",
    "confirmed via x",
    "your text here",
    "fill me in",
    "fill in",
    "to be determined",
)


def _looks_like_placeholder(value: str) -> bool:
    """Return True if `value` looks like an unfilled template
    placeholder rather than real content. See the comment block above
    for the rejected shapes + rationale."""
    stripped = value.strip()
    if not stripped:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(stripped):
        return True
    if _PLACEHOLDER_MARKER_RE.match(stripped):
        return True
    lower = stripped.lower()
    return any(phrase in lower for phrase in _PLACEHOLDER_PHRASES)


def _repo_root() -> Path:
    """Walk upward from CWD until a `.git` directory is found."""
    p = Path.cwd().resolve()
    for cand in (p, *p.parents):
        if (cand / ".git").exists():
            return cand
    return p


def _is_bug_fix_subject(subject: str) -> str | None:
    """Return the matching pattern's source string if subject looks
    like a bug-fix commit, else None."""
    for rx in _BUG_FIX_SUBJECT_PATTERNS:
        m = rx.search(subject)
        if m:
            return rx.pattern
    return None


def _is_merge_commit(message_lines: list[str]) -> bool:
    if not message_lines:
        return False
    return message_lines[0].startswith(
        ("Merge branch ", "Merge pull request ", "Merge remote-tracking ")
    )


def _is_revert_commit(message_lines: list[str]) -> bool:
    if not message_lines:
        return False
    return message_lines[0].startswith("Revert ")


def _strip_comments(message: str) -> str:
    """Strip `# comment` lines so an opt-out hidden in a comment
    doesn't satisfy the hook."""
    return "\n".join(
        line for line in message.splitlines() if not line.lstrip().startswith("#")
    )


def _field_value_or_none(message: str, field: str) -> str | None:
    """Return the captured value for `<field>:` if present and
    non-empty on the same line, else None.

    Use `[ \\t]*` (literal space/tab only) around the colon and
    value, NOT `\\s*` — `\\s` matches newlines, which would let
    the regex span multiple lines and treat the NEXT line's
    content as the field value. Caught in test_fires_on_field_with_empty_value
    during round-13 development."""
    pattern = re.compile(
        r"^[ \t\-*]*" + re.escape(field) + r"[ \t]*:[ \t]*(\S.*\S|\S)[ \t]*$",
        re.IGNORECASE | re.MULTILINE,
    )
    m = pattern.search(message)
    return m.group(1).strip() if m else None


def _field_problem(message: str, field: str) -> str | None:
    """Return None if the field is present, non-empty, and not a
    placeholder. Otherwise return a human-readable problem string."""
    value = _field_value_or_none(message, field)
    if value is None:
        return "missing or empty"
    if _looks_like_placeholder(value):
        return f"unfilled placeholder ({value!r})"
    return None


# Round-17 lesson 19 — domain detection for the round-16 self-audit
# Layer 1 (blind-spot checklists). Closes the gameability finding the
# DIY ultrareview surfaced on its own commits: round-16 added a
# `Cluster searched:` template recommendation to reference checklists,
# but the hook only checked non-empty/non-placeholder content. So
# `Cluster searched: grep -> 0 hits` (no checklist) passed the hook
# despite the diff touching a domain that has a checklist. Same
# class as round-14: template-recommended ≠ hook-enforced.
#
# Detection rules (mirrors the checklists' "When to consult" sections):
#
#   - "regex" domain: any `.py` file in the staged diff that uses
#     `re.compile|re.match|re.search|re.fullmatch|re.sub|re.findall`.
#   - "yaml-parsing" domain: any `.yaml`/`.yml` file in the staged
#     set OR any `.py` file using `yaml.safe_load|yaml.load`.
#   - "commit-msg-hooks" domain: either of the two existing
#     commit-msg hooks (`scripts/check_finding_response.py`,
#     `scripts/check_postmortem_for_bug_fix.py`) in the staged set.
#
# Detection has TWO layers (— eliminates Phase 2.1's
# residual string-literal false positive):
#
#   1. AST-based for parseable .py files (preferred, precise):
#      walk the AST for Call nodes whose .func is an Attribute
#      `<module>.<call>` where module ∈ {re, yaml} and call is in
#      _RE_CALLS / _YAML_CALLS. String literals containing
#      "yaml.safe_load(" do NOT match — they parse as Constant,
#      not Call.
#
#   2. Regex fallback for non-parseable content (e.g., a partial
#      file from `git show :0:<path>` that lost the closing brace,
#      or files with syntax errors that haven't been resolved):
#      `\b<module>\.<call>\(` — the form. Anchors on
#      `\(` so prose mentions in comments don't match. String
#      literals can still false-positive in this fallback path,
#      but the fallback only fires when AST parse fails (rare).
#
# History:
#   - self-found: original `\b...\b` regex matched call
#     names in COMMENTS (line-255 prose said "any `.py` file using
#     `yaml.safe_load|yaml.load`"). Tightened to `\b...\(`.
#   - (this commit): adds AST layer to eliminate the
#     remaining string-literal false positive. Calibration
#     baseline jumped from 54% to 100% precision after this change.
#
# Per-domain opt-out shape (inline in the `Cluster searched:` value):
#   `(checklist <domain> not applicable: <reason>)`
# Reason must be non-empty + non-placeholder (same contract as
# field values + opt-out tags).
_COMMIT_MSG_HOOK_FILES: frozenset[str] = frozenset({
    "scripts/check_finding_response.py",
    "scripts/check_postmortem_for_bug_fix.py",
})

_RE_CALLS: frozenset[str] = frozenset({
    "compile", "match", "search", "fullmatch", "sub", "findall",
})
_YAML_CALLS: frozenset[str] = frozenset({"safe_load", "load"})

# Regex fallbacks (form) for files that fail AST parse.
_RE_USE_RE = re.compile(
    r"\bre\.(compile|match|search|fullmatch|sub|findall)\("
)
_YAML_USE_RE = re.compile(r"\byaml\.(safe_load|load)\(")
# ast-parsing domain detection. Any `ast.<attr>(` call
# is treated as AST-domain work — covers parse/walk/dump/unparse/
# literal_eval/iter_child_nodes/copy_location/etc. without needing
# to enumerate. Fallback regex is similarly broad: `\bast\.<word>\(`.
_AST_USE_RE = re.compile(r"\bast\.[A-Za-z_][A-Za-z_0-9]*\(")


def _detect_python_uses(content: str) -> tuple[bool, bool, bool]:
    """Return (uses_re, uses_yaml, uses_ast) for Python file content.

    Tries AST parsing first (precise — string literals and
    comments can't false-positive). Falls back to regex (Phase 2.1
    `\\b...\\(` form) if the content doesn't parse as Python.

    AST detection rule: a Call node whose .func is an Attribute
    where (.value.id resolves via alias_map to canonical 're',
    'yaml', or 'ast') AND .attr is in _RE_CALLS / _YAML_CALLS for
    re/yaml (for ast, ANY attribute is treated as AST-domain work).

    added the third return value (uses_ast). Phase 2.13
    added two-pass AST walking with alias_map: Pass 1 collects
    `import <mod> as <name>` aliases for re/yaml/ast; Pass 2 uses
    `alias_map.get(local_name, local_name)` so canonical references
    AND aliased references both detect.

    Documented coverage gaps (lens-6 dogfood findings, ast-parsing.md
    classes #4 and #8):
      - `from re import compile; compile(...)` — bare Call(func=Name)
        with no Attribute access; the walker never sees a re.<attr>
        shape. Project convention is qualified imports (ruff F403/
        F405 enforces no star-imports).
      - SCOPE-UNAWARE alias_map (lens-6 finding): the
        alias_map is built across the WHOLE tree without scope
        tracking, so cross-scope name collisions collapse to
        whichever Import ast.walk visits LAST. E.g.,
        `import re; def f(): import yaml as re` makes alias_map['re']
        = 'yaml', misclassifying ALL top-level re.<call> sites as
        yaml. Low severity for this project (utility scripts don't
        shadow stdlib aliases) but a real CHECKLIST-CLASS-GAP
        documented in ast-parsing.md class #4. Scope-aware walking
        via ast.NodeVisitor + scope stack is the canonical fix —
        deferred until a real bug surfaces.

    added the third return value (uses_ast). Calibration
    labels for commits that touch ast.<call>(...) code now expect
    'ast-parsing' in the domain set.
    """
    # defensive isinstance guard at boundary. Lens-1
    # (adversarial-input) flagged that `ast.parse(None)` raises
    # TypeError, which wasn't in the except tuple. Live callers
    # (`_staged_file_content`, etc.) always pass str from
    # `subprocess.run(..., text=True).stdout`, so this is
    # theoretical for the production path — but the function is
    # also imported by `scripts/calibrate_diy_ultrareview.py` and
    # the bash helper's python -c shim, both of which COULD pass
    # non-str if their plumbing changes. The isinstance guard +
    # extended except tuple makes the function defensively safe.
    if not isinstance(content, str):
        return (False, False, False)
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        # Fallback: regex (form). Less precise but
        # better than nothing for files that don't parse.
        #
        # catch RecursionError and MemoryError too:
        # the lens-6 (external-corpus) DIY ultrareview specialist
        # flagged that ast.parse() docs warn about deeply-nested
        # input crashing the parser. Without these in the except
        # tuple, a maliciously-crafted .py file (or just a
        # pathologically large one) would propagate the exception
        # up and crash both the commit-msg hook AND the pre-commit
        # calibration gate (which re-walks 17 historical SHAs;
        # any one bad SHA would brick every developer's commit).
        # added TypeError per lens-1 finding.
        return (
            bool(_RE_USE_RE.search(content)),
            bool(_YAML_USE_RE.search(content)),
            bool(_AST_USE_RE.search(content)),
        )

    # wrap ast.walk too. ast.walk recurses into the
    # tree; a pathologically deep AST (which parsed successfully
    # but is huge) can hit Python's recursion limit during walk.
    # Same RecursionError / MemoryError fallback as the parse step.
    #
    # handle aliased imports. Pre-Phase-2.13:
    # `import re as r; r.compile(...)` produced a Call where
    # func.value.id is 'r' not 're', so the walker missed it
    # (documented coverage gap in a prior round / ast-parsing.md
    # class #4). Now: build an alias_map by walking Import / ImportFrom
    # nodes first, then look up the local name in the map when
    # checking Call nodes. Bare-import callees from `from re import
    # compile` remain a separate gap (no Attribute access at the
    # call site).
    try:
        # Pass 1: alias_map. Each entry maps a LOCAL name (the alias
        # if specified, else the module name) to the CANONICAL
        # module name. Only the three modules of interest are
        # tracked — minimizes alias_map churn on giant files.
        alias_map: dict[str, str] = {}
        _CANONICAL = ("re", "yaml", "ast")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in _CANONICAL:
                        alias_map[a.asname or a.name] = a.name
            # ast.ImportFrom (e.g., `from re import compile`) is a
            # separate gap — the call site has no Attribute access
            # to track. Documented in ast-parsing.md class #4.

        # Pass 2: detect Call nodes using the alias_map.
        uses_re = False
        uses_yaml = False
        uses_ast = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if not isinstance(func.value, ast.Name):
                continue
            local_name = func.value.id
            attr = func.attr
            # Look up the canonical module via alias_map. If
            # local_name isn't in the map, it's not one of the
            # tracked modules (or there's no import statement —
            # fallback: assume local_name IS the canonical name,
            # which preserves pre-Phase-2.13 behavior for files
            # that don't import the module explicitly but
            # reference it via builtins-like patterns).
            canonical = alias_map.get(local_name, local_name)
            if canonical == "re" and attr in _RE_CALLS:
                uses_re = True
            elif canonical == "yaml" and attr in _YAML_CALLS:
                uses_yaml = True
            elif canonical == "ast":
                # any ast.<call>( = AST-domain work.
                uses_ast = True
            if uses_re and uses_yaml and uses_ast:
                break  # short-circuit
    except (RecursionError, MemoryError, TypeError):
        # AST walk blew up. Fall back to regex on the raw content.
        # added TypeError to the walk except too — same
        # rule-13 sibling-parity as the parse except tuple.
        return (
            bool(_RE_USE_RE.search(content)),
            bool(_YAML_USE_RE.search(content)),
            bool(_AST_USE_RE.search(content)),
        )
    return (uses_re, uses_yaml, uses_ast)


def _staged_files(repo: Path) -> list[str]:
    """Return list of staged file paths (relative to repo root) for
    files added/copied/modified/renamed/typechanged in the index."""
    try:
        r = subprocess.run(
            [
                "git", "diff", "--cached", "--name-only",
                "--diff-filter=ACMRT",
            ],
            cwd=repo, capture_output=True, text=True, check=False,
        timeout=30,
        )
        if r.returncode != 0:
            return []
        return [f.strip() for f in r.stdout.splitlines() if f.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def _staged_file_content(repo: Path, rel: str) -> str:
    """Return the staged version of a file's content (post-`git add`),
    or empty string on error. Used for content-based domain detection."""
    try:
        r = subprocess.run(
            ["git", "show", f":0:{rel}"],
            cwd=repo, capture_output=True, text=True, check=False,
        timeout=30,
        )
        if r.returncode != 0:
            return ""
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _detect_domains(repo: Path) -> set[tuple[str, str]]:
    """Return set of (domain_name, checklist_filename) for domains
    the staged diff touches. Empty set if no domain hits.

    See the comment block above for detection rules per domain."""
    files = _staged_files(repo)
    if not files:
        return set()

    domains: set[tuple[str, str]] = set()

    # commit-msg-hooks (path-based)
    if any(f in _COMMIT_MSG_HOOK_FILES for f in files):
        domains.add(("commit-msg-hooks", "commit-msg-hooks.md"))

    # yaml-parsing (extension-based — config/fixture files)
    if any(f.endswith((".yaml", ".yml")) for f in files):
        domains.add(("yaml-parsing", "yaml-parsing.md"))

    # regex + yaml-parsing + ast-parsing (AST-based for .py files;
    # regex fallback inside _detect_python_uses for non-parseable
    # content). added ast-parsing domain detection.
    for f in files:
        if not f.endswith(".py"):
            continue
        content = _staged_file_content(repo, f)
        uses_re, uses_yaml, uses_ast = _detect_python_uses(content)
        if uses_re:
            domains.add(("regex", "regex.md"))
        if uses_yaml:
            domains.add(("yaml-parsing", "yaml-parsing.md"))
        if uses_ast:
            domains.add(("ast-parsing", "ast-parsing.md"))

    return domains


# anchor at end of cluster_value (`\s*$`). Lens-5
# (forcing-function-gameability) found that the unanchored regex
# matched mid-paragraph: a contributor could write
#   `Cluster searched: (checklist regex not applicable: kidding) grep -> 5 hits`
# and the gate would be satisfied because the opt-out shape exists
# anywhere in the line. Round-14 lesson 17 already named this class
# for `_OPT_OUT_TAG` (the meta `[meta-fix-not-applicable: ...]` tag,
# line-anchored — search `_OPT_OUT_TAG = re.compile` above; line
# numbers were dropped in because they drifted on edits).
# Per rule-13 sibling-parity, the
# per-domain opt-out should have the same anchoring discipline.
# `cluster_value` is a single-line field per `_field_value_or_none`,
# so `$` (end-of-line) suffices — no MULTILINE needed.
_DOMAIN_OPT_OUT_TEMPLATE = (
    r"\(\s*checklist\s+{domain}\s+not\s+applicable\s*:\s*"
    r"(?P<reason>[^)]+?)\s*\)\s*$"
)


def _domain_satisfied(cluster_value: str, domain: str, checklist: str) -> bool:
    """Return True if the `Cluster searched:` field's value EITHER
    references the checklist for `domain` OR carries a per-domain
    opt-out with a non-placeholder reason.

    — the opt-out regex is line-anchored at end of line
    (re.MULTILINE + `\\s*$`). Lens-5 (forcing-function-gameability)
    found that the unanchored regex matched mid-paragraph: the
    body could contain narrative like
        "Cluster searched: I considered (checklist regex not applicable:
         kidding) but actually grep -> 5 sites"
    and the gate would be satisfied because the opt-out shape
    appears anywhere in the body. Anchoring at end-of-line requires
    the opt-out to be a TRAILING parenthetical clause — same
    discipline rule-13 applied to `_OPT_OUT_TAG` (the meta opt-out
    tag) in a prior round.
    """
    # Reference path: filename literal OR domain identifier
    if checklist in cluster_value:
        return True
    # Opt-out path: `(checklist <domain> not applicable: <reason>)`
    # at end of some line in the cleaned body.
    rx = re.compile(
        _DOMAIN_OPT_OUT_TEMPLATE.format(domain=re.escape(domain)),
        re.IGNORECASE | re.MULTILINE,
    )
    m = rx.search(cluster_value)
    if not m:
        return False
    reason = m.group("reason").strip()
    return bool(reason) and not _looks_like_placeholder(reason)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(
            "check-finding-response: usage: "
            "check_finding_response.py <commit-msg-file>",
            file=sys.stderr,
        )
        return 2
    msg_path = Path(args[0])
    if not msg_path.is_file():
        print(
            f"check-finding-response: commit-msg file not found: {msg_path}",
            file=sys.stderr,
        )
        return 2

    raw = msg_path.read_text(encoding="utf-8")
    cleaned = _strip_comments(raw)
    lines = cleaned.splitlines()

    if not lines or not lines[0].strip():
        # Empty commit message — git itself rejects.
        return 0

    if _is_merge_commit(lines) or _is_revert_commit(lines):
        return 0

    subject = lines[0].strip()
    matched_pattern = _is_bug_fix_subject(subject)
    if matched_pattern is None:
        return 0

    # Opt-out path
    opt = _OPT_OUT_TAG.search(cleaned)
    if opt:
        reason = opt.group(1).strip()
        if not reason:
            print(
                "check-finding-response: [meta-fix-not-applicable:] "
                "tag is present but the reason is empty. Provide a brief "
                "reason (docs-only follow-up, typo rename, etc.) so the "
                "opt-out is auditable.",
                file=sys.stderr,
            )
            return 1
        if _looks_like_placeholder(reason):
            print(
                f"check-finding-response: [meta-fix-not-applicable: "
                f"{reason}] reason looks like an unfilled template "
                "placeholder (bracket-wrapped, TODO/FIXME marker, or a "
                "template-prompt phrase). Replace with a real reason.",
                file=sys.stderr,
            )
            return 1
        print(
            f"check-finding-response: bug-fix commit accepted with "
            f"[meta-fix-not-applicable: {reason}]",
            file=sys.stderr,
        )
        return 0

    # Required-fields path. Each field must be present, non-empty,
    # AND not a placeholder (a prior round).
    problems: list[tuple[str, str]] = []
    for field in _REQUIRED_FIELDS:
        problem = _field_problem(cleaned, field)
        if problem is not None:
            problems.append((field, problem))

    # Round-17 lesson 19: domain-detection extension. For every
    # blind-spot-checklists domain the staged diff touches, the
    # commit message body must reference the checklist OR carry a
    # per-domain opt-out. Closes the round-14 class recurrence:
    # previously the message passed the hook even when the diff
    # touched a checklist'd domain without the operator having
    # consulted the checklist.
    #
    # Scans the WHOLE cleaned message body, not just the
    # Cluster-searched field value, because continuation-line
    # values (multi-line field content indented under the colon)
    # aren't captured by the line-anchored field regex. The
    # operator's show-work can land in the field OR the surrounding
    # narrative — both count.
    repo = _repo_root()
    detected_domains = _detect_domains(repo)
    for domain_name, checklist_filename in sorted(detected_domains):
        if not _domain_satisfied(cleaned, domain_name, checklist_filename):
            problems.append((
                "Cluster searched",
                f"diff touches {domain_name!r} domain but commit message "
                f"doesn't reference docs/blind-spot-checklists/"
                f"{checklist_filename} (or carry a `(checklist "
                f"{domain_name} not applicable: <reason>)` per-domain "
                "opt-out)",
            ))

    if not problems:
        return 0

    print(
        "check-finding-response: BUG-FIX COMMIT MISSING CLASS-OF-BUG FIELDS",
        file=sys.stderr,
    )
    print("=" * 72, file=sys.stderr)
    print(
        f"  subject:           {subject!r}\n"
        f"  matched pattern:   {matched_pattern}",
        file=sys.stderr,
    )
    for field, problem in problems:
        print(f"  {field}: {problem}", file=sys.stderr)
    print(
        "\nThe four required fields force the class-of-bug thinking that "
        "rules 11/13/15 named:\n"
        "\n"
        "  Bug class:           <one-line summary — NOT the symptom>\n"
        "  Cluster searched:    <grep command + result count>\n"
        "  Lock-down:           <mechanism + path>\n"
        "  Verbatim-shape verified: <yes/no with evidence>\n"
        "\n"
        "See docs/templates/finding_response.md for the copy-paste "
        "template + per-field guidance. See AGENTS.md 'Responding to "
        "an audit finding' for the full protocol.\n"
        "\n"
        "If this commit is genuinely class-less (docs-only follow-up, "
        "typo rename), use the opt-out tag with a specific reason:\n"
        "  [meta-fix-not-applicable: <reason>]",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())   # pragma: no cover
