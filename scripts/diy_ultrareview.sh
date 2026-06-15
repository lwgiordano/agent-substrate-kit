#!/usr/bin/env bash
#
# diy_ultrareview.sh — print the diff under review + the seven
# specialist prompts (6 parallel + 1 synthesizer), ready to copy
# into Agent tool calls.
#
# Round-16 lesson 18 helper, extended in (synthesizer)
# and (external-corpus WebFetch lens). Use this when you
# want to spawn the DIY ultrareview seven-specialist review (the
# closest substitute for /ultrareview without leaving the current
# session).
#
# Usage:
#   scripts/diy_ultrareview.sh                  # diff HEAD~1..HEAD
#   scripts/diy_ultrareview.sh HEAD~3..HEAD     # last 3 commits
#   scripts/diy_ultrareview.sh main..HEAD       # branch vs main
#   scripts/diy_ultrareview.sh <SHA>            # a specific commit
#
# Output: prints to stdout the diff + a 7-specialist prompt block
# (6 parallel lenses + 1 sequential synthesizer). Does NOT spawn
# the agents — that's the operator/AI's job (paste lenses 1-6 in a
# single message for parallel execution; lens 7 in a follow-up
# message after lenses 1-6 finish).
#
# See docs/templates/diy_ultrareview_prompts.md for the full
# specialist prompt content; this script just shells out the diff
# and references the prompts file.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PROMPTS_FILE="$REPO/docs/templates/diy_ultrareview_prompts.md"

# Diff range — first arg, default HEAD~1..HEAD
DIFF_RANGE="${1:-HEAD~1..HEAD}"

if [ ! -f "$PROMPTS_FILE" ]; then
    echo "diy_ultrareview: prompts file not found: $PROMPTS_FILE" >&2
    echo "  Did you mean to run from a different repo?" >&2
    exit 2
fi

# Auto-convert single ref (e.g., HEAD or a SHA) to <ref>~..<ref>.
# Without this, `git diff <single-ref>` produces a working-tree-vs-ref
# diff, which silently reviews staged+unstaged changes instead of the
# commit the user pointed at. The documented usage `<SHA>` means
# "the diff this single commit introduced", which is <SHA>~..<SHA>.
#
# Edge case: root commit has no parent (<SHA>~ doesn't resolve). Use
# the empty-tree sentinel as the "base" so `git diff` produces the
# full diff of the root commit's contents. This is git's canonical
# way to diff against "before any history".
ROOT_SHA=""
case "$DIFF_RANGE" in
    *..*) ;;  # already a range — leave alone
    *)
        if git -C "$REPO" rev-parse --verify "$DIFF_RANGE" >/dev/null 2>&1; then
            if git -C "$REPO" rev-parse --verify "${DIFF_RANGE}~" >/dev/null 2>&1; then
                DIFF_RANGE="${DIFF_RANGE}~..${DIFF_RANGE}"
            else
                # Root commit — no parent. Use git's empty-tree
                # SHA-1 (well-known constant). `git diff
                # 4b825dc6...<sha>` gives the root commit's diff.
                ROOT_SHA="$(git -C "$REPO" rev-parse "$DIFF_RANGE")"
                DIFF_RANGE="4b825dc642cb6eb9a060e54bf8d69288fbee4904..${ROOT_SHA}"
            fi
        else
            echo "diy_ultrareview: '$DIFF_RANGE' is not a valid ref or range" >&2
            echo "  Pass a range like HEAD~3..HEAD, main..HEAD, or a single <SHA>." >&2
            exit 2
        fi
        ;;
esac

# Verify the diff range resolves (covers explicit ranges + the
# auto-converted form above). The empty-tree sentinel is well-known
# but isn't in the object DB until referenced; skip the check when
# it's the base.
if [[ "$DIFF_RANGE" != 4b825dc6* ]]; then
    if ! git -C "$REPO" rev-parse --verify "$DIFF_RANGE" >/dev/null 2>&1 \
       && ! git -C "$REPO" rev-parse --verify "${DIFF_RANGE%..*}" >/dev/null 2>&1; then
        echo "diy_ultrareview: diff range '$DIFF_RANGE' doesn't resolve" >&2
        exit 2
    fi
fi

# ----- Domain auto-detection (round-16 layer 1 + a prior round)
#
# Mirrors `_detect_domains()` in scripts/check_finding_response.py.
# shells out to the canonical Python `_detect_python_uses`
# for `.py` file content checks (eliminates the precision asymmetry
# noted in — bash helper used regex `\b...\(` while the
# Python hook used AST). Now both code paths run the SAME logic
# (true rule-13 sibling-parity, not just "same shape").
#
# Fallback: if `python3 -c` fails (e.g., Python missing, import
# error), the per-file content check is silently skipped — the
# helper's checklist suggestions become a slight under-estimate
# rather than mis-firing. Pre-commit's gate on the Python side is
# unaffected by helper failures.
#
# Domains:
#   regex             — .py file uses `re.<call>(` (AST Call nodes)
#   yaml-parsing      — .yaml/.yml file present, OR .py file uses
#                       `yaml.<call>(` (AST Call nodes)
#   commit-msg-hooks  — diff touches a commit-msg hook script
COMMIT_MSG_HOOK_FILES=(
    "scripts/check_finding_response.py"
    "scripts/check_postmortem_for_bug_fix.py"
)

# End-ref of the range: substring after `..`.
END_REF="${DIFF_RANGE##*..}"
# If the range was `A..` (no end), default to HEAD.
[ -z "$END_REF" ] && END_REF="HEAD"

detected_domains=""
add_domain() {
    case ",$detected_domains," in
        *",$1,"*) ;;  # already in set
        *) detected_domains="${detected_domains:+$detected_domains,}$1" ;;
    esac
}

# canonical AST-based detection, shelled out to Python
# so the bash helper and Python hook share one source of truth.
# Stdin: Python file content. Stdout: zero or more domain names
# (one per line). Exits 0 on success, non-zero on Python failure
# (caller treats as "no domains detected").
detect_py_uses_via_python() {
    PYTHONPATH="$REPO" python3 -c '
import sys
try:
    from scripts.check_finding_response import _detect_python_uses
except ImportError:
    sys.exit(2)  # caller falls back silently
# added uses_ast as the third return value.
result = _detect_python_uses(sys.stdin.read())
# Backward-compat: pre-2.12 sites returned 2-tuple. Detect arity.
if len(result) == 3:
    uses_re, uses_yaml, uses_ast = result
else:
    uses_re, uses_yaml = result
    uses_ast = False
if uses_re:
    print("regex")
if uses_yaml:
    print("yaml-parsing")
if uses_ast:
    print("ast-parsing")
'
}

# Iterate files in the diff.
while IFS= read -r f; do
    [ -z "$f" ] && continue

    # Commit-msg hook check (filename only).
    for hook in "${COMMIT_MSG_HOOK_FILES[@]}"; do
        if [ "$f" = "$hook" ]; then
            add_domain "commit-msg-hooks"
            break
        fi
    done

    # YAML extension check (filename only).
    case "$f" in
        *.yaml|*.yml) add_domain "yaml-parsing" ;;
    esac

    # Content check for .py files: shell out to canonical Python AST
    # detection. Pre-Phase-2.8 used bash regex `\b...\(`; matched
    # string literals (test fixtures with literal "yaml.safe_load(").
    # AST sees Call nodes, not Constants, so string-literal false-
    # positives are eliminated.
    if [[ "$f" == *.py ]]; then
        # Get post-image content (right side of diff). Fall back
        # silently if file was deleted in this range.
        content=$(git -C "$REPO" show "${END_REF}:${f}" 2>/dev/null) \
            || continue
        # Run AST detection. Non-zero exit (Python missing / import
        # failure) → silently skip per-file content check; the
        # filename / extension checks above still fire.
        py_domains=$(printf '%s' "$content" | detect_py_uses_via_python 2>/dev/null) \
            || py_domains=""
        while IFS= read -r d; do
            [ -n "$d" ] && add_domain "$d"
        done <<< "$py_domains"
    fi
done < <(git -C "$REPO" diff --name-only "$DIFF_RANGE" -- 2>/dev/null)

# Dynamic class-count: count `### N. ` headings in each checklist so
# this stays in lockstep with the checklist files.
class_count() {
    grep -cE '^### [0-9]+\. ' "$REPO/docs/blind-spot-checklists/$1" 2>/dev/null || echo 0
}

# Domain → most-relevant lens (operator hint).
domain_priority_lens() {
    case "$1" in
        regex)            echo "lens #4 (verbatim-shape) — rule 15 highest leverage" ;;
        yaml-parsing)     echo "lens #1 (adversarial-input) — rule 12 grid coverage" ;;
        commit-msg-hooks) echo "lens #5 (forcing-function gameability) — rule 17" ;;
        ast-parsing)      echo "lens #6 (external-corpus) — Python ast docs / CWE-674 + CWE-1284" ;;
        *)                echo "all five lenses" ;;
    esac
}

cat <<HEADER
================================================================
DIY ultrareview — seven-specialist parallel + synthesizer review
================================================================

Diff range: $DIFF_RANGE
Repo:       $REPO
Prompts:    $PROMPTS_FILE

To use:
  1. Read the diff below.
  2. Open $PROMPTS_FILE for the seven specialist prompts.
  3. Phase A — spawn lenses 1-6 in parallel (single message, six
     Agent tool calls — concurrency requires single-message
     dispatch). Specialist 6 (external-corpus) needs WebFetch
     access — use a subagent type that has it.
  4. Each agent gets one specialist prompt + the diff.
  5. Phase B (optional, recommended for non-trivial diffs) — spawn
     specialist 7 (synthesizer) with the diff + the six reports
     as input. Sequential after Phase A.
  6. Synthesize findings per the synthesis template at the bottom
     of the prompts file (the synthesizer's [A]/[B]/[C]/[D] cross-
     pattern findings go at the top, then specialist 6's [EXTERNAL]
     findings, then per-severity tiers).

The seven lenses:
  1. Adversarial-input  (rule-12)         — Phase A parallel
  2. Sibling-cluster    (rule-13)         — Phase A parallel
  3. Documentation-drift (rule-5)         — Phase A parallel
  4. Verbatim-shape     (rule-15)         — Phase A parallel
  5. Forcing-function gameability (rule-17) — Phase A parallel
  6. External-corpus    (Phase 2.3, WebFetch) — Phase A parallel
  7. Synthesizer / cross-checker — Phase B sequential
HEADER

# Recommended-checklists block (domain-aware).
if [ -n "$detected_domains" ]; then
    cat <<DOMAINS_HEADER

================================================================
RECOMMENDED CHECKLISTS (round-16 layer 1 — cheapest, ~3 min each)
================================================================

The diff touches these domains. Read the named checklists BEFORE
composing specialist prompts, so the layer-3 specialists can focus
on findings the canonical-bug-class lists won't catch mechanically.

  Detected domains: $detected_domains

DOMAINS_HEADER
    IFS=',' read -ra _domain_arr <<< "$detected_domains"
    for d in "${_domain_arr[@]}"; do
        case "$d" in
            regex)            cl="regex.md" ;;
            yaml-parsing)     cl="yaml-parsing.md" ;;
            commit-msg-hooks) cl="commit-msg-hooks.md" ;;
            ast-parsing)      cl="ast-parsing.md" ;;
            *)                continue ;;
        esac
        n=$(class_count "$cl")
        printf "  - docs/blind-spot-checklists/%-22s (%s classes)\n" "$cl" "$n"
        printf "      priority lens: %s\n" "$(domain_priority_lens "$d")"
    done
    echo ""
    echo "Reference these in the four-field commit-msg hook's"
    echo "'Cluster searched:' field (e.g.,"
    echo " \"Checklist: docs/blind-spot-checklists/regex.md (13 classes"
    echo "  reviewed; class #N hit)\"). Round-17 lesson 19 forcing"
    echo "  function rejects commits that touch these domains without"
    echo "  a checklist reference or explicit opt-out."
else
    cat <<NO_DOMAINS

================================================================
RECOMMENDED CHECKLISTS — none detected for this diff
================================================================

The diff doesn't appear to touch the regex / yaml-parsing /
commit-msg-hooks domains. The checklist forcing function (round-17
lesson 19) won't fire. Consider whether the diff touches a NEW
domain that should get its own checklist (template:
docs/blind-spot-checklists/_template.md).
NO_DOMAINS
fi

cat <<DIFF_HEADER

================================================================
DIFF UNDER REVIEW
================================================================
DIFF_HEADER

# `--` separator: tell git everything before is refs, nothing after
# is a path. Defends against the (unlikely but real) ambiguity where
# DIFF_RANGE happens to match a filename in the working tree.
git -C "$REPO" diff "$DIFF_RANGE" --

cat <<FOOTER

================================================================
END OF DIFF — paste each specialist prompt + this diff into a
parallel Agent tool call. See $PROMPTS_FILE for full prompts.
================================================================
FOOTER
