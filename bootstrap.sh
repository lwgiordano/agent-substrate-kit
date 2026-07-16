#!/usr/bin/env bash
set -euo pipefail
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$(pwd)"; RUNNER="auto"; WORKFLOW="superpowers"; UI_ENABLED="no"; PROFILE="standard"; LANG_PRIMARY="auto"; FORCE="no"; INSTALL_TOOLS="no"; RUN_DOCTOR="yes"; SANDBOX="0"; REMOTE_GOVERNANCE="0"; DEV_TESTS="no"
usage(){ cat <<'HELP'
Agent Substrate Kit v3 bootstrap
Options:
  --target PATH
  --runner auto|uv|python|poetry
  --workflow superpowers|gsd|none
  --ui yes|no
  --profile starter|standard|strict[+sandbox][+remote]   (+sandbox = egress containment; +remote = remote governance)
  --lang auto|python|node|go|none
  --force
  --install-tools
  --no-doctor
  --dev-tests   (vendor the kit's FULL self-test suite for dogfooding; default
                omits the heavy behavioral self-tests from the install)
HELP
}
while [[ $# -gt 0 ]]; do case "$1" in --target) TARGET="$2"; shift 2;; --runner) RUNNER="$2"; shift 2;; --workflow) WORKFLOW="$2"; shift 2;; --ui) UI_ENABLED="$2"; shift 2;; --profile) PROFILE="$2"; shift 2;; --lang) LANG_PRIMARY="$2"; shift 2;; --force) FORCE="yes"; shift;; --install-tools) INSTALL_TOOLS="yes"; shift;; --no-doctor) RUN_DOCTOR="no"; shift;; --dev-tests) DEV_TESTS="yes"; shift;; -h|--help) usage; exit 0;; *) echo "Unknown option $1"; usage; exit 1;; esac; done
case "$RUNNER" in auto|uv|python|poetry) ;; *) echo "invalid runner"; exit 1;; esac
case "$WORKFLOW" in superpowers|gsd|none) ;; *) echo "invalid workflow"; exit 1;; esac
# `+`-separated suffixes are CLI ALIASES, not new config enums: `strict+sandbox`,
# `strict+remote`, `strict+remote+sandbox` expand to the base governance profile PLUS
# orthogonal flags (SUBSTRATE_SANDBOX=1 egress containment, SUBSTRATE_REMOTE_GOVERNANCE=1
# remote governance). Capabilities are orthogonal to the governance level, so they are
# flags — NOT a combinatorial profile matrix. (v3.5.0 sandbox; v3.6.0 remote.)
if [[ "$PROFILE" == *+* ]]; then
  _base="${PROFILE%%+*}"; _flags="${PROFILE#*+}"; PROFILE="$_base"
  IFS='+' read -ra _flag_list <<< "$_flags"
  for _f in "${_flag_list[@]}"; do
    case "$_f" in
      sandbox) SANDBOX="1";;
      remote)  REMOTE_GOVERNANCE="1";;
      *) echo "invalid profile flag: $_f (allowed: sandbox, remote)"; exit 1;;
    esac
  done
fi
case "$PROFILE" in
  starter|standard|strict) ;;
  *) echo "invalid profile"; exit 1;;
esac
case "$LANG_PRIMARY" in auto|python|node|go|none) ;; *) echo "invalid lang"; exit 1;; esac
case "$UI_ENABLED" in yes|no|true|false|ui|no-ui) ;; *) echo "invalid ui"; exit 1;; esac
[[ "$UI_ENABLED" == "true" || "$UI_ENABLED" == "ui" ]] && UI_ENABLED="yes"; [[ "$UI_ENABLED" == "false" || "$UI_ENABLED" == "no-ui" ]] && UI_ENABLED="no"
mkdir -p "$TARGET"; cd "$TARGET"; REPO_ROOT="$(pwd)"; REPO_ROOT_REAL="$(pwd -P)"
# v3.8.14 (P1): refuse if ANY symlink in the target ESCAPES it — copy()/render()/`mkdir -p`
# would follow a symlinked ANCESTOR and write outside the repo (the v3.8.13 leaf-only rm -f
# did not cover a symlinked PARENT dir). Guards DIRECT bootstrap too, not just via upgrade.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$REPO_ROOT" <<'PYEOF' || exit 2
import os, sys
root = os.path.realpath(sys.argv[1])
bad = []
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d not in (".git", "venv", ".venv", "node_modules")]
    for n in list(dns) + fns:
        p = os.path.join(dp, n)
        if os.path.islink(p):
            rp = os.path.realpath(p)
            if rp != root and not rp.startswith(root + os.sep):
                bad.append(p + " -> " + rp)
if bad:
    sys.stderr.write("bootstrap: refusing — symlink(s) escape the repo (a render would "
                     "write outside it):\n" + "\n".join(bad) + "\n")
    sys.exit(2)
PYEOF
fi
[ -d .git ] || { echo "==> Initializing git repository"; git init >/dev/null; }
# Language auto-detect: existing project markers win; empty repo defaults to python.
if [[ "$LANG_PRIMARY" == "auto" ]]; then
  if [ -f pyproject.toml ] || [ -f setup.py ]; then LANG_PRIMARY="python"
  elif [ -f package.json ]; then LANG_PRIMARY="node"
  elif [ -f go.mod ]; then LANG_PRIMARY="go"
  else LANG_PRIMARY="python"; fi
fi
RUN_PREFIX=""; if [[ "$RUNNER" == "uv" ]]; then RUN_PREFIX="uv run"; elif [[ "$RUNNER" == "poetry" ]]; then RUN_PREFIX="poetry run"; elif [[ "$RUNNER" == "auto" && "$LANG_PRIMARY" == "python" ]]; then if command -v uv >/dev/null 2>&1; then RUN_PREFIX="uv run"; elif command -v poetry >/dev/null 2>&1; then RUN_PREFIX="poetry run"; fi; fi
PROJECT_SLUG="$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-' | sed 's/^-//; s/-$//')"; [ -n "$PROJECT_SLUG" ] || PROJECT_SLUG="agent-substrate-project"; TODAY="$(date +%F)"
# Per-write no-follow guard (v3.8.15): the startup escaping-symlink scan is check-then-write;
# a symlink planted AFTER it would still be followed. Re-resolve the destination's real parent
# dir immediately before EACH write and refuse if it is not inside the repo — a per-write
# invariant, not a one-time scan. (Residual: a symlink planted between this `pwd -P` and the
# cp/sed is a sub-ms window a shell installer cannot fully close without OS-level locking.)
_safe_dest(){ local d="$1" pd; pd="$(cd "$(dirname "$d")" 2>/dev/null && pwd -P)" || { echo "bootstrap: refusing — cannot resolve destination dir for ${d#./}" >&2; exit 2; }; case "$pd" in "$REPO_ROOT_REAL"|"$REPO_ROOT_REAL"/*) : ;; *) echo "bootstrap: refusing write outside the repo: ${d#./} (real parent -> $pd)" >&2; exit 2 ;; esac; }
# rm -f the destination BEFORE writing (v3.8.13): plain `cp`/`sed >` FOLLOW a symlinked
# destination, so a symlink planted at a render target would write through it to an external
# file. Removing the link first makes cp/sed create a fresh regular file (no-follow write).
copy(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"; _safe_dest "$d"; if [ -e "$d" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP ${d#./}"; else rm -f "$d"; cp "$s" "$d"; echo "    +    ${d#./}"; fi; }
render(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"; _safe_dest "$d"; if [ -e "$d" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP ${d#./}"; else rm -f "$d"; sed -e "s/{{PROJECT_SLUG}}/$PROJECT_SLUG/g" -e "s/{{WORKFLOW}}/$WORKFLOW/g" -e "s/{{UI_ENABLED}}/$UI_ENABLED/g" -e "s/{{RUNNER}}/$RUNNER/g" -e "s/{{PROFILE}}/$PROFILE/g" -e "s/{{LANG}}/$LANG_PRIMARY/g" -e "s#{{RUN_PREFIX}}#$RUN_PREFIX#g" "$s" > "$d"; echo "    +    ${d#./}"; fi; }
# wprep / wappend: the SAME per-write no-follow invariant copy()/render() inline, for the
# DIRECT redirection sites below (render_precommit + the config/lock/sandbox/docs/metadata
# `>`/`>>` writes). v3.8.13's _safe_dest guard was wired only into copy()/render(), so these
# raw redirections followed a PERSISTENT symlinked destination straight out of the repo — a
# deterministic external write, not the documented sub-ms race (v3.8.18 / bootstrap:136).
#   wprep  (truncating `>`): validate the real parent is in-repo, then unlink any leaf so `>`
#          creates a fresh regular file instead of following a planted link.
#   wappend (`>>` to .gitattributes/.gitignore, which must KEEP existing content): validate the
#          parent and REFUSE if the leaf is a symlink (a legit tracked dotfile is a regular file).
wprep(){ mkdir -p "$(dirname "$1")"; _safe_dest "$1"; rm -f "$1"; }
wappend(){ _safe_dest "$1"; if [ -L "$1" ]; then echo "bootstrap: refusing — $1 is a symlink (would append outside the repo)" >&2; exit 2; fi; }
# render_precommit: render + strip profile/lang marker blocks.
#   starter  -> strip standard + strict blocks
#   standard -> strip strict blocks
#   strict   -> keep all
#   lang != python -> strip python-only blocks
render_precommit(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"; _safe_dest "$d"
  if [ -e "$d" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP ${d#./}"; return; fi
  local tmp; tmp="$(mktemp)"
  # {{PY}} = substrate-venv python (always present after `manage.sh setup`,
  # has PyYAML + stdlib — runs validators in any language repo).
  sed -e "s#{{RUN_PREFIX}}#$RUN_PREFIX#g" -e "s#{{PY}}#.substrate/venv/bin/python#g" "$s" > "$tmp"
  if [[ "$PROFILE" == "starter" ]]; then
    awk '/^ *# >>> standard$/{skip=1} /^ *# <<< standard$/{skip=0; next} !skip' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
  fi
  if [[ "$PROFILE" != "strict" ]]; then
    awk '/^ *# >>> strict$/{skip=1} /^ *# <<< strict$/{skip=0; next} !skip' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
  fi
  if [[ "$LANG_PRIMARY" != "python" ]]; then
    awk '/^ *# >>> python-only$/{skip=1} /^ *# <<< python-only$/{skip=0; next} !skip' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
  fi
  rm -f "$d"; grep -v '^ *# >>> \|^ *# <<< ' "$tmp" > "$d"; rm -f "$tmp"; echo "    +    ${d#./}"
}
echo "==> Installing Agent Substrate Kit v3 into $REPO_ROOT (profile=$PROFILE lang=$LANG_PRIMARY)"
# scripts/ is RESERVED by the substrate. If the target already has a scripts/ with the
# project's OWN files, warn + guide migration (advisory — never moves/clobbers anything;
# the copy below is SKIP-if-exists, so a name collision would otherwise silently leave
# the project's file shadowed by/mixed with substrate code). Real-repo trial #1.
if [ -d scripts ]; then
  _preexisting=""
  for _pf in scripts/*; do
    [ -f "$_pf" ] || continue
    _bn="$(basename "$_pf")"
    [ -f "$KIT_DIR/scripts/$_bn" ] && continue   # substrate-owned (about to be (re)written)
    _preexisting="$_preexisting $_bn"
  done
  if [ -n "$_preexisting" ]; then
    echo "    !!   scripts/ is reserved by the substrate; found pre-existing project files:$_preexisting"
    echo "    !!   move them to tools/ or bin/ to avoid mixing project + substrate code (advisory; nothing was changed)."
  fi
fi
mkdir -p scripts .substrate
for f in "$KIT_DIR"/scripts/*; do [ -f "$f" ] || continue; copy "$f" "scripts/$(basename "$f")"; chmod +x "scripts/$(basename "$f")" || true; done
# Extras (heavier ceremony) install only at strict profile.
if [[ "$PROFILE" == "strict" ]]; then for f in "$KIT_DIR"/extras/*.py; do [ -f "$f" ] || continue; copy "$f" "scripts/$(basename "$f")"; chmod +x "scripts/$(basename "$f")" || true; done; fi
# Substrate config: manage.sh + doctor read this. Operator may edit LINT/TYPECHECK/TEST commands.
if [ ! -e .substrate/config ] || [ "$FORCE" == "yes" ]; then
  wprep .substrate/config
  { echo "# Written by bootstrap.sh; parsed as DATA by scripts/_substrate_config.sh."; echo "# Do NOT source this file as shell."
    echo "SUBSTRATE_PROFILE=\"$PROFILE\""
    echo "SUBSTRATE_LANG=\"$LANG_PRIMARY\""
    echo "SUBSTRATE_RUNNER=\"$RUNNER\""
    echo "SUBSTRATE_SANDBOX=\"$SANDBOX\"   # 1 = contain agent egress via scripts/sandbox_exec.sh (backend resolved from .substrate/sandbox.json)"
    echo "SUBSTRATE_REMOTE_GOVERNANCE=\"$REMOTE_GOVERNANCE\"   # 1 = enforce remote governance (CODEOWNERS coverage + trusted-base authority); needs a GitHub remote"
    case "$LANG_PRIMARY" in
      python) echo 'LINT_CMD=""        # ruff runs via pre-commit'; echo 'TYPECHECK_CMD=""   # e.g. "uv run mypy src/"'; echo 'TEST_CMD=""        # pytest runs via pre-commit';;
      node|go) # gates run through the adapter, which detects opt-in and skips cleanly.
              echo 'LINT_CMD="bash scripts/lang_gate.sh lint"'; echo 'TYPECHECK_CMD="bash scripts/lang_gate.sh typecheck"'; echo 'TEST_CMD="bash scripts/lang_gate.sh test"';;
      *)      echo 'LINT_CMD=""'; echo 'TYPECHECK_CMD=""'; echo 'TEST_CMD=""';;
    esac
    echo '# SUBSTRATE_CODE_SUFFIXES=".rs,.kt"   # extend doc-drift code suffixes'
  } > .substrate/config; echo "    +    .substrate/config"
fi
# Profile LOCK: the minimum profile this repo may run at. check_substrate_config
# and the runtime hook refuse to go BELOW it, so a PR can't flip strict->standard
# to disable strict-only behavior. CODEOWNED + frozen by the trusted-base guard;
# lowering it is a deliberate, reviewed act. (Re)written to match the install.
wprep .substrate/required_profile; echo "$PROFILE" > .substrate/required_profile; echo "    +    .substrate/required_profile"
# Sandbox LOCK: the minimum containment requirement, frozen like required_profile.
# `--profile strict+sandbox` pins this to 1, so a PR can RAISE but never silently
# DISABLE containment (check_substrate_config + trusted-base enforce it). v3.5.1.
wprep .substrate/required_sandbox; echo "$SANDBOX" > .substrate/required_sandbox; echo "    +    .substrate/required_sandbox"
# Remote-governance LOCK: the minimum remote-governance requirement, frozen like
# required_profile/required_sandbox. `--profile *+remote` pins this to 1 so a PR can
# RAISE but never silently DISABLE remote governance (check_substrate_config +
# trusted-base enforce it). Orthogonal to the profile — decoupled from strict. v3.6.0.
wprep .substrate/required_remote_governance; echo "$REMOTE_GOVERNANCE" > .substrate/required_remote_governance; echo "    +    .substrate/required_remote_governance"
# Release/upgrade TRUST ANCHOR (v3.7.13): copy the kit maintainer's minisign public key so
# this repo can VERIFY the authenticity of a kit release before applying an upgrade
# (scripts/verify_release.py / `./manage.sh verify-release`). Public key only — no secret.
if [ -f "$KIT_DIR/.substrate/trust/minisign.pub" ]; then
  mkdir -p .substrate/trust; copy "$KIT_DIR/.substrate/trust/minisign.pub" .substrate/trust/minisign.pub
fi
# Sandbox backend policy (DATA, validated fail-closed by scripts/sandbox_detect.py).
# Written always so it's discoverable + editable; only ENFORCED when SUBSTRATE_SANDBOX=1.
# backend=auto prefers @anthropic-ai/sandbox-runtime (srt) if present, else the OS-native
# primitive (Linux bubblewrap / macOS seatbelt), else none (fail-closed in strict+sandbox).
if [ ! -e .substrate/sandbox.json ] || [ "$FORCE" == "yes" ]; then
  wprep .substrate/sandbox.json
  { echo '{'
    echo '  "backend": "auto",'
    echo '  "network": "deny",'
    echo '  "allowed_domains": [],'
    echo '  "write_scope": "repo",'
    echo '  "deny_read": ["~/.ssh", "~/.aws", "~/.config/gh", ".env"]'
    echo '}'
  } > .substrate/sandbox.json; echo "    +    .substrate/sandbox.json"
fi
render "$KIT_DIR/templates/AGENTS.md" AGENTS.md; render "$KIT_DIR/templates/CLAUDE.md" CLAUDE.md
if [[ "$LANG_PRIMARY" == "python" ]]; then render "$KIT_DIR/templates/pyproject.toml.template" pyproject.toml; fi
render_precommit "$KIT_DIR/templates/pre-commit-config.yaml.template" .pre-commit-config.yaml
render "$KIT_DIR/templates/manage.sh.template" manage.sh; chmod +x manage.sh
render "$KIT_DIR/templates/codex/config.toml.template" .codex/config.toml; render "$KIT_DIR/templates/codex/hooks.json.template" .codex/hooks.json; render "$KIT_DIR/templates/claude/settings.json.template" .claude/settings.json
# Skills: copy the whole skill dir (SKILL.md + any references/) to both harnesses.
for sd in "$KIT_DIR"/skills/*; do [ -d "$sd" ] || continue; sn="$(basename "$sd")"; mkdir -p ".agents/skills" ".claude/skills"; _safe_dest ".claude/skills/$sn"; _safe_dest ".agents/skills/$sn"
  if [ -d ".claude/skills/$sn" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP .claude/skills/$sn"; else rm -rf ".claude/skills/$sn"; cp -R "$sd" ".claude/skills/$sn"; echo "    +    .claude/skills/$sn"; fi
  if [ -d ".agents/skills/$sn" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP .agents/skills/$sn"; else rm -rf ".agents/skills/$sn"; cp -R "$sd" ".agents/skills/$sn"; echo "    +    .agents/skills/$sn"; fi
done
mkdir -p .claude/agents .codex/agents; for f in "$KIT_DIR"/agents/claude/*; do [ -f "$f" ] && copy "$f" ".claude/agents/$(basename "$f")"; done; for f in "$KIT_DIR"/agents/codex/*; do [ -f "$f" ] && copy "$f" ".codex/agents/$(basename "$f")"; done
mkdir -p docs/decisions docs/postmortems docs/knowledge docs/templates docs/blind-spot-checklists
copy "$KIT_DIR/templates/0000-adr-template.md" docs/decisions/0000-template.md; copy "$KIT_DIR/templates/postmortem_template.md" docs/postmortems/_template.md; copy "$KIT_DIR/templates/knowledge_doc_template.md" docs/knowledge/_template.md; copy "$KIT_DIR/templates/finding_response.md" docs/templates/finding_response.md; copy "$KIT_DIR/templates/diy_ultrareview_prompts.md" docs/templates/diy_ultrareview_prompts.md
for f in "$KIT_DIR"/templates/blind-spot-checklists/*.md; do [ -f "$f" ] && copy "$f" "docs/blind-spot-checklists/$(basename "$f")"; done
if [ ! -e docs/HISTORY.md ] || [ "$FORCE" == "yes" ]; then wprep docs/HISTORY.md; cat > docs/HISTORY.md <<'HISTORY'
# HISTORY.md — Append-only project changelog

**DO NOT EDIT prior entries.** Update only via `scripts/append_history.py`.
This file is `merge=union` in `.gitattributes` so concurrent branch entries combine.

HISTORY
echo "    +    docs/HISTORY.md"; fi
if [ ! -e docs/README.md ] || [ "$FORCE" == "yes" ]; then wprep docs/README.md; cat > docs/README.md <<'DOCS'
# docs/

Project documentation index.

- `HISTORY.md` — append-only changelog.
- `manifest.json` — generated index of knowledge docs and ADRs.
- `decisions/` — Architecture Decision Records.
- `postmortems/` — bug/finding postmortems.
- `knowledge/` — subsystem knowledge docs with `covers:` frontmatter.
- `blind-spot-checklists/` — per-domain bug-class catalogs (read by the
  checklist-auditor subagent, not by the main context).
DOCS
echo "    +    docs/README.md"; fi
[ -e docs/ARCHITECTURE.md ] || { wprep docs/ARCHITECTURE.md; echo '# Architecture

TODO.' > docs/ARCHITECTURE.md; echo "    +    docs/ARCHITECTURE.md"; }
[ -e docs/INTENT.md ] || { wprep docs/INTENT.md; echo '# Intent

TODO.' > docs/INTENT.md; echo "    +    docs/INTENT.md"; }
if [ ! -e docs/knowledge/00_substrate.md ] || [ "$FORCE" == "yes" ]; then wprep docs/knowledge/00_substrate.md; { echo '---'; echo 'purpose: Universal Agent Substrate Kit v3 files installed in this repo.'; echo "last_human_reviewed: $TODAY"; echo 'covers:'; find scripts -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) | sort | while read -r p; do echo "  - $p"; done; echo '---'; echo; echo '# Substrate'; echo; echo 'This document covers the installed AI/self-audit substrate scripts.'; } > docs/knowledge/00_substrate.md; echo "    +    docs/knowledge/00_substrate.md"; fi
# Consumer install OMITS the kit's heavy behavioral self-tests (test_hook_scripts,
# test_doc_consistency): on byte-identical vendored code they re-prove what the kit's
# OWN CI already proves, adding ~2 min to every consumer CI run for ~zero marginal
# safety (content-pins already detect vendored-file tampering more cheaply). The cheap
# install-integrity tests are KEPT — test_substrate_files.py runs only in an installed
# repo, test_smoke.py keeps pytest off exit-5 before the project adds tests, and
# conftest.py carries their fixtures. The kit's own tests/ dir is untouched. --dev-tests
# vendors the full suite (dogfooding). Strip list = scripts/_substrate_surfaces.py (SSOT).
mkdir -p tests
STRIP_TESTS=""
if [[ "$DEV_TESTS" != "yes" ]]; then
  STRIP_TESTS="$(python3 "$KIT_DIR/scripts/_substrate_surfaces.py" --consumer-strip-tests 2>/dev/null \
              || python "$KIT_DIR/scripts/_substrate_surfaces.py" --consumer-strip-tests 2>/dev/null || true)"
fi
for f in "$KIT_DIR"/tests/*.py; do
  [ -f "$f" ] || continue
  bn="$(basename "$f")"
  if [[ -n "$STRIP_TESTS" ]] && printf '%s\n' "$STRIP_TESTS" | grep -qxF "$bn"; then
    echo "    -    tests/$bn  (kit self-test; omitted from install — see --dev-tests)"; continue
  fi
  copy "$f" "tests/$bn"
done
copy "$KIT_DIR/templates/pytest.ini.template" pytest.ini   # deterministic, hermetic test runs in the installed repo too
mkdir -p .github/workflows; render "$KIT_DIR/workflows/ci.yml.template" .github/workflows/ci.yml; render "$KIT_DIR/workflows/scheduled-audit.yml.template" .github/workflows/scheduled-audit.yml; render "$KIT_DIR/workflows/agent-config-audit.yml.template" .github/workflows/agent-config-audit.yml
# Stage the trusted-base template under .substrate/ ALWAYS (like .substrate/sandbox.json)
# so `manage.sh enable remote --write` can install the active workflow later WITHOUT a
# re-bootstrap — the "scale on demand, one command" path. (No render placeholders in it;
# this raw copy == what the remote-tier render produces.) v3.6.1.
copy "$KIT_DIR/workflows/trusted-base-audit.yml.template" .substrate/trusted-base-audit.yml.template
# Distribution-tier templates (v3.7.18): staged DORMANT like trusted-base, activated on demand
# by `./manage.sh enable release ci|keyless` / `enable auto-upgrade` — the "ready
# out-of-the-box, scale by one command" path (no re-bootstrap needed to climb a rung).
for _rt in release-ci-minisign.yml.template release-keyless.yml.template auto-upgrade.yml.template; do
  [ -f "$KIT_DIR/workflows/$_rt" ] && copy "$KIT_DIR/workflows/$_rt" ".substrate/$_rt"
done
# Profile-ratchet staging (v3.8.2): the RAW pre-commit template (placeholders + marker
# blocks intact) plus the strict-only extras, so `manage.sh enable profile <p> --write`
# (scripts/substrate_profile.py) can re-render + install strict extras IN PLACE later —
# no kit checkout, no re-bootstrap. Same dormant-staging pattern as the workflow tiers.
copy "$KIT_DIR/templates/pre-commit-config.yaml.template" .substrate/pre-commit-config.yaml.template
for _xf in "$KIT_DIR"/extras/*.py; do
  [ -f "$_xf" ] && copy "$_xf" ".substrate/extras/$(basename "$_xf")"
done
# Strict root-of-trust: run base-branch validators against PR content so a PR
# cannot weaken both the policy and its own validator. This is a REMOTE-governance
# artifact (a CI workflow + CODEOWNERS authority that only mean anything on a GitHub
# remote), so v3.6.0 gates it on the remote tier — NOT the strict profile. A
# strict-LOCAL repo (no remote) no longer gets a useless CI workflow; `strict+remote`
# (or `enable remote`) writes it. (Decouples remote governance from `strict`.)
if [[ "$REMOTE_GOVERNANCE" == "1" ]]; then render "$KIT_DIR/workflows/trusted-base-audit.yml.template" .github/workflows/trusted-base-audit.yml; fi
copy "$KIT_DIR/templates/pull_request_template.md" .github/pull_request_template.md; copy "$KIT_DIR/templates/CODEOWNERS.template" .github/CODEOWNERS.suggested; copy "$KIT_DIR/templates/SECURITY.md" SECURITY.md; copy "$KIT_DIR/templates/CONTRIBUTING.md" CONTRIBUTING.md
# GitHub Copilot reads .github/copilot-instructions.md natively; point it at AGENTS.md.
copy "$KIT_DIR/templates/copilot-instructions.md" .github/copilot-instructions.md
# Path-scoped Copilot instructions (the dir copilot-instructions.md references).
mkdir -p .github/instructions; for f in "$KIT_DIR"/templates/github/*.instructions.md; do [ -f "$f" ] && copy "$f" ".github/instructions/$(basename "$f")"; done
# Copilot coding-agent hooks (preToolUse exfil guard via adapter + session handoff).
mkdir -p .github/hooks; copy "$KIT_DIR/templates/github/exfil-guard.hook.json" .github/hooks/exfil-guard.json
# Language-aware Dependabot: the project ecosystem + github-actions.
if [ ! -e .github/dependabot.yml ] || [ "$FORCE" == "yes" ]; then
  wprep .github/dependabot.yml
  case "$LANG_PRIMARY" in node) ECO="npm";; go) ECO="gomod";; python) ECO="pip";; *) ECO="";; esac
  { echo "# Dependabot — generated for lang=$LANG_PRIMARY. See docs for tuning."; echo "version: 2"; echo "updates:";
    if [ -n "$ECO" ]; then echo "  - package-ecosystem: \"$ECO\""; echo "    directory: \"/\""; echo "    schedule: {interval: \"weekly\"}"; echo "    open-pull-requests-limit: 5"; echo "    labels: [\"dependencies\", \"$LANG_PRIMARY\"]"; fi
    echo "  - package-ecosystem: \"github-actions\""; echo "    directory: \"/\""; echo "    schedule: {interval: \"weekly\"}"; echo "    open-pull-requests-limit: 3"; echo "    labels: [\"dependencies\", \"ci\"]";
  } > .github/dependabot.yml; echo "    +    .github/dependabot.yml"
fi
if [ "$UI_ENABLED" == "yes" ]; then mkdir -p design-system/pages design-system/tokens; [ -e design-system/MASTER.md ] || { wprep design-system/MASTER.md; echo '# Design System Master

TODO.' > design-system/MASTER.md; echo "    +    design-system/MASTER.md"; }; fi
if [ ! -e .gitattributes ] || ! grep -q 'docs/HISTORY.md' .gitattributes; then wappend .gitattributes; echo 'docs/HISTORY.md merge=union' >> .gitattributes; echo "    +    .gitattributes"; fi
wappend .gitignore; [ -e .gitignore ] || touch .gitignore; for line in docs/CURRENT_SESSION.md docs/.todo_state.json .substrate/memory/tasks/ .substrate/traces/ .substrate/venv/ .substrate/dep_cooldown_cache.json 'ai/audits/*/audit-report.json' __pycache__/ .venv/ .pytest_cache/ .ruff_cache/ .mypy_cache/ node_modules/ dist/ build/; do grep -qxF "$line" .gitignore || echo "$line" >> .gitignore; done
[ -e docs/.todo_state.json ] || { wprep docs/.todo_state.json; echo '{"version":1,"items":[]}' > docs/.todo_state.json; }
python3 scripts/update_manifest.py --fix >/dev/null || python scripts/update_manifest.py --fix >/dev/null
# Provenance + drift baseline for `./manage.sh upgrade` (v3.7.14): record the kit
# version/commit/source, the FULL answer set, and a hash of every owned file.
KIT_VER="$(tr -d '[:space:]' < "$KIT_DIR/VERSION" 2>/dev/null || echo 0.0.0)"
# SUBSTRATE_KIT_COMMIT/SOURCE let a verified installer (substrate-init) pass the commit parsed
# from the signed trusted comment — a .zip extract has no .git, so git rev-parse would record
# 'none' (v3.7.16 P2b). Env override wins; else fall back to the kit's own git metadata.
KIT_COMMIT="${SUBSTRATE_KIT_COMMIT:-$(git -C "$KIT_DIR" rev-parse --short HEAD 2>/dev/null || echo none)}"
KIT_SRC="${SUBSTRATE_KIT_SOURCE:-$(git -C "$KIT_DIR" remote get-url origin 2>/dev/null || echo "$KIT_DIR")}"
python3 scripts/write_install_json.py --root . --version "$KIT_VER" --commit "$KIT_COMMIT" \
  --source "$KIT_SRC" --installed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --profile "$PROFILE" --lang "$LANG_PRIMARY" --runner "$RUNNER" --ui "$UI_ENABLED" \
  --workflow "$WORKFLOW" --sandbox "$SANDBOX" --remote-governance "$REMOTE_GOVERNANCE" >/dev/null 2>&1 || true
[ "$INSTALL_TOOLS" == "yes" ] && ./manage.sh setup || true
# Default post-bootstrap check is --quick: the substrate venv does not
# exist until `./manage.sh setup`, so an operational/full doctor here
# would always BLOCK (the v3.2 bootstrap-deadlock bug). --install-tools
# runs setup first, so a full doctor is safe in that path.
if [ "$RUN_DOCTOR" == "yes" ]; then
  if [ "$INSTALL_TOOLS" == "yes" ]; then DOCTOR_MODE=""; else DOCTOR_MODE="--quick"; fi
  python3 scripts/substrate_doctor.py $DOCTOR_MODE || python scripts/substrate_doctor.py $DOCTOR_MODE
fi
echo; echo "==> Agent Substrate Kit v3 installed (profile=$PROFILE, lang=$LANG_PRIMARY)."; echo "Next: ./manage.sh setup && ./manage.sh doctor --operational && ./manage.sh check"; echo "Then edit AGENTS.md project-specific section and make your first commit."
