#!/usr/bin/env bash
set -euo pipefail
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$(pwd)"; RUNNER="auto"; WORKFLOW="superpowers"; UI_ENABLED="no"; PROFILE="standard"; LANG_PRIMARY="auto"; FORCE="no"; INSTALL_TOOLS="no"; RUN_DOCTOR="yes"
usage(){ cat <<'HELP'
Agent Substrate Kit v3 bootstrap
Options:
  --target PATH
  --runner auto|uv|python|poetry
  --workflow superpowers|gsd|none
  --ui yes|no
  --profile starter|standard|strict
  --lang auto|python|node|go|none
  --force
  --install-tools
  --no-doctor
HELP
}
while [[ $# -gt 0 ]]; do case "$1" in --target) TARGET="$2"; shift 2;; --runner) RUNNER="$2"; shift 2;; --workflow) WORKFLOW="$2"; shift 2;; --ui) UI_ENABLED="$2"; shift 2;; --profile) PROFILE="$2"; shift 2;; --lang) LANG_PRIMARY="$2"; shift 2;; --force) FORCE="yes"; shift;; --install-tools) INSTALL_TOOLS="yes"; shift;; --no-doctor) RUN_DOCTOR="no"; shift;; -h|--help) usage; exit 0;; *) echo "Unknown option $1"; usage; exit 1;; esac; done
case "$RUNNER" in auto|uv|python|poetry) ;; *) echo "invalid runner"; exit 1;; esac
case "$WORKFLOW" in superpowers|gsd|none) ;; *) echo "invalid workflow"; exit 1;; esac
case "$PROFILE" in starter|standard|strict) ;; *) echo "invalid profile"; exit 1;; esac
case "$LANG_PRIMARY" in auto|python|node|go|none) ;; *) echo "invalid lang"; exit 1;; esac
case "$UI_ENABLED" in yes|no|true|false|ui|no-ui) ;; *) echo "invalid ui"; exit 1;; esac
[[ "$UI_ENABLED" == "true" || "$UI_ENABLED" == "ui" ]] && UI_ENABLED="yes"; [[ "$UI_ENABLED" == "false" || "$UI_ENABLED" == "no-ui" ]] && UI_ENABLED="no"
mkdir -p "$TARGET"; cd "$TARGET"; REPO_ROOT="$(pwd)"
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
copy(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"; if [ -e "$d" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP ${d#./}"; else cp "$s" "$d"; echo "    +    ${d#./}"; fi; }
render(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"; if [ -e "$d" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP ${d#./}"; else sed -e "s/{{PROJECT_SLUG}}/$PROJECT_SLUG/g" -e "s/{{WORKFLOW}}/$WORKFLOW/g" -e "s/{{UI_ENABLED}}/$UI_ENABLED/g" -e "s/{{RUNNER}}/$RUNNER/g" -e "s/{{PROFILE}}/$PROFILE/g" -e "s/{{LANG}}/$LANG_PRIMARY/g" -e "s#{{RUN_PREFIX}}#$RUN_PREFIX#g" "$s" > "$d"; echo "    +    ${d#./}"; fi; }
# render_precommit: render + strip profile/lang marker blocks.
#   starter  -> strip standard + strict blocks
#   standard -> strip strict blocks
#   strict   -> keep all
#   lang != python -> strip python-only blocks
render_precommit(){ local s="$1" d="$2"; mkdir -p "$(dirname "$d")"
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
  grep -v '^ *# >>> \|^ *# <<< ' "$tmp" > "$d"; rm -f "$tmp"; echo "    +    ${d#./}"
}
echo "==> Installing Agent Substrate Kit v3 into $REPO_ROOT (profile=$PROFILE lang=$LANG_PRIMARY)"
mkdir -p scripts .substrate
for f in "$KIT_DIR"/scripts/*; do [ -f "$f" ] || continue; copy "$f" "scripts/$(basename "$f")"; chmod +x "scripts/$(basename "$f")" || true; done
# Extras (heavier ceremony) install only at strict profile.
if [[ "$PROFILE" == "strict" ]]; then for f in "$KIT_DIR"/extras/*.py; do [ -f "$f" ] || continue; copy "$f" "scripts/$(basename "$f")"; chmod +x "scripts/$(basename "$f")" || true; done; fi
# Substrate config: manage.sh + doctor read this. Operator may edit LINT/TYPECHECK/TEST commands.
if [ ! -e .substrate/config ] || [ "$FORCE" == "yes" ]; then
  { echo "# Written by bootstrap.sh; parsed as DATA by scripts/_substrate_config.sh."; echo "# Do NOT source this file as shell."
    echo "SUBSTRATE_PROFILE=\"$PROFILE\""
    echo "SUBSTRATE_LANG=\"$LANG_PRIMARY\""
    echo "SUBSTRATE_RUNNER=\"$RUNNER\""
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
echo "$PROFILE" > .substrate/required_profile; echo "    +    .substrate/required_profile"
render "$KIT_DIR/templates/AGENTS.md" AGENTS.md; render "$KIT_DIR/templates/CLAUDE.md" CLAUDE.md
if [[ "$LANG_PRIMARY" == "python" ]]; then render "$KIT_DIR/templates/pyproject.toml.template" pyproject.toml; fi
render_precommit "$KIT_DIR/templates/pre-commit-config.yaml.template" .pre-commit-config.yaml
render "$KIT_DIR/templates/manage.sh.template" manage.sh; chmod +x manage.sh
render "$KIT_DIR/templates/codex/config.toml.template" .codex/config.toml; render "$KIT_DIR/templates/codex/hooks.json.template" .codex/hooks.json; render "$KIT_DIR/templates/claude/settings.json.template" .claude/settings.json
# Skills: copy the whole skill dir (SKILL.md + any references/) to both harnesses.
for sd in "$KIT_DIR"/skills/*; do [ -d "$sd" ] || continue; sn="$(basename "$sd")"; mkdir -p ".agents/skills" ".claude/skills"
  if [ -d ".claude/skills/$sn" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP .claude/skills/$sn"; else rm -rf ".claude/skills/$sn"; cp -R "$sd" ".claude/skills/$sn"; echo "    +    .claude/skills/$sn"; fi
  if [ -d ".agents/skills/$sn" ] && [ "$FORCE" != "yes" ]; then echo "    SKIP .agents/skills/$sn"; else rm -rf ".agents/skills/$sn"; cp -R "$sd" ".agents/skills/$sn"; echo "    +    .agents/skills/$sn"; fi
done
mkdir -p .claude/agents .codex/agents; for f in "$KIT_DIR"/agents/claude/*; do [ -f "$f" ] && copy "$f" ".claude/agents/$(basename "$f")"; done; for f in "$KIT_DIR"/agents/codex/*; do [ -f "$f" ] && copy "$f" ".codex/agents/$(basename "$f")"; done
mkdir -p docs/decisions docs/postmortems docs/knowledge docs/templates docs/blind-spot-checklists
copy "$KIT_DIR/templates/0000-adr-template.md" docs/decisions/0000-template.md; copy "$KIT_DIR/templates/postmortem_template.md" docs/postmortems/_template.md; copy "$KIT_DIR/templates/knowledge_doc_template.md" docs/knowledge/_template.md; copy "$KIT_DIR/templates/finding_response.md" docs/templates/finding_response.md; copy "$KIT_DIR/templates/diy_ultrareview_prompts.md" docs/templates/diy_ultrareview_prompts.md
for f in "$KIT_DIR"/templates/blind-spot-checklists/*.md; do [ -f "$f" ] && copy "$f" "docs/blind-spot-checklists/$(basename "$f")"; done
if [ ! -e docs/HISTORY.md ] || [ "$FORCE" == "yes" ]; then cat > docs/HISTORY.md <<'HISTORY'
# HISTORY.md — Append-only project changelog

**DO NOT EDIT prior entries.** Update only via `scripts/append_history.py`.
This file is `merge=union` in `.gitattributes` so concurrent branch entries combine.

HISTORY
echo "    +    docs/HISTORY.md"; fi
if [ ! -e docs/README.md ] || [ "$FORCE" == "yes" ]; then cat > docs/README.md <<'DOCS'
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
[ -e docs/ARCHITECTURE.md ] || { echo '# Architecture

TODO.' > docs/ARCHITECTURE.md; echo "    +    docs/ARCHITECTURE.md"; }
[ -e docs/INTENT.md ] || { echo '# Intent

TODO.' > docs/INTENT.md; echo "    +    docs/INTENT.md"; }
if [ ! -e docs/knowledge/00_substrate.md ] || [ "$FORCE" == "yes" ]; then { echo '---'; echo 'purpose: Universal Agent Substrate Kit v3 files installed in this repo.'; echo "last_human_reviewed: $TODAY"; echo 'covers:'; find scripts -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) | sort | while read -r p; do echo "  - $p"; done; echo '---'; echo; echo '# Substrate'; echo; echo 'This document covers the installed AI/self-audit substrate scripts.'; } > docs/knowledge/00_substrate.md; echo "    +    docs/knowledge/00_substrate.md"; fi
mkdir -p tests; for f in "$KIT_DIR"/tests/*.py; do [ -f "$f" ] && copy "$f" "tests/$(basename "$f")"; done
copy "$KIT_DIR/templates/pytest.ini.template" pytest.ini   # deterministic, hermetic test runs in the installed repo too
mkdir -p .github/workflows; render "$KIT_DIR/workflows/ci.yml.template" .github/workflows/ci.yml; render "$KIT_DIR/workflows/scheduled-audit.yml.template" .github/workflows/scheduled-audit.yml; render "$KIT_DIR/workflows/agent-config-audit.yml.template" .github/workflows/agent-config-audit.yml
# Strict root-of-trust: run base-branch validators against PR content so a PR
# cannot weaken both the policy and its own validator. Strict profile only.
if [[ "$PROFILE" == "strict" ]]; then render "$KIT_DIR/workflows/trusted-base-audit.yml.template" .github/workflows/trusted-base-audit.yml; fi
copy "$KIT_DIR/templates/pull_request_template.md" .github/pull_request_template.md; copy "$KIT_DIR/templates/CODEOWNERS.template" .github/CODEOWNERS.suggested; copy "$KIT_DIR/templates/SECURITY.md" SECURITY.md; copy "$KIT_DIR/templates/CONTRIBUTING.md" CONTRIBUTING.md
# GitHub Copilot reads .github/copilot-instructions.md natively; point it at AGENTS.md.
copy "$KIT_DIR/templates/copilot-instructions.md" .github/copilot-instructions.md
# Path-scoped Copilot instructions (the dir copilot-instructions.md references).
mkdir -p .github/instructions; for f in "$KIT_DIR"/templates/github/*.instructions.md; do [ -f "$f" ] && copy "$f" ".github/instructions/$(basename "$f")"; done
# Copilot coding-agent hooks (preToolUse exfil guard via adapter + session handoff).
mkdir -p .github/hooks; copy "$KIT_DIR/templates/github/exfil-guard.hook.json" .github/hooks/exfil-guard.json
# Language-aware Dependabot: the project ecosystem + github-actions.
if [ ! -e .github/dependabot.yml ] || [ "$FORCE" == "yes" ]; then
  case "$LANG_PRIMARY" in node) ECO="npm";; go) ECO="gomod";; python) ECO="pip";; *) ECO="";; esac
  { echo "# Dependabot — generated for lang=$LANG_PRIMARY. See docs for tuning."; echo "version: 2"; echo "updates:";
    if [ -n "$ECO" ]; then echo "  - package-ecosystem: \"$ECO\""; echo "    directory: \"/\""; echo "    schedule: {interval: \"weekly\"}"; echo "    open-pull-requests-limit: 5"; echo "    labels: [\"dependencies\", \"$LANG_PRIMARY\"]"; fi
    echo "  - package-ecosystem: \"github-actions\""; echo "    directory: \"/\""; echo "    schedule: {interval: \"weekly\"}"; echo "    open-pull-requests-limit: 3"; echo "    labels: [\"dependencies\", \"ci\"]";
  } > .github/dependabot.yml; echo "    +    .github/dependabot.yml"
fi
if [ "$UI_ENABLED" == "yes" ]; then mkdir -p design-system/pages design-system/tokens; [ -e design-system/MASTER.md ] || { echo '# Design System Master

TODO.' > design-system/MASTER.md; echo "    +    design-system/MASTER.md"; }; fi
if [ ! -e .gitattributes ] || ! grep -q 'docs/HISTORY.md' .gitattributes; then echo 'docs/HISTORY.md merge=union' >> .gitattributes; echo "    +    .gitattributes"; fi
[ -e .gitignore ] || touch .gitignore; for line in docs/CURRENT_SESSION.md docs/.todo_state.json .substrate/memory/tasks/ .substrate/traces/ .substrate/venv/ 'ai/audits/*/audit-report.json' __pycache__/ .venv/ .pytest_cache/ .ruff_cache/ .mypy_cache/ node_modules/ dist/ build/; do grep -qxF "$line" .gitignore || echo "$line" >> .gitignore; done
[ -e docs/.todo_state.json ] || echo '{"version":1,"items":[]}' > docs/.todo_state.json
python3 scripts/update_manifest.py --fix >/dev/null || python scripts/update_manifest.py --fix >/dev/null
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
