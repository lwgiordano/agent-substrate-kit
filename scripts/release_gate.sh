#!/usr/bin/env bash
set -euo pipefail
# Language-aware release gate. Substrate validators are always Python
# (stdlib + PyYAML). Language-native test/lint run via .substrate/config
# indirection so this gate works in node/go repos too.
SUBSTRATE_LANG="python"; LINT_CMD=""; TYPECHECK_CMD=""; TEST_CMD=""
. scripts/_substrate_config.sh; load_substrate_config || { echo "substrate-config: refusing to run with invalid .substrate/config" >&2; exit 2; }
SUBVENV=".substrate/venv"
if command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then RUN=(uv run); elif command -v poetry >/dev/null 2>&1 && [ -f pyproject.toml ]; then RUN=(poetry run); else RUN=(); fi
# Validators run from the substrate venv if present (works in any
# language); else fall back to the project runner.
# `-I` (isolated): repo-local stdlib shadows (scripts/hashlib.py …) can't
# hijack a validator's imports and defeat the hash pins.
run_py(){ if [ -x "$SUBVENV/bin/python" ]; then "$SUBVENV/bin/python" -I "$@"; else "${RUN[@]}" python3 -I "$@" 2>/dev/null || "${RUN[@]}" python -I "$@"; fi; }
# Substrate tools (pre-commit) ALWAYS come from the substrate venv —
# never ambient PATH (the v3.2 release-gate `pre-commit: command not
# found` bug in node/go repos).
# Route project/test execution (pytest etc.) through the sandbox when the tier is
# enabled (v3.5.3) — but NOT pre-commit itself (it orchestrates hooks that route their
# own leaves via run_python_gate/lang_gate, and may need fs/net for some hooks).
run_tool(){ local t="$1"; shift || true; local -a c
  if [ -x "$SUBVENV/bin/$t" ]; then c=("$SUBVENV/bin/$t"); else c=("${RUN[@]}" "$t"); fi
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ] && [ "$t" != "pre-commit" ]; then scripts/sandbox_exec.sh "${c[@]}" "$@"; else "${c[@]}" "$@"; fi; }
# Configured LINT_CMD/TYPECHECK_CMD/TEST_CMD are executable PROJECT code → contained too.
run_lang(){ local label="$1" cmd="$2"; [ -z "$cmd" ] && return 0; echo "==> $label: $cmd"
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ]; then scripts/sandbox_exec.sh bash -c "$cmd"; else bash -c "$cmd"; fi; }
echo "==> Import shadowing"; run_py scripts/check_import_shadowing.py  # no repo-local stdlib shadow can subvert hash validators
echo "==> Doctor"; run_py scripts/substrate_doctor.py
echo "==> Manifest"; run_py scripts/update_manifest.py --check
echo "==> Doc drift"; run_py scripts/check_doc_drift.py --strict
echo "==> Python syntax"; run_py scripts/check_python_syntax.py        # broken hook would fail-open as rc1, not block
echo "==> Harness patterns"; run_py scripts/check_harness_patterns.py  # safety-policy data intact (regexes hash-pinned)
echo "==> Policy code integrity"; run_py scripts/check_policy_code_integrity.py  # policy + scanner LOGIC intact (AST-pinned)
echo "==> Harness smoke"; run_py scripts/check_harness_smoke.py        # scanner actually blocks injected context (multi-family)
echo "==> Hook smoke"; run_py scripts/check_hook_smoke.py              # hooks must actually DENY (compile-clean but neutered hook)
echo "==> Agent harness"; run_py scripts/check_agent_harness.py
echo "==> Config commands"; run_py scripts/check_substrate_config.py   # before run_lang executes them
echo "==> Secrets"; run_py scripts/check_secrets.py
echo "==> History"; run_py scripts/check_history_sha.py
# Durable memory integrity: verify the hash chain, and the anchor in strict
# (the structured handoff + event log are the tamper-evident record).
if [ -f .substrate/memory/events.jsonl ]; then
  echo "==> Memory chain"
  if [ "$SUBSTRATE_PROFILE" = "strict" ] && [ -n "$(git notes --ref=substrate-memory list 2>/dev/null)" ]; then
    run_py scripts/memory_log.py verify --anchor
  else
    run_py scripts/memory_log.py verify
  fi
fi
if [ "$SUBSTRATE_LANG" = "python" ]; then
  echo "==> Tests (pytest)"; run_tool pytest tests/ -q
else
  run_lang "lint" "$LINT_CMD"; run_lang "typecheck" "$TYPECHECK_CMD"; run_lang "test" "$TEST_CMD"
fi
echo "==> Pre-commit"; run_tool pre-commit run --all-files --show-diff-on-failure
echo "==> Behavior evals"; run_py scripts/run_substrate_evals.py   # measured block-rate / FP-rate
echo "==> Audit report"; run_py scripts/substrate_audit.py --mode quick --write-report
echo "release-gate: passed"
