#!/usr/bin/env bash
# Python gate adapter — resolves the tool runner CONSISTENTLY with what
# `manage.sh setup` installed, so explicit --runner python/poetry don't
# render ambient or mismatched commands (the v3.2.1 runner-flexibility
# finding). Used by the python-only pre-commit hooks.
#
# Usage: scripts/run_python_gate.sh <format|lint|typecheck|test>
set -euo pipefail
SUBSTRATE_RUNNER="auto"
# Fail CLOSED on an invalid config (don't silently run under defaults).
if [ -f scripts/_substrate_config.sh ]; then
  . scripts/_substrate_config.sh
  load_substrate_config || { echo "run_python_gate: refusing to run with invalid .substrate/config" >&2; exit 2; }
elif [ -f .substrate/config ]; then
  echo "run_python_gate: .substrate/config present but parser missing" >&2; exit 2
fi
gate="${1:?usage: run_python_gate.sh <format|lint|typecheck|test>}"; shift || true

# Resolve a runner prefix deterministically. Explicit runner wins; if it
# is unavailable we FAIL loudly rather than silently falling back (a
# silent fallback is how the wrong env ran tools in v3.2.1).
resolve() {
  case "$SUBSTRATE_RUNNER" in
    uv)     command -v uv >/dev/null 2>&1 || { echo "run_python_gate: --runner uv selected but uv not found" >&2; exit 3; }; echo "uv run";;
    poetry) command -v poetry >/dev/null 2>&1 || { echo "run_python_gate: --runner poetry selected but poetry not found" >&2; exit 3; }; echo "poetry run";;
    python) echo "VENV";;
    auto|*)
      if command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then echo "uv run"
      elif command -v poetry >/dev/null 2>&1 && [ -f pyproject.toml ]; then echo "poetry run"
      else echo "VENV"; fi;;
  esac
}
PREFIX="$(resolve)"
# VENV: prefer project .venv, then substrate venv, then ambient.
run_tool() {
  local tool="$1"; shift || true
  if [ "$PREFIX" = "VENV" ]; then
    if [ -x ".venv/bin/$tool" ]; then ".venv/bin/$tool" "$@"
    elif [ -x ".substrate/venv/bin/$tool" ]; then ".substrate/venv/bin/$tool" "$@"
    else "$tool" "$@"; fi
  else
    $PREFIX "$tool" "$@"
  fi
}
case "$gate" in
  format)    run_tool ruff format "$@";;
  lint)      run_tool ruff check --fix "$@";;
  typecheck) run_tool mypy "$@";;
  test)      run_tool pytest tests/ -q "$@";;
  *) echo "run_python_gate: unknown gate '$gate'" >&2; exit 2;;
esac
