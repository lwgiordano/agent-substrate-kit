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
_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
run_tool() {
  local tool="$1"; shift || true
  local -a cmd
  if [ "$PREFIX" = "VENV" ]; then
    if [ -x ".venv/bin/$tool" ]; then cmd=(".venv/bin/$tool")
    elif [ -x ".substrate/venv/bin/$tool" ]; then cmd=(".substrate/venv/bin/$tool")
    else cmd=("$tool"); fi
  else
    # shellcheck disable=SC2206
    cmd=($PREFIX "$tool")
  fi
  # Contain test/lint execution when the sandbox tier is enabled (v3.5.2): ruff/mypy/
  # pytest run project + test code. Fails closed (exit 3) if a backend is required but
  # absent. (run_tool here only ever runs ruff/mypy/pytest — never pre-commit itself.)
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ] && [ -x "$_SCRIPTS_DIR/sandbox_exec.sh" ]; then
    "$_SCRIPTS_DIR/sandbox_exec.sh" "${cmd[@]}" "$@"
  else
    "${cmd[@]}" "$@"
  fi
}
# Drop substrate-RESERVED paths from the ruff FILE ARGUMENTS (v3.8.26 / adoption:pyproject).
# Bootstrap correctly REFUSES to clobber a pre-existing pyproject.toml, so a repo that already
# had one (i.e. essentially every real Python product) never received the kit's
# `[tool.ruff] extend-exclude` — ruff then fell back to its defaults, linted the VENDORED
# substrate code, and E402 in scripts/*.py BLOCKED every commit. Config the operator may not
# have cannot be the only thing standing between them and a working install, so the invariant
# lives in the adapter. Filtering ARGUMENTS (rather than passing --config/--exclude) is purely
# additive: it never overrides the repo's own ruff excludes, and it works identically for
# `ruff check` and `ruff format` (which do not accept the same exclude flags).
# `tests/` is deliberately NOT filtered: it is CONSUMER-owned (the vendored consumer tests are
# ruff-clean), so skipping it would silently drop linting of the project's own tests.
_ruff_args=()
_had_paths="no"
for _a in "$@"; do
  case "$_a" in -*) _ruff_args+=("$_a"); continue;; esac
  _had_paths="yes"
  case "${_a#./}" in
    scripts|extras|scripts/*|extras/*) continue;;
    *) _ruff_args+=("$_a");;
  esac
done
# If EVERY path argument was substrate-reserved, there is nothing left to lint — do NOT fall
# through to a bare `ruff check` (with no paths ruff would walk the whole repo instead).
_only_reserved="no"
if [ "$_had_paths" = "yes" ]; then
  _remaining="no"
  for _a in ${_ruff_args[@]+"${_ruff_args[@]}"}; do
    case "$_a" in -*) ;; *) _remaining="yes";; esac
  done
  [ "$_remaining" = "no" ] && _only_reserved="yes"
fi
case "$gate" in
  # --force-exclude: honor extend-exclude (substrate-owned dirs) even though pre-commit passes
  # filenames explicitly on the command line; without it, ruff lints/formats explicitly-passed
  # paths regardless of the exclude list.
  format)    [ "$_only_reserved" = "yes" ] && exit 0
             run_tool ruff format --force-exclude ${_ruff_args[@]+"${_ruff_args[@]}"};;
  lint)      [ "$_only_reserved" = "yes" ] && exit 0
             run_tool ruff check --fix --force-exclude ${_ruff_args[@]+"${_ruff_args[@]}"};;
  typecheck) run_tool mypy "$@";;
  test)      run_tool pytest tests/ -q "$@";;
  *) echo "run_python_gate: unknown gate '$gate'" >&2; exit 2;;
esac
