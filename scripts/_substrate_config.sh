#!/usr/bin/env bash
# Safe loader for .substrate/config. NEVER `source` the config — that
# executes arbitrary shell BEFORE the substrate can validate it (a PR
# editing .substrate/config would run code during `manage.sh doctor/
# check` and in CI). This parses it as DATA: KEY=VALUE only, a fixed
# allowlist of keys, no command substitution. Invalid input aborts.
#
# Usage:  . scripts/_substrate_config.sh ; load_substrate_config
# (this file is substrate code — owned + harness-scanned, unlike the
# project-owned .substrate/config it reads.)

# Defaults (also the canonical allowed-key set).
SUBSTRATE_PROFILE="${SUBSTRATE_PROFILE:-standard}"
SUBSTRATE_LANG="${SUBSTRATE_LANG:-python}"
SUBSTRATE_RUNNER="${SUBSTRATE_RUNNER:-auto}"
LINT_CMD="${LINT_CMD:-}"
TYPECHECK_CMD="${TYPECHECK_CMD:-}"
TEST_CMD="${TEST_CMD:-}"
SUBSTRATE_CODE_SUFFIXES="${SUBSTRATE_CODE_SUFFIXES:-}"
SUBSTRATE_SANDBOX="${SUBSTRATE_SANDBOX:-0}"
SUBSTRATE_REMOTE_GOVERNANCE="${SUBSTRATE_REMOTE_GOVERNANCE:-0}"
SUBSTRATE_DEP_COOLDOWN="${SUBSTRATE_DEP_COOLDOWN:-0}"
SUBSTRATE_SECURITY_SCANNERS="${SUBSTRATE_SECURITY_SCANNERS:-0}"
SUBSTRATE_RELEASE_BACKEND="${SUBSTRATE_RELEASE_BACKEND:-local}"

# Balanced-quote check. Returns 0 if quoting is balanced (no surrounding
# quote, OR a matching pair), 1 if a lone leading/trailing quote makes the
# value ambiguous. Mirrors check_substrate_config.py:_strip_quotes_checked
# so the shell loader and the Python validator agree on what is valid data.
_subcfg_quotes_balanced() {
  local v="$1" first last
  first="${v:0:1}"; last="${v: -1}"
  case "$first" in
    \"|\')
      # opens with a quote: must be >=2 chars and close with the same quote
      [ "${#v}" -ge 2 ] && [ "$last" = "$first" ] && return 0
      return 1;;
  esac
  case "$last" in
    \"|\') return 1;;   # trailing quote with no matching leader
  esac
  return 0
}

_subcfg_strip_quotes() {
  local v="$1"
  case "$v" in
    \"*\") v="${v#\"}"; v="${v%\"}";;
    \'*\') v="${v#\'}"; v="${v%\'}";;
  esac
  printf '%s' "$v"
}

load_substrate_config() {
  local cfg="${1:-.substrate/config}" line key raw val
  [ -f "$cfg" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|\#*|[[:space:]]*\#*) continue;;       # blank / comment line
    esac
    # strip a trailing inline comment that starts with " #"
    line="${line%%  #*}"
    case "$line" in *' #'*) line="${line%% #*}";; esac
    line="${line%"${line##*[![:space:]]}"}"    # rstrip
    [ -z "$line" ] && continue
    # must be KEY=VALUE with an uppercase/underscore key
    if ! printf '%s' "$line" | grep -Eq '^[A-Z][A-Z0-9_]*='; then
      echo "substrate-config: invalid line (only KEY=VALUE allowed): $line" >&2; return 2
    fi
    key="${line%%=*}"; raw="${line#*=}"
    case "$key" in
      SUBSTRATE_PROFILE|SUBSTRATE_LANG|SUBSTRATE_RUNNER|LINT_CMD|TYPECHECK_CMD|TEST_CMD|SUBSTRATE_CODE_SUFFIXES|SUBSTRATE_SANDBOX|SUBSTRATE_REMOTE_GOVERNANCE|SUBSTRATE_DEP_COOLDOWN|SUBSTRATE_SECURITY_SCANNERS|SUBSTRATE_RELEASE_BACKEND) ;;
      *) echo "substrate-config: unknown key: $key" >&2; return 2;;
    esac
    # reject ambiguous quoting (e.g. SUBSTRATE_PROFILE="strict with no close)
    if ! _subcfg_quotes_balanced "$raw"; then
      echo "substrate-config: unbalanced quotes in $key" >&2; return 2
    fi
    val="$(_subcfg_strip_quotes "$raw")"
    # command substitution / backticks must not appear — config is data,
    # not code. Dangerous command VALUES (curl|bash etc.) are rejected by
    # scripts/check_substrate_config.py (run by doctor/check before the
    # gate adapter executes them) — that validator reuses the canonical
    # harness_patterns.json instead of duplicating danger strings here.
    case "$val" in
      *'$('*|*'`'*|*'${'*) echo "substrate-config: command substitution forbidden in $key" >&2; return 2;;
    esac
    # enum keys must hold a value from their fixed domain. A typo like
    # SUBSTRATE_PROFILE="stirct" would otherwise silently fall through to
    # the default and disable strict governance. Kept in lockstep with
    # check_substrate_config.py:_ENUMS.
    case "$key" in
      SUBSTRATE_PROFILE)
        case "$val" in starter|standard|strict) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_LANG)
        case "$val" in python|node|go|none) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_RUNNER)
        case "$val" in auto|uv|python|poetry) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_SANDBOX)
        case "$val" in 0|1) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_REMOTE_GOVERNANCE)
        case "$val" in 0|1) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_DEP_COOLDOWN)
        # non-negative integer (days). 0 = off. Kept in lockstep with
        # check_substrate_config.py:_INT_KEYS.
        case "$val" in ''|*[!0-9]*) echo "substrate-config: invalid $key: $val (want non-negative integer days)" >&2; return 2;; esac;;
      SUBSTRATE_SECURITY_SCANNERS)
        case "$val" in 0|1) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
      SUBSTRATE_RELEASE_BACKEND)
        case "$val" in local|ci-minisign|keyless) ;;
          *) echo "substrate-config: invalid $key: $val" >&2; return 2;; esac;;
    esac
    printf -v "$key" '%s' "$val"
  done < "$cfg"
  return 0
}
