#!/usr/bin/env bash
set -euo pipefail
# Language-aware release gate. Substrate validators are always Python
# (stdlib + PyYAML). Language-native test/lint run via .substrate/config
# indirection so this gate works in node/go repos too.
SUBSTRATE_LANG="python"; LINT_CMD=""; TYPECHECK_CMD=""; TEST_CMD=""
SUBVENV=".substrate/venv"
if command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then RUN=(uv run); elif command -v poetry >/dev/null 2>&1 && [ -f pyproject.toml ]; then RUN=(poetry run); else RUN=(); fi
# Validators run from the substrate venv if present (works in any
# language); else fall back to the project runner.
# `-I` (isolated): repo-local stdlib shadows (scripts/hashlib.py …) can't
# hijack a validator's imports and defeat the hash pins.
# `${RUN[@]+"${RUN[@]}"}`, not `"${RUN[@]}"` (round-39 P2). On Bash 3.2 — still
# the /bin/bash on macOS — expanding an EMPTY array under `set -u` aborts, so a
# consumer with no venv and no pyproject could not run the gate at all. The
# fallback existed and was unreachable on exactly the hosts that needed it.
run_py(){ if [ -x "$SUBVENV/bin/python" ]; then "$SUBVENV/bin/python" -I "$@"; else ${RUN[@]+"${RUN[@]}"} python3 -I "$@" 2>/dev/null || ${RUN[@]+"${RUN[@]}"} python -I "$@"; fi; }
# Substrate tools (pre-commit) ALWAYS come from the substrate venv —
# never ambient PATH (the v3.2 release-gate `pre-commit: command not
# found` bug in node/go repos).
# Route project/test execution (pytest etc.) through the sandbox when the tier is
# enabled (v3.5.3) — but NOT pre-commit itself (it orchestrates hooks that route their
# own leaves via run_python_gate/lang_gate, and may need fs/net for some hooks).
run_tool(){ local t="$1"; shift || true; local -a c
  if [ -x "$SUBVENV/bin/$t" ]; then c=("$SUBVENV/bin/$t"); else c=(${RUN[@]+"${RUN[@]}"} "$t"); fi
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ] && [ "$t" != "pre-commit" ]; then scripts/sandbox_exec.sh "${c[@]}" "$@"; else "${c[@]}" "$@"; fi; }
# Configured LINT_CMD/TYPECHECK_CMD/TEST_CMD are executable PROJECT code → contained too.
run_lang(){ local label="$1" cmd="$2"; [ -z "$cmd" ] && return 0; echo "==> $label: $cmd"
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ]; then scripts/sandbox_exec.sh bash -c "$cmd"; else bash -c "$cmd"; fi; }
# The gate certifies ONE configuration, and every check below reads policy from it.
# Fingerprint it NOW (round-37 P1) so the success line at the end can refuse if the
# file changed underneath the run. Absent and unreadable are distinct VALUES here,
# not skips: a config that appears or disappears mid-run is drift like any other.
# ABSENT and NON-REGULAR are distinct values, not one bucket: a config replaced by
# a FIFO or a directory is drift even where none existed at start. Tool failure is
# NOT a value at all — this returns nonzero and the caller says so, rather than
# reporting a fingerprint it could not compute as a changed file.
_substrate_config_fingerprint(){
  run_py -c 'import hashlib, pathlib, sys
p = pathlib.Path(".substrate/config")
sys.stdout.write(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file()
                 else "nonregular" if p.exists() else "absent")' 2>/dev/null
}
_SUBSTRATE_CONFIG_AT_START="$(_substrate_config_fingerprint)" || {
  echo "release-gate: cannot fingerprint .substrate/config — refusing to start a run" >&2
  echo "  whose configuration it could not pin. Fix the environment and re-run." >&2
  exit 1
}
# SNAPSHOT, then load FROM THE SNAPSHOT (round-39 P1). Comparing the file before
# and after the load left an A-B-A race: pin strict, swap to standard for exactly
# as long as the loader reads, restore strict, and both fingerprints matched while
# the gate ran on the standard values it had cached. Comparing bytes at two
# moments can never exclude that. Taking a private copy and loading from it makes
# the values provably the ones that were pinned — there is no window to lose.
#
# The CONFIG LOADER ITSELF is copied and sourced the same way, and only AFTER the
# validators have run over the live tree. It used to be sourced at line 11, before
# anything attested it, so a helper that wrote during the trusted release and
# restored itself was clean by the time any integrity check looked.
_SUBSTRATE_SNAP="$(mktemp -d "${TMPDIR:-/tmp}/substrate-gate.XXXXXX")" || {
  echo "release-gate: cannot create a private snapshot directory — refusing" >&2; exit 1; }
trap 'rm -rf "$_SUBSTRATE_SNAP"' EXIT
for _f in .substrate/config scripts/_substrate_config.sh; do
  [ -e "$_f" ] || continue
  if [ -L "$_f" ] || [ ! -f "$_f" ]; then
    echo "release-gate: REFUSING — $_f is a symlink or not a regular file. The gate" >&2
    echo "  reads it as trusted input; a link or FIFO there is tampering, not config." >&2
    exit 1
  fi
done
[ -f .substrate/config ] && cp .substrate/config "$_SUBSTRATE_SNAP/config"
cp scripts/_substrate_config.sh "$_SUBSTRATE_SNAP/_substrate_config.sh"
_SUBSTRATE_HELPER_AT_START="$(run_py -c 'import hashlib,pathlib,sys
sys.stdout.write(hashlib.sha256(pathlib.Path("scripts/_substrate_config.sh").read_bytes()).hexdigest())' 2>/dev/null)" || {
  echo "release-gate: cannot fingerprint scripts/_substrate_config.sh — refusing" >&2; exit 1; }
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
#
# v3.8.51 (self-audit P1): this used to require the anchor only when a note
# happened to exist — `strict && [ -n "$(git notes list)" ]`. Nothing ever
# wrote a note, so in strict the ABSENCE of the trust anchor silently
# downgraded to the unanchored check: a trust anchor failing open, which
# INTENT.md forbids ("absence and unreadability are different states").
# Observed live: the memory directory was replaced wholesale by an older
# valid chain and `verify` reported OK. In strict the anchor is now REQUIRED
# and its absence is a gate failure with the remedy named; the anchor itself
# is written below once the whole gate has passed, so every release re-ties
# the chain to a known-good commit.
# The validators above have now run over the live tree. Prove the helper they saw
# is the helper about to run, then source the COPY: hashing the live file and then
# sourcing the live file is check-then-use, which is the whole subject of the last
# five rounds.
_helper_now="$(run_py -c 'import hashlib,pathlib,sys
sys.stdout.write(hashlib.sha256(pathlib.Path("scripts/_substrate_config.sh").read_bytes()).hexdigest())' 2>/dev/null)" || {
  echo "release-gate: cannot re-fingerprint scripts/_substrate_config.sh — refusing" >&2; exit 1; }
if [ "$_helper_now" != "$_SUBSTRATE_HELPER_AT_START" ]; then
  echo "release-gate: REFUSING — scripts/_substrate_config.sh changed while the" >&2
  echo "  validators ran. The config loader is trusted code; it cannot be swapped" >&2
  echo "  underneath the run that vouches for it. Re-run the gate." >&2
  exit 1
fi
. "$_SUBSTRATE_SNAP/_substrate_config.sh"
load_substrate_config "$_SUBSTRATE_SNAP/config" || { echo "substrate-config: refusing to run with invalid .substrate/config" >&2; exit 2; }

# Whether memory is PART OF THIS RELEASE is decided once, here, and reused at the
# anchor block (round-38 P1). Re-testing `-f` there let a log that existed for this
# check disappear before the anchor block, and the release then SKIPPED its final
# verification rather than refusing — the same fail-open-on-absence shape v3.8.51
# removed from the anchor itself.
# `-e`, not `-f` (round-39 P1): `-f` is FALSE for a FIFO, so a non-regular
# events.jsonl planted after the earlier validators read as ABSENT at both the
# start and the end check, and every memory verification was skipped while the
# gate passed. Present-but-not-regular is tampering, and it is a refusal.
if [ -e .substrate/memory/events.jsonl ] && { [ -L .substrate/memory/events.jsonl ] || [ ! -f .substrate/memory/events.jsonl ]; }; then
  echo "release-gate: REFUSING — .substrate/memory/events.jsonl exists but is a" >&2
  echo "  symlink or not a regular file. A tamper-evident log cannot be a link or" >&2
  echo "  a FIFO; treating it as absent is how the memory checks got skipped." >&2
  exit 1
fi
_MEMORY_IN_RELEASE=0
if [ -e .substrate/memory/events.jsonl ]; then
  _MEMORY_IN_RELEASE=1
  echo "==> Memory chain"
  if [ "$SUBSTRATE_PROFILE" = "strict" ]; then
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
# Re-tie the memory chain to THIS commit now that every gate has passed. Done in
# every profile: writing a note is harmless, and it is what makes the strict
# requirement above satisfiable after a profile ratchet instead of a fresh
# chicken-and-egg.
#
# v3.8.52 (round-34 P2): THE PRODUCER PUBLISHES. The previous version wrote the
# note and left a comment telling someone to push it. That step is impossible
# anywhere but here: git does not transport refs/notes/* on a normal push,
# clone, or fetch, so another clone never receives the ref and
# `git push origin refs/notes/substrate-memory` there fails with
# "src refspec ... does not match any" (reproduced). Delegating it was a
# handoff that could not be executed. So: push it from this clone, and when
# that is refused (no remote, no permission, an egress policy) print the exact
# payload and the one command that recreates the note anywhere, because the
# payload travels in text where the ref does not.
# Presence at the end must match presence at the start, in BOTH directions: a log
# that vanished cannot be re-verified, and one that appeared was never verified at
# all, so announcing success would certify a chain nothing checked.
if [ "$_MEMORY_IN_RELEASE" = "1" ] && [ ! -e .substrate/memory/events.jsonl ]; then
  echo "release-gate: REFUSING — .substrate/memory/events.jsonl was part of this" >&2
  echo "  release and disappeared before the anchor could be re-verified. A memory" >&2
  echo "  log that goes missing mid-run is a refusal, not a skip. Re-run the gate." >&2
  exit 1
fi
if [ "$_MEMORY_IN_RELEASE" = "0" ] && [ -e .substrate/memory/events.jsonl ]; then
  echo "release-gate: REFUSING — .substrate/memory/events.jsonl appeared during this" >&2
  echo "  run, so its chain was never verified by the check above. Re-run the gate." >&2
  exit 1
fi
if [ "$_MEMORY_IN_RELEASE" = "1" ]; then
  echo "==> Memory anchor"; run_py scripts/memory_log.py anchor
  if git remote | grep -qx origin; then
    if git push --quiet origin refs/notes/substrate-memory 2>/dev/null; then
      echo "memory-anchor: published refs/notes/substrate-memory to origin"
    else
      _anchor_commit="$(git rev-parse HEAD)"
      _anchor_payload="$(git notes --ref=substrate-memory show "$_anchor_commit" 2>/dev/null | head -1)"
      echo "memory-anchor: WARNING — could not push refs/notes/substrate-memory to origin." >&2
      echo "  The anchor exists only in this clone, where whatever can rewrite the log" >&2
      echo "  can rewrite it too. A normal push/clone does NOT carry refs/notes/*, so no" >&2
      echo "  other clone can publish it for you. Either push FROM THIS CLONE:" >&2
      echo "    git push origin refs/notes/substrate-memory" >&2
      echo "  or recreate it from this payload on any clone and push from there:" >&2
      echo "    git notes --ref=substrate-memory add -f -m '${_anchor_payload}' ${_anchor_commit}" >&2
      echo "    git push origin refs/notes/substrate-memory" >&2
      echo "  Confirm either way with: git ls-remote origin 'refs/notes/*'" >&2
    fi
  else
    echo "memory-anchor: no 'origin' remote — the anchor is local-only by construction" >&2
  fi
  # CERTIFY THE END STATE, NOT THE PRE-STATE (v3.8.54, round-36 P1b).
  #
  # The memory-chain check above runs BEFORE this block writes a new note, so
  # the success line used to describe the anchor state the release
  # started with. When the push was refused the gate still exited 0 while the
  # repo it left behind failed `verify --anchor` outright — reproduced with an
  # origin that rejects refs/notes/*, and lived through in this kit's own
  # v3.8.53 release, which printed "passed" with the push refused and was
  # reported as green.
  #
  # v3.8.54 branched here on "$SUBSTRATE_PROFILE" — the value `load_substrate_config`
  # read at process START. So a config raised to strict DURING the run was certified
  # by the standard-tier check: the gate re-read the anchor but not the policy, and
  # the end state it certified was judged by a rule from a different moment (round-37
  # P1, reproduced). The fix is not to re-read the variable here but to stop asking
  # the shell at all: `verify --anchor` decides strictness inside memory_log, from
  # the LIVE .substrate/config, at the instant it runs. Base tiers still pass with an
  # unpublished anchor (LOCAL-ONLY, LOCAL AHEAD, LOCAL (no remote) are all rc 0), so
  # this is unconditional without breaking the offline-complete promise.
  echo "==> Memory anchor re-check (end state)"
  run_py scripts/memory_log.py verify --anchor
fi
# The gate certifies ONE configuration. If .substrate/config changed while the gate
# ran, every result above was produced under a policy that is no longer the
# repository's, so success would be a claim about a config that no longer exists.
# Refuse rather than report; a re-run under the settled config is the remedy.
# Report the RIGHT cause. A fingerprint the tool could not compute is not evidence
# that the file changed, and saying it changed would send the operator looking for
# an edit nobody made — the same "a failure is not the failure you meant" mistake
# this release fixes in two evals.
if ! _end_config_fp="$(_substrate_config_fingerprint)"; then
  echo "release-gate: REFUSING to report success — could not re-read .substrate/config" >&2
  echo "  to confirm it is unchanged. This is NOT a drift finding: the fingerprint" >&2
  echo "  itself failed, so the run is unverifiable either way. Re-run the gate." >&2
  exit 1
fi
if [ "$_end_config_fp" != "$_SUBSTRATE_CONFIG_AT_START" ]; then
  echo "release-gate: REFUSING to report success — .substrate/config changed while the gate ran." >&2
  echo "  Everything above was checked under the configuration loaded at start, so this" >&2
  echo "  run cannot certify the configuration the repository now has. Re-run the gate." >&2
  exit 1
fi
echo "release-gate: passed"
