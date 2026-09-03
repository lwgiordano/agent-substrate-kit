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
if [ -f .substrate/memory/events.jsonl ]; then
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
if [ -f .substrate/memory/events.jsonl ]; then
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
  # reported as green. Re-run the SAME verification the profile demands, after
  # the anchor is written and published, and let `set -e` make its result the
  # release's result. In strict a failed publication now fails the release; in
  # the offline-complete base tiers the unpublished anchor is not an error and
  # the plain chain check is what applies.
  echo "==> Memory anchor re-check (end state)"
  if [ "$SUBSTRATE_PROFILE" = "strict" ]; then
    run_py scripts/memory_log.py verify --anchor
  else
    run_py scripts/memory_log.py verify
  fi
fi
echo "release-gate: passed"
