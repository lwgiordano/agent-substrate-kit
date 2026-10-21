---
date: 2026-10-21
severity: high
caught_by: self-audit
related_commits:
  - 76f3d53 (lang_gate failure is never a skip; config loaders agree on bytes)
  - 3800413 (imported HISTORY means on the base; refusals must be refusals)
  - WORKING (release smoke stages _doc_common.py for the strict-lock step)
gates_added:
  - tests/test_hook_scripts.py::test_lang_gate_failure_is_never_a_skip
  - tests/test_hook_scripts.py::test_lang_gate_sandbox_refusal_fails_the_gate
  - tests/test_project_status.py::test_release_package_really_leaves_out_local_state
  - tests/test_history_evidence_portability.py::test_a_committed_claim_not_on_the_base_needs_local_proof
  - tests/test_doc_consistency.py::test_scheduled_audit_can_open_its_failure_issue
---

# 2026-10-21 — failure-read-as-success

## What happened

A seven-lens review of v3.10.0 to v3.10.4 found gates that turned a failure,
a skip or an unknown into success. `scripts/lang_gate.sh` ran
`npm_script test && maybe_sandbox npm test || skip "no 'test' npm script"`, so a
FAILING `npm test`, `npm run lint`, `go vet` or `go test`, and the sandbox's
fail-closed exit 3, fell through to "skipped" with exit 0: a consumer's node or
go gate could never fail. A Go package that did not compile made `go list`
fail, which read as "no go packages". The release smoke's "strict profile lock
blocks a downgrade" step ran `check_substrate_config.py` in a minimal stage
that lacked `_doc_common.py`; since v3.8.36 the validator crashed with
`ModuleNotFoundError`, and the step counted any non-zero exit as the refusal it
wanted, so it proved nothing for two months. `check_history_sha` counted any
entry committed at HEAD as imported, so in CI a forged `shipped-green` entry
committed with `--no-verify` passed. The same review found the v3.10.2 alert
(HTTP 403 since September) and the v3.10.3 full-audit SKIP-as-PASS were the same
class.

## Why it happened

The meta-pattern is a check whose success condition is the ABSENCE of a
specific failure rather than the PRESENCE of the specific success. `a && b ||
skip` treats every non-zero `b` as "not applicable". `if cmd; then fail; fi`
treats every non-zero `cmd` as "refused", including a crash or a timeout. "Not
yet proven false" (committed, so imported) was read as "proven". Each was
written for the happy and the intended-failure paths only; nobody enumerated
the third outcome, "the check itself could not run".

## Why our tooling didn't catch it

No test exercised `lang_gate.sh` at all; the only test grepped it for the word
`maybe_sandbox`. The release smoke's assertion was the same shape as the bug
(any non-zero passes), so the crash satisfied it. The eval helper
`_validator_blocks` already refused rc 124, but not a traceback, and the
ratchet eval did not use the helper. `check_history_sha`'s tests used fixture
repos with no remote, where HEAD and the base are the same thing.

## Preventative gate added

- `test_lang_gate_failure_is_never_a_skip` runs the real gate against real npm
  and Go projects: failing, passing, broken, testdata-only, no files; and
  `test_lang_gate_sandbox_refusal_fails_the_gate` for the sandbox's exit.
- The release smoke and the strict matrix job require exit 2 AND the lock's own
  message; `test_release_package_really_leaves_out_local_state` builds the real
  package, so the smoke step now runs for real in the test suite.
- `_validator_blocks` reports a traceback as could-not-verify; the ratchet eval
  requires rc 2 and its reason.
- `test_a_committed_claim_not_on_the_base_needs_local_proof` and its no-chain
  twin pin the base-branch provenance rule.
- Lesson L52 carries the rule into session start for these files.

## Carry-forward rule

A check that something fails or is refused asserts the exact exit code and
message, never `!= 0`, `! cmd` or `|| skip`: before committing a gate, grep the
diff for `returncode != 0`, `^\s*! `, `&& .* || skip` and `|| true`, and give
each hit a test where the checked command crashes or times out.

## Reproduction

```bash
mkdir -p /tmp/lg/scripts /tmp/lg/.substrate && cd /tmp/lg
cp <kit>/scripts/{lang_gate.sh,_substrate_config.sh,sandbox_exec.sh} scripts/
printf 'SUBSTRATE_LANG="node"\n' > .substrate/config
printf '{"scripts":{"test":"exit 3"}}' > package.json
bash scripts/lang_gate.sh test; echo $?   # before: "skipped", 0; after: 3
```
