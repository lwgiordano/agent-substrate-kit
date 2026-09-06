---
purpose: Behavioral evals, the malicious and benign corpus, and assurance limits.
last_human_reviewed: 2026-09-06
covers:
  - manage.sh
  - extras/calibrate_diy_ultrareview.py
  - scripts/agent_system_audit.sh
  - scripts/build_review_bundle.py
  - scripts/check_finding_response.py
  - scripts/check_postmortem_for_bug_fix.py
  - scripts/check_postmortem_gates_resolved.py
  - scripts/check_raw_file_io.py
  - scripts/check_validator_input_coverage.py
  - scripts/diy_ultrareview.sh
  - scripts/run_smoke_verification.py
  - scripts/run_substrate_evals.py
  - scripts/substrate_audit.py
---


# Evals and assurance

[Back to the substrate map](00_substrate.md).

`manage.sh check` proves structure and deterministic test outcomes.
`manage.sh evals` proves policy behavior against malicious and benign tasks. A
release is green only when malicious tasks block, benign tasks remain allowed,
and any required containment task actually runs.

## Eval semantics

Each eval records `ok`, `status`, and detail. A task that cannot run because a
backend is absent reports `status=skipped` and `ok=null`; it is excluded from the
block-rate numerator and denominator. Requiring sandbox evals converts that skip
into failure. The single-task diagnostic uses the same semantics.

The benign corpus tests false positives in real kit and consumer layouts.
Staged fixtures resolve both source assets and their installed `.substrate`
locations. A missing required fixture is an error, not a vacuous pass.

Some invariants are cheap to state and impossible to keep by review alone.
`check_raw_file_io.py` fails the gate when raw file I/O targets a path rooted at
the process's own repo root — the set an attacker can pre-link, swap, or replace
with a FIFO before the process runs. Detection is AST-based, so a string literal
naming a primitive cannot false-positive, and paths rooted at a freshly created
temporary directory inside a fixture are deliberately ignored: the code creates
that directory itself, so no attacker-controlled link can exist, and flagging it
would be the noise that gets a gate switched off. Resolution is scope-aware and resolved BEFORE any body is
scanned: import bindings are a property of the module's shape, not of the order
a walker reaches them, so a module-level import binds everywhere regardless of
textual position while a function's own import binds only inside it. Learning
bindings during the walk instead produced three separate escapes at once —
use-before-import dropped, a nested import clobbering a sibling's alias, and a
nested definition suppressing a star import.

Resolution also covers ordinary binding and origin spellings rather than only
the ones that happened to appear in the first repro: assignment aliases such as
`op = open` or `op = shutil.copy` use the last effective binding, function
defaults can bind either a path or a callable, destructuring/loop/comprehension
targets and `match` captures inherit governed provenance, walrus callees bind
before the call is inspected, assigned lambdas are re-scanned at call time under
the caller's current bindings, `MatchOr` alternatives bind their captures,
`io.open`/`builtins.open` aliases are recognized, `os.path` wrappers are
recognized through module aliases, function aliases, and star imports,
`Path.joinpath` aliases preserve receiver/argument provenance when their result
feeds raw I/O, and `pathlib.Path` constructor aliases plus repo-relative origins such as
`Path("docs")`, `Path.cwd()`, `Path(__file__)...`, `os.path.abspath(...)`, and
`os.path.join(...)` are treated as checkout paths when they appear in real file
I/O operands. The safety invariant remains the same: a construct the analyzer
cannot resolve should be printed as unresolved, not silently disappear.

The scan surface is every tree that BECOMES `scripts/` under some profile, not
just `scripts/` itself: `extras/*.py` are copied in on a strict install, so a
file that is governed in the install but sits elsewhere in the source would
otherwise never be audited. Findings and exemptions from a staging tree are
namespaced by tree so they cannot share identity with a same-named file.

The gate also runs in generated CONSUMERS — wired into the manage.sh and
pre-commit templates, with a derived parity test asserting that every validator
the kit's own `check` runs reaches those templates. A gate that runs only in the
repo that authored it protects nobody else, and a hand-maintained parity list
agrees with itself.

Exemptions live in a small
allowlist where every entry carries a reason AND an expected match COUNT, and an
entry that no longer matches any call site — or that silently starts covering
more sites than were reviewed — is itself a failure. An exemption is granted to a
call site a human actually read, not to a shape. Reviewed openat-style component
walks can also consume an otherwise unresolved single-component call through the
same allowlist accounting, so intentional helper internals are not left as
unexplained background noise. A stale or widened exemption is a gate failure,
because otherwise stale exemptions become permanent cover. The gate exists
because the class it guards recurred across twelve
consecutive audit rounds while being fixed correctly each time: shared helpers
make the safe path available, and only a gate makes it mandatory.

A hang is a failure, not a pending result. Tasks that exercise a blocking shape
(a FIFO in place of a lock, a log, or a governed surface) assert that the tool
fails fast inside the per-subprocess cap, and a `TimeoutExpired` is reported as
a failed block rather than allowed to wedge the run. Evidence-suppression
attacks are in the malicious corpus for the same reason a bypass is: an eval
covers the gate that reads forged evidence, not only the gate that writes it.

A NONZERO exit is not evidence of the failure a task means: by exit code alone, a
missing file, a typo, or an unbound variable scores as a block. Two release-gate
tasks did exactly that — one referencing a variable defined above its split, one
running a script never staged. Assert the REASON the refusal prints.

Generated shell must quote what it interpolates: a gate fragment built around a
bare interpreter path split on the first space, so under a directory with a space
every invocation returned 127 and the task measured that. A space-free path cannot
test this.

A task that SKIPS has left the denominator. Skips exist for absent backends, so a
task whose setup stops reproducing its own baseline reports exactly as a missing
sandbox does and measures nothing without failing — which happened when narrowing
the anchor-conflict semantics turned one setup into a non-conflict. Read the skip
lines on any release that changes a semantic the corpus depends on.

A detection task needs a companion asking whether the detection can be ERASED.
`memory_anchor_mismatch_detected` proved a replaced memory chain was caught, and
that stayed true while the finding could be undone by re-running the shipped
`anchor` command over the replacement — the round-34 P1. `memory_anchor_relaunder_blocked`
covers the escalation. Where a gate records its own verdict somewhere writable,
assume an attacker's next move is against the record, and put that move in the
corpus too.

`evals --report` regenerates `BENCHMARK.md` with version, counts, surfaced skips,
and a reproduction command. Exact commit, source-tree, and artifact provenance
belongs to the release manifest rather than a mutable pre-commit hash embedded in
the benchmark.

The deterministic validators that run alongside these evals — syntax, config,
secrets, AST pins, coverage floors, doc assertions, the append-only HISTORY
gate — are described in [deterministic validators](09_deterministic_validators.md).
