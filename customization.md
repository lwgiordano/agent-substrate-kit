# Agent Substrate Kit — Customization

What to keep, what to change, what to remove. The kit is opinionated
but the project-specific details are yours.

---

## Decision tree: what to install

### Always install (universal substrate)

These are pure substrate, project-agnostic. Copy verbatim:

| File | Why |
|---|---|
| `AGENTS.md` | Keystone (customize bottom section only) |
| `scripts/_doc_common.py` | Shared helpers |
| `scripts/append_history.py` | HISTORY tool with off-by-one guard |
| `scripts/session_handoff.py` | Hook-fired compaction handoff (capture/restore) |
| `scripts/todo_state_hook.py` | PostToolUse TodoWrite mirror |
| `scripts/lint_on_write.py` | PostToolUse lint-on-write |
| `scripts/update_manifest.py` | Auto-regens docs/manifest.json |
| `scripts/check_doc_drift.py` | Knowledge-doc drift detector |
| `scripts/check_history_sha.py` | HISTORY entry SHA validity |
| `scripts/check_postmortem_for_bug_fix.py` | Bug-fix → postmortem requirement |
| `scripts/check_finding_response.py` | Four-field bug-fix protocol |
| `scripts/check_postmortem_gates_resolved.py` | Postmortem gate cross-ref |
| `scripts/check_validator_input_coverage.py` | Meta-validator |
| `scripts/check_secrets.py` | Pattern-based secrets lint |
| `scripts/check_coverage_floors.py` | Per-area coverage ratchet (start with empty floors dict) |
| `scripts/check_bandit_skip_baseline.py` | Bandit skip drift |
| `scripts/diy_ultrareview.sh` | 7-lens parallel review helper |
| `docs/decisions/0000-template.md` | ADR template |
| `docs/postmortems/_template.md` | Postmortem template |
| `docs/knowledge/_template.md` | Knowledge doc template |
| `.gitattributes` (HISTORY merge=union line) | Merge-safe HISTORY |

### Install with customization

Copy and adapt. Specific tuning points called out in each file:

| File | Customization point |
|---|---|
| `.pre-commit-config.yaml` | Remove hooks for absent features (codegen drift if no codegen, bundle-size if no frontend, etc.) |
| `.github/workflows/ci.yml` | Adjust to your dep manager (uv → pip → poetry as needed) |
| `.github/dependabot.yml` | Match your dep ecosystem(s) |
| `extras/calibrate_diy_ultrareview.py` (strict only) | Start with `CALIBRATION = ()`; populate as you find real bugs |
| `extras/check_stale_phrases.py` (strict only) | `STALE_PHRASES` list is project-specific; start empty |
| `pyproject.toml` | Add the dev-group deps (see below) |

### Don't install (project-specific patterns)

These were in the source project but are too specific to port. Use
them as PATTERNS, not files:

- `scripts/check_extensibility_configs.py` — project-specific YAML cross-ref
- `scripts/check_grain.py` — canonical_grain.yaml structure
- `scripts/check_strict_bool.py` — SQL NULL-bool conventions
- `scripts/check_codegen_drift.py` (and 4 sibling drift checks) — codegen pipelines
- `scripts/check_bundle_size.py` — frontend SPA budgets
- `scripts/check_dq_thresholds.py` — DQ rule alarms
- `scripts/check_schema_evolution.py` — source-header drift
- `scripts/check_pii_classification.py` — PII column tagging
- `scripts/check_audit_regressions.py` — audit-finding registry
- `scripts/check_supersession_completeness.py` — vocabulary supersession
- `scripts/check_spec_coverage.py` — spec/code cross-ref
- `scripts/check_adr_numeric_claims.py` — numeric-claim drift in ADRs

These all follow the SAME PATTERN:
1. A `scripts/check_<thing>.py` validator with main() returning 0/1/2
2. A paired `tests/test_validator_<thing>.py` with adversarial cases
3. A pre-commit hook entry in `.pre-commit-config.yaml`
4. (Optional) An opt-out marker (`# coverage-opt-out: <reason>`)

When you find a class of bug specific to YOUR project, write a new
validator following this pattern. The four meta-validators (doc-drift,
history-sha, validator-input-coverage, postmortem-gates-resolved) will
keep your new validators in line.

---

## pyproject.toml dev-group deps

Add these to `[dependency-groups].dev` (or equivalent for your dep
manager):

```toml
[dependency-groups]
dev = [
  # Core gate machinery
  "pre-commit>=3.7",
  "pytest>=8",
  "pytest-cov>=5",
  "ruff>=0.5",
  "mypy>=1.10",

  # Security
  "bandit>=1.7",
  "pip-audit>=2.7",

  # Type stubs
  "types-pyyaml>=6.0",

  # Test depth
  "hypothesis>=6.100",
  "pytest-benchmark>=4.0",
  "pytest-randomly>=3.15",
  "pytest-rerunfailures>=14.0",
]
# Optional: add `mutmut>=2.5` for mutation testing if you're on
# Linux. Known to hang on macOS+cloud-sync filesystems.
```

If you don't use `uv`, equivalent for poetry / pip is straightforward.

---

## AGENTS.md customization (the bottom section)

The keystone has a "Project-specific instructions" section at the
bottom. Replace the placeholder with:

```markdown
## Project-specific instructions

This is the **<YOUR PROJECT NAME>** project. The execution playbook is
**`<YOUR_PLAYBOOK.md>`** (e.g., `BUILD_INSTRUCTIONS.md`). Architecture is
**`docs/ARCHITECTURE.md`**. Why we're building this is **`docs/INTENT.md`**.

<!-- Add any project-specific scopes / forms / phases / build paths here -->

<Project-specific phase markers>
<Project-specific scopes>
<Project-specific forbidden actions>

---

*Keystone last touched: YYYY-MM-DD (initial bootstrap).*
```

Examples of what goes in project-specific:

- "Form A is authorized. Form B is explicitly out of scope. If a
  request looks like Form B, refuse and reference BUILD_INSTRUCTIONS.md
  §6."
- "Phases P0a → P0b → P1 → P2 → P3 → P4 are the build sequence. Don't
  jump ahead."
- "The dashboard runs at http://127.0.0.1:5180. If you start a dev
  server, kill any existing one first (Playwright trap)."

---

## .pre-commit-config.yaml customization

The kit's `pre-commit-config.yaml.template` is profile-filtered at
bootstrap: starter installs ~6 hooks, standard ~10, strict ~13
(commit-msg gates + validator-coverage). Project-
specific hooks (codegen-drift, schema validators, bundle-size, DQ
thresholds, etc.) go BELOW the universal block; see the marker
comment at the bottom of the template. Walk the file and decide:

### Universal hooks (already in the kit template — keep all)

These ship verbatim in `pre-commit-config.yaml.template`. The kit's
empty defaults (CALIBRATION = (), STALE_PHRASES = (), _FLOORS = {},
_DOCUMENTED_SKIPS = set()) make every gate pass on a fresh repo;
populate them as your project grows.

```yaml
# Substrate scaffolding
- id: update-manifest                  # docs/manifest.json regen
- id: check-doc-drift                  # knowledge-doc drift detector

# Code quality
- id: ruff                             # lint
- id: pytest                           # full suite
- id: mypy                             # strict type checking
- id: bandit                           # security lint

# Substrate self-defense
- id: check-secrets                    # pattern-based secrets lint
- id: check-stale-phrases              # descriptive-claim drift (start empty)
- id: check-history-sha                # HISTORY entry SHA validity
- id: check-coverage-floors            # per-area ratchet (start empty)
- id: check-bandit-skip-baseline       # security skip drift
- id: check-license-headers            # SPDX header enforcement (start empty)
- id: check-validator-input-coverage   # meta-validator
- id: check-postmortem-gates-resolved  # postmortem cross-ref
- id: calibrate-diy-ultrareview        # detection regression (start empty)

# Commit-msg gates (commit-msg stage)
- id: check-postmortem-for-bug-fix     # bug-fix → postmortem requirement
- id: check-finding-response           # four-field protocol enforcer

# Off-the-shelf baseline (pre-commit-hooks/v6.0.0)
- id: trailing-whitespace
- id: end-of-file-fixer
- id: check-yaml
- id: check-json
- id: check-merge-conflict
- id: check-added-large-files
- id: check-case-conflict
- id: mixed-line-ending
```

### Project-specific hooks (NOT in kit — write your own)

The kit template does NOT ship these. Add them BELOW the universal
block in `pre-commit-config.yaml`, following the four-step pattern:
`scripts/check_<thing>.py` + `tests/test_validator_<thing>.py` +
hook entry + (optional) `# coverage-opt-out: <reason>` markers.

Common project-specific candidates:

```yaml
- id: check-strict-bool                # SQL with NULL-bool concerns
- id: check-grain                      # canonical_grain.yaml invariants
- id: check-spec-refs                  # numbered-spec section validity
- id: check-extensibility-configs      # multi-catalog YAML cross-ref
- id: check-codegen-drift              # YAML/JSON spec → generated code
- id: check-bundle-size                # frontend SPA budgets
- id: check-dq-thresholds              # DQ rule alarms
- id: check-schema-evolution           # source-header tracking
- id: check-pii-classification         # PII tagging
- id: check-audit-regressions          # AUDIT_REGRESSIONS.yaml registry
- id: check-spec-coverage              # spec_coverage.yaml
- id: check-supersession-completeness  # vocabulary surface forms
- id: check-adr-numeric-claims         # ADR count drift
- id: check-volatile-docs              # auto-managed doc sections
```

---

## extras/check_stale_phrases.py — STALE_PHRASES list (strict profile)

The list starts empty. Add an entry whenever you find a descriptive
claim in docs that drifts from code. Example pattern (from the source
project):

```python
StalePhrase(
    phrase=r"placeholder app",
    hint="The placeholder app was replaced by the live dashboard "
         "in P2. The Form A dashboard mounts PeriodSelector + KpiGrid "
         "+ 4 charts and there's no scaffold-ready landing page anymore.",
    allowlist=("docs/HISTORY.md", "docs/postmortems/", "docs/AUDIT_REGRESSIONS.yaml"),
)
```

The `phrase` is a regex. The `hint` is what to say when the regex
fires. The `allowlist` is paths/prefixes where the phrase is
acceptable (typically: HISTORY entries that legitimately quote old
phrasing, postmortems documenting the drift, audit registries
recording the supersession).

**Don't add stale-phrase entries pre-emptively.** Add them ONLY after
you've found a real instance of drift. The list grows organically.

---

## extras/calibrate_diy_ultrareview.py — CALIBRATION list (strict profile)

Starts empty: `CALIBRATION = ()`. Add entries as you find real bugs
that the detection logic catches. Each entry:

```python
CalibrationCommit(
    sha="abc1234",                 # short SHA of the fix-commit
    title="<commit subject>",
    expected_domains=frozenset({"regex", "yaml-parsing"}),
    found_by="external-audit",     # who originally caught this bug
    notes="...",                   # what's noteworthy about this entry
    is_ground_truth=True,          # True for human-labeled (start here)
)
```

For the first ~5-10 entries, set `is_ground_truth=True` (you've read
the diff and labeled it manually). After the gate is in pre-commit and
catching real bugs, you can auto-curate with `is_ground_truth=False`
for additional regression coverage.

The minimum-size floor (`tests/test_validator_finding_response.py
::test_calibration_set_minimum_size_locked`) starts at 0 (or whatever
your initial set is, minus a small margin). Bump it as the set grows.

---

## scripts/check_coverage_floors.py — _FLOORS dict

Starts empty: `_FLOORS = {}`. Add entries as your codebase grows. Each
entry:

```python
"path/to/module.py": <floor-percent>,
```

Set floors **2-4 percentage points below current observed coverage**.
This catches catastrophic regression (e.g., a refactor that loses 20%
of coverage) without flagging minor day-to-day variation.

Recompute current coverage with:
```sh
pytest tests/ --cov=path/to/module --cov-report=term-missing
```

Update the floor when you intentionally improve coverage, OR when a
refactor genuinely deletes uncovered code (raising the headroom
naturally).

---

## scripts/check_finding_response.py — domain detection

The script auto-detects which domains a fix-commit touches:
- regex
- yaml-parsing
- commit-msg-hooks
- ast-parsing

These are the universal domains. Add project-specific domains by
extending `_DOMAIN_DETECTORS` if your project has consistent failure
modes in another area (e.g., "sql-codegen", "react-state-management").

Each new domain needs:
1. An entry in `_DOMAIN_DETECTORS`
2. A blind-spot checklist at `docs/blind-spot-checklists/<domain>.md`
3. (Eventually) a calibration entry that touches the domain

---

## Enterprise / multi-team templates

The kit ships 5 enterprise-oriented templates for projects that need
multi-team review routing, vulnerability disclosure, contributor
onboarding, or license tracking. Bootstrap copies them; customize the
placeholder values:

- **`.github/CODEOWNERS`** — replace `@your-org/maintainers`,
  `@your-org/substrate-maintainers`, `@your-org/architects`,
  `@your-org/devops`, etc. with your real GitHub team handles. Add
  project-specific source-path patterns at the bottom.
- **`SECURITY.md`** — replace `security@your-org.example`, the GitHub
  Security Advisories link, and the supported-versions table with
  your project's real disclosure channels and release policy.
- **`CONTRIBUTING.md`** — adjust dep-manager commands (uv/poetry/pip)
  and branch-model conventions for your project. The substrate
  workflow section is universal; everything else is customizable.
- **`.github/pull_request_template.md`** — adjust the substrate
  checklist if you have additional review gates.
- **`extras/check_license_headers.py`** (strict only) — populate
  `_REQUIRED_HEADER_PATHS` with the path-prefixes you want to
  enforce SPDX headers on (e.g., `("src", "scripts", "apps")`).
  Auto-prepend missing headers via
  `python scripts/check_license_headers.py --add MIT`. Wired into
  pre-commit; ships empty (no-op until populated).

---

## docs/blind-spot-checklists/

Per-domain bug-class catalogs. The kit ships 4 starter checklists +
1 authoring template:
- `regex.md` — 13 canonical regex bugs (greedy, anchoring,
  boundary-with-paren, character-class-range, escaping, etc.)
- `yaml-parsing.md` — 15 YAML/dict input handling bugs (missing
  key, wrong type, empty list, NULL coercion, duplicate keys, etc.)
- `commit-msg-hooks.md` — 15 commit-msg hook bugs (unanchored
  opt-out, placeholder-acceptance, comment-stripping, calibration
  drift, etc.)
- `ast-parsing.md` — 12 Python AST parsing bugs (SyntaxError,
  RecursionError, aliased imports, scope-unaware walks, etc.)
- `_template.md` — copy this to author a new domain checklist.

These are reading material for Layer 1 of the three-layer self-audit.
The four starters cover the most common Python-codebase domains;
add more as you find patterns specific to your project (e.g.,
codegen-drift, schema-evolution, SQL-NULL-bool).

Pattern for authoring (copy `_template.md` first):
1. Find a bug class via external audit, internal review, or postmortem.
2. Add it to the relevant checklist with: pattern name, example shape,
   "smell" (what to look for), "fix" (what to do instead).
3. Future commits in the domain re-read the checklist before
   composing the message.

---

## .github/workflows/ci.yml customization

The template uses `uv`. Adapt for your dep manager:

```yaml
# uv (default)
- name: Install uv
  run: pipx install uv
- name: Sync workspace deps
  run: uv sync --all-packages
- name: Pytest
  run: uv run pytest tests/ -q

# pip
- name: Install deps
  run: pip install -e .[dev]
- name: Pytest
  run: pytest tests/ -q

# poetry
- name: Install poetry
  uses: snok/install-poetry@v1
- name: Sync deps
  run: poetry install
- name: Pytest
  run: poetry run pytest tests/ -q
```

The two CI jobs (`pre-commit-and-tests` + `pip-audit`) are universal.
The third optional job is `coverage-floors` — runs after pytest, asserts
floors hold.

---

## docs/OPERATOR_ENABLEMENT.md

The operator (you, the human) needs to enable several GitHub-side
controls that the kit can't set:

1. **Branch protection on `main`** — required CI checks before merge.
2. **Dependabot enable** — Settings → Code security → Dependabot version updates.
3. **Devcontainer test** — VS Code → "Reopen in Container" once.

Copy `docs/OPERATOR_ENABLEMENT.md` from the source project as the
runbook for these (it's in the source repo as a real working document).

---

## How to grow the substrate

When a new bug class shows up:

1. Write the postmortem (`docs/postmortems/YYYY-MM-DD-<slug>.md`).
2. Identify the gate that should have caught it. If none exists, add
   one (new validator at `scripts/check_<thing>.py`).
3. Add a paired test (`tests/test_validator_<thing>.py`) with adversarial cases.
4. Wire into `.pre-commit-config.yaml`.
5. Add the bug to the calibration set (with `is_ground_truth=True`).
6. If the bug is in a new domain, write a blind-spot checklist.
7. Cross-link the postmortem from `docs/AUDIT_REGRESSIONS.yaml`
   (if you maintain one) via the `lessons:` field.

The substrate grows organically. Don't add validators pre-emptively;
add them in response to real bugs.

---

## When to retire a substrate piece

Yes, retire. The substrate is not write-only.

A validator should be retired when:
- It hasn't fired in 12+ months
- The class of bug it catches is now provably impossible (e.g., the
  field it validates was removed)
- A more general validator subsumes it

Retirement process:
1. Write a brief postmortem-style note explaining why
2. Remove the validator + its paired test
3. Remove the pre-commit hook entry
4. Update the relevant knowledge doc (drop the file from `covers:`)
5. `update_manifest.py`

Keeping a stale validator is worse than removing it — it implies
defense that no longer exists.

---

## The portability test

If you can apply this kit to an empty repo, customize the bottom
section of AGENTS.md, and have a clean `pre-commit run --all-files`
within an hour, the kit is portable to your context.

If you can't, the kit is over-fitted to the source project. Patches
to make it more portable are welcome.

---

## Inevitable adaptations

You will deviate from the kit in your project. That's expected. Track
the deviations:

```
<your-repo>/
├── docs/
│   └── Agent Substrate Kit_DELTA.md   # what you changed and why
```

Don't bury the deviations in commit messages. Make them visible. The
delta doc is what the next session reads to understand WHY your
substrate looks different from the kit.

Common deviations:
- Different dep manager (poetry vs uv)
- Different test framework (rspec, jest, etc.)
- Single-language vs polyglot (the kit is Python-centric; multi-lang
  needs more wiring)
- Different LLM agent (Cursor, Aider, etc.) — adjust AGENTS.md
  filename/path
