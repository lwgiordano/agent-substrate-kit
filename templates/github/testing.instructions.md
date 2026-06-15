---
applyTo: "tests/**"
---

# Testing instructions

- Every validator (`scripts/check_*.py`) needs a paired adversarial
  test in `tests/` (enforced by `check_validator_input_coverage.py` at
  strict profile).
- Tests that spawn subprocesses MUST pass an explicit `timeout=`.
- Prefer hermetic tests: do not depend on network, a project venv, or
  tool auto-install. For lint-on-write tests, force the direct linter
  (no `uv` venv creation) so the suite stays fast and offline.
- Run the suite from the substrate venv: `.substrate/venv/bin/python -m
  pytest tests/ -q` (or `./manage.sh check`).
