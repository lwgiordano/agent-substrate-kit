"""Test session setup: keep the suite hermetic, fast, and self-diagnosing.

- Forces direct linters (no `uv run` venv creation — the v3.2 hang source).
- Arms a faulthandler watchdog: if any test (or the whole session) stalls
  past the timeout, Python dumps every thread's traceback to stderr so a
  hang is diagnosable instead of silent. Every subprocess in the suite
  also carries its own 30s timeout (see tests/test_hook_scripts.py).
"""
import faulthandler
import os
import sys

_FULL_SUITE_WATCHDOG_SECONDS = 1800


def pytest_configure(config):
    os.environ.setdefault("SUBSTRATE_LINT_DIRECT", "1")
    # Watchdog: dump all thread stacks and fail if the session genuinely wedges.
    # The full pre-commit suite measured 602.85s on the slow supported host in
    # v3.8.32; 1800s retains a finite bound with nearly 3x measured margin.
    try:
        faulthandler.enable()
        faulthandler.dump_traceback_later(
            _FULL_SUITE_WATCHDOG_SECONDS, exit=True, file=sys.stderr
        )
    except Exception:
        pass


def pytest_unconfigure(config):
    try:
        faulthandler.cancel_dump_traceback_later()
    except Exception:
        pass
