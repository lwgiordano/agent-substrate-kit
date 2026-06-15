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


def pytest_configure(config):
    os.environ.setdefault("SUBSTRATE_LINT_DIRECT", "1")
    # Watchdog: dump all thread stacks if the session wedges. 600s is far
    # above the real ~6s runtime, so it only fires on a genuine hang.
    try:
        faulthandler.enable()
        faulthandler.dump_traceback_later(600, exit=True, file=sys.stderr)
    except Exception:
        pass


def pytest_unconfigure(config):
    try:
        faulthandler.cancel_dump_traceback_later()
    except Exception:
        pass
