"""Test session setup: keep the suite hermetic, fast, and self-diagnosing.

- Forces direct linters (no `uv run` venv creation — the v3.2 hang source).
- Arms a faulthandler watchdog: if the whole session runs past 30 minutes,
  Python dumps every thread's traceback to .pytest_cache/watchdog-dump.txt and
  exits 1, so a hang is bounded AND diagnosable. The dump used to go to stderr,
  which pytest captures, so a watchdog kill printed nothing at all and read as
  a plain hook failure (found in a consumer, domain-lookup b061a74). Every
  subprocess in the suite also carries its own timeout.
- Loads the PROJECT's fixtures from tests/conftest_project.py when present
  (v3.9.1). This file is substrate-owned and replaced on upgrade; a consumer
  that put its own fixtures here (live-DNS refusal, per-test resets) had to
  choose between losing them and refusing the upgrade. conftest_project.py is
  preserved by upgrades and left out of the drift baseline.
"""
import contextlib
import faulthandler
import importlib.util
import os
from pathlib import Path

_FULL_SUITE_WATCHDOG_SECONDS = 1800
_watchdog_file = None
_PROJECT_CONFTEST = Path(__file__).with_name("conftest_project.py")


def _load_project_conftest():
    """Import tests/conftest_project.py and expose its fixtures and hooks here.
    Names this file already defines win: the project extends the substrate's
    session setup, it does not replace it (its own pytest_configure is called
    from ours)."""
    if not _PROJECT_CONFTEST.is_file() or _PROJECT_CONFTEST.is_symlink():
        return None
    spec = importlib.util.spec_from_file_location("conftest_project", _PROJECT_CONFTEST)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, value in vars(mod).items():
        if not name.startswith("__") and name not in ("pytest_configure", "pytest_unconfigure"):
            globals().setdefault(name, value)
    return mod


_project = _load_project_conftest()


def pytest_configure(config):
    global _watchdog_file
    os.environ.setdefault("SUBSTRATE_LINT_DIRECT", "1")
    # Watchdog over the WHOLE session. The full suite measured 602.85s on the
    # slow supported host in v3.8.32; 1800s keeps a finite bound with ~3x margin.
    # The dump file is best-effort; the watchdog is not. A dump path that cannot be
    # opened falls back to stderr rather than leaving the session unbounded.
    try:
        rootpath = getattr(config, "rootpath", None) or _PROJECT_CONFTEST.parent.parent
        dump = Path(str(rootpath)) / ".pytest_cache" / "watchdog-dump.txt"
        dump.parent.mkdir(parents=True, exist_ok=True)
        _watchdog_file = open(dump, "w", encoding="utf-8")  # noqa: SIM115 — lives for the session
    except Exception:
        _watchdog_file = None
    try:
        faulthandler.enable()
        if _watchdog_file is not None:
            faulthandler.dump_traceback_later(
                _FULL_SUITE_WATCHDOG_SECONDS, exit=True, file=_watchdog_file
            )
        else:
            faulthandler.dump_traceback_later(_FULL_SUITE_WATCHDOG_SECONDS, exit=True)
    except Exception:
        pass
    if _project is not None and hasattr(_project, "pytest_configure"):
        _project.pytest_configure(config)


def pytest_unconfigure(config):
    if _project is not None and hasattr(_project, "pytest_unconfigure"):
        _project.pytest_unconfigure(config)
    with contextlib.suppress(Exception):
        faulthandler.cancel_dump_traceback_later()
    if _watchdog_file is not None:
        with contextlib.suppress(Exception):
            _watchdog_file.close()
