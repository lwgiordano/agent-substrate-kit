"""substrate-init — verify-then-install bootstrapper for the Agent Substrate Kit.

The whole point of this package: the minisign TRUST KEY is embedded HERE (in the
pip-installed package), out-of-band from the repository being bootstrapped. So a forked
or tampered kit repo cannot substitute its own key — first-install authenticity is
anchored on this package's integrity (PyPI), not trust-on-first-use of a cloned repo.
"""

__version__ = "0.1.0"
