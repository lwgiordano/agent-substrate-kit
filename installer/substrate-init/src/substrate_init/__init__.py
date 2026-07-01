"""substrate-init — verify-then-install bootstrapper for the Agent Substrate Kit.

The whole point of this package: the TRUST ANCHORS are embedded HERE (in the pip-installed
package) — the minisign public key, and (when the kit signs keyless) a Sigstore identity —
out-of-band from the repository being bootstrapped. So a forked or tampered kit repo cannot
substitute its own key/identity; first-install authenticity is anchored on this package's
integrity (PyPI), not trust-on-first-use of a cloned repo. Verification is multi-backend,
identical to the kit's own verifier (minisign .minisig / Sigstore .sigstore).
"""

__version__ = "0.1.0"
