---
purpose: Installation and adoption across new and existing repositories.
asserts:
  - bootstrap.sh::_safe_mkdir_p
  - bootstrap.sh::wappend
  - scripts/run_python_gate.sh::_ruff_args
last_human_reviewed: 2026-08-24
covers:
  - bootstrap.sh
  - manage.sh
  - scripts/_substrate_config.sh
  - scripts/_substrate_root.py
  - scripts/check_substrate_config.py
  - scripts/lang_gate.sh
  - scripts/new_validator.py
  - scripts/run_python_gate.sh
  - scripts/substrate_doctor.py
  - scripts/substrate_profile.py
  - scripts/update_manifest.py
  - scripts/write_install_json.py
---

# Install and adoption

[Back to the substrate map](00_substrate.md).

Bootstrap installs the substrate into a new or existing repository. It renders
profile, language, runner, workflow, UI, sandbox, and remote-governance choices
as data in `.substrate/config`; the config parser validates a fixed key and value
grammar and never sources that file as shell.

## Write safety

Bootstrap creates directories through `_safe_mkdir_p` and routes file writes
through guarded helpers. Owned destinations and their real parents must remain
inside the target root. Write helpers replace leaves instead of following
symlinks or hard links, preserve the intended normal-dotfile modes, and verify
that the provenance finalizer produced a non-empty owned-file baseline that
vouches for the rendered `manage.sh`.

The shell installer still has a narrow check-to-write interval because it cannot
impose a mandatory OS lock on every process with repository access. It checks at
startup and again at each write. A non-cooperating writer may make installation
abort, but `--force` does not authorize an external write.

`--install-tools` runs the rendered `manage.sh setup` and fails the bootstrap if
setup fails. Interpreter selection falls back from `python3` to `python` only
where the installer explicitly supports that path.

## Existing repositories

The substrate reserves `scripts/`. Project automation belongs in `tools/`,
`bin/`, or `project-scripts/`. Bootstrap warns when an existing project already
uses the reserved directory and refuses unsafe ownership conflicts unless the
operator chooses the documented force path.

Existing project configuration remains authoritative. Bootstrap does not
replace a pre-existing `pyproject.toml`. The Python gate filters substrate-owned
`scripts/` and `extras/` arguments before Ruff runs, while keeping consumer-owned
tests in scope. If every explicit Ruff path is substrate-reserved, the adapter
exits successfully instead of invoking a bare whole-repository scan.

Substrate runtime memory is ignored in consumer Git state so hook activity does
not make commits perpetually dirty. Setup supports the project runner selected in
config and installs both substrate tools and the relevant project development
toolchain.

## Source and installed layouts

Source-only assets under `templates/` and `extras/` are staged into consumer
locations under `.substrate/`. Code that can run in either layout resolves both
locations explicitly and treats an absent required asset as an error rather than
silently skipping work.

The source kit holds eight functional knowledge documents. A consumer install
gets one generated `docs/knowledge/00_substrate.md` with a live inventory of its
installed scripts. Upgrade preserves consumer-authored sibling knowledge docs
and does not add the seven source-only documents to the owned overwrite set.
The generated `00_substrate.md` and installed `_template.md` are provenance-owned;
additional project knowledge siblings remain governed context but stay outside
the upgrade drift baseline.

`doctor` reports operational readiness, integrity, hook wiring, and configured
governance. Offline doctor and go-live checks do not claim live remote protection
or a sandbox backend that the host cannot prove.
