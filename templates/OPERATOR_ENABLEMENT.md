# Operator enablement checklist

The substrate has three responsibilities the kit cannot fulfill on
its own — each requires a human (or an authorized agent acting on
your behalf) to click through GitHub UI or local IDE settings.

Do these once after `bash bootstrap.sh` + first commit.

---

## 1. Branch protection on `main` (GitHub)

The substrate's gates run locally via pre-commit AND in CI via the
GitHub Actions workflow. Branch protection ensures CI must pass
before merge — the third line of defense after pre-commit
(local) and CI (cloud).

**Steps:**

1. Open the repo on github.com.
2. Settings → Branches → Branch protection rules → Add rule.
3. Branch name pattern: `main` (or `master`, whichever your default is).
4. Check **"Require status checks to pass before merging"**.
5. Search for and require:
   - `pre-commit-and-tests`  (the pre-commit + pytest job from CI)
   - `pip-audit`             (the dep-vuln scan job)
6. (Optional but recommended) Check:
   - **"Require pull request reviews before merging"** with 1 approval
   - **"Require linear history"** (no merge commits)
   - **"Include administrators"** (no bypass for repo owners)
7. Save.

**Why**: without branch protection, a contributor can merge directly
to main bypassing CI. The substrate's "second line of defense" only
holds when CI is required.

---

## 2. Dependabot — enable version updates

The kit ships `.github/dependabot.yml` configured for weekly
updates of Python dependencies + GitHub Actions versions, with
dev-tooling bumps grouped into a single PR. The config is inert
until enabled GitHub-side.

**Steps:**

1. Open the repo on github.com.
2. Settings → Code security → Dependabot → Dependabot version updates.
3. Click **Enable**.
4. (Optional) Settings → Code security → Dependabot → Dependabot
   alerts: also enable for security advisory notifications.

After enable, dependabot opens PRs against `main` on the cadence
configured in `.github/dependabot.yml`. The PRs trigger CI (which
re-runs pip-audit + pre-commit), so vulnerable deps are blocked at
merge time.

---

## 3. (Optional) Devcontainer for reproducible dev env

If you use VS Code or another editor with the Dev Containers
extension, you can ship a `.devcontainer/devcontainer.json` that
captures the project's Python version + dep-manager + pre-commit
state. The kit doesn't ship one by default — consider adding when
the team grows beyond 1-2 contributors.

**Quick-start template** (drop in `.devcontainer/devcontainer.json`
if you want it):

```json
{
  "name": "<your-project>",
  "image": "mcr.microsoft.com/devcontainers/python:3.11",
  "postCreateCommand": "pip install uv && uv sync --group dev && uv run pre-commit install && uv run pre-commit install --hook-type commit-msg",
  "customizations": {
    "vscode": {
      "extensions": ["ms-python.python", "charliermarsh.ruff"]
    }
  }
}
```

Adapt `postCreateCommand` to your dep manager (poetry / pip / etc.).

---

## 4. (Codex/Copilot) Trust the substrate hooks

The kit wires deterministic hooks for Codex (`.codex/hooks.json`) and
Copilot (`.github/hooks/`) in addition to Claude.

- **Codex** requires you to review and TRUST each command hook before it
  runs — Codex records the hook's hash and skips it until approved.
  Review `.codex/hooks.json`, confirm the commands only invoke
  repo-local `scripts/*.py`, then trust them.
- Never enable `--dangerously-bypass-hook-trust` (Codex) or
  `--dangerously-skip-permissions` (Claude) in committed config —
  `check_agent_harness.py` flags both as BLOCK.
- The exfil guard is a **tripwire, not a sandbox**. For high-stakes
  work, also run the agent without ambient access to real secrets.
- (Strict, high-stakes) anchor the memory chain outside the repo:
  `./manage.sh memory anchor` writes the head hash to a git note; push
  `refs/notes/substrate-memory` to a protected remote so a local
  rewrite is detectable (`./manage.sh memory verify --anchor`).

---

## Operator tools & conventions

- **Readiness, in one command:** `./manage.sh go-live` prints a single report
  separating *repo-local ready* from *production-hardened*, and warns on what's
  missing (sandbox, GitHub governance, memory anchor). `--json`
  (`./manage.sh go-live --json`) emits a stable machine-readable contract
  (`repo_local`, `production_hardened`, `checks[]`) for installers / agents /
  dashboards. It never reports production-hardened while the sandbox tier is
  absent.
- **Branch protection:** `scripts/setup_branch_protection.sh --plan` prints the
  exact strict-mode GitHub settings to enable; `--check` (in CI, admin token)
  verifies them via `check_github_governance.py --require`. There is no
  auto-apply — enabling protection is your explicit action.
- **Reserved namespace:** in strict mode `scripts/` is **substrate-owned** and
  frozen by the trusted-base guard. Put PROJECT scripts in `tools/`, `bin/`, or
  `project-scripts/` — a project file under `scripts/` will trip the freeze.

## After all three are done

The substrate is fully active:
- **Local**: pre-commit hooks fire on every `git commit`.
- **CI**: branch protection requires CI green; CI re-runs pre-commit + pip-audit.
- **Updates**: dependabot opens weekly PRs; CI catches CVEs.

First product work can start now. Read `AGENTS.md` before composing
any non-trivial commit.
