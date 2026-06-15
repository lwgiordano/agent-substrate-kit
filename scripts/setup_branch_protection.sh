#!/usr/bin/env bash
# Operator helper for the strict root-of-trust GitHub settings.
#
# READ-ONLY by design. The kit can recommend and VERIFY the required branch
# protection, but enabling it is an explicit operator action (it is a
# repository setting, not a repo file). There is intentionally NO --apply yet:
# mutating branch protection / rulesets via the API is operator territory and
# easy to get subtly wrong, so this helper stops at plan + check.
#
#   --plan   print the exact branch-protection settings strict mode needs
#   --check  verify the live repo against them (delegates to
#            check_github_governance.py --require; needs GITHUB_TOKEN +
#            GITHUB_REPOSITORY, an admin-readable token, run in CI)
#
# Exit: 0 plan printed / governance ok | non-zero governance insufficient.
set -euo pipefail
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode="${1:---plan}"
case "$mode" in
  --plan)
    cat <<'PLAN'
Strict root-of-trust — required GitHub branch protection on the protected base branch:
  - require a pull request before merging
  - require Code Owner review (CODEOWNERS must cover scripts/, workflows, .substrate/required_profile)
  - require status check: trusted-base policy audit
  - require status check: CI (tests / lint)
  - block force pushes
  - block branch deletion

Set these under: Settings -> Branches -> Branch protection rules (or a Ruleset).
Then verify from CI with an admin-readable token:
  ./scripts/setup_branch_protection.sh --check
Until these are enforced by GitHub, the trusted-base workflow is developer
feedback, not the final authority (see SECURITY.md / OPERATOR_ENABLEMENT.md).
PLAN
    ;;
  --check)
    py="python3"; [ -x ".substrate/venv/bin/python" ] && py=".substrate/venv/bin/python"
    exec "$py" -I "$SCRIPTS_DIR/check_github_governance.py" --require
    ;;
  -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" ;;
  *) echo "usage: $0 [--plan|--check]" >&2; exit 2 ;;
esac
