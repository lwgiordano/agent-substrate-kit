# Security Policy

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

Instead, use one of these private channels:

- **GitHub Security Advisories**: <https://github.com/YOUR-ORG/YOUR-REPO/security/advisories/new>
  (preferred — gives us a private workspace to coordinate the fix)
- **Email**: security@your-org.example (PGP key: <link>)

Please include:

- A description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- The affected version(s) (commit SHA, release tag, or branch)
- Any relevant logs, traces, or screenshots
- Your name + contact info (or "anonymous" — we'll respect that)

We aim to acknowledge reports within **2 business days** and provide
a fix or mitigation timeline within **10 business days** for
high-severity issues.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: |
| <older> | :x:                |

(Customize this table for your release cadence.)

## Disclosure Policy

We follow **coordinated disclosure**:

1. You report privately.
2. We confirm + assess severity.
3. We develop + test a fix.
4. We agree on a public-disclosure date (typically 30–90 days from
   report, sooner if the issue is being actively exploited).
5. We credit the reporter (unless they opt out).

## What's in scope

- The codebase in this repository.
- Dependencies pinned in `pyproject.toml` / `package.json` / etc.
- The CI/CD pipeline if it processes untrusted input.

## What's out of scope

- Social engineering, phishing, or physical attacks.
- Denial-of-service via excessive resource consumption (unless
  triggered by a specific input we can patch against).
- Issues in third-party services we depend on (report those to the
  vendor; we'll coordinate if it affects us).
- Findings from automated scanners without a working exploit.

## Recognition

Researchers who report valid vulnerabilities are credited in our
release notes (with permission) and listed in
`docs/security/HALL_OF_FAME.md` (project-specific).

---

*This file is a Agent Substrate Kit template. Customize the contact
channels, severity SLAs, and recognition policy for your
organization.*
