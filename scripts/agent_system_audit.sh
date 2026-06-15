#!/usr/bin/env bash
set -euo pipefail
python scripts/check_agent_harness.py
if command -v agentseal >/dev/null 2>&1; then agentseal guard || true; else echo "agentseal not installed"; fi
if command -v codeburn >/dev/null 2>&1; then codeburn optimize -p week || true; codeburn compare -p week || true; codeburn yield -p 30days || true; else echo "codeburn not installed"; fi
