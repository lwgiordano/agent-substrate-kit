# Audit report — 2026-08-26T154159Z

Mode: `quick`
Final: **PASS**

## Checks

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/substrate_doctor.py`

```text
substrate-doctor: PASS with warnings
  - CODEOWNERS.suggested present but no active .github/CODEOWNERS (fill in real teams, then rename)
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/update_manifest.py --check`

```text
update_manifest: manifest is current (8 knowledge, 1 decisions)
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_doc_drift.py --strict`

```text
doc-drift: no drift detected.
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_agent_harness.py`

```text
agent-harness: ok (168 files scanned under /home/user/agent-substrate-kit)
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_secrets.py`

```text
check-secrets: scanned 286 files, 0 secret-pattern hits.
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_history_sha.py`

```text
check-history-sha: 46 entries verified (46 sha-resolved / 0 bootstrap / 0 correction).
```

