# Audit report — 2026-10-15T004018Z

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
update_manifest: manifest is current (12 knowledge, 2 decisions)
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_doc_drift.py --strict`

```text
doc-drift: no drift detected.
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_agent_harness.py`

```text
agent-harness: ok (188 files scanned under /home/user/agent-substrate-kit)
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_leaks.py`

```text
check-leaks: scanned 280 files, 0 secret-pattern hits.
```

### PASS: `/home/user/agent-substrate-kit/.substrate/venv/bin/python scripts/check_history_sha.py`

```text
check-history-sha: 71 entries checked (71 sha-resolved / 0 bootstrap / 0 correction; 6 outcome-labelled; 4 imported-unverified / 1 locally-verified / 0 invalid outcome).
check-history-sha: 4 shipped-green label(s) NOT verifiable in this checkout — unchanged committed claims without matching local proof (.substrate/memory/ is gitignored). Committed provenance is NOT release evidence.
```

