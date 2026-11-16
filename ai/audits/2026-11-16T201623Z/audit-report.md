# Audit report — 2026-11-16T201623Z

Mode: `quick`
Final: **PASS**

## Checks

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/substrate_doctor.py`

```text
substrate-doctor: PASS
```

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/update_manifest.py --check`

```text
update_manifest: manifest is current (12 knowledge, 3 decisions)
```

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/check_doc_drift.py --strict`

```text
doc-drift: no drift detected.
```

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/check_agent_harness.py`

```text
agent-harness: ok (192 files scanned under /Users/lgiordano/Projects/agent-substrate-kit-v3112-gate)
```

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/check_leaks.py`

```text
check-leaks: scanned 294 files, 0 secret-pattern hits.
```

### PASS: `/Users/lgiordano/Projects/agent-substrate-kit-v3112-gate/.substrate/venv/bin/python scripts/check_history_sha.py`

```text
check-history-sha: 83 entries checked (83 sha-resolved / 0 bootstrap / 0 correction; 7 outcome-labelled; 15 imported-unverified / 1 locally-verified / 0 new-unverified / 0 invalid outcome).
check-history-sha: 15 shipped-green label(s) NOT verifiable in this checkout — unchanged committed claims without matching local proof (.substrate/memory/ is gitignored). Committed provenance is NOT release evidence.
```

