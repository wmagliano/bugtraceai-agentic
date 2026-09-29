# Source integrity

## Public Alpha staging record

The source tree prepared for `v0.1.0-alpha` was built from the supplied research artifacts:

- Agent baseline: `bugtraceai-agent-v3.0.5b-r0-v2-repair-final-perfecto.tar.xz`
- Final Reasoner: supplied corrected `reasoner_llm.py`
- MCP: `kali_mcp-v2.5.6d-open`

## Deliberate transformations

The staging process:

1. removed `__pycache__`, `*.pyc`, macOS metadata and generated runtime directories;
2. excluded the experimental `config/sites/bwapp.json` from the DVWA-only Alpha;
3. removed the historical embedded MCP copy from the Agent tree in favor of the separately supplied stable `kali_mcp-v2.5.6d-open`;
4. replaced the baseline `reasoner_llm.py` with the supplied final version.

The Reasoner diff is limited to the bounded contract-repair guard that rejects a missing/non-string/empty `action` before indexing `ACTION_REQUIRED_FIELDS`.

## Verification

The staged public tree was checked before publication:

- 177 files including documentation and release metadata;
- 45 Python source files compiled successfully;
- no bWAPP-named paths in the release tree;
- no Python bytecode/runtime output directories;
- no private-key or API-secret patterns detected.

A compressed `agent/ + mcp/` source snapshot was generated with SHA-256:

```text
d03b8e28240506430b8236708a142f18cbde0af667f9640df9beab0c2b21f66d
```

This record is intended to make later Alpha changes distinguishable from the closed DVWA baseline.
