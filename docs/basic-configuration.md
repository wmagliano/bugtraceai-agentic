# BugTraceAI Alpha — Basic Configuration Guide

This document covers the minimum configuration required to adapt the **DVWA Alpha** to another isolated laboratory.

The primary runtime configuration for the published runner is **`agent/config/site.json`**. The runner defaults to `--config config/site.json`. Other configuration files are retained for research/history and should not be assumed active from their filename alone.

## Change the DVWA IP

In `agent/config/site.json`, update the target block:

```json
"target": {
  "base_url": "http://192.168.0.200",
  "target_host": "192.168.0.200",
  "kali_host": "192.168.0.34",
  "kali_mcp_base": "http://192.168.0.34:9001"
}
```

If DVWA changes, update both `base_url` and `target_host`, and make `authentication.login_url` follow the same target.

Also update the Kali MCP target restriction:

```bash
cd mcp/kali_mcp-v2.5.6d-open
./update_bugtraceai_mcp_ip.sh <DVWA_IP>
```

Restart Uvicorn afterward.

## Change the Kali MCP address

In the same target block, change both `kali_host` and `kali_mcp_base`. Keep the configured port consistent with the Uvicorn service.

## Change the DVWA security/cookie level

In `agent/config/site.json`, locate the authentication block:

```json
"authentication": {
  "enabled": true,
  "type": "dvwa_form",
  "username": "admin",
  "password": "password",
  "security": "high",
  "login_url": "http://192.168.0.200/login.php",
  "cookie_jar": "/tmp/bugtraceai-session/dvwa_cookie.txt"
}
```

Set `security` to the experimental DVWA level: `"low"`, `"medium"` or `"high"`.

The configuration layer exports this as `BUGTRACEAI_DVWA_SECURITY`, while the login/session workflow uses the configured cookie jar. **Do not invent a PHPSESSID or paste an arbitrary cookie into the Reasoner.** Let the supplied login/session workflow establish the laboratory session.

## Change DVWA laboratory credentials

The reference disposable DVWA lab uses `admin/password`. If your isolated instance differs, change `username` and `password` in the active configuration. Do not place production credentials in this repository.

## Change the local LLM address

The baseline Reasoner contains:

```python
LLAMA_URL = "http://127.0.0.1:8080/completion"
```

If Agent and llama-server are on different hosts, change `LLAMA_URL` in `agent/reasoner_llm.py`. The reference distributed lab uses:

```python
LLAMA_URL = "http://192.168.0.9:8080/completion"
```

The Alpha intentionally preserves this direct baseline setting instead of introducing a new abstraction solely for publication.

## Select the config explicitly

```bash
python3 bugtraceai-runner.py --ciclos 1 --bucles 50 --config config/site.json
```

The reset script accepts the same configuration:

```bash
./reset_v254_sessioncheck.sh config/site.json
```

This is preferable to assuming a historical `config.env` marker determines the experiment.

## Cassette/RAG

Changing cassette content changes contextual knowledge available to the Reasoner and therefore changes an experimental variable. For a simple Kavacon/DVWA reproduction, preserve the supplied validated arrangement unless the experiment specifically studies RAG behavior.

## Quick checklist

1. Set DVWA IP/URL in `config/site.json`.
2. Set Kali MCP IP/URL.
3. Set `authentication.security` to the intended DVWA level.
4. Confirm disposable lab credentials and `login_url`.
5. Update MCP `TARGET_HOST` with `update_bugtraceai_mcp_ip.sh`.
6. Confirm the Reasoner's `LLAMA_URL`.
7. Run the reset/login check.
8. Start with `1 × 50` before increasing budgets.

The security level is an **experimental condition**. Record it with the run results; Low, Medium and High results should not be treated as the same condition.
