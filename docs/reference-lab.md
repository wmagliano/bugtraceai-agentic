# Reference laboratory

| Component | Reference address | Role |
|---|---|---|
| Local LLM | `192.168.0.9:8080` | llama.cpp completion endpoint |
| DVWA | `192.168.0.200:80` | intentionally vulnerable target |
| Kali MCP | `192.168.0.34:9001` | controlled execution host |

Use an isolated laboratory network. These IPs are values from the validated experiment and may be changed for another lab.

## Local LLM

```bash
~/llama.cpp/build/bin/llama-server \
  -m ~/llm/models/offensive/BugTraceAI-CORE-Ultra-SFT-Q6_K.gguf \
  --host 0.0.0.0 --port 8080 --ctx-size 16384 \
  --threads 8 --threads-http 4 --n-gpu-layers 99 \
  --batch-size 512 --parallel 1 --flash-attn on --reasoning off
```

## DVWA authentication

The baseline uses the standard laboratory credentials `admin/password`. The cookie jar is expected on Kali at `/tmp/bugtraceai-session/dvwa_cookie.txt`. These are lab defaults, not private credentials.

The configured DVWA security level must agree with the experiment being run. Inspect the active `agent/config/*.json` profile rather than relying on an old filename or comment.

## Startup concept

1. Start DVWA and verify it from Kali.
2. Install/start the supplied Kali MCP.
3. Start the local llama-server.
4. Confirm the active Agent config points at the three correct endpoints.
5. Initialize/reset the research run.
6. Execute the selected budget and retain generated reports outside version control.
