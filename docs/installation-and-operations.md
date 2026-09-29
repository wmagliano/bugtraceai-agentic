# BugTraceAI Alpha — Installation and Operations Guide

This guide prepares and runs the **v0.1.0-alpha DVWA research release**. It accompanies the Kavacon research presentation; it is not a production deployment guide.

> Use only in an isolated laboratory or on systems for which you have explicit authorization.

## Reference topology

| Role | Reference address |
|---|---|
| Local LLM | `192.168.0.9:8080` |
| DVWA | `192.168.0.200:80` |
| Kali MCP | `192.168.0.34:9001` |

Adapt these research-lab addresses to your own isolated laboratory.

## Components

A complete experiment uses the BugTraceAI Agent in `agent/`, Kali MCP in `mcp/kali_mcp-v2.5.6d-open/`, a local LLM served through llama.cpp, and an isolated DVWA target.

## Obtain the repository

```bash
git clone https://github.com/wmagliano/bugtraceai-agentic.git
cd bugtraceai-agentic
```

## Prepare Kali MCP

On the Kali host:

```bash
cd mcp/kali_mcp-v2.5.6d-open
```

The supplied Python requirements are `fastapi` and `uvicorn`. Install them in the Python environment you intend to use, then:

```bash
./bootstrap_mcp.sh
```

The installer places the active files under `/opt/bugtraceai-mcp` by default and installs the DVWA login helper.

If DVWA has another IP:

```bash
./update_bugtraceai_mcp_ip.sh <DVWA_IP>
```

Restart Uvicorn after changing the target. Example service start:

```bash
cd /opt/bugtraceai-mcp
uvicorn kali_mcp_server:app --host 0.0.0.0 --port 9001
```

Then validate the MCP from the source directory:

```bash
./validate_bugtraceai_mcp.sh <DVWA_IP>
```

The supplied validator includes a DVWA login smoke test using the laboratory defaults and `low` security. The Agent experiment level is selected independently in `agent/config/site.json`.

## Start the local LLM

Reference research command:

```bash
~/llama.cpp/build/bin/llama-server \
  -m ~/llm/models/offensive/BugTraceAI-CORE-Ultra-SFT-Q6_K.gguf \
  --host 0.0.0.0 --port 8080 --ctx-size 16384 \
  --threads 8 --threads-http 4 --n-gpu-layers 99 \
  --batch-size 512 --parallel 1 --flash-attn on --reasoning off
```

The published Reasoner preserves `LLAMA_URL = "http://127.0.0.1:8080/completion"`. If Agent and LLM are on different machines, edit `agent/reasoner_llm.py` to the real llama-server endpoint; the reference distributed lab uses `http://192.168.0.9:8080/completion`.

## Configure the Agent

```bash
cd agent
```

The multi-cycle runner uses **`config/site.json` by default**. Before execution review the DVWA URL/IP, Kali MCP URL/IP, disposable lab credentials, DVWA security level, scope/blacklists and LLM endpoint.

See [Basic Configuration Guide](basic-configuration.md).

## Pre-flight reset

The runner performs the reset automatically before each cycle. It can also be tested manually:

```bash
./reset_v254_sessioncheck.sh config/site.json
```

This loads the selected configuration, resets operational state, performs the remote DVWA login through MCP, establishes session context, initializes discovery and prepares the scheduler.

## Small smoke test

Start with a short reproduction run:

```bash
python3 bugtraceai-runner.py --ciclos 1 --bucles 50 --config config/site.json
```

The runner uses `./run_v302_auto.sh` as its default single-cycle entry point and `./reset_v254_sessioncheck.sh` as its default reset command.

## Longer experiments

Only after the smoke test is stable should budgets be increased. Example:

```bash
python3 bugtraceai-runner.py --ciclos 5 --bucles 500 --config config/site.json
```

Experiment outputs are written under `runs/`; multi-cycle execution also produces aggregate results and records the selected configuration and experiment parameters.

## Before every run

Confirm that DVWA is isolated and authorized; `config/site.json` points only to the lab; `authentication.security` matches the intended DVWA level; MCP `TARGET_HOST` matches DVWA; Kali MCP and the LLM are reachable; and a short smoke test succeeds before increasing budgets.

## Alpha scope

This release documents the validated DVWA research line. It does not claim production readiness or general target support. bWAPP and other targets belong to the continuing generalization study.
