# Configuration guide

This Alpha intentionally exposes laboratory-specific configuration instead of adding a new abstraction layer solely for publication.

## Primary files

### `agent/config.env`

Contains the active config path, cassette/RAG defaults, iteration/error limits, logging parameters and compatibility variables such as `TARGET_HOST` and `TARGET_BASE`.

The inherited `BUGTRACEAI_VERSION=3.0.2` is historical metadata. The source baseline is the R0-v2-repair line; the public repository release is `v0.1.0-alpha`. The Alpha preserves provenance instead of silently normalizing that marker.

### `agent/config/dvwa.json`

Defines target, Kali MCP endpoint, authentication, HTTP behavior, scheduler budgets, discovery behavior, validation profiles, cassette and Reasoner settings.

Reference values include `http://192.168.0.200` for DVWA and `http://192.168.0.34:9001` for Kali MCP.

## LLM endpoint

The validated distributed lab places the LLM at `192.168.0.9:8080`. Check the active `LLAMA_URL` in `agent/reasoner_llm.py` when reproducing on separate hosts. A loopback endpoint is valid only when llama-server and the Agent share a host or equivalent forwarding exists.

## Blacklists and scope

URL/vulnerability restrictions belong to configuration/policy, not to the Cassette. Their purpose is to control selection, analysis, execution cost and permitted scope without pretending that a referenced URL disappeared from an HTTP response.

## Cassette selection

The baseline contains `bt-core-2026`, `bt-core-tech-php-2026` and `bt-layered-dvwa-2026`. Cassette content informs reasoning; it is not evidence that the active target is vulnerable.
