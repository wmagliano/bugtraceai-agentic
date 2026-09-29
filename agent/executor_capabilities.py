#!/usr/bin/env python3
"""Runtime capability discovery for BugTraceAI v2.6.3.

The MCP is the authoritative source. A conservative local fallback is used only
when /capabilities cannot be reached. This module describes execution limits;
it does not prescribe vulnerability techniques or payloads.
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
from pathlib import Path

MCP_BASE = os.environ.get("BUGTRACEAI_KALI_MCP_BASE", "http://192.168.0.34:9001").rstrip("/")
CACHE_FILE = Path("logs/runtime_capabilities.json")
_CACHE_TTL = 60
_mem_cache: tuple[float, dict] | None = None

FALLBACK = {
    "version": "agent-fallback-v2.6.3-r4b-open",
    "source": "local_fallback",
    "execution_model": "synchronous",
    "shell_supported": True,
    "allowed_shell_operators": ["open-bash"],
    "blocked_shell_constructs": [],
    "available_tools": [
        "curl", "sqlmap", "nmap", "ffuf", "nikto", "nuclei", "whatweb",
        "hydra", "echo", "printf", "base64", "cat", "md5sum", "file", "ls", "stat",
        "grep", "sed", "awk", "head", "tail", "cut", "sort", "uniq", "tr", "jq", "tee", "wc"
    ],
    "safe_local_paths": {
        "read": ["/tmp/bugtraceai-session/", "/tmp/bugtraceai-artifacts/"],
        "write": ["/tmp/bugtraceai-session/", "/tmp/bugtraceai-artifacts/"]
    },
    "scope_policy": {"same_target_host_required": True, "external_hosts": False},
    "retry_guidance": {
        "unsupported_shell_construct": "Use separate simple MCP actions instead of a shell loop.",
        "tool_not_allowed": "Choose a tool listed in available_tools.",
        "scope_violation": "Remain on the authorized target host and active Analysis Item scope.",
        "unsafe_local_path": "Use only a safe_local_paths prefix."
    },
    "capability_discovery_error": None,
}


def _save(payload: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def _remote() -> dict:
    req = urllib.request.Request(MCP_BASE + "/capabilities", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=3) as response:
        value = json.loads(response.read().decode("utf-8", errors="replace"))
    if not isinstance(value, dict) or not value.get("available_tools"):
        raise ValueError("respuesta /capabilities incompleta")
    value["source"] = "mcp:/capabilities"
    value["mcp_base"] = MCP_BASE
    return value


def capabilities_payload(force_refresh: bool = False) -> dict:
    global _mem_cache
    now = time.time()
    if not force_refresh and _mem_cache and now - _mem_cache[0] < _CACHE_TTL:
        return _mem_cache[1]
    try:
        payload = _remote()
    except Exception as exc:
        payload = dict(FALLBACK)
        payload["capability_discovery_error"] = f"{type(exc).__name__}: {exc}"
        payload["mcp_base"] = MCP_BASE
    _mem_cache = (now, payload)
    _save(payload)
    return payload


def available_tools() -> list[str]:
    return list(capabilities_payload().get("available_tools", []))
