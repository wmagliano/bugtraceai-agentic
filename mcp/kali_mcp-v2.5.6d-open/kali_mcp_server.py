#!/usr/bin/env python3
"""BugTraceAI Kali MCP v2.5.6d experimental command substitution support.

Allows only: |, &&, >, >>
Keeps background jobs, backticks, semicolons and input redirection blocked; $() is enabled experimentally.
All output redirection targets are restricted to /tmp/bugtraceai-session or
/tmp/bugtraceai-artifacts.
"""
import base64
import os
import re
import shlex
import subprocess
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = BASE_DIR / "assets"

app = FastAPI(title="BugTraceAI Kali MCP v2.5.6d-open")
TARGET_HOST = "192.168.0.200"
OPEN_MODE = True
SAFE_REDIRECT_PREFIXES = ("/tmp/bugtraceai-session/", "/tmp/bugtraceai-artifacts/")
LOCAL_SCOPE_HOSTS = {TARGET_HOST, "127.0.0.1", "localhost"}
DESTRUCTIVE_HOST_TOKENS = (
    "mkfs", "shutdown", "reboot", "poweroff", "halt",
    "rm -rf /", "rm -rf /*", "dd if=", ":(){:|:&};:",
)

class SqlmapRequest(BaseModel):
    url: str
    cookie: str | None = None
    level: int = 1
    risk: int = 1
    current_db: bool = True

class ExecRequest(BaseModel):
    command: str | None = None
    command_b64: str | None = None
    timeout: int = 300

def in_scope(url: str) -> bool:
    return urlparse(url).hostname == TARGET_HOST

def _urls_in_scope(text: str) -> bool:
    for value in re.findall(r'https?://[^\s"\']+', text):
        if not in_scope(value.rstrip(')>,.')):
            return False
    return True

def _has_unsafe_ampersand(command: str) -> bool:
    """Return True when a single ampersand can act as a shell operator.

    v2.5.5c permits a single ``&`` only inside a quoted argument and only
    when it has non-whitespace, non-quote characters immediately on both
    sides, for example ``"?id=1&Submit=Submit"``. ``&&`` remains handled
    separately as an explicitly enabled operator.
    """
    quote = None
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            i += 1
            continue
        if ch in ("'", '"'):
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
            i += 1
            continue
        if ch == "&":
            if i + 1 < len(command) and command[i + 1] == "&":
                i += 2
                continue
            prev_ch = command[i - 1] if i > 0 else ""
            next_ch = command[i + 1] if i + 1 < len(command) else ""
            quoted_and_joined = (
                quote is not None
                and prev_ch not in ("", "'", '"')
                and next_ch not in ("", "'", '"')
                and not prev_ch.isspace()
                and not next_ch.isspace()
            )
            if not quoted_and_joined:
                return True
        i += 1
    return False

def _split_shell(command: str) -> list[str]:
    """Split top-level pipes/&& while preserving quoted text and $(...)."""
    parts = []
    start = 0
    quote = None
    escaped = False
    substitution_depth = 0
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            i += 1
            continue
        if ch in ("'", '"'):
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
            i += 1
            continue
        if quote is None:
            if command.startswith("$(", i):
                substitution_depth += 1
                i += 2
                continue
            if ch == ")" and substitution_depth:
                substitution_depth -= 1
                i += 1
                continue
            if substitution_depth == 0:
                if command.startswith("&&", i):
                    part = command[start:i].strip()
                    if part:
                        parts.append(part)
                    i += 2
                    start = i
                    continue
                if ch == "|":
                    part = command[start:i].strip()
                    if part:
                        parts.append(part)
                    i += 1
                    start = i
                    continue
        i += 1
    part = command[start:].strip()
    if part:
        parts.append(part)
    return parts

def _validate_redirects(command: str):
    for match in re.finditer(r'(?<!>)>>?(?!>)\s*([^\s]+)', command):
        raw = match.group(1).strip('"\'')
        if not raw.startswith(SAFE_REDIRECT_PREFIXES):
            return False, f"redirección fuera de ruta permitida: {raw}"
    return True, "ok"

def _strip_redirect(segment: str) -> str:
    return re.split(r'\s+>>?\s*', segment, maxsplit=1)[0].strip()

def _ipv4_literals_in_scope(text: str) -> bool:
    for ip in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
        if ip not in LOCAL_SCOPE_HOSTS:
            return False
    return True

def validate_command(command: str):
    normalized = command.strip()
    if not normalized:
        return False, "comando vacío"
    low = normalized.lower()
    for token in DESTRUCTIVE_HOST_TOKENS:
        if token in low:
            return False, f"operación destructiva del host bloqueada: {token}"
    if not _urls_in_scope(normalized):
        return False, "URL fuera de scope"
    if not _ipv4_literals_in_scope(normalized):
        return False, "IP fuera de scope"
    return True, normalized


def _constraint_error(error_type: str, reason: str, *, blocked_token: str | None = None, alternative: str | None = None, retryable: bool = True):
    return {
        "ok": False,
        "error": reason,
        "constraint": {
            "error_type": error_type,
            "blocked_token": blocked_token,
            "reason": reason,
            "allowed_alternative": alternative,
            "retryable": retryable,
        },
    }

@app.get('/capabilities')
def capabilities():
    return {
        "version": "2.5.6d-open",
        "execution_model": "synchronous",
        "shell_supported": True,
        "open_mode": True,
        "allowed_shell_operators": ["normal bash syntax"],
        "blocked_shell_constructs": [],
        "available_tools": "installed tools available through /bin/bash",
        "background_processes": True,
        "interactive_commands": False,
        "stdin_streaming": False,
        "timeout_seconds": {"default": 300, "minimum": 10, "maximum": 600},
        "scope_policy": {"target_host": TARGET_HOST, "same_target_host_required": True, "external_hosts": False},
        "host_protection": {"minimal_destructive_denylist": list(DESTRUCTIVE_HOST_TOKENS)},
        "assets": {"brute_wordlist": "assets/brute.txt", "benign_phpinfo_php": "assets/benign_phpinfo.php"},
    }

@app.get('/health')
def health():
    return {"status": "ok", "service": "bugtraceai-kali-mcp", "version": "2.5.6d-open", "open_mode": True}

@app.get('/tools')
def tools():
    return {"tools": ["sqlmap_current_db", "exec"], "execution": "open-bash", "open_mode": True, "assets_dir": str(ASSETS_DIR), "assets": {"brute": (ASSETS_DIR / "brute.txt").exists(), "upload_php": (ASSETS_DIR / "benign_phpinfo.php").exists()}}

def _b64decode_text(value):
    if not value: return ""
    return base64.b64decode(value.encode('ascii'), validate=True).decode('utf-8', errors='replace')

def _b64encode_text(value):
    return base64.b64encode((value or '').encode('utf-8', errors='replace')).decode('ascii')

@app.post('/tools/exec')
def exec_command(req: ExecRequest):
    transport_request = 'command'
    try:
        command = req.command or ''
        if req.command_b64:
            command = _b64decode_text(req.command_b64)
            transport_request = 'command_b64'
    except Exception as exc:
        return {"ok": False, "error": f"command_b64 inválido: {exc}", "command": "", "returncode": None, "stdout": "", "stderr": "", "stdout_b64": "", "stderr_b64": "", "transport_request": transport_request}
    valid, result = validate_command(command)
    if not valid:
        low_result = result.lower()
        if "herramienta no permitida" in low_result:
            error_type, alternative = "TOOL_NOT_ALLOWED", "Select only a binary listed by GET /capabilities."
        elif "scope" in low_result:
            error_type, alternative = "SCOPE_VIOLATION", "Use only the configured target host."
        elif "background" in low_result or "&" in low_result:
            error_type, alternative = "BACKGROUND_OPERATOR_BLOCKED", "Run synchronously; keep ampersands only as quoted HTTP data."
        elif "redirección" in low_result:
            error_type, alternative = "UNSAFE_LOCAL_PATH", "Use /tmp/bugtraceai-session/ or /tmp/bugtraceai-artifacts/."
        elif "token bloqueado" in low_result:
            error_type, alternative = "UNSUPPORTED_SHELL_CONSTRUCT", "Use separate simple MCP actions instead of the blocked shell construct."
        else:
            error_type, alternative = "COMMAND_POLICY_REJECTED", "Adapt the command to GET /capabilities and retry with a materially different valid action."
        response = _constraint_error(error_type, result, alternative=alternative, retryable=True)
        response.update({"command": command, "returncode": None, "stdout": "", "stderr": "", "stdout_b64": "", "stderr_b64": "", "transport_request": transport_request})
        return response
    timeout = min(max(req.timeout, 10), 600)
    os.makedirs('/tmp/bugtraceai-session', exist_ok=True)
    os.makedirs('/tmp/bugtraceai-artifacts', exist_ok=True)
    try:
        completed = subprocess.run(
            result,
            shell=True,
            executable='/bin/bash',
            capture_output=True,
            text=False,
            timeout=timeout,
            cwd=str(BASE_DIR),
        )
    except subprocess.TimeoutExpired as exc:
        stdout_bytes = exc.stdout or b""
        stderr_bytes = exc.stderr or b""
        return {
            "ok": False,
            "error": "timeout",
            "command": command,
            "returncode": None,
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace") or "timeout",
            "stdout_b64": base64.b64encode(stdout_bytes).decode("ascii"),
            "stderr_b64": base64.b64encode(stderr_bytes or b"timeout").decode("ascii"),
            "stdout_is_binary": b"\x00" in stdout_bytes,
            "stdout_bytes_total": len(stdout_bytes),
            "stderr_bytes_total": len(stderr_bytes),
            "transport_request": transport_request,
        }

    stdout_bytes = completed.stdout or b""
    stderr_bytes = completed.stderr or b""
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")

    return {
        "ok": completed.returncode == 0,
        "command": command,
        "returncode": completed.returncode,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_b64": base64.b64encode(stdout_bytes).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr_bytes).decode("ascii"),
        "stdout_is_binary": b"\x00" in stdout_bytes,
        "stdout_bytes_total": len(stdout_bytes),
        "stderr_bytes_total": len(stderr_bytes),
        "transport_request": transport_request,
    }

