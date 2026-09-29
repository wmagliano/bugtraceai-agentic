#!/usr/bin/env python3
from capability_gate import evaluate_architecture_validation
"""
BugTraceAI-Agent v1.4 final Executor MCP Unificado

Objetivo:
- Mantener al LLM server como nodo de razonamiento/análisis.
- Enviar toda ejecución activa contra el objetivo a Kali vía MCP /tools/exec.
- Mantener compatibilidad con decisiones V1.2/V1.3:
  - run_interior
  - review_forms
  - propose_command        -> alias legacy, ejecutado vía MCP
  - propose_mcp_command    -> ejecución vía MCP
  - propose_mcp_tool       -> fallback endpoint MCP
  - operator_verdict
  - ask_operator
  - stop_on_error

Nota:
- run_interior ya usa Kali/MCP mediante curl.
- review_forms solo lee knowledge.json localmente; no toca el objetivo.
- propose_command ya NO usa subprocess local; se enruta a Kali MCP.
"""

import json
import os
import shlex
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from runtime_diagnostics import emit as runtime_event
from flow_trace import executor_event
from lifecycle_trace import persist_snapshot
from urllib.parse import urlparse, urljoin, parse_qs
from html.parser import HTMLParser
import hashlib
import re
import base64
import uuid
from decision_contract import ALLOWED_RESOURCE_STATES
from discovery_manager import register_urls
from analysis_queue import sync_runtime, set_state, set_active, find_item, active_item, apply_llm_assessment, finalize_runtime_assessment
from evidence_matcher import evaluate_expected_evidence

DECISION_FILE = Path("logs/last_llm_decision.json")
KNOWLEDGE_FILE = Path("data/knowledge.json")
EXEC_STATE_FILE = Path("logs/executor_state.json")
EXEC_LOG = Path("logs/executor_mcp.log")

DEFAULT_KALI_MCP_BASE = "http://192.168.0.34:9001"
MCP_EXEC_ENDPOINT = "/tools/exec"
DEFAULT_TARGET_HOST = os.environ.get("BUGTRACEAI_TARGET_HOST", "192.168.0.200")
COOKIE_PLACEHOLDERS = ["{{DVWA_COOKIE}}", "AUTO_DVWA_COOKIE"]
KALI_SESSION_DIR = "/tmp/bugtraceai-session"
KALI_COOKIE_JAR = f"{KALI_SESSION_DIR}/dvwa_cookie.txt"
KALI_DVWA_LOGIN_SCRIPT = "bugtraceai_dvwa_login"
VERSION = "2.5.6a"
MAX_REFERENCE_EXPLOITS_PER_ROUND = 2
TERMINAL_RESOURCE_STATES = {"COMPLETED", "INCONCLUSIVE", "FAILED"}
TERMINAL_ALIASES = {"DOCUMENTED": "COMPLETED", "DONE": "COMPLETED", "FINISHED": "COMPLETED", "CLOSED": "COMPLETED"}


ALLOWED_ACTIONS = {
    "run_login",
    "run_interior",
    "review_forms",
    "ask_operator",
    "stop_on_error",
    "propose_command",
    "propose_mcp_command",
    "propose_mcp_tool",
    "operator_verdict",
    "finalize_analysis",
    "submit_benign_upload",
}

ALLOWED_MCP_COMMANDS = {
    "curl",
    "wget",
    "ping",
    "sqlmap",
    "nmap",
    "ffuf",
    "nikto",
    "nuclei",
    "whatweb",
    "hydra",
    "echo",
    "printf",
    "base64",
    "cat",
    "md5sum",
    "file",
    "ls",
    "stat",
}

ALLOWED_MCP_TOOLS = {
    "sqlmap_current_db": "/tools/sqlmap/current-db",
}

BLOCKED_TOKENS = [
    "`",
    " rm", "rm ", " chmod", "chmod ", " chown", "chown ",
    " nc ", " ncat ", " socat ",
    " bash ", " sh ", " python ", " python3 ", " perl ", " php ",
    "mkfifo", "/dev/tcp", " sudo ", " dd ", "mkfs", "shutdown", "reboot",
    "curl |", "wget |", "base64 -d", "eval "
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def log_event(text):
    EXEC_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EXEC_LOG.open("a", encoding="utf-8") as f:
        f.write(text + "\n")


def load_json_file(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_decision():
    if not DECISION_FILE.exists():
        print("[ERROR] No existe logs/last_llm_decision.json")
        sys.exit(1)
    try:
        return json.loads(DECISION_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print("[ERROR] JSON inválido en last_llm_decision.json")
        print(e)
        sys.exit(1)


def load_knowledge():
    return load_json_file(KNOWLEDGE_FILE, {})


def save_knowledge(k):
    sync_runtime(k)
    write_json_file(KNOWLEDGE_FILE, k)
    persist_snapshot(k,component='executor_mcp.save_knowledge',path=str(KNOWLEDGE_FILE))


def normalize_resource_url(url):
    """Normalize a resource without discarding its query-string identity.

    Since v1.9/v2.x an Analysis Item is keyed by the complete entry URL. Query
    parameters may identify a distinct resource variant (for example page=...).
    Removing the query here caused run_interior to replace the scheduler's active
    URL with the bare path, after which reconcile() released it as missing.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip().split("#", 1)[0]
    if not url.startswith(("http://", "https://")):
        return url
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))




def _completed_set(k):
    out=set()
    for item in k.get("completed_urls", []) or []:
        if isinstance(item, str): out.add(item)
        elif isinstance(item, dict):
            u=item.get("url") or item.get("resource")
            if isinstance(u,str): out.add(u)
    return out

def next_unvisited_candidate(k, exclude=None):
    visited=set(u for u in (k.get("visited_urls") or []) if isinstance(u,str))
    completed=_completed_set(k)
    skipped=set(u for u in (k.get("loop_skipped_urls") or []) if isinstance(u,str))
    for u in k.get("candidate_urls") or []:
        if isinstance(u,str) and u and u != exclude and u not in visited and u not in completed and u not in skipped:
            return u
    return None

def advance_after_loop(resource, reason, decision_id=None):
    k=load_knowledge()
    if resource:
        if resource not in k.setdefault("loop_skipped_urls", []):
            k["loop_skipped_urls"].append(resource)
    nxt=next_unvisited_candidate(k, exclude=resource)
    event={"timestamp":utc_now(),"type":"loop_escape","resource":resource,"reason":reason,"recommended_next_url":nxt}
    k.setdefault("runtime_feedback", []).append(event)
    k["runtime_feedback"]=k["runtime_feedback"][-10:]
    k["active_resource"] = ({"resource":nxt,"source":"loop_escape_guard","previous_resource":resource,"decision_id":decision_id,"timestamp":utc_now()} if nxt else None)
    k["recommended_next_url"]=nxt
    save_knowledge(k)
    print("[LOOP ESCAPE]", resource, "->", nxt or "sin siguiente URL")
    return nxt

def register_repeated_action(action_obj, decision_id):
    action=str(action_obj.get("action") or "")
    resource=action_obj.get("url") or action_obj.get("resource") or _extract_first_url(action_obj.get("command", "")) or get_active_resource()
    signature=action+"|"+str(resource or "global")
    k=load_knowledge()
    guard=k.setdefault("loop_guard", {"last_signature":None,"consecutive":0,"events":[]})
    if guard.get("last_signature") == signature:
        guard["consecutive"] = int(guard.get("consecutive") or 0) + 1
    else:
        guard["last_signature"] = signature
        guard["consecutive"] = 1
    guard["last_decision_id"]=decision_id
    guard["last_timestamp"]=utc_now()
    guard.setdefault("events", []).append({"timestamp":utc_now(),"signature":signature,"count":guard["consecutive"]})
    guard["events"]=guard["events"][-10:]
    save_knowledge(k)
    if guard["consecutive"] >= 3:
        advance_after_loop(resource, "misma acción/recurso repetida 3 veces", decision_id)
        return True
    return False

def register_navigation_failure(resource, reason, decision_id):
    k=load_knowledge()
    bucket=k.setdefault("navigation_failures", {})
    obj=bucket.setdefault(resource, {"count":0,"events":[]})
    obj["count"]=int(obj.get("count") or 0)+1
    obj["last_reason"]=str(reason)
    obj["last_timestamp"]=utc_now()
    obj.setdefault("events", []).append({"timestamp":utc_now(),"reason":str(reason),"decision_id":decision_id})
    obj["events"]=obj["events"][-5:]
    save_knowledge(k)
    print(f"[NAVIGATION ERROR] {resource} count={obj['count']} reason={reason}")
    if obj["count"] >= 3:
        advance_after_loop(resource, f"3 errores de navegación: {reason}", decision_id)
        return True
    return False

def execute_finalize_analysis(action_obj, decision, decision_id):
    """Close the active Analysis Item only after an explicit terminal LLM assessment."""
    k = load_knowledge()
    item = active_item(k)
    if not item:
        resource = get_active_resource()
        item = find_item(k, url=resource) if resource else None
    if not item:
        print("[FINALIZE BLOCKED] No hay Analysis Item activo.")
        return

    reflection = decision.get("reflection") or {}
    assessment = str(reflection.get("assessment") or "CONTINUE").upper()
    if assessment not in {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "NO_FINDING"}:
        print("[FINALIZE BLOCKED] reflection.assessment no es terminal:", assessment)
        return

    verdict = (item.get("vulnerability_verdict") or {}).get("status")
    if str(verdict or "UNKNOWN").upper() in {"UNKNOWN", "CONTINUE"}:
        print("[FINALIZE BLOCKED] El veredicto no fue persistido antes del cierre.")
        return

    terminal_state = "INCONCLUSIVE" if assessment == "INCONCLUSIVE" else "COMPLETED"
    resource = item.get("entry_url")
    set_state(k, resource, terminal_state, action_obj.get("reason") or reflection.get("interpretation") or "Assessment terminal", "llm_finalize_analysis")
    completed = k.setdefault("completed_urls", [])
    if resource and resource not in completed:
        completed.append(resource)
    k["active_resource"] = None
    k["active_analysis_id"] = None
    save_knowledge(k)
    print(f"[FINALIZED] {item.get('analysis_id')} {assessment} -> {terminal_state}")

def set_active_resource(resource, source="runtime", decision_id=None):
    resource = normalize_resource_url(resource)
    if not resource:
        return
    k = load_knowledge()
    k["active_resource"] = {
        "resource": resource,
        "source": source,
        "decision_id": decision_id,
        "timestamp": utc_now(),
    }
    save_knowledge(k)


def get_active_resource(k=None):
    k = k if isinstance(k, dict) else load_knowledge()
    active = k.get("active_resource")
    if isinstance(active, dict) and active.get("resource"):
        return active.get("resource")
    if isinstance(active, str):
        return active
    return None



def save_state_updates_from_decision(decision):
    """V1.6 CSE: persistir índice operativo por recurso.

    El runtime no decide transiciones ni interpreta vulnerabilidades. Solo valida
    que state pertenezca al conjunto permitido, agrega metadatos y guarda.
    """
    updates = decision.get("state_updates") or []
    if not isinstance(updates, list) or not updates:
        return 0

    k = load_knowledge()
    resource_state = k.setdefault("resource_state", {})
    history = k.setdefault("resource_state_history", [])
    added = 0

    for item in updates:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        state = str(item.get("state") or "").upper().strip()
        state = TERMINAL_ALIASES.get(state, state)
        reason = item.get("reason") or ""
        # v2.2.2 containment: AUTO mode has no human checkpoint.
        # A WAITING_OPERATOR proposal is treated as operator YES/continue-close
        # and remains eligible for autonomous handling instead of blocking the queue.
        if autonomous_mode_enabled() and state == "WAITING_OPERATOR":
            state = "CONFIRMED"
            reason = (str(reason) + " | AUTO-YES: checkpoint de operador resuelto automáticamente.").strip(" |")
        if not isinstance(resource, str) or not resource.strip():
            continue
        if state not in ALLOWED_RESOURCE_STATES and state not in TERMINAL_RESOURCE_STATES:
            continue
        if not isinstance(reason, str):
            reason = str(reason)

        resource = resource.strip()
        previous = resource_state.get(resource)
        previous_state = str(previous.get("state") or "").upper() if isinstance(previous, dict) else ""
        previous_state = TERMINAL_ALIASES.get(previous_state, previous_state)
        if previous_state in TERMINAL_RESOURCE_STATES and state not in TERMINAL_RESOURCE_STATES:
            print(f"[TERMINAL LOCK] Ignorada degradación {previous_state} -> {state} para {resource}")
            continue
        if isinstance(previous, dict) and previous_state == state and previous.get("reason") == reason.strip():
            continue

        goal = item.get("resource_goal") or item.get("goal")
        if isinstance(goal, str):
            goal = goal.strip().lower()
            if goal not in {"document", "exploit", "enumerate", "deep"}:
                goal = None
        else:
            goal = None

        state_obj = {
            "state": state,
            "updated_at": utc_now(),
            "updated_by": "llm",
            "decision_id": decision.get("decision_id"),
            "reason": reason.strip(),
        }
        if goal:
            state_obj["resource_goal"] = goal
            k.setdefault("resource_goals", {})[resource] = goal
        resource_state[resource] = state_obj
        history.append({
            "timestamp": utc_now(),
            "decision_id": decision.get("decision_id"),
            "resource": resource,
            "state": state,
            "resource_goal": goal,
            "reason": reason.strip(),
        })
        added += 1

    if added:
        save_knowledge(k)
        print(f"[DONE] resource_state actualizado: +{added}")
    return added


def _normalize_confidence(value):
    value = str(value or "medium").lower().strip()
    if value not in {"low", "medium", "high"}:
        return "medium"
    return value


def _normalize_kind(value):
    value = str(value or "note").lower().strip()
    if value not in {"fact", "hypothesis", "evidence", "verdict", "pending", "note"}:
        return "note"
    return value


def cognitive_updates_to_items(decision):
    """V1.5.3 CSE: convertir cognitive_updates a objetos genéricos.

    El runtime no interpreta contenido. Solo traduce secciones del estado
    cognitivo a la lista cognitive_knowledge compatible.
    """
    cu = decision.get("cognitive_updates") or {}
    items = []
    if isinstance(cu, dict):
        section_kind = {
            "facts": "fact",
            "hypotheses": "hypothesis",
            "evidence": "evidence",
            "pending": "pending",
            "verdicts": "verdict",
        }
        for section, kind in section_kind.items():
            entries = cu.get(section) or []
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                item = {
                    "kind": kind,
                    "resource": entry.get("resource", "global"),
                    "text": entry.get("text", ""),
                    "confidence": entry.get("confidence", "medium"),
                }
                if section == "hypotheses" and entry.get("status"):
                    item["status"] = entry.get("status")
                items.append(item)
    # Compatibilidad legacy: también aceptar new_knowledge si aparece.
    legacy = decision.get("new_knowledge") or []
    if isinstance(legacy, list):
        for item in legacy:
            if isinstance(item, dict):
                items.append(item)
    return items


def save_new_knowledge_from_decision(decision):
    """V1.5.3 CSE: guardar memoria genérica escrita por el LLM.

    Acepta cognitive_updates como contrato principal y new_knowledge como
    compatibilidad. El runtime no interpreta contenido: solo valida forma,
    agrega metadatos y evita duplicados exactos para no inflar knowledge.json.
    """
    items = cognitive_updates_to_items(decision)
    if not isinstance(items, list) or not items:
        return 0

    k = load_knowledge()
    store = k.setdefault("cognitive_knowledge", [])
    history = k.setdefault("cognitive_updates_history", [])
    existing = {
        (
            str(x.get("kind")),
            str(x.get("resource")),
            str(x.get("text")),
        )
        for x in store
        if isinstance(x, dict)
    }

    added = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        resource = item.get("resource")
        if not isinstance(text, str) or not text.strip():
            continue
        if not isinstance(resource, str) or not resource.strip():
            resource = "global"
        normalized = {
            "timestamp": utc_now(),
            "source": "llm",
            "decision_id": decision.get("decision_id"),
            "kind": _normalize_kind(item.get("kind")),
            "resource": resource.strip(),
            "text": text.strip(),
            "confidence": _normalize_confidence(item.get("confidence")),
        }
        if item.get("status"):
            normalized["status"] = str(item.get("status"))
        key = (normalized["kind"], normalized["resource"], normalized["text"])
        if key in existing:
            continue
        store.append(normalized)
        existing.add(key)
        added += 1

    if added:
        history.append({
            "timestamp": utc_now(),
            "decision_id": decision.get("decision_id"),
            "added": added,
        })
        save_knowledge(k)
        print(f"[DONE] cognitive_knowledge actualizado: +{added}")
    return added


def save_operator_verdict_as_knowledge(action_obj, decision):
    """Fallback Camino B: si el LLM emite veredicto, conservarlo como objeto genérico.

    Sigue siendo conocimiento originado por el LLM; el runtime no interpreta el tipo
    de vulnerabilidad ni la evidencia, solo lo serializa.
    """
    url = action_obj.get("url") or "global"
    text = action_obj.get("verdict") or action_obj.get("finding")
    if not text:
        return
    synthetic = dict(decision)
    synthetic["cognitive_updates"] = {
        "facts": [],
        "hypotheses": [],
        "evidence": [],
        "pending": [],
        "verdicts": [{
            "resource": url,
            "text": str(text),
            "confidence": "high",
        }],
    }
    save_new_knowledge_from_decision(synthetic)


def mark_decision_executed(decision_id):
    if not decision_id:
        return
    write_json_file(
        EXEC_STATE_FILE,
        {
            "last_executed_decision_id": decision_id,
            "last_executed_timestamp": utc_now(),
        },
    )


def is_stale_decision(decision_id):
    if not decision_id or not EXEC_STATE_FILE.exists():
        return False
    state = load_json_file(EXEC_STATE_FILE, {})
    return state.get("last_executed_decision_id") == decision_id


def current_scope():
    k = load_knowledge()
    scope = k.get("scope", {})
    target_host = scope.get("target_host") or urlparse(scope.get("target_base", "")).hostname or DEFAULT_TARGET_HOST
    kali_host = scope.get("kali_host") or "192.168.0.34"
    kali_mcp_base = scope.get("kali_mcp_base") or f"http://{kali_host}:9001"
    return target_host, kali_mcp_base


def url_in_scope(url):
    target_host, _ = current_scope()
    parsed = urlparse(url)
    return parsed.hostname == target_host


def target_token_in_scope(token):
    target_host, _ = current_scope()
    if token == target_host:
        return True
    if token.startswith("http://") or token.startswith("https://"):
        return url_in_scope(token)
    return False


def extract_urls_from_parts(parts):
    urls = []
    for p in parts:
        if p.startswith("http://") or p.startswith("https://"):
            urls.append(p)
    return urls


def command_mentions_target(parts):
    for p in parts:
        if target_token_in_scope(p):
            return True
    return False


def _compact_stdout_preview(stdout, limit=3000):
    """Conserva el inicio y el final del resultado.

    Muchas evidencias aparecen al comienzo de stdout y el HTML de la aplicación al
    final. Guardar solo los últimos bytes ocultaba la evidencia al LLM y al reporte.
    """
    text = stdout or ""
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return text[:head] + "\n...[stdout recortado]...\n" + text[-tail:]


def extract_verified_evidence(stdout):
    """Extrae únicamente señales verificadas directamente en stdout.

    No interpreta la vulnerabilidad ni la ruta. Una señal se considera verificada
    solo cuando el contenido real contiene firmas suficientemente específicas.
    """
    text = stdout or ""
    verified = []
    low = text.lower()

    # Exige root UID/GID 0 y al menos otra cuenta Unix bien formada. Esto evita
    # considerar evidencia una cadena aislada reflejada por la aplicación.
    unix_lines = re.findall(
        r"(?m)^[A-Za-z_][A-Za-z0-9_-]*:[^\r\n:]*:[0-9]+:[0-9]+:[^\r\n]*$",
        text,
    )
    root_line = next((line for line in unix_lines if re.match(r"^root:[^:]*:0:0:", line)), None)
    if root_line and len(unix_lines) >= 2:
        verified.append({
            "kind": "structured_unix_accounts",
            "text": "Contenido estructurado de cuentas Unix observado directamente en stdout",
            "excerpt": "\n".join(unix_lines[:4]),
        })

    if "<script>alert(1)</script>" in text or "bugtraceai_xss" in low:
        verified.append({"kind":"controlled_reflection","text":"Payload controlado observado literalmente en la respuesta","excerpt":"payload controlado presente"})
    if "you have an error in your sql syntax" in low:
        verified.append({"kind":"sql_error","text":"Error de sintaxis SQL visible en stdout","excerpt":"You have an error in your SQL syntax"})
    if "parameter:" in low and "is vulnerable" in low:
        verified.append({"kind":"tool_vulnerability_report","text":"Una herramienta reportó explícitamente un parámetro vulnerable","excerpt":"parameter ... is vulnerable"})
    return verified


def extract_evidence_hint(stdout):
    # Compatibilidad con Evidence Bundle v2.1: solo textos de evidencia verificada.
    return [item["text"] for item in extract_verified_evidence(stdout)]


def get_cookie_from_jar():
    """Devuelve la cookie jar que vive en Kali.

    En V1.4-kali-session, la sesión se crea y se conserva en Kali.
    Ubuntu no lee ni transporta PHPSESSID. Solo referencia el archivo remoto
    para comandos como curl/sqlmap que soportan cookie jar.
    """
    return KALI_COOKIE_JAR


def build_cookie_args_for_command():
    return ["-b", KALI_COOKIE_JAR]


def enrich_command_with_cookie(command):
    if not any(p in command for p in COOKIE_PLACEHOLDERS):
        return command
    cookie_ref = KALI_COOKIE_JAR
    for placeholder in COOKIE_PLACEHOLDERS:
        command = command.replace(placeholder, cookie_ref)
    print("[INFO] Placeholder de cookie reemplazado por cookie jar en Kali:", cookie_ref)
    return command


PASSWORD_CHANGE_MARKERS = (
    "password_new", "password_conf", "new_password", "new-password",
    "change_password", "change-password", "passwd"
)


def enforce_fixed_attack_credentials(command):
    """V2.5.5b: no reescribe credenciales usadas durante el análisis.

    La sesión de inicialización del laboratorio continúa usando admin/password,
    pero los comandos propuestos por el LLM pueden probar credenciales distintas
    y cambiar la contraseña dentro del Analysis Item activo. El siguiente recurso
    deberá restaurar el laboratorio mediante su flujo de inicialización.
    """
    return command


def _split_shell_segments(command):
    """Split on |, && and || outside quotes; preserve redirections."""
    segments=[]; buf=[]; quote=None; escape=False; i=0
    while i < len(command):
        ch=command[i]
        if escape:
            buf.append(ch); escape=False; i+=1; continue
        if ch == "\\" and quote != "'":
            buf.append(ch); escape=True; i+=1; continue
        if quote:
            buf.append(ch)
            if ch == quote: quote=None
            i+=1; continue
        if ch in ("'", '"'):
            quote=ch; buf.append(ch); i+=1; continue
        op=None
        if command.startswith('&&',i) or command.startswith('||',i): op=command[i:i+2]
        elif ch=='|': op='|'
        if op:
            part=''.join(buf).strip()
            if part: segments.append(part)
            buf=[]; i+=len(op); continue
        buf.append(ch); i+=1
    if quote: raise ValueError('No closing quotation')
    part=''.join(buf).strip()
    if part: segments.append(part)
    return segments


def _strip_redirections(segment):
    pattern = r"(?:^|\s)(?:\d?>>|\d?>|2>&1)\s*(?:\"[^\"]*\"|'[^']*'|[^\s]+)"
    return re.sub(pattern, ' ', segment)


def _has_unsafe_ampersand(command):
    """Block shell-background ampersands; allow joined ampersands in quotes.

    Accepted example: ``curl "http://host/?a=1&b=2"``.
    Rejected examples: ``x & y``, ``x&y`` (unquoted), ``"&"`` and trailing ``&``.
    ``&&`` remains an explicitly supported shell operator.
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


def validate_mcp_command(command):
    """r4b-open: permissive execution validator with target URL scope."""
    if not isinstance(command, str) or not command.strip():
        return False, "Comando vacío"
    lowered = command.lower()
    for token in ("mkfs", "shutdown", "reboot", "poweroff",
                  "rm -rf /", "rm -rf /*", "dd if=", ":(){:|:&};:"):
        if token in lowered:
            return False, f"Operación destructiva bloqueada en modo open: {token}"
    for url in re.findall(r"https?://[^\\s\"']+", command):
        url = url.rstrip(")>,.;")
        if not url_in_scope(url):
            return False, f"URL fuera de scope: {url}"
    return True, "Comando MCP validado (r4b-open)"


def active_analysis_entry_url(k=None):
    """Return the authoritative entry URL for the active Analysis Item.

    Payload/test URLs must never replace this identity.
    """
    k = k if isinstance(k, dict) else load_knowledge()
    item = active_item(k)
    if isinstance(item, dict) and item.get("entry_url"):
        return normalize_resource_url(item.get("entry_url"))
    return normalize_resource_url(get_active_resource(k))


def execution_owner_resource(tested_url=None, k=None):
    """Resolve the Analysis Item that owns an execution.

    The tested URL is metadata; accounting and persistence belong to the active
    Analysis Item whenever one exists.
    """
    k = k if isinstance(k, dict) else load_knowledge()
    return active_analysis_entry_url(k) or normalize_resource_url(tested_url) or "global"


def autonomous_mode_enabled():
    return str(os.environ.get("BUGTRACEAI_AUTONOMOUS", "0")).strip().lower() in {"1", "true", "yes", "on"}


def autonomous_max_mcp_commands():
    try:
        return max(1, int(os.environ.get("BUGTRACEAI_MAX_MCP_COMMANDS", "6")))
    except ValueError:
        return 6


def resource_mcp_execution_count(resource=None):
    k = load_knowledge()
    owner = execution_owner_resource(resource, k)
    counters = k.setdefault("autonomous_resource_counters", {})
    item = counters.setdefault(owner or "global", {})
    return int(item.get("mcp_executions", 0) or 0)


def register_resource_mcp_execution(resource, source, command_or_tool, result, tested_url=None):
    k = load_knowledge()
    owner = execution_owner_resource(resource, k)
    counters = k.setdefault("autonomous_resource_counters", {})
    item = counters.setdefault(owner, {})
    item["mcp_executions"] = int(item.get("mcp_executions", 0) or 0) + 1
    item["last_source"] = source
    item["last_command_or_tool"] = command_or_tool
    item["last_tested_url"] = normalize_resource_url(tested_url or resource)
    item["last_ok"] = bool(result.get("ok")) if isinstance(result, dict) else False
    item["last_returncode"] = result.get("returncode") if isinstance(result, dict) else None
    item["updated_at"] = utc_now()
    ai = find_item(k, url=owner)
    if ai:
        ai.setdefault("attempt_state", {})["total_attempts"] = item["mcp_executions"]
        ai["attempt_state"]["last_tested_url"] = item["last_tested_url"]
        ai["updated_at"] = utc_now()
    save_knowledge(k)
    return item["mcp_executions"]


def close_resource_autonomous_limit(resource, decision_id, reason):
    resource = normalize_resource_url(resource or get_active_resource())
    if not resource or resource == "global":
        return False
    k = load_knowledge()
    count = resource_mcp_execution_count(resource)
    k = load_knowledge()
    completed = k.setdefault("completed_urls", [])
    if not any(normalize_resource_url(resource_url(x)) == resource for x in completed):
        completed.append({
            "decision_id": decision_id,
            "timestamp": utc_now(),
            "url": resource,
            "status": "inconclusive",
            "finding": "Límite autónomo de ejecuciones MCP alcanzado",
            "analysis_summary": reason,
            "evidence": [],
            "impact": None,
            "recommendation": "Revisar manualmente si se requiere mayor profundidad.",
            "closed_from": "autonomous_mcp_limit",
            "mcp_executions": count,
        })
    k.setdefault("resource_state", {})[resource] = {
        "state": "INCONCLUSIVE",
        "updated_at": utc_now(),
        "updated_by": "autonomous_mcp_limit",
        "decision_id": decision_id,
        "reason": reason,
    }
    # v2.3.2: analysis_queue is authoritative and a terminal operational
    # state must also close the assessment layer. No vulnerability semantics
    # are inferred here; the runtime records an explicit inconclusive result.
    sync_runtime(k)
    finalize_runtime_assessment(k, resource, "INCONCLUSIVE", reason, decision_id)
    set_state(k, resource, "INCONCLUSIVE", reason, "autonomous_mcp_limit")
    set_active(k, None)
    k["active_resource"] = None
    save_knowledge(k)
    print(f"[AUTONOMOUS] Límite MCP {count}/{autonomous_max_mcp_commands()} alcanzado. Recurso INCONCLUSIVE; avanzando.")
    return True


def _normalize_mcp_approval_answer(answer):
    value = str(answer or "").strip().lower()
    if value in {"yes", "y", "si", "sí", "1", "ejecutar", "execute"}:
        return "execute"
    if value in {"next", "n", "3", "cerrar", "cerrar y seguir", "siguiente", "skip", "close"}:
        return "close_next"
    return "reject"


def confirm_mcp_command_execution(command, reason, risk_level):
    if autonomous_mode_enabled():
        print("\n[AUTO APPROVAL] YES - modo autónomo")
        return "execute"
    print("\n[MCP COMMAND APPROVAL REQUIRED]")
    print("Risk level:", risk_level)
    print("Reason:", reason)
    print("Command:")
    print(command)
    print()
    print("Opciones: YES=ejecutar | NO=rechazar este comando | NEXT=cerrar análisis/explotación y pasar al siguiente recurso")
    try:
        answer = input("Respuesta [YES/NO/NEXT]: ").strip()
    except EOFError:
        answer = "NO"
    return _normalize_mcp_approval_answer(answer)


def confirm_mcp_tool_execution(tool, args, reason, risk_level):
    if autonomous_mode_enabled():
        print("\n[AUTO APPROVAL] YES - modo autónomo")
        return "execute"
    print("\n[MCP TOOL APPROVAL REQUIRED]")
    print("Risk level:", risk_level)
    print("Tool:", tool)
    print("Reason:", reason)
    print("Arguments:")
    print(json.dumps(args, indent=2, ensure_ascii=False))
    print()
    print("Opciones: YES=ejecutar | NO=rechazar esta herramienta | NEXT=cerrar análisis/explotación y pasar al siguiente recurso")
    try:
        answer = input("Respuesta [YES/NO/NEXT]: ").strip()
    except EOFError:
        answer = "NO"
    return _normalize_mcp_approval_answer(answer)


def close_resource_from_mcp_prompt(resource, decision_id, reason, source):
    resource = normalize_resource_url(resource or get_active_resource())
    if not resource or resource == "global":
        print("[WARN] NEXT solicitado, pero no se pudo determinar el recurso activo.")
        return False
    k = load_knowledge()
    completed = k.setdefault("completed_urls", [])
    already = any(normalize_resource_url(resource_url(x)) == resource for x in completed)
    state_obj = (k.get("resource_state") or {}).get(resource) or {}
    previous_state = str(state_obj.get("state") or "UNKNOWN").upper()
    if not already:
        completed.append({
            "decision_id": decision_id,
            "timestamp": utc_now(),
            "url": resource,
            "status": "completed",
            "finding": "Análisis/explotación cerrado por decisión del operador durante la aprobación MCP",
            "analysis_summary": reason,
            "evidence": [],
            "impact": None,
            "recommendation": "El recurso puede reabrirse explícitamente desde el scheduler si se desea continuar.",
            "operator_message": "Operador seleccionó NEXT en la aprobación MCP.",
            "closed_from": source,
            "previous_state": previous_state,
        })
    k.setdefault("resource_state", {})[resource] = {
        "state": "COMPLETED",
        "updated_at": utc_now(),
        "updated_by": "operator_mcp_approval",
        "decision_id": decision_id,
        "reason": "Operador seleccionó NEXT para cerrar el recurso y continuar con el siguiente.",
    }
    k.setdefault("resource_state_history", []).append({
        "timestamp": utc_now(),
        "decision_id": decision_id,
        "resource": resource,
        "state": "COMPLETED",
        "reason": "Cierre explícito desde aprobación MCP mediante NEXT.",
    })
    k.setdefault("operator_mcp_decisions", []).append({
        "timestamp": utc_now(),
        "decision_id": decision_id,
        "resource": resource,
        "choice": "close_next",
        "source": source,
        "reason": reason,
    })
    k["active_resource"] = None
    save_knowledge(k)
    print("[COMPLETED] Recurso cerrado por el operador desde la aprobación MCP:", resource)
    print("[SCHEDULER] El siguiente ciclo seleccionará automáticamente el próximo recurso pendiente.")
    return True


def resource_url(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("url") or value.get("resource") or value.get("endpoint")
    return None


def _b64encode_text(value):
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    return base64.b64encode(value.encode("utf-8", errors="replace")).decode("ascii")



def normalize_mcp_exec_result(result):
    """Normaliza respuestas MCP legacy y nuevas.

    Nuevo protocolo v1.4 simple:
      request:  {"command_b64":"..."}
      response: {"ok":bool,"returncode":int,"stdout_b64":"...","stderr_b64":"..."}

    Compatibilidad legacy:
      request/response con command/stdout/stderr en texto plano.
    """
    result = result or {}
    out = dict(result)
    if "stdout_b64" in out:
        out["stdout"] = _b64decode_text(out.get("stdout_b64"))
    else:
        out.setdefault("stdout", "")
    if "stderr_b64" in out:
        out["stderr"] = _b64decode_text(out.get("stderr_b64"))
    else:
        out.setdefault("stderr", "")
    return out


def call_mcp_endpoint(endpoint, payload):
    _, kali_mcp_base = current_scope()
    url = kali_mcp_base + endpoint
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=900) as response:
        return json.loads(response.read().decode("utf-8"))


def call_mcp_exec_command(command, timeout=900):
    """Envía comandos a Kali por protocolo base64 simple.

    Protocolo preferido:
      request  -> {"command_b64":"...", "timeout": N}
      response -> {"stdout_b64":"...", "stderr_b64":"..."}

    Compatibilidad V1.4 transicional:
      si el MCP todavía no acepta command_b64 y responde 400/422,
      reintenta una sola vez con {"command":"..."}.
    """
    timeout = int(timeout)
    payload = {"command_b64": _b64encode_text(command), "timeout": timeout}
    try:
        result = call_mcp_endpoint(MCP_EXEC_ENDPOINT, payload)
        result = normalize_mcp_exec_result(result)
        result.setdefault("transport_request", "command_b64")
    except urllib.error.HTTPError as e:
        # 400/422 normalmente indica que el MCP de Kali aún espera {command: ...}.
        # No lo tratamos como fallo del agente: usamos compatibilidad legacy.
        if e.code not in (400, 415, 422):
            raise
        legacy_payload = {"command": command, "timeout": timeout}
        result = call_mcp_endpoint(MCP_EXEC_ENDPOINT, legacy_payload)
        result = normalize_mcp_exec_result(result)
        result.setdefault("transport_request", "legacy_command_fallback")
        result.setdefault("transport_warning", f"MCP no aceptó command_b64; fallback legacy usado tras HTTP {e.code}")
    result.setdefault("command", command)
    return result


def normalize_command(command):
    try:
        return " ".join(shlex.split(command))
    except Exception:
        return command


def was_mcp_command_already_successful(command):
    k = load_knowledge()
    normalized = normalize_command(command)
    for obs in k.get("mcp_command_observations", []):
        old_norm = normalize_command(obs.get("command"))
        if old_norm == normalized and obs.get("returncode") == 0:
            return True
    return False


def was_mcp_tool_already_successful(tool, target_url):
    k = load_knowledge()
    for obs in k.get("mcp_observations", []):
        if obs.get("tool") != tool:
            continue
        obs_args = obs.get("arguments", {})
        if obs_args.get("url") == target_url and obs.get("returncode") == 0:
            return True
    return False


def _get_resource_state(k, resource):
    if not isinstance(k, dict) or not resource:
        return {}
    st = (k.get("resource_state") or {}).get(resource)
    return st if isinstance(st, dict) else {}


def _is_reference_exploitation_active(k, resource):
    st = _get_resource_state(k, resource)
    goal = st.get("resource_goal") or (k.get("resource_goals") or {}).get(resource)
    return st.get("state") == "EXPLOITING" and goal in {"exploit", "enumerate", "deep"}


def _get_reference_counter(k, resource):
    counters = k.setdefault("reference_exploit_counters", {})
    obj = counters.setdefault(resource, {"count": 0, "commands": [], "round": 1, "max_per_round": MAX_REFERENCE_EXPLOITS_PER_ROUND})
    obj.setdefault("count", 0)
    obj.setdefault("commands", [])
    obj.setdefault("round", 1)
    obj.setdefault("max_per_round", MAX_REFERENCE_EXPLOITS_PER_ROUND)
    return obj


def _set_reference_limit_waiting(k, resource, decision_id, reason):
    phase = k.setdefault("reference_exploitation", {}).setdefault(resource, {})
    phase.update({
        "awaiting_final_operator": True,
        "limit_reached": True,
        "max_per_round": MAX_REFERENCE_EXPLOITS_PER_ROUND,
        "updated_at": utc_now(),
        "reason": reason,
    })
    st = _get_resource_state(k, resource)
    goal = st.get("resource_goal") or (k.get("resource_goals") or {}).get(resource) or "exploit"
    k.setdefault("resource_state", {})[resource] = {
        "state": "WAITING_OPERATOR",
        "resource_goal": goal,
        "updated_at": utc_now(),
        "updated_by": "reference_exploit_limiter",
        "decision_id": decision_id,
        "reason": reason,
    }
    k.setdefault("resource_state_history", []).append({
        "timestamp": utc_now(),
        "decision_id": decision_id,
        "resource": resource,
        "state": "WAITING_OPERATOR",
        "resource_goal": goal,
        "reason": reason,
    })
    latest = k.get("latest_operator_checkpoint")
    if isinstance(latest, dict) and normalize_resource_url(latest.get("resource")) == resource and latest.get("status") == "answered":
        latest["status"] = "consumed_reference_round"
        latest["consumed_at"] = utc_now()
        k["latest_operator_checkpoint"] = latest
    for cp in k.get("operator_checkpoints", []) or []:
        if isinstance(cp, dict) and normalize_resource_url(cp.get("resource")) == resource and cp.get("status") == "answered":
            cp["status"] = "consumed_reference_round"
            cp["consumed_at"] = utc_now()


def register_reference_exploit_success(k, resource, command, result, decision_id):
    if not resource or not _is_reference_exploitation_active(k, resource):
        return
    if not result.get("ok") or result.get("returncode") != 0:
        return
    counter = _get_reference_counter(k, resource)
    if command not in counter["commands"]:
        counter["commands"].append(command)
        counter["count"] = int(counter.get("count") or 0) + 1
        counter["last_command"] = command
        counter["last_decision_id"] = decision_id
        counter["last_timestamp"] = utc_now()
    if int(counter.get("count") or 0) >= int(counter.get("max_per_round") or MAX_REFERENCE_EXPLOITS_PER_ROUND):
        _set_reference_limit_waiting(
            k,
            resource,
            decision_id,
            f"Se alcanzó el límite de {counter['count']} explotación/es referenciales para este ciclo. Requiere decisión final del operador.",
        )


def reference_limit_blocks_command(command, decision_id):
    k = load_knowledge()
    resource = normalize_resource_url(_extract_first_url(command) or get_active_resource(k) or "global")
    if not resource:
        return False
    phase = (k.get("reference_exploitation") or {}).get(resource) or {}
    counter = (k.get("reference_exploit_counters") or {}).get(resource) or {}
    if phase.get("awaiting_final_operator") or int(counter.get("count") or 0) >= int(counter.get("max_per_round") or MAX_REFERENCE_EXPLOITS_PER_ROUND):
        _set_reference_limit_waiting(k, resource, decision_id, "Runtime bloqueó nueva explotación porque ya hay evidencia referencial suficiente y falta decisión final del operador.")
        save_knowledge(k)
        print("[WAITING_OPERATOR]")
        print("Límite de explotaciones referenciales alcanzado para:", resource)
        print("El LLM debe emitir ask_operator para cerrar/documentar, conectar con otra vulnerabilidad o autorizar otro ciclo referencial.")
        return True
    return False


def save_mcp_command_observation(command, reason, risk_level, result, decision_id=None, source_action="propose_mcp_command", owner_resource=None, tested_url=None, expected_evidence=None):
    k = load_knowledge()
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    tested_url = normalize_resource_url(tested_url or _extract_first_url(command))
    resource = execution_owner_resource(owner_resource or tested_url, k)
    # Preserve the Analysis Item identity. The payload URL is only test metadata.
    if resource and resource != "global":
        k["active_resource"] = {
            "resource": resource,
            "source": source_action,
            "decision_id": decision_id,
            "timestamp": utc_now(),
        }
        set_active(k, resource)
    predicate_result = evaluate_expected_evidence(expected_evidence, result) if expected_evidence else None
    executor_id = "EX-" + uuid.uuid4().hex
    mcp_execution_id = "MCP-" + uuid.uuid4().hex
    evidence_id = "EVD-" + uuid.uuid4().hex
    runtime_event("EXECUTOR_DISPATCH", stage="executor", status="started", decision_id=decision_id, resource=resource, action=source_action, executor_id=executor_id, mcp_execution_id=mcp_execution_id, data={"tested_url":tested_url,"command":command,"reason":reason})
    obs={
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "source_action": source_action,
        "resource": resource,
        "tested_url": tested_url,
        "command": command,
        "reason": reason,
        "risk_level": risk_level,
        "requested_by": "LLM",
        "approved": True,
        "executed": True,
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", "replace")).hexdigest(),
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "stdout_preview": _compact_stdout_preview(stdout, 3000),
        "stderr_preview": _compact_stdout_preview(stderr, 1000),
        "evidence_hint": extract_evidence_hint(stdout),
        "verified_evidence": extract_verified_evidence(stdout),
        "expected_evidence": expected_evidence,
        "predicate_result": predicate_result,
    }
    k.setdefault("mcp_command_observations", []).append(obs)
    runtime_event("MCP_COMMAND_RESULT", stage="mcp", status="ok" if result.get("ok") else "error", decision_id=decision_id, resource=resource, action=source_action, executor_id=executor_id, mcp_execution_id=mcp_execution_id, evidence_id=evidence_id, flags={"executor_reached":True,"mcp_reached":True,"ok":bool(result.get("ok")),"returncode":result.get("returncode")}, data={"tested_url":tested_url,"command":command,"reason":reason,"expected_evidence":expected_evidence,"predicate_result":predicate_result,"stdout_sha256":obs["stdout_sha256"],"stderr_sha256":obs["stderr_sha256"]})
    runtime_event("EVIDENCE_RECORDED", stage="evidence", status="recorded", decision_id=decision_id, resource=resource, action=source_action, executor_id=executor_id, mcp_execution_id=mcp_execution_id, evidence_id=evidence_id, data={"predicate_result":predicate_result,"stdout_sha256":obs["stdout_sha256"],"stderr_sha256":obs["stderr_sha256"]})
    runtime_event("EXECUTOR_COMPLETED", stage="executor", status="ok" if result.get("ok") else "error", decision_id=decision_id, resource=resource, action=source_action, executor_id=executor_id, mcp_execution_id=mcp_execution_id, evidence_id=evidence_id, data={"returncode":result.get("returncode")})
    register_reference_exploit_success(k, resource, command, result, decision_id)
    save_knowledge(k)
    print("[DONE] Observación MCP command guardada en data/knowledge.json")


def save_mcp_tool_observation(tool, args, reason, risk_level, result, decision_id=None):
    k = load_knowledge()
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    runtime_obs = {
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "source_action": "propose_mcp_tool",
        "tool": tool,
        "arguments": args,
        "reason": reason,
        "risk_level": risk_level,
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "command": result.get("command"),
        "stdout_preview": _compact_stdout_preview(stdout, 3000),
        "stderr_preview": _compact_stdout_preview(stderr, 1000),
        "evidence_hint": extract_evidence_hint(stdout),
        "verified_evidence": extract_verified_evidence(stdout),
    }
    k.setdefault("mcp_observations", []).append(runtime_obs)
    runtime_event("MCP_TOOL_RESULT", stage="mcp", status="ok" if result.get("ok") else "error", decision_id=decision_id, action="propose_mcp_tool", flags={"executor_reached":True,"mcp_reached":True,"ok":bool(result.get("ok")),"returncode":result.get("returncode")}, data={"tool":tool,"arguments":args,"reason":reason,"command":result.get("command")})
    save_knowledge(k)
    print("[DONE] Observación MCP tool guardada en data/knowledge.json")


def save_operator_verdict(action_obj, decision):
    k = load_knowledge()
    verdict_resource = normalize_resource_url(action_obj.get("url"))
    # Consumir checkpoint respondido para evitar que el LLM vuelva a preguntar o documentar lo mismo.
    latest = k.get("latest_operator_checkpoint")
    if isinstance(latest, dict) and normalize_resource_url(latest.get("resource")) == verdict_resource:
        latest["status"] = "consumed"
        latest["consumed_at"] = utc_now()
        k["latest_operator_checkpoint"] = latest
    for cp in k.get("operator_checkpoints", []) or []:
        if isinstance(cp, dict) and cp.get("decision_id") == (latest or {}).get("decision_id"):
            cp["status"] = "consumed"
            cp["consumed_at"] = utc_now()
    verdict = {
        "decision_id": decision.get("decision_id"),
        "timestamp": utc_now(),
        "url": verdict_resource or action_obj.get("url"),
        "status": "completed",
        "finding": action_obj.get("verdict") or action_obj.get("finding"),
        "analysis_summary": decision.get("analysis_summary"),
        "evidence": action_obj.get("evidence", []),
        "impact": action_obj.get("impact"),
        "recommendation": action_obj.get("recommendation"),
        "operator_message": decision.get("operator_message"),
    }
    k.setdefault("completed_urls", []).append(verdict)
    save_knowledge(k)
    save_operator_verdict_as_knowledge(action_obj, decision)
    print("[DONE] operator_verdict guardado en completed_urls")





def _normalize_scope_path(path):
    """Normalize only the URL path for Analysis Item scope comparison.

    Query strings and fragments are intentionally ignored. A trailing slash is
    treated as equivalent except for the root path.
    """
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/") or "/"
    return path


def extract_http_urls(text):
    """Return every explicit HTTP(S) URL present in an MCP command."""
    if not isinstance(text, str):
        return []
    return re.findall(r"https?://[^\s\"'<>]+", text)


def validate_active_host_path_scope(command, k=None):
    """Allow an MCP command only inside the active Analysis Item host/path.

    This guard deliberately checks only host and path. Query-string values may
    vary freely, which preserves LFI and parameter-focused testing within the
    same route. URLs belonging to other discovered Analysis Items are not
    blacklisted; they are simply unavailable while this item is active.
    """
    k = k if isinstance(k, dict) else load_knowledge()
    item = active_item(k)
    active_url = None
    analysis_id = None
    if isinstance(item, dict):
        active_url = item.get("entry_url") or item.get("normalized_entry_url")
        analysis_id = item.get("analysis_id")
    active_url = normalize_resource_url(active_url or get_active_resource(k))
    if not active_url or not str(active_url).startswith(("http://", "https://")):
        return True, None

    proposed_urls = extract_http_urls(command)
    if not proposed_urls:
        return True, None

    active = urlparse(active_url)
    expected_host = (active.hostname or "").lower()
    expected_path = _normalize_scope_path(active.path)
    # v3.0.2-fileupload-domain-scope: File Upload is the only Analysis Item
    # allowed to follow paths outside its entry route. The host remains exact:
    # no other host/subdomain is accepted. All other Analysis Items retain the
    # original exact host+path containment.
    fileupload_domain_scope = expected_path == "/vulnerabilities/upload"

    for raw_url in proposed_urls:
        proposed = urlparse(raw_url)
        proposed_host = (proposed.hostname or "").lower()
        proposed_path = _normalize_scope_path(proposed.path)
        host_mismatch = proposed_host != expected_host
        path_mismatch = (not fileupload_domain_scope) and proposed_path != expected_path
        if host_mismatch or path_mismatch:
            return False, {
                "analysis_id": analysis_id,
                "active_url": active_url,
                "allowed_host": expected_host,
                "allowed_path": "/* (File Upload same-host scope)" if fileupload_domain_scope else expected_path,
                "scope_mode": "fileupload_same_host" if fileupload_domain_scope else "analysis_item_exact_path",
                "proposed_url": raw_url,
                "proposed_host": proposed_host,
                "proposed_path": proposed_path,
            }
    return True, None


def register_scope_block(command, details, decision_id, source_action):
    k = load_knowledge()
    event = {
        "timestamp": utc_now(),
        "type": "active_path_scope_block",
        "decision_id": decision_id,
        "source_action": source_action,
        "command": command,
        **(details or {}),
    }
    k.setdefault("runtime_feedback", []).append(event)
    k["runtime_feedback"] = k["runtime_feedback"][-10:]
    k.setdefault("recent_blocked_actions", []).append(event)
    k["recent_blocked_actions"] = k["recent_blocked_actions"][-5:]
    save_knowledge(k)
    log_event(
        "[SCOPE BLOCKED] "
        + f"analysis_id={event.get('analysis_id')} active={event.get('active_url')} "
        + f"proposed={event.get('proposed_url')} command={command}"
    )

def _extract_first_url(text):
    if not isinstance(text, str):
        return None
    m = re.search(r"https?://[^\s\"'<>]+", text)
    return m.group(0) if m else None


def infer_error_resource(k, decision):
    """Inferencia operativa para contabilizar errores por recurso.

    No interpreta vulnerabilidades. Solo intenta asociar un error de ciclo al
    recurso activo más reciente para evitar loops operativos.
    """
    action_obj = (decision.get("next_actions") or [{}])[0]
    active = get_active_resource(k)
    if active and active != "global":
        return active
    for field in ("url", "resource"):
        value = action_obj.get(field)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value
    cmd_url = _extract_first_url(action_obj.get("command", ""))
    if cmd_url:
        return cmd_url.split("?", 1)[0].rstrip("/").rstrip(".") + "/"
    obs = k.get("mcp_command_observations") or []
    if obs:
        cmd_url = _extract_first_url((obs[-1] or {}).get("command", ""))
        if cmd_url:
            return cmd_url.split("?", 1)[0].rstrip("/").rstrip(".") + "/"
    visited = k.get("visited_urls") or []
    if visited:
        return visited[-1]
    return "global"


def register_stop_on_error(decision):
    """V1.6.1: controla errores repetidos por recurso.

    1er/2do error: registra y permite reintento en ciclos siguientes.
    3er error: marca el recurso como INCONCLUSIVE, documenta y lo agrega a
    completed_urls para que el agente avance a otro recurso.
    """
    k = load_knowledge()
    resource = infer_error_resource(k, decision)
    reason = ((decision.get("next_actions") or [{}])[0]).get("reason") or "stop_on_error"
    technical_reasons = {"llm_format_error", "llm_transport_error", "llm_json_parse_error", "llm_contract_validation_error", "llm_thinking_truncated", "stdout_processing_not_allowed"}
    if reason in technical_reasons:
        bucket_name = {"llm_format_error":"llm_format_errors", "llm_transport_error":"llm_transport_errors", "llm_json_parse_error":"llm_json_parse_errors", "llm_contract_validation_error":"llm_contract_validation_errors", "llm_thinking_truncated":"llm_thinking_truncated_errors", "stdout_processing_not_allowed":"runtime_interaction_errors"}.get(reason, "llm_errors")
        bucket = k.setdefault(bucket_name, {})
        obj = bucket.setdefault(resource, {"error_count": 0, "events": []})
        obj["error_count"] = int(obj.get("error_count") or 0) + 1
        obj["last_error"] = reason
        obj["last_decision_id"] = decision.get("decision_id")
        obj["last_timestamp"] = utc_now()
        obj.setdefault("events", []).append({"timestamp": utc_now(), "decision_id": decision.get("decision_id"), "reason": reason, "validation_error": decision.get("validation_error"), "rejection_id": (decision.get("validation_error") or {}).get("rejection_id"), "reason_code": (decision.get("validation_error") or {}).get("reason_code")})
        obj["events"] = obj.get("events", [])[-5:]
        print(f"[LLM ERROR] {resource} type={reason} count={obj['error_count']} (no marca INCONCLUSIVE)")
        save_knowledge(k)
        return

    errors = k.setdefault("resource_errors", {})
    obj = errors.setdefault(resource, {"error_count": 0, "events": []})
    obj["error_count"] = int(obj.get("error_count") or 0) + 1
    obj["last_error"] = reason
    obj["last_decision_id"] = decision.get("decision_id")
    obj["last_timestamp"] = utc_now()
    obj.setdefault("events", []).append({
        "timestamp": utc_now(),
        "decision_id": decision.get("decision_id"),
        "reason": reason,
        "operator_message": decision.get("operator_message"),
    })
    # Mantener ventana corta.
    obj["events"] = obj.get("events", [])[-5:]

    print(f"[RESOURCE ERROR] {resource} count={obj['error_count']} reason={reason}")

    if obj["error_count"] >= 3:
        resource_state = k.setdefault("resource_state", {})
        resource_state[resource] = {
            "state": "INCONCLUSIVE",
            "resource_goal": "document",
            "updated_at": utc_now(),
            "updated_by": "runtime_error_guard",
            "decision_id": decision.get("decision_id"),
            "reason": f"Recurso marcado INCONCLUSIVE tras {obj['error_count']} errores operativos consecutivos: {reason}",
        }
        k.setdefault("resource_state_history", []).append({
            "timestamp": utc_now(),
            "decision_id": decision.get("decision_id"),
            "resource": resource,
            "state": "INCONCLUSIVE",
            "reason": f"3 errores operativos sobre el recurso: {reason}",
        })
        already_completed = any(
            (item.get("url") == resource if isinstance(item, dict) else item == resource)
            for item in k.get("completed_urls", [])
        )
        if not already_completed:
            k.setdefault("completed_urls", []).append({
                "decision_id": decision.get("decision_id"),
                "timestamp": utc_now(),
                "url": resource,
                "status": "inconclusive",
                "finding": "Análisis inconcluso por errores repetidos",
                "analysis_summary": decision.get("analysis_summary"),
                "evidence": [f"Se alcanzó el límite de {obj['error_count']} errores operativos para este recurso."],
                "impact": None,
                "recommendation": "Revisar manualmente la causa del error o retomar el recurso luego.",
                "operator_message": decision.get("operator_message"),
            })
        k.setdefault("cognitive_knowledge", []).append({
            "timestamp": utc_now(),
            "source": "runtime_error_guard",
            "decision_id": decision.get("decision_id"),
            "kind": "verdict",
            "resource": resource,
            "text": f"Análisis marcado como INCONCLUSIVE tras {obj['error_count']} errores operativos. Último error: {reason}",
            "confidence": "medium",
            "status": "inconclusive",
        })
        print("[INCONCLUSIVE] Recurso documentado como inconcluso y agregado a completed_urls")
    save_knowledge(k)


def _b64decode_text(value):
    """Decodifica base64 transportado por MCP sin romper HTML con caracteres raros."""
    if not value:
        return ""
    try:
        data = base64.b64decode(value.encode("ascii"), validate=False)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_interior_capture(stdout):
    """Lee el formato robusto de run_interior p2.

    Formato esperado desde Kali/MCP:
      __BUGTRACEAI_CAPTURE_V1__
      returncode=N
      headers_b64=...
      body_b64=...
      __END_BUGTRACEAI_CAPTURE_V1__

    Si no encuentra el marcador, conserva compatibilidad con curl -D - anterior.
    """
    stdout = stdout or ""
    meta = {"transport": "exec_b64_stdout"}
    start = "__BUGTRACEAI_CAPTURE_V1__"
    end = "__END_BUGTRACEAI_CAPTURE_V1__"
    if start not in stdout or end not in stdout:
        headers, body = split_curl_i_output(stdout)
        return headers, body, meta
    block = stdout.split(start, 1)[1].split(end, 1)[0]
    fields = {}
    for line in block.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    headers = _b64decode_text(fields.get("headers_b64", ""))
    body = _b64decode_text(fields.get("body_b64", ""))
    meta = {
        "transport": "base64_capture_v1",
        "capture_returncode": fields.get("returncode"),
        "headers_b64_len": len(fields.get("headers_b64", "")),
        "body_b64_len": len(fields.get("body_b64", "")),
    }
    return headers, body, meta


def build_interior_command(url, cookie=None):
    """Construye un curl simple para observar una página usando la sesión de Kali."""
    parts = ["curl", "-ksS", "-m", "15", "-L", "-D", "-"]
    if cookie:
        parts.extend(["-b", cookie])
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


def split_curl_i_output(raw):
    """Separa headers/body de una salida curl con headers + HTML.

    Importante: la versión anterior usaba una regex demasiado ambiciosa y
    podía tragarse casi todo el HTML, dejando body_bytes=7. Esta versión es
    deliberadamente simple:

    1. Normaliza CRLF a LF.
    2. Busca el último bloque que empieza con HTTP/ (por redirects con -L).
    3. Corta en la primera línea en blanco posterior a ese bloque.
    4. Todo lo que queda después es body real.
    """
    raw = raw or ""
    if not raw:
        return "", ""

    text = raw.replace("\r\n", "\n")

    # Si no parece respuesta con headers, tratar todo como body.
    if not text.startswith("HTTP/") and "\nHTTP/" not in text:
        return "", raw

    # Último header HTTP, útil cuando curl -L sigue redirects.
    positions = []
    if text.startswith("HTTP/"):
        positions.append(0)
    positions.extend(m.start() + 1 for m in re.finditer(r"\nHTTP/", text))
    start = positions[-1]

    sep = text.find("\n\n", start)
    if sep == -1:
        # Hay headers pero no body visible.
        return text[start:].strip(), ""

    headers = text[start:sep].strip()
    body = text[sep + 2:]
    return headers, body


class PageHTMLParser(HTMLParser):
    """Parser estructural mínimo: observa HTML, no decide significado de seguridad."""

    def __init__(self, base_url, target_base):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.target_base = target_base.rstrip("/")
        self.links = []
        self.forms = []
        self._current_form = None
        self._title_mode = False
        self.title_parts = []
        self.text_parts = []
        self._skip_text_depth = 0

    def _attrs(self, attrs):
        return {k.lower(): (v if v is not None else "") for k, v in attrs}

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        a = self._attrs(attrs)
        if tag in {"script", "style", "noscript"}:
            self._skip_text_depth += 1
            return
        if tag == "title":
            self._title_mode = True
            return
        if tag == "a" and a.get("href"):
            href = a.get("href", "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                return
            absu = urljoin(self.base_url, href)
            # Descarta fragmento para evitar falsas URLs distintas.
            absu = absu.split("#", 1)[0]
            if absu.rstrip("/").startswith(self.target_base):
                self.links.append(absu)
            return
        if tag == "form":
            self._current_form = {
                "method": (a.get("method") or "GET").upper(),
                "action": urljoin(self.base_url, a.get("action") or self.base_url),
                "inputs": [],
                "buttons": [],
            }
            return
        if self._current_form is not None and tag in {"input", "textarea", "select"}:
            self._current_form["inputs"].append({
                "tag": tag,
                "name": a.get("name"),
                "type": a.get("type") if tag == "input" else tag,
                "value_present": "value" in a,
                "placeholder_present": "placeholder" in a,
                "required": "required" in a,
            })
            return
        if self._current_form is not None and tag == "button":
            self._current_form["buttons"].append({
                "name": a.get("name"),
                "type": a.get("type"),
                "value_present": "value" in a,
            })

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "noscript"} and self._skip_text_depth:
            self._skip_text_depth -= 1
            return
        if tag == "title":
            self._title_mode = False
            return
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        text = " ".join((data or "").split())
        if not text:
            return
        if self._title_mode:
            self.title_parts.append(text)
        elif not self._skip_text_depth:
            self.text_parts.append(text)

    def result(self):
        # Orden estable + dedupe conservador.
        seen = set()
        links = []
        for link in self.links:
            if link not in seen:
                seen.add(link)
                links.append(link)
        visible_text = " ".join(self.text_parts)
        return {
            "title": " ".join(self.title_parts).strip() or None,
            "internal_links": links[:150],
            "forms": self.forms[:50],
            "visible_text_excerpt": visible_text[:2500],
        }


def parse_page_html(body, url, target_base):
    parser = PageHTMLParser(url, target_base)
    try:
        parser.feed(body or "")
        parser.close()
        return parser.result()
    except Exception:
        # Fallback regex si HTMLParser falla con HTML roto.
        title_match = re.search(r"<title>(.*?)</title>", body or "", re.I | re.S)
        return {
            "title": title_match.group(1).strip() if title_match else None,
            "internal_links": parse_internal_links_regex(body or "", url, target_base),
            "forms": parse_forms_regex(body or ""),
            "visible_text_excerpt": " ".join(re.sub(r"<[^>]+>", " ", body or "").split())[:2500],
        }


def parse_forms_regex(body):
    forms = []
    for form in re.findall(r"<form\b.*?</form>", body or "", re.I | re.S):
        action = re.search(r"action=[\"']?([^\"' >]+)", form, re.I)
        method = re.search(r"method=[\"']?([^\"' >]+)", form, re.I)
        inputs = []
        for inp in re.findall(r"<input\b[^>]*>", form, re.I):
            name = re.search(r"name=[\"']?([^\"' >]+)", inp, re.I)
            typ = re.search(r"type=[\"']?([^\"' >]+)", inp, re.I)
            value = re.search(r"value=[\"']?([^\"'>]*)", inp, re.I)
            inputs.append({
                "tag": "input",
                "name": name.group(1) if name else None,
                "type": typ.group(1) if typ else None,
                "value_present": bool(value),
            })
        forms.append({
            "method": method.group(1).upper() if method else "GET",
            "action": action.group(1) if action else None,
            "inputs": inputs,
            "buttons": [],
        })
    return forms


def parse_internal_links_regex(body, url, target_base):
    links = []
    base = target_base.rstrip("/")
    for href in re.findall(r"href\s*=\s*[\"']([^\"']+)", body or "", re.I):
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absu = urljoin(url, href).split("#", 1)[0]
        if absu.rstrip("/").startswith(base):
            links.append(absu)
    return sorted(set(links))[:150]


# Compatibilidad con selftest y scripts anteriores.
def parse_forms(body):
    return parse_forms_regex(body)


def parse_internal_links(body, url, target_base):
    return parse_internal_links_regex(body, url, target_base)


def save_raw_page_artifacts(url, headers, body):
    outdir = Path("logs/pages")
    outdir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    html_file = outdir / f"{digest}.html"
    headers_file = outdir / f"{digest}.headers.txt"
    meta_file = outdir / f"{digest}.meta.json"
    html_file.write_text(body or "", encoding="utf-8", errors="replace")
    headers_file.write_text(headers or "", encoding="utf-8", errors="replace")
    meta_file.write_text(json.dumps({
        "url": url,
        "timestamp": utc_now(),
        "html_file": str(html_file),
        "headers_file": str(headers_file),
        "body_sha256": hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest(),
        "body_bytes": len((body or "").encode("utf-8", errors="replace")),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(html_file), str(headers_file), str(meta_file)


def update_knowledge_from_interior_mcp(url, result, decision_id):
    k = load_knowledge()
    target_host, _ = current_scope()
    target_base = (k.get("scope", {}).get("target_base") or f"http://{target_host}").rstrip("/")
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    headers, body, transport_meta = decode_interior_capture(stdout)
    parsed_url = urlparse(url)
    page = parse_page_html(body, url, target_base)
    html_file, headers_file, meta_file = save_raw_page_artifacts(url, headers, body)

    status_line = None
    for line in (headers or "").splitlines():
        if line.startswith("HTTP/"):
            status_line = line.strip()
            break

    forms = page.get("forms", [])
    internal_links = page.get("internal_links", [])
    body_bytes = len(body.encode("utf-8", errors="replace"))
    if result.get("returncode") != 0 or not result.get("ok"):
        observation_quality = "mcp_error"
    elif body_bytes == 0:
        observation_quality = "empty_body"
    elif not forms and not internal_links:
        observation_quality = "captured_but_no_structure"
    else:
        observation_quality = "structured"

    ctx = {
        "timestamp": utc_now(),
        "url": url,
        "source": "kali_mcp:/tools/exec",
        "decision_id": decision_id,
        "status_line": status_line,
        "title": page.get("title"),
        "forms": forms,
        "internal_links": internal_links,
        "query_params": parse_qs(parsed_url.query),
        "visible_text_excerpt": page.get("visible_text_excerpt"),
        "raw_artifacts": {
            "html_file": html_file,
            "headers_file": headers_file,
            "meta_file": meta_file,
            "body_bytes": body_bytes,
        },
        "observation_quality": observation_quality,
        "body_indicators": {
            "contains_dvwa_vulnerability": "vulnerability" in url.lower() or "Vulnerability" in body,
            "contains_error": bool(re.search(r"warning|error|syntax|mysql|mysqli|undefined", body, re.I)),
            "contains_login_hint": bool(re.search(r"login|username|password|csrf|user_token", body, re.I)),
            "contains_reflected_input_hint": bool(re.search(r"hello|welcome|result|output", body, re.I)),
        },
        "mcp_returncode": result.get("returncode"),
        "mcp_ok": result.get("ok"),
        "transport_meta": transport_meta,
        "stderr_preview": stderr[-1000:],
    }

    # Fallback solo de descubrimiento, no de explotación: si la base no entregó links
    # pero hay sesión DVWA, index.php suele ser el dashboard real.
    fallback_candidates = []
    if not internal_links:
        base_index = target_base + "/index.php"
        if url.rstrip("/") == target_base and base_index != url:
            fallback_candidates.append(base_index)
    if fallback_candidates:
        ctx["fallback_candidates"] = fallback_candidates

    k.setdefault("visited_urls", [])
    if url not in k["visited_urls"]:
        k["visited_urls"].append(url)
    k.setdefault("url_context", {})
    k["url_context"][url] = ctx

    # Descubrimiento neutral: las URLs sólo entran a candidate_urls mediante
    # discovery.mode=auto u operator. No se clasifican vulnerabilidades ni rutas.
    discovered = list(internal_links) + list(fallback_candidates)
    added_urls, rejected_urls = register_urls(k, url, discovered, interactive=True)
    ctx["discovery"] = {
        "mode": os.environ.get("BUGTRACEAI_DISCOVERY_MODE", "auto"),
        "detected_count": len(discovered),
        "added_count": len(added_urls),
        "rejected_count": len(rejected_urls),
        "added_urls": added_urls,
    }

    k.setdefault("mcp_interior_observations", []).append({
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "url": url,
        "command": result.get("command"),
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "status_line": ctx["status_line"],
        "title": ctx["title"],
        "forms_count": len(forms),
        "internal_links_count": len(internal_links),
        "body_bytes": body_bytes,
        "observation_quality": observation_quality,
        "transport": transport_meta.get("transport"),
        "capture_returncode": transport_meta.get("capture_returncode"),
        "html_file": html_file,
        "stderr_preview": stderr[-1000:],
    })
    save_knowledge(k)
    print("[DONE] Contexto incremental guardado desde Kali/MCP para:", url)
    print(json.dumps({
        "url": url,
        "status_line": status_line,
        "title": ctx["title"],
        "forms_count": len(forms),
        "internal_links_count": len(internal_links),
        "candidate_urls_count": len(k.get("candidate_urls", [])),
        "observation_quality": observation_quality,
        "html_file": html_file,
    }, indent=2, ensure_ascii=False))

def execute_run_login(action_obj, decision_id):
    """Ejecuta login DVWA dentro de Kali vía MCP.

    La cookie queda en Kali en KALI_COOKIE_JAR. Ubuntu solo guarda metadatos
    de sesión, nunca PHPSESSID.
    """
    k = load_knowledge()
    scope = k.get("scope", {})
    target_base = scope.get("target_base") or f"http://{scope.get('target_host', DEFAULT_TARGET_HOST)}"
    # V1.8.1: las credenciales del laboratorio son una política fija del runtime.
    # El LLM no puede seleccionar ni reemplazar usuario o contraseña.
    user = os.environ.get("BUGTRACEAI_USERNAME", "admin")
    password = os.environ.get("BUGTRACEAI_PASSWORD", "password")
    security = action_obj.get("security") or os.environ.get("BUGTRACEAI_DVWA_SECURITY") or k.get("dvwa_security") or "low"

    command = " ".join(shlex.quote(p) for p in [
        KALI_DVWA_LOGIN_SCRIPT,
        target_base,
        user,
        password,
        security,
        os.environ.get("BUGTRACEAI_COOKIE_JAR", KALI_COOKIE_JAR),
    ])
    print("[MCP RUN_LOGIN]", target_base)
    log_event("[MCP RUN_LOGIN] " + command)
    try:
        result = call_mcp_exec_command(command, timeout=120)
    except Exception as e:
        print("[ERROR] Falló llamada MCP /tools/exec para run_login:")
        print(e)
        sys.exit(1)

    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    print(json.dumps({
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "stdout_preview": stdout[-1000:],
        "stderr_preview": stderr[-1000:],
    }, indent=2, ensure_ascii=False))

    if result.get("returncode") != 0 or not result.get("ok"):
        print("[ERROR] Login remoto en Kali no confirmado.")
        sys.exit(1)

    k = load_knowledge()
    k["session"] = {
        "authenticated": True,
        "dvwa_security": security,
        "cookie_jar": os.environ.get("BUGTRACEAI_COOKIE_JAR", KALI_COOKIE_JAR),
        "cookie_location": "kali",
        "timestamp": utc_now(),
    }
    k.setdefault("mcp_command_observations", []).append({
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "source_action": "run_login",
        "command": command,
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "stdout_preview": stdout[-2000:],
        "stderr_preview": stderr[-1000:],
    })
    save_knowledge(k)
    print("[DONE] Sesión DVWA creada en Kali:", os.environ.get("BUGTRACEAI_COOKIE_JAR", KALI_COOKIE_JAR))


def execute_run_interior(action_obj, decision_id, decision=None):
    url = action_obj.get("url")
    if not url:
        print("[ERROR] run_interior requiere URL")
        sys.exit(1)
    if not url_in_scope(url):
        print("[BLOCKED] URL fuera de alcance:", url)
        sys.exit(1)
    k = load_knowledge()
    active = normalize_resource_url(get_active_resource(k))
    requested = normalize_resource_url(url)
    scheduler_generated = isinstance(decision, dict) and str(decision.get("version") or "").startswith("1.8.0-scheduler")
    if autonomous_mode_enabled() and active and requested != active and not scheduler_generated:
        print("[SCHEDULER BLOCK] Navegación global del LLM rechazada.")
        print("active_resource:", active)
        print("requested_url:", requested)
        return
    visited_urls = k.get("visited_urls", [])
    if url in visited_urls and not action_obj.get("force_repeat"):
        previous_ctx = k.get("url_context", {}).get(url, {})
        quality = previous_ctx.get("observation_quality")
        # Permite una recuperación automática si la observación previa fue claramente inútil.
        recoverable = quality in {"empty_body", "mcp_error"}
        if not recoverable:
            print("[DEDUP] run_interior omitido.")
            print("URL ya visitada:", url)
            print("observation_quality:", quality)
            mark_decision_executed(decision_id)
            return
        print("[RETRY] Reintentando run_interior por observación previa defectuosa:", quality)

    set_active_resource(url, source="run_interior", decision_id=decision_id)
    cookie = get_cookie_from_jar()
    command = build_interior_command(url, cookie)

    print("[MCP RUN_INTERIOR]", url)
    log_event("[MCP RUN_INTERIOR] " + command)
    try:
        result = call_mcp_exec_command(command)
    except Exception as e:
        print("[ERROR] Falló llamada MCP /tools/exec para run_interior:")
        print(e)
        register_navigation_failure(url, e, decision_id)
        mark_decision_executed(decision_id)
        return

    print(json.dumps({
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "stderr_preview": (result.get("stderr") or "")[-500:],
    }, indent=2, ensure_ascii=False))
    update_knowledge_from_interior_mcp(url, result, decision_id)


def execute_review_forms():
    print("[LOCAL READ] review_forms solo resume data/knowledge.json; no toca el objetivo.")
    result = subprocess.run([sys.executable, "./scripts/review_forms.py"], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)


def execute_submit_benign_upload(action_obj, decision_id):
    resource = str(action_obj.get("resource") or get_active_resource() or "")
    if "/vulnerabilities/upload/" not in resource:
        print("[UPLOAD BLOCKED] El recurso activo no es DVWA Upload:", resource)
        return
    artifact = "assets/benign_phpinfo.php"
    command = (
        "curl -ksS -L "
        "-b /tmp/bugtraceai-session/dvwa_cookie.txt "
        "-F 'MAX_FILE_SIZE=100000' "
        f"-F 'uploaded=@{artifact};type=application/x-httpd-php' "
        "-F 'Upload=Upload' "
        f"'{resource}'"
    )
    generated = {
        "action":"propose_mcp_command",
        "command":command,
        "risk_level":1,
        "approval_required":True,
        "reason":action_obj.get("reason") or "Enviar el artefacto benigno preinstalado",
        "expected_evidence":action_obj.get("expected_evidence") or {
            "matcher":"contains",
            "value":"succesfully uploaded!",
            "meaning":"La respuesta del mismo POST confirma que DVWA aceptó la carga del artefacto benigno"
        },
    }
    print("[STRUCTURED UPLOAD] Usando", artifact)
    execute_mcp_command(generated, decision_id, "submit_benign_upload")


def execute_mcp_command(action_obj, decision_id, source_action):
    command = action_obj.get("command")
    reason = action_obj.get("reason", "")
    executor_event("EXECUTOR_RECEIVED", decision_id=decision_id, source_action=source_action, command=str(command or ""))
    risk_level = action_obj.get("risk_level", 3)
    approval_required = action_obj.get("approval_required", True)
    force_repeat = action_obj.get("force_repeat", False)
    if not command:
        print(f"[ERROR] {source_action} requiere campo command")
        sys.exit(1)
    original_command = command
    command = enrich_command_with_cookie(command)
    executor_event("EXECUTOR_AFTER_COOKIE_ENRICH", decision_id=decision_id, source_action=source_action,
                   original_command=original_command, command=command, changed=(command != original_command))
    before_credentials = command
    command = enforce_fixed_attack_credentials(command)
    executor_event("EXECUTOR_AFTER_CREDENTIAL_POLICY", decision_id=decision_id, source_action=source_action,
                   original_command=before_credentials, command=command, changed=(command != before_credentials))
    if reference_limit_blocks_command(command, decision_id):
        mark_decision_executed(decision_id)
        return
    tested_url = normalize_resource_url(_extract_first_url(command) or action_obj.get("url") or action_obj.get("resource"))
    k_owner = load_knowledge()
    scope_ok, scope_details = validate_active_host_path_scope(command, k_owner)
    if not scope_ok:
        print("[SCOPE BLOCKED] El comando intenta salir del host/ruta del Analysis Item activo.")
        print(f"Analysis Item : {scope_details.get('analysis_id') or 'UNKNOWN'}")
        print(f"Host permitido: {scope_details.get('allowed_host')}")
        print(f"Ruta permitida: {scope_details.get('allowed_path')}")
        print(f"URL propuesta : {scope_details.get('proposed_url')}")
        print("La URL propuesta no fue ejecutada. Podrá analizarse cuando Discovery active su propio A-xxxx.")
        register_scope_block(command, scope_details, decision_id, source_action)
        mark_decision_executed(decision_id)
        return
    cmd_resource = execution_owner_resource(tested_url, k_owner)
    if cmd_resource and cmd_resource != "global":
        set_active_resource(cmd_resource, source=source_action, decision_id=decision_id)
    if autonomous_mode_enabled() and resource_mcp_execution_count(cmd_resource) >= autonomous_max_mcp_commands():
        close_resource_autonomous_limit(cmd_resource, decision_id, "Máximo de comandos MCP por Analysis Item alcanzado sin veredicto confirmado.")
        return
    ok, msg = validate_mcp_command(command)
    executor_event("EXECUTOR_VALIDATION", decision_id=decision_id, source_action=source_action,
                   command=command, validation_ok=ok, validation_message=msg, tested_url=tested_url,
                   owner_resource=cmd_resource)
    if not ok:
        print("[BLOCKED]", msg)
        log_event("[BLOCKED MCP COMMAND] " + msg + " :: " + command)
        k = load_knowledge()
        resource = cmd_resource or infer_error_resource(k, {"next_actions":[action_obj]})
        # v2.0.1 no relabels valid shell syntax as stdout processing.
        is_stdout_processing = False
        if is_stdout_processing:
            event = {
                "timestamp": utc_now(),
                "resource": resource,
                "type": "stdout_processing_not_allowed",
                "blocked_command": command,
                "explanation": "El runtime captura stdout/stderr completos. Ejecute solo la herramienta principal y analice la observación en el ciclo siguiente.",
                "correction": "Eliminar pipes, filtros y redirecciones; conservar únicamente el comando principal.",
            }
            k.setdefault("recent_blocked_actions", []).append(event)
            k["recent_blocked_actions"] = k["recent_blocked_actions"][-5:]
            save_knowledge(k)
            print("[RUNTIME PROTOCOL] stdout_processing_not_allowed")
            print("El runtime conservará stdout completo para el siguiente ciclo. Este bloqueo no marca el recurso INCONCLUSIVE.")
            register_stop_on_error({
                "decision_id": decision_id,
                "analysis_summary": "El comando intentó procesar stdout dentro del shell.",
                "operator_message": event["explanation"],
                "next_actions": [{"action": "stop_on_error", "reason": "stdout_processing_not_allowed"}],
            })
        else:
            register_stop_on_error({
                "decision_id": decision_id,
                "analysis_summary": f"Comando MCP bloqueado por runtime guard: {msg}",
                "operator_message": f"Comando bloqueado por política de ejecución segura: {msg}",
                "next_actions": [{"action": "stop_on_error", "reason": f"blocked_mcp_command: {msg}"}],
            })
        sys.exit(1)
    if was_mcp_command_already_successful(command) and not force_repeat:
        print("[DEDUP] MCP command omitido.")
        print("Comando MCP exitoso ya ejecutado anteriormente.")
        print("Command:", command)
        print("Para repetirlo, el LLM debe incluir force_repeat=true con justificación.")
        return
    print("[VALIDATED]", msg)
    if approval_required or risk_level >= 2:
        approval = confirm_mcp_command_execution(command, reason, risk_level)
        if approval == "close_next":
            close_resource_from_mcp_prompt(cmd_resource, decision_id, reason, source_action)
            return
        if approval != "execute":
            print("[CANCELLED] Operador rechazó este comando MCP. El recurso permanece activo.")
            return
    print("[MCP EXEC COMMAND]", command)
    log_event("[MCP EXEC COMMAND] " + command)
    executor_event("MCP_DISPATCH", decision_id=decision_id, source_action=source_action,
                   command=command, tested_url=tested_url, owner_resource=cmd_resource)
    try:
        result = call_mcp_exec_command(command)
    except Exception as e:
        print("[ERROR] Falló llamada MCP /tools/exec:")
        print(e)
        print("[HINT] Verificá que el servidor MCP Kali tenga implementado POST /tools/exec")
        sys.exit(1)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    executor_event("MCP_RESULT", decision_id=decision_id, source_action=source_action, command=command,
                   tested_url=tested_url, owner_resource=cmd_resource, ok=result.get("ok"),
                   returncode=result.get("returncode"), stdout=str(result.get("stdout") or "")[:4000],
                   stderr=str(result.get("stderr") or "")[:4000], transport_request=result.get("transport_request"))
    count = register_resource_mcp_execution(cmd_resource, source_action, command, result, tested_url=tested_url)
    if autonomous_mode_enabled():
        print(f"[AUTONOMOUS] MCP execution {count}/{autonomous_max_mcp_commands()} para {cmd_resource}")
    save_mcp_command_observation(command, reason, risk_level, result, decision_id, source_action, owner_resource=cmd_resource, tested_url=tested_url, expected_evidence=action_obj.get("expected_evidence"))


def execute_mcp_tool(action_obj, decision_id):
    tool = action_obj.get("tool")
    args = action_obj.get("arguments", {})
    reason = action_obj.get("reason", "")
    risk_level = action_obj.get("risk_level", 3)
    approval_required = action_obj.get("approval_required", True)
    force_repeat = action_obj.get("force_repeat", False)
    if not tool:
        print("[ERROR] propose_mcp_tool requiere campo tool")
        sys.exit(1)
    if tool not in ALLOWED_MCP_TOOLS:
        print("[BLOCKED] Tool MCP no permitida:", tool)
        sys.exit(1)
    if not isinstance(args, dict):
        print("[ERROR] arguments debe ser objeto JSON")
        sys.exit(1)
    target_url = args.get("url")
    if not target_url:
        print("[ERROR] arguments.url es obligatorio")
        sys.exit(1)
    if not url_in_scope(target_url):
        print("[BLOCKED] URL fuera de scope:", target_url)
        sys.exit(1)
    tool_owner = execution_owner_resource(target_url)
    if autonomous_mode_enabled() and resource_mcp_execution_count(tool_owner) >= autonomous_max_mcp_commands():
        close_resource_autonomous_limit(tool_owner, decision_id, "Máximo de herramientas MCP por Analysis Item alcanzado sin veredicto confirmado.")
        return
    if was_mcp_tool_already_successful(tool, target_url) and not force_repeat:
        print("[DEDUP] MCP tool omitida.")
        print("Esta herramienta MCP ya fue ejecutada exitosamente contra esta URL.")
        print("Para repetirla, el LLM debe incluir force_repeat=true con justificación.")
        return
    if not args.get("cookie"):
        cookie = get_cookie_from_jar()
        if cookie:
            args["cookie"] = cookie
            print("[INFO] Cookie DVWA referenciada desde Kali:", cookie)
        else:
            print("[ERROR] No se recibió cookie y no se pudo preparar referencia de cookie en Kali")
            sys.exit(1)
    if approval_required or risk_level >= 2:
        approval = confirm_mcp_tool_execution(tool, args, reason, risk_level)
        if approval == "close_next":
            close_resource_from_mcp_prompt(target_url, decision_id, reason, "propose_mcp_tool")
            return
        if approval != "execute":
            print("[CANCELLED] Operador rechazó esta herramienta MCP. El recurso permanece activo.")
            return
    print("[MCP EXEC TOOL]", tool)
    log_event("[MCP EXEC TOOL] " + tool + " " + json.dumps(args, ensure_ascii=False))
    try:
        result = call_mcp_endpoint(ALLOWED_MCP_TOOLS[tool], args)
    except Exception as e:
        print("[ERROR] Falló llamada MCP tool:")
        print(e)
        sys.exit(1)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    executor_event("MCP_RESULT", decision_id=decision_id, source_action=source_action, command=command,
                   tested_url=tested_url, owner_resource=cmd_resource, ok=result.get("ok"),
                   returncode=result.get("returncode"), stdout=str(result.get("stdout") or "")[:4000],
                   stderr=str(result.get("stderr") or "")[:4000], transport_request=result.get("transport_request"))
    count = register_resource_mcp_execution(tool_owner, "propose_mcp_tool", tool, result, tested_url=target_url)
    if autonomous_mode_enabled():
        print(f"[AUTONOMOUS] MCP execution {count}/{autonomous_max_mcp_commands()} para {tool_owner}")
    save_mcp_tool_observation(tool, args, reason, risk_level, result, decision_id)


def print_operator_verdict(action_obj, decision):
    print("\n[OPERATOR VERDICT]")
    print(decision.get("operator_message", "El LLM entregó un veredicto asistido."))
    print()
    for field in [
        "verdict", "attempted_actions", "failed_or_blocked", "confirmed_evidence",
        "evidence", "needed_to_continue", "impact", "recommendation", "reason",
    ]:
        if field in action_obj:
            print(f"{field}:")
            value = action_obj[field]
            if isinstance(value, list):
                for item in value:
                    print("-", item)
            else:
                print(value)
            print()



def authoritative_active_analysis_resource(k=None):
    """Return the authoritative active Analysis Item URL.

    In autonomous mode the action payload is advisory. The queue's active item
    owns the lifecycle and must be closed instead of any URL mentioned in the
    question/context.
    """
    k = k if isinstance(k, dict) else load_knowledge()
    item = active_item(k)
    if isinstance(item, dict) and item.get("entry_url"):
        return normalize_resource_url(item.get("entry_url"))
    active_id = k.get("active_analysis_id")
    if active_id:
        item = find_item(k, analysis_id=active_id)
        if isinstance(item, dict) and item.get("entry_url"):
            return normalize_resource_url(item.get("entry_url"))
    return normalize_resource_url(get_active_resource(k))


def autonomous_close_confirmed_resource(resource, decision, decision_id, context=""):
    """Atomically persist CONFIRMED, document, complete and release the active item."""
    k = load_knowledge()
    authoritative = authoritative_active_analysis_resource(k)
    requested = normalize_resource_url(resource)
    resource = authoritative or requested
    if not resource:
        print("[AUTONOMOUS BLOCKED] No se pudo resolver el Analysis Item activo.")
        return False
    if authoritative and requested and authoritative != requested:
        print(f"[AUTONOMOUS] URL del checkpoint ignorada: {requested}; activo autoritativo: {authoritative}")

    item = find_item(k, url=resource) or active_item(k)
    if not item:
        print(f"[AUTONOMOUS BLOCKED] No existe Analysis Item para {resource}")
        return False

    reflection = decision.get("reflection") or {}
    existing_verdict = item.get("vulnerability_verdict") or {}
    evidence = list(item.get("evidence") or [])
    cu = decision.get("cognitive_updates") or {}
    for raw in cu.get("evidence") or []:
        text = str(raw.get("text")) if isinstance(raw, dict) and raw.get("text") else str(raw) if raw else ""
        if text and not any((e.get("text") if isinstance(e, dict) else str(e)) == text for e in evidence):
            evidence.append({"text": text, "source": "autonomous_checkpoint", "decision_id": decision_id, "timestamp": utc_now()})
    if context and not any((e.get("text") if isinstance(e, dict) else str(e)) == context for e in evidence):
        evidence.append({"text": context, "source": "ask_operator_context", "decision_id": decision_id, "timestamp": utc_now()})
    item["evidence"] = evidence

    # v3.0.3h authoritative architecture gate: never trust/require an LLM declaration.
    item["capability_assessment"] = evaluate_architecture_validation(resource)
    item["capability_assessment"]["decision_id"] = decision_id
    item["capability_assessment"]["updated_at"] = utc_now()

    summary = (existing_verdict.get("summary") or reflection.get("interpretation") or
               decision.get("analysis_summary") or context or
               "Vulnerabilidad confirmada y cerrada automáticamente.")
    confidence = str(existing_verdict.get("confidence") or reflection.get("confidence") or "MEDIUM").upper()
    item["vulnerability_verdict"] = {
        "status": "CONFIRMED", "confidence": confidence, "summary": summary,
        "evidence_ids": [str(e.get("evidence_id")) for e in evidence if isinstance(e, dict) and e.get("evidence_id")],
        "decision_id": decision_id, "updated_at": utc_now(), "source": "autonomous_confirmed_closure_v261a"
    }
    item.setdefault("exploitation", {
        "status": "NOT_CONFIRMED",
        "summary": "Vulnerabilidad confirmada; la explotación no fue demostrada antes del cierre autónomo.",
        "command_ids": [], "result_ids": [], "decision_id": decision_id,
        "updated_at": utc_now(), "source": "autonomous_confirmed_closure_v261a"
    })
    item["closure"] = {
        "assessment": "CONFIRMED", "reason": summary, "decision_id": decision_id,
        "timestamp": utc_now(), "source": "autonomous_confirmed_closure_v261a"
    }
    item["report"] = {
        "finding": summary,
        "recommendation": "Revisar la evidencia y aplicar mitigaciones específicas del hallazgo.",
        "source": "autonomous_confirmed_closure_v261a"
    }

    closure_reason = "AUTO-YES v2.5.4: hallazgo CONFIRMED documentado y cerrado atómicamente."
    set_state(k, resource, "COMPLETED", closure_reason,
              "autonomous_confirmed_closure_v261a")
    # Keep the legacy runtime mirror consistent before save_knowledge()->sync_runtime().
    k.setdefault("resource_state", {})[resource] = {
        "state": "COMPLETED", "resource_goal": "document",
        "updated_at": utc_now(), "updated_by": "autonomous_confirmed_closure_v261a",
        "decision_id": decision_id, "reason": closure_reason
    }
    k.setdefault("resource_state_history", []).append({
        "timestamp": utc_now(), "decision_id": decision_id, "resource": resource,
        "state": "COMPLETED", "resource_goal": "document", "reason": closure_reason
    })
    completed = k.setdefault("completed_urls", [])
    if not any(normalize_resource_url(x.get("url") if isinstance(x, dict) else x) == resource for x in completed):
        completed.append({
            "decision_id": decision_id, "timestamp": utc_now(), "url": resource,
            "status": "completed", "finding": summary, "analysis_summary": summary,
            "vulnerability_verdict": item["vulnerability_verdict"],
            "evidence": evidence, "impact": None,
            "recommendation": item["report"]["recommendation"],
            "operator_message": "AUTO-YES v2.5.4: cierre sin intervención humana."
        })
    set_active(k, None)
    k["active_resource"] = None
    k["active_analysis_id"] = None
    if isinstance(k.get("scheduler"), dict):
        k["scheduler"]["active_resource"] = None
    save_knowledge(k)
    print(f"[AUTONOMOUS CONFIRMED -> COMPLETED] {resource}")
    print("[SCHEDULER] Analysis Item liberado; se seleccionará la siguiente URL.")
    return True

def execute_ask_operator(action_obj, decision, decision_id):
    """V1.6.2: checkpoint humano real.

    Antes solo se imprimía el mensaje. Ahora el executor solicita una elección,
    la persiste en knowledge.json y el siguiente ciclo LLM puede actuar según
    esa respuesta. El runtime no decide pentesting; solo guarda la respuesta.
    """
    question = action_obj.get("question") or decision.get("operator_message") or "El LLM solicita intervención del operador."
    context = action_obj.get("context") or action_obj.get("reason") or ""
    resource = normalize_resource_url(action_obj.get("url") or action_obj.get("resource") or _extract_first_url(context) or get_active_resource() or "global")
    if autonomous_mode_enabled():
        # The active Analysis Item is authoritative; never close a URL merely mentioned by the LLM.
        resource = authoritative_active_analysis_resource() or resource

    print("[ASK_OPERATOR]")
    print(question)
    if context:
        print("\n[CONTEXT]")
        print(context)
    print("\nOpciones sugeridas:")
    print("1) Cerrar/documentar y pasar a la siguiente vulnerabilidad")
    print("2) Continuar con explotación controlada")
    print("3) Saltar esta vulnerabilidad como INCONCLUSIVE")
    print("4) Enumerar más evidencia no destructiva")
    print("5) Análisis profundo controlado")
    if autonomous_mode_enabled():
        answer = "1"
        print("[AUTONOMOUS] AUTO-YES: cerrar/documentar y avanzar según el checkpoint solicitado por el LLM.")
    else:
        try:
            answer = input("Respuesta del operador [1/2/3/4/5 o texto libre]: ").strip()
        except EOFError:
            answer = ""

    normalized = answer.lower()
    resource_goal = None
    if normalized in {"1", "cerrar", "documentar", "close", "document"}:
        choice = "close_document_next"
        resource_goal = "document"
    elif normalized in {"2", "continuar", "explotar", "continue", "exploit"}:
        choice = "continue_controlled_exploitation"
        resource_goal = "exploit"
    elif normalized in {"3", "skip", "saltar", "inconclusive"}:
        choice = "mark_inconclusive_skip"
        resource_goal = "document"
    elif normalized in {"4", "prueba", "adicional", "non_destructive", "enumerar", "enumerate"}:
        choice = "request_additional_non_destructive_test"
        resource_goal = "enumerate"
    elif normalized in {"5", "deep", "profundo", "profundizar"}:
        choice = "continue_deep_analysis"
        resource_goal = "deep"
    else:
        choice = "free_text"

    if autonomous_mode_enabled() and choice == "close_document_next":
        autonomous_close_confirmed_resource(resource, decision, decision_id, context)
        return

    k = load_knowledge()
    checkpoint = {
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "resource": resource,
        "question": question,
        "context": context,
        "answer": answer,
        "choice": choice,
        "resource_goal": resource_goal,
        "status": "answered" if answer else "unanswered",
    }
    k.setdefault("operator_checkpoints", []).append(checkpoint)
    k["latest_operator_checkpoint"] = checkpoint
    if resource:
        k["active_resource"] = {
            "resource": resource,
            "source": "ask_operator",
            "decision_id": decision_id,
            "timestamp": utc_now(),
        }
        if resource_goal:
            k.setdefault("resource_goals", {})[resource] = resource_goal
        if choice in {"continue_controlled_exploitation", "continue_deep_analysis", "request_additional_non_destructive_test"}:
            prev = (k.get("reference_exploit_counters") or {}).get(resource) or {}
            next_round = int(prev.get("round") or 1) + (1 if int(prev.get("count") or 0) >= int(prev.get("max_per_round") or MAX_REFERENCE_EXPLOITS_PER_ROUND) else 0)
            k.setdefault("reference_exploit_counters", {})[resource] = {"count": 0, "commands": [], "round": next_round, "max_per_round": MAX_REFERENCE_EXPLOITS_PER_ROUND}
            k.setdefault("reference_exploitation", {})[resource] = {"awaiting_final_operator": False, "limit_reached": False, "max_per_round": MAX_REFERENCE_EXPLOITS_PER_ROUND, "updated_at": utc_now()}
            k.setdefault("resource_state", {})[resource] = {
                "state": "EXPLOITING",
                "resource_goal": resource_goal or "exploit",
                "updated_at": utc_now(),
                "updated_by": "operator_checkpoint",
                "decision_id": decision_id,
                "reason": f"Operador seleccionó continuar con objetivo {resource_goal or 'exploit'}.",
            }
            k.setdefault("resource_state_history", []).append({
                "timestamp": utc_now(),
                "decision_id": decision_id,
                "resource": resource,
                "state": "EXPLOITING",
                "resource_goal": resource_goal or "exploit",
                "reason": f"Operador seleccionó continuar con objetivo {resource_goal or 'exploit'}.",
            })
        elif choice == "close_document_next":
            k.setdefault("resource_state", {})[resource] = {
                "state": "DOCUMENTED",
                "resource_goal": "document",
                "updated_at": utc_now(),
                "updated_by": "operator_checkpoint",
                "decision_id": decision_id,
                "reason": "Operador seleccionó documentar y pasar al siguiente recurso.",
            }

    if choice == "mark_inconclusive_skip" and resource:
        k.setdefault("resource_state", {})[resource] = {
            "state": "INCONCLUSIVE",
            "updated_at": utc_now(),
            "updated_by": "operator_checkpoint",
            "decision_id": decision_id,
            "reason": "Operador decidió saltar el recurso como inconcluso.",
        }
        k.setdefault("completed_urls", []).append({
            "decision_id": decision_id,
            "timestamp": utc_now(),
            "url": resource,
            "status": "inconclusive",
            "finding": "Análisis saltado por decisión del operador",
            "analysis_summary": decision.get("analysis_summary"),
            "evidence": [],
            "impact": None,
            "recommendation": "Retomar manualmente si es necesario.",
            "operator_message": decision.get("operator_message"),
        })
        print("[INCONCLUSIVE] Recurso saltado por decisión del operador.")

    save_knowledge(k)
    print(f"[DONE] checkpoint operador guardado: choice={choice} resource={resource}")

def execute_operator_verdict(action_obj, decision, decision_id):
    verdict_url = normalize_resource_url(action_obj.get("url"))
    if verdict_url:
        k = load_knowledge()
        completed_urls = k.get("completed_urls", [])
        already_completed = any(
            (item.get("url") == verdict_url if isinstance(item, dict) else item == verdict_url)
            for item in completed_urls
        )
        if already_completed:
            print("[DEDUP] operator_verdict omitido.")
            print("URL ya completada:", verdict_url)
            mark_decision_executed(decision_id)
            return

        # V1.7 guard: el LLM no puede cerrar/documentar una vulnerabilidad confirmada
        # sin una respuesta explícita del operador. Esto evita el salto automático
        # CONFIRMED -> completed_urls detectado en v1.6.2.
        latest = k.get("latest_operator_checkpoint")
        allowed_by_operator = (
            isinstance(latest, dict)
            and normalize_resource_url(latest.get("resource")) == verdict_url
            and latest.get("status") == "answered"
            and latest.get("choice") == "close_document_next"
        )
        state_obj = (k.get("resource_state") or {}).get(verdict_url)
        allowed_by_state = isinstance(state_obj, dict) and state_obj.get("resource_goal") == "document" and state_obj.get("state") == "DOCUMENTED"
        if not (allowed_by_operator or allowed_by_state) and autonomous_mode_enabled():
            print("[AUTONOMOUS] operator_verdict aceptado sin checkpoint de operador.")
            allowed_by_state = True
        if not (allowed_by_operator or allowed_by_state):
            k.setdefault("resource_state", {})[verdict_url] = {
                "state": "WAITING_OPERATOR",
                "resource_goal": None,
                "updated_at": utc_now(),
                "updated_by": "runtime_operator_guard",
                "decision_id": decision_id,
                "reason": "V1.7 bloqueó operator_verdict porque falta decisión explícita del operador.",
            }
            k.setdefault("resource_state_history", []).append({
                "timestamp": utc_now(),
                "decision_id": decision_id,
                "resource": verdict_url,
                "state": "WAITING_OPERATOR",
                "resource_goal": None,
                "reason": "operator_verdict bloqueado hasta recibir decisión del operador.",
            })
            save_knowledge(k)
            print("[WAITING_OPERATOR]")
            print("operator_verdict bloqueado: falta decisión explícita del operador para cerrar/documentar este recurso.")
            print("Ejecutá nuevamente reasoner.py + reasoner_llm.py para que el LLM emita ask_operator.")
            mark_decision_executed(decision_id)
            return

    print_operator_verdict(action_obj, decision)
    save_operator_verdict(action_obj, decision)
    if autonomous_mode_enabled() and verdict_url:
        k = load_knowledge()
        apply_llm_assessment(k, decision, verdict_url)
        set_state(k, verdict_url, "COMPLETED",
                  "AUTO-YES: operator_verdict aceptado y documentado en modo autónomo.",
                  "autonomous_yes")
        set_active(k, None)
        k["active_resource"] = None
        if isinstance(k.get("scheduler"), dict):
            k["scheduler"]["active_resource"] = None
        save_knowledge(k)
        print(f"[AUTONOMOUS COMPLETED] {verdict_url}")


def main():
    decision = load_decision()
    decision_id = decision.get("decision_id")
    if is_stale_decision(decision_id):
        print("[STALE DECISION]")
        print("Esta decisión ya fue ejecutada y no se repetirá.")
        print("decision_id:", decision_id)
        sys.exit(0)

    # CSE: guardar actualizaciones propuestas por el LLM antes de ejecutar.
    # Esto permite que memoria/estado avancen aunque la acción posterior falle o sea bloqueada.
    save_new_knowledge_from_decision(decision)
    save_state_updates_from_decision(decision)
    # Persist explicit LLM assessment separately from operational state.
    _k = load_knowledge()
    if apply_llm_assessment(_k, decision):
        save_knowledge(_k)

    actions = decision.get("next_actions", [])
    if not actions:
        print("[STOP] El LLM no propuso next_actions.")
        print(decision.get("operator_message", "Sin mensaje del operador."))
        return
    action_obj = actions[0]
    action = action_obj.get("action")
    reason = action_obj.get("reason", "")
    print("[LLM ACTION]", action)
    print("[REASON]", reason)
    if action in {"run_interior", "review_forms", "propose_command", "propose_mcp_command", "propose_mcp_tool", "submit_benign_upload"}:
        if register_repeated_action(action_obj, decision_id):
            print("[AUTO SKIP] Loop detectado antes de ejecutar la tercera repetición.")
            mark_decision_executed(decision_id)
            return
    if action not in ALLOWED_ACTIONS:
        print("[BLOCKED] Acción no permitida:", action)
        sys.exit(1)
    if action == "run_login":
        execute_run_login(action_obj, decision_id)
    elif action == "run_interior":
        execute_run_interior(action_obj, decision_id, decision)
    elif action == "review_forms":
        execute_review_forms()
    elif action in {"propose_command", "propose_mcp_command"}:
        execute_mcp_command(action_obj, decision_id, action)
        mark_decision_executed(decision_id)
        return
    elif action == "propose_mcp_tool":
        execute_mcp_tool(action_obj, decision_id)
        mark_decision_executed(decision_id)
        return
    elif action == "operator_verdict":
        execute_operator_verdict(action_obj, decision, decision_id)
    elif action == "finalize_analysis":
        execute_finalize_analysis(action_obj, decision, decision_id)
    elif action == "submit_benign_upload":
        execute_submit_benign_upload(action_obj, decision_id)
        mark_decision_executed(decision_id)
        return
    elif action == "ask_operator":
        execute_ask_operator(action_obj, decision, decision_id)
    elif action == "stop_on_error":
        print("[STOP_ON_ERROR]")
        print(decision.get("operator_message", "El LLM solicitó detenerse."))
        register_stop_on_error(decision)
    mark_decision_executed(decision_id)


if __name__ == "__main__":
    main()
