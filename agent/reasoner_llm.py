#!/usr/bin/env python3
import json
from semantic_claim_gate import normalize_hypothesis_type, can_confirm_vulnerability
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
import uuid
import hashlib
from decision_contract import ACTION_REQUIRED_FIELDS, ALLOWED_ACTIONS, ALLOWED_RESOURCE_STATES, get_action_example
from contract_diagnostics import record_rejection, record_acceptance
from policy_engine_v260 import repair_contract, evaluate_lab_policies
from cassette_manager import selected_cassette, log_reaction
from runtime_diagnostics import emit as runtime_event

PROMPT_FILE = Path("logs/last_llm_prompt.md")
OUT_FILE = Path("logs/last_llm_decision.json")
RAW_FILE = Path("logs/last_llm_raw.txt")
BAD_FILE = Path("logs/last_llm_invalid.json")
METRICS_FILE = Path("logs/last_llm_call_metrics.json")
DEBUG_FILE = Path("logs/llm_contract_debug.jsonl")
HASH_STATE_FILE = Path("logs/llm_prompt_hash_state.json")
HASH_EVENTS_FILE = Path("logs/v3/prompt_hash_events.jsonl")

def debug_event(event_type, **fields):
    """Best-effort JSONL contract trace. Debugging must never stop reasoning."""
    try:
        DEBUG_FILE.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": str(event_type),
            "component": "reasoner_llm",
            "version": VERSION,
        }
        record.update(fields)
        with DEBUG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:
        print(f"[WARN] llm_contract_debug no disponible: {exc}", file=sys.stderr)

LLAMA_URL = "http://127.0.0.1:8080/completion"
VERSION = "3.0.1f"
LLM_EVENTS_FILE = Path("logs/v3/llm_events.jsonl")

def llm_event(event_type, **fields):
    """Persist one normalized LLM observability event without affecting execution."""
    try:
        LLM_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": str(event_type),
            "component": "reasoner_llm",
            "version": VERSION,
        }
        record.update(fields)
        with LLM_EVENTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:
        print(f"[WARN] llm_events no disponible: {exc}", file=sys.stderr)

def classify_llm_error(exc=None, *, phase="unknown", message=""):
    """Return a stable model-error code for telemetry only."""
    text = (message or str(exc or "")).lower()
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timeout"
    if isinstance(exc, urllib.error.URLError) or any(x in text for x in ("connection refused", "connection reset", "name or service not known", "no route to host")):
        return "connection"
    if phase == "json":
        return "invalid_json"
    if phase == "schema":
        if "requiere" in text or "faltante" in text or "no tiene campo" in text:
            return "missing_field"
        return "schema_error"
    return "model_error"


def _strip_model_wrappers(text):
    text = (text or "").strip()
    if "</think>" in text:
        text = text.split("</think>", 1)[1].strip()
    text = text.replace("```json", "").replace("```", "").strip()
    return text

def _minimal_json_repair(candidate):
    """Conservative syntax-only repair: smart quotes and trailing commas."""
    import re
    repaired = candidate.replace("“", '"').replace("”", '"').replace("’", "'")
    repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
    return repaired


def _fit_prompt_to_context(text, max_chars=36000):
    """Preserve contract/header and newest resource context when prompt nears 12k tokens."""
    text = text or ""
    if len(text) <= max_chars:
        return text, False
    head_chars = 20000
    tail_chars = max_chars - head_chars
    marker = "\n\n[CONTEXTO INTERMEDIO RECORTADO PREVENTIVAMENTE]\n\n"
    fitted = text[:head_chars] + marker + text[-tail_chars:]
    return fitted, True

if not PROMPT_FILE.exists():
    print("[ERROR] No existe logs/last_llm_prompt.md")
    sys.exit(1)

prompt = PROMPT_FILE.read_text(encoding="utf-8")
# Recorte preventivo equilibrado: conserva contrato inicial y contexto más reciente.
base_prompt, prompt_pretrimmed = _fit_prompt_to_context(prompt, max_chars=36000)
final_prompt = base_prompt + "\nRESPONDE AHORA. SOLO JSON. EMPIEZA CON { Y TERMINA CON }."
debug_event(
    "PROMPT_READY",
    original_prompt_chars=len(prompt),
    prompt_chars=len(final_prompt),
    estimated_prompt_tokens=round(len(final_prompt)/4),
    preventive_trim=prompt_pretrimmed,
)

# v3.0.3c-hash: guardia arquitectónica genérica contra inferencias idénticas.
# El hash cubre el prompt final efectivo; si cambia estado/evidencia/contexto, cambia el hash.
def _append_hash_event(event):
    try:
        HASH_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with HASH_EVENTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:
        print(f"[WARN] prompt_hash_events no disponible: {exc}", file=sys.stderr)

def _prompt_hash_guard(text):
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    previous = {}
    try:
        if HASH_STATE_FILE.exists():
            previous = json.loads(HASH_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        previous = {}
    duplicate = previous.get("sha256") == digest
    count = int(previous.get("consecutive_duplicates", 0)) + 1 if duplicate else 0
    state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sha256": digest,
        "previous_sha256": previous.get("sha256"),
        "duplicate": duplicate,
        "consecutive_duplicates": count,
        "prompt_chars": len(text),
    }
    HASH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    HASH_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    _append_hash_event({"event":"PROMPT_HASH_DUPLICATE" if duplicate else "PROMPT_HASH_NEW", **state})
    return state

hash_state = _prompt_hash_guard(final_prompt)
if hash_state["duplicate"] and OUT_FILE.exists():
    # No se vuelve a gastar una inferencia sobre un estado literalmente idéntico.
    # Se reutiliza la última decisión; el scheduler conserva su mecanismo genérico
    # de detección de loops y decide cuándo avanzar el recurso.
    try:
        previous_decision = json.loads(OUT_FILE.read_text(encoding="utf-8"))
        previous_decision["hash_validator"] = {
            "status": "duplicate_prompt_reused",
            "sha256": hash_state["sha256"],
            "consecutive_duplicates": hash_state["consecutive_duplicates"],
        }
        OUT_FILE.write_text(json.dumps(previous_decision, indent=2, ensure_ascii=False), encoding="utf-8")
        debug_event("PROMPT_HASH_DUPLICATE", sha256=hash_state["sha256"], consecutive_duplicates=hash_state["consecutive_duplicates"], llm_call_skipped=True)
        runtime_event("LLM_PROMPT_DUPLICATE", stage="reasoner", status="skipped", reason_code="identical_prompt", data=hash_state)
        print(f"[HASH VALIDATOR] Prompt idéntico detectado ({hash_state['sha256'][:12]}...). Se omite llamada LLM y se reutiliza la decisión previa.")
        sys.exit(0)
    except Exception as exc:
        # Fail-open: si no puede reutilizar una decisión válida, el flujo original continúa.
        debug_event("PROMPT_HASH_REUSE_FAILED", error=str(exc)[:300], sha256=hash_state["sha256"])


def safe_decision(reason, message):
    return {
        "decision_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "llm_valid_json": False,
        "analysis_summary": message,
        "reflection": {"observation":"No hubo resultado interpretable.","interpretation":message,"hypothesis_effect":"NOT_EVALUATED","learned_fact":"No se obtuvo una respuesta válida del motor de razonamiento.","evidence_candidate":False,"next_requirement":"Recuperar la operación del LLM."},
        "hypotheses": [], "needed_context": [],
        "cognitive_updates": {"facts": [], "hypotheses": [], "evidence": [], "pending": [], "verdicts": []},
        "state_updates": [], "new_knowledge": [],
        "next_actions": [{"action": "stop_on_error", "reason": reason}],
        "operator_message": message,
    }


def call_llm(text, n_predict):
    payload={"prompt":text,"n_predict":n_predict,"temperature":0.0,"top_p":0.9,"reasoning_format":"none","cache_prompt":False}
    req=urllib.request.Request(LLAMA_URL,data=json.dumps(payload).encode("utf-8"),headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise RuntimeError(f"llama-server HTTP {exc.code}: {body[:1200]}") from exc

print("[+] Enviando prompt unified-action-contract a llama-server...")
metrics={"version":VERSION,"original_prompt_chars":len(prompt),"prompt_chars":len(final_prompt),"estimated_prompt_tokens":round(len(final_prompt)/4),"preventive_trim":prompt_pretrimmed,"attempts":[]}
try:
    result=call_llm(final_prompt, 1800)
    metrics["attempts"].append({"mode":"compact_no_think","ok":True,"n_predict":1800})
    llm_event("transport_success", attempt=1, mode="compact_no_think")
except Exception as first_error:
    metrics["attempts"].append({"mode":"focused","ok":False,"error":str(first_error)[:300]})
    llm_event("transport_failure", attempt=1, error_type=classify_llm_error(first_error, phase="transport"), error=str(first_error)[:500])
    print("[WARN] Falló consulta focused; reintentando con contexto recortado...")
    retry_base, _ = _fit_prompt_to_context(final_prompt, max_chars=24000)
    retry=retry_base + "\nSOLO JSON VÁLIDO."
    try:
        result=call_llm(retry, 1400)
        metrics["attempts"].append({"mode":"compact_retry_no_think","ok":True,"n_predict":1400,"prompt_chars":len(retry)})
        llm_event("transport_success", attempt=2, mode="compact_retry_no_think")
    except Exception as second_error:
        metrics["attempts"].append({"mode":"focused_retry","ok":False,"error":str(second_error)[:300]})
        llm_event("transport_failure", attempt=2, error_type=classify_llm_error(second_error, phase="transport"), error=str(second_error)[:500], unrecoverable=True)
        METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
        OUT_FILE.write_text(json.dumps(safe_decision("llm_transport_error", f"Error de transporte con llama-server: {second_error}"),indent=2,ensure_ascii=False),encoding="utf-8")
        print("[ERROR] Falló llama-server en ambos intentos:", second_error)
        sys.exit(0)
METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")

content = result.get("content", "").strip()
metrics["result"] = {
    "content_chars": len(content),
    "stop": result.get("stop"),
    "stopped_eos": result.get("stopped_eos"),
    "stopped_limit": result.get("stopped_limit"),
    "tokens_predicted": result.get("tokens_predicted"),
    "tokens_evaluated": result.get("tokens_evaluated"),
}
METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
RAW_FILE.write_text(content, encoding="utf-8")
debug_event("RAW_RESPONSE", response_chars=len(content), starts_with_json=content.lstrip().startswith("{"), stopped_limit=result.get("stopped_limit"), tokens_predicted=result.get("tokens_predicted"))
llm_event("response_received", response_chars=len(content), starts_with_json=content.lstrip().startswith("{"), stopped_limit=bool(result.get("stopped_limit")), tokens_predicted=result.get("tokens_predicted"), tokens_evaluated=result.get("tokens_evaluated"))
runtime_event("LLM_RESPONSE_RECEIVED", stage="reasoner", status="ok", flags={"starts_with_json":content.lstrip().startswith("{"),"stopped_limit":bool(result.get("stopped_limit"))}, data={"response_chars":len(content),"tokens_predicted":result.get("tokens_predicted"),"tokens_evaluated":result.get("tokens_evaluated")})

# Qwen/otros modelos pueden emitir razonamiento <think>. Solo se parsea lo posterior.
if "</think>" in content:
    content = content.split("</think>", 1)[1].strip()
elif content.lstrip().startswith("<think>"):
    # v2.0.1: one compact recovery call before counting a model error.
    compact_base, _ = _fit_prompt_to_context(prompt, max_chars=18000)
    compact = compact_base + "\nNO EXPLIQUES NI RAZONES. DEVUELVE SOLO EL OBJETO JSON FINAL."
    try:
        retry_result = call_llm(compact, 1200)
        retry_content = retry_result.get("content", "").strip()
        if "</think>" in retry_content:
            retry_content = retry_content.split("</think>", 1)[1].strip()
        if retry_content.lstrip().startswith("{"):
            content = retry_content
            RAW_FILE.write_text(content, encoding="utf-8")
        else:
            raise ValueError("compact retry did not return JSON")
    except Exception as retry_error:
        diagnostic = {
            "error_type": "thinking_truncated",
            "message": "La generación terminó dentro de un bloque <think> y el reintento compacto no produjo JSON.",
            "response_chars": len(content),
            "stopped_limit": result.get("stopped_limit"),
            "tokens_predicted": result.get("tokens_predicted"),
            "retry_error": str(retry_error),
            "raw_response": content,
        }
        BAD_FILE.write_text(json.dumps(diagnostic, indent=2, ensure_ascii=False), encoding="utf-8")
        failure = safe_decision("llm_thinking_truncated", "El modelo agotó la generación dentro de su razonamiento y no produjo el JSON final.")
        failure["validation_error"] = diagnostic
        runtime_event("LLM_THINKING_TRUNCATED", stage="reasoner", status="error", reason_code="thinking_truncated", message=diagnostic.get("message"), flags={"executor_reached":False,"mcp_reached":False}, data=diagnostic)
        OUT_FILE.write_text(json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
        print("[SAFE STOP] Razonamiento <think> truncado antes del JSON final.")
        print("Revisar diagnóstico en:", BAD_FILE)
        sys.exit(0)

content = content.replace("```json", "").replace("```", "").strip()

def extract_first_json_object(text):
    start = text.find("{")
    if start == -1:
        return text

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]

    return text[start:]

# content = "JSON INVALIDO DE PRUEBA"


json_candidate = extract_first_json_object(content).strip()

PLACEHOLDER_PATTERNS = [
    "resumen breve",
    "acción permitida",
    "accion permitida",
    "motivo técnico",
    "motivo tecnico",
    "mensaje corto",
    "veredicto técnico",
    "veredicto tecnico",
    "qué intentaste",
    "que intentaste",
    "qué necesitas",
    "que necesitas",
    "COMANDO_COMPLETO",
]

ALLOWED_UPDATE_SECTIONS = {"facts", "hypotheses", "evidence", "pending", "verdicts"}
ALLOWED_CONFIDENCE = {"low", "medium", "high"}
ALLOWED_HYPOTHESIS_STATUS = {"new", "active", "confirmed", "rejected", "superseded"}
ALLOWED_RESOURCE_GOALS = {"document", "exploit", "enumerate", "deep"}


def normalize_cognitive_updates(parsed):
    """V1.5.3 CSE: normalizar cognitive_updates sin interpretar contenido.

    Compatibilidad: si un modelo antiguo devuelve new_knowledge, se convierte
    en cognitive_updates por kind.
    """
    cu = parsed.get("cognitive_updates")
    if cu is None:
        cu = {section: [] for section in ALLOWED_UPDATE_SECTIONS}
        legacy = parsed.get("new_knowledge") or []
        if isinstance(legacy, list):
            kind_map = {
                "fact": "facts",
                "hypothesis": "hypotheses",
                "evidence": "evidence",
                "pending": "pending",
                "verdict": "verdicts",
                "note": "facts",
            }
            for item in legacy:
                if not isinstance(item, dict):
                    continue
                section = kind_map.get(str(item.get("kind", "note")).lower(), "facts")
                cu[section].append({
                    "resource": item.get("resource", "global"),
                    "text": item.get("text", ""),
                    "confidence": item.get("confidence", "medium"),
                })
        parsed["cognitive_updates"] = cu
    return cu


def validate_cognitive_updates(parsed):
    cu = normalize_cognitive_updates(parsed)
    if not isinstance(cu, dict):
        return False, "cognitive_updates debe ser un objeto"
    for section in ALLOWED_UPDATE_SECTIONS:
        cu.setdefault(section, [])
        if not isinstance(cu[section], list):
            return False, f"cognitive_updates.{section} debe ser lista"
        for i, item in enumerate(cu[section]):
            if not isinstance(item, dict):
                return False, f"cognitive_updates.{section}[{i}] debe ser objeto"
            for field in ["resource", "text", "confidence"]:
                if field not in item:
                    return False, f"cognitive_updates.{section}[{i}] requiere {field}"
            if not isinstance(item.get("resource"), str) or not item.get("resource").strip():
                return False, f"cognitive_updates.{section}[{i}].resource inválido"
            if not isinstance(item.get("text"), str) or len(item.get("text").strip()) < 8:
                return False, f"cognitive_updates.{section}[{i}].text demasiado corto"
            if item.get("confidence") not in ALLOWED_CONFIDENCE:
                return False, f"cognitive_updates.{section}[{i}].confidence no permitido"
            if section == "hypotheses":
                item.setdefault("status", "active")
                if item.get("status") not in ALLOWED_HYPOTHESIS_STATUS:
                    return False, f"cognitive_updates.hypotheses[{i}].status no permitido"
    return True, "ok"


def normalize_state_updates(parsed):
    su = parsed.get("state_updates")
    if su is None:
        su = []
        parsed["state_updates"] = su
    return su


def validate_state_updates(parsed):
    su = normalize_state_updates(parsed)
    if not isinstance(su, list):
        return False, "state_updates debe ser una lista"
    for i, item in enumerate(su):
        if not isinstance(item, dict):
            return False, f"state_updates[{i}] debe ser objeto"
        for field in ["resource", "state", "reason"]:
            if field not in item:
                return False, f"state_updates[{i}] requiere {field}"
        if not isinstance(item.get("resource"), str) or not item.get("resource").strip():
            return False, f"state_updates[{i}].resource inválido"
        state = str(item.get("state") or "").upper().strip()
        if state not in ALLOWED_RESOURCE_STATES:
            return False, f"state_updates[{i}].state no permitido: {item.get('state')}"
        item["state"] = state
        if not isinstance(item.get("reason"), str) or len(item.get("reason").strip()) < 8:
            return False, f"state_updates[{i}].reason demasiado corto"
        goal = item.get("resource_goal")
        if goal is not None:
            if goal not in ALLOWED_RESOURCE_GOALS:
                return False, f"state_updates[{i}].resource_goal no permitido: {goal}"
            if state not in {"WAITING_OPERATOR", "EXPLOITING", "DOCUMENTED", "COMPLETED", "INCONCLUSIVE"}:
                # Compatibilidad defensiva: el modelo puede anticipar resource_goal en NEW/MAPPED.
                # Se elimina porque aún no existe decisión del operador; no invalida toda la decisión.
                item.pop("resource_goal", None)
    return True, "ok"


def normalize_reflection(parsed):
    ref=parsed.get("reflection")
    if not isinstance(ref,dict):
        ref={}
    ref.setdefault("observation", "No se registró una observación explícita en esta decisión.")
    ref.setdefault("interpretation", parsed.get("analysis_summary") or "La decisión no incluyó una interpretación detallada.")
    effect=str(ref.get("hypothesis_effect") or "NOT_EVALUATED").upper()
    if effect not in {"SUPPORTED","WEAKENED","REFUTED","NOT_EVALUATED"}: effect="NOT_EVALUATED"
    ref["hypothesis_effect"]=effect
    # v3.0.4: semantic claim typing separates vulnerability reasoning from discovery/attack-surface reasoning.
    htype=normalize_hypothesis_type(ref.get("hypothesis_type"))
    ref["hypothesis_type"]=htype
    ref.setdefault("learned_fact", "No se consolidó un aprendizaje nuevo en esta iteración.")
    ref["evidence_candidate"]=bool(ref.get("evidence_candidate",False))
    ref.setdefault("next_requirement", None)
    assessment=str(ref.get("assessment") or "CONTINUE").upper()
    if assessment not in {"CONTINUE","CONFIRMED","NOT_CONFIRMED","INCONCLUSIVE","NO_FINDING"}: assessment="CONTINUE"
    ref["assessment"]=assessment
    confidence=str(ref.get("confidence") or "MEDIUM").upper()
    if confidence not in {"LOW","MEDIUM","HIGH"}: confidence="MEDIUM"
    ref["confidence"]=confidence
    ref.setdefault("evidence_reason", None)
    ref["command_result_saved"] = bool(ref.get("command_result_saved", False))
    ref["previous_result_used"] = bool(ref.get("previous_result_used", False))
    ref.setdefault("memory_confirmation", "No se confirmó explícitamente el uso de memoria en esta decisión.")
    ref.setdefault("next_attempt_difference", "No se describió una diferencia relevante para el próximo intento.")
    gain = str(ref.get("information_gain") or "NONE").upper()
    if gain not in {"NONE","LOW","MEDIUM","HIGH"}: gain = "NONE"
    ref["information_gain"] = gain
    parsed["reflection"]=ref
    return ref

def validate_reflection(parsed):
    ref=normalize_reflection(parsed)
    for field in ("observation","interpretation","learned_fact","memory_confirmation","next_attempt_difference"):
        if not isinstance(ref.get(field),str) or len(ref.get(field).strip())<8:
            return False,f"reflection.{field} demasiado corto"
    return True,"ok"

def validate_decision_schema(parsed):
    if not isinstance(parsed, dict):
        return False, "La raíz JSON debe ser un objeto"
    if "next_action" in parsed and "next_actions" not in parsed:
        parsed["next_actions"]=[parsed.pop("next_action")]
    parsed.setdefault("analysis_summary", parsed.get("reflection",{}).get("interpretation") if isinstance(parsed.get("reflection"),dict) else "Decisión cognitiva")
    parsed.setdefault("hypotheses", [])
    parsed.setdefault("needed_context", [])
    parsed.setdefault("operator_message", "")
    ok_ref, ref_msg = validate_reflection(parsed)
    if not ok_ref:
        return False, ref_msg
    actions = parsed.get("next_actions")
    if not isinstance(actions, list) or len(actions) != 1:
        return False, "next_actions debe contener exactamente una acción"
    action_obj = actions[0]
    if not isinstance(action_obj, dict):
        return False, "La acción debe ser un objeto JSON"
    action = action_obj.get("action")
    if not isinstance(action, str) or not action:
        return False, "La acción no tiene campo action válido"
    if action not in ALLOWED_ACTIONS:
        return False, f"Acción no permitida por schema: {action}"
    missing = [field for field in ACTION_REQUIRED_FIELDS[action] if field not in action_obj]
    if missing:
        return False, f"next_actions[0] ({action}) requiere campos faltantes: {', '.join(missing)}"
    if action not in {"ask_operator", "stop_on_error"}:
        reason = action_obj.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            return False, "La acción requiere reason técnico no vacío"
    text_blob = json.dumps(parsed, ensure_ascii=False)
    low_blob = text_blob.lower()
    for pat in PLACEHOLDER_PATTERNS:
        if pat.lower() in low_blob:
            return False, f"Placeholder o texto genérico detectado: {pat}"
    if action in {"propose_mcp_command", "propose_command"}:
        command = action_obj.get("command")
        if not isinstance(command, str) or not command.strip():
            return False, "propose_mcp_command requiere command"
        if "approval_required" not in action_obj:
            return False, "propose_mcp_command requiere approval_required"
        if action_obj.get("approval_required") is not True:
            return False, "propose_mcp_command debe usar approval_required=true"
        if "risk_level" not in action_obj:
            return False, "propose_mcp_command requiere risk_level"
        if not isinstance(action_obj.get("risk_level"), int) or not (0 <= action_obj.get("risk_level") <= 5):
            return False, "risk_level debe ser entero entre 0 y 5"
    if action == "run_interior":
        url = action_obj.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return False, "run_interior requiere url absoluta"

    # v2.5.2: cierre coherente en la frontera contractual.
    # Una decisión inconsistente no debe llegar al Executor para ser bloqueada tarde.
    if action == "finalize_analysis":
        assessment = str((parsed.get("reflection") or {}).get("assessment") or "CONTINUE").upper()
        terminal = {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "NO_FINDING"}
        if assessment not in terminal:
            return False, "finalize_analysis requiere reflection.assessment terminal: CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE o NO_FINDING"
        if assessment == "CONFIRMED" and not bool((parsed.get("reflection") or {}).get("evidence_candidate")):
            return False, "finalize_analysis con CONFIRMED requiere reflection.evidence_candidate=true"
        # v3.0.4 invariant: only a vulnerability hypothesis may produce Vulnerability=CONFIRMED.
        # Discovery/attack-surface confirmation is useful evidence for mapping, never a security verdict by itself.
        if assessment == "CONFIRMED":
            htype = str((parsed.get("reflection") or {}).get("hypothesis_type") or "UNCLASSIFIED").upper()
            if not can_confirm_vulnerability(htype):
                return False, f"CONFIRMED de vulnerabilidad requiere reflection.hypothesis_type=VULNERABILITY; recibido {htype}"

    # v2.5.2 DVWA LOW: cuando el modelo envía multipart al recurso Upload,
    # debe usar el artefacto benigno instalado y no inventar shells/rutas locales.
    if action in {"propose_mcp_command", "propose_command"}:
        command_text = str(action_obj.get("command") or "")
        low_command = command_text.lower()
        is_dvwa_upload = "/vulnerabilities/upload/" in low_command
        is_file_submission = any(token in low_command for token in (" -f ", " -f'", ' -f"', "--form", "uploaded=@"))
        if is_dvwa_upload and is_file_submission:
            # v2.6.0: artifact choice is a non-blocking lab policy.
            # Webshell construction remains a hard security restriction.
            if "shell.php" in low_command or "system(" in low_command or "passthru(" in low_command:
                return False, "DVWA Upload prohíbe generar o cargar webshells; usar un artefacto benigno"

    # v2.5.3: proteger sesión y estado global del laboratorio.
    if action in {"propose_mcp_command", "propose_command"}:
        command_text = str(action_obj.get("command") or "")
        low_command = command_text.lower()
        if "cookie:" in low_command or "phpsessid=" in low_command:
            return False, "Existe cookie_jar autenticado: no inventar Cookie ni PHPSESSID; usar -b /tmp/bugtraceai-session/dvwa_cookie.txt"
        mutation_markers = ("security=low", "security=medium", "security=high", "phpids=on", "phpids=off", "clear_log=", "create / reset database", "create_db")
        if any(token in low_command for token in mutation_markers):
            return False, "Acción mutable del laboratorio bloqueada: no cambiar security/PHPIDS, resetear DB ni borrar logs"

    if action == "submit_benign_upload":
        resource = str(action_obj.get("resource") or "")
        if "/vulnerabilities/upload/" not in resource:
            return False, "submit_benign_upload solo es válido para el recurso Upload activo"

    # V1.5.3 CSE: cognitive_updates es memoria genérica generada por el LLM.
    # Se valida forma, no significado.
    ok_updates, updates_msg = validate_cognitive_updates(parsed)
    if not ok_updates:
        return False, updates_msg

    ok_states, states_msg = validate_state_updates(parsed)
    if not ok_states:
        return False, states_msg

    if action == "operator_verdict":
        for field in ["url", "verdict", "evidence", "impact", "recommendation"]:
            if field not in action_obj:
                return False, f"operator_verdict requiere {field}"
        if not isinstance(action_obj.get("evidence"), list) or not action_obj.get("evidence"):
            return False, "operator_verdict requiere evidence no vacío"
    return True, "ok"

def attempt_contract_field_repair(parsed, validation_message):
    """CR1: one bounded LLM repair for missing required action fields only.

    The original action and every already-present field are immutable.  The repair
    may only supply fields that ACTION_REQUIRED_FIELDS says are missing.  The
    normal validator remains authoritative and is run again by the caller.
    """
    if not isinstance(parsed, dict):
        return parsed, False, "not_object"
    actions = parsed.get("next_actions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        return parsed, False, "not_single_action"
    action_obj = actions[0]
    action = action_obj.get("action")
    if not isinstance(action, str) or not action:
        return parsed, False, "invalid_action_type"
    if action not in ACTION_REQUIRED_FIELDS:
        return parsed, False, "unknown_action"
    missing = [f for f in ACTION_REQUIRED_FIELDS[action] if f not in action_obj]
    # CR1 is deliberately narrow: do not repair policy, semantic, type, URL,
    # placeholder, evidence, or any other rejection class.
    if not missing or "campos faltantes" not in str(validation_message):
        return parsed, False, "not_missing_required_field"

    context = {
        "action": action,
        "current_action": action_obj,
        "missing_fields": missing,
        "required_fields": ACTION_REQUIRED_FIELDS[action],
        "contract_example": get_action_example(action),
        "reflection": parsed.get("reflection"),
        "state_updates": parsed.get("state_updates"),
        "analysis_summary": parsed.get("analysis_summary"),
    }
    repair_prompt = (
        "CONTRACT REPAIR CR1. Repara SOLO campos obligatorios ausentes de una decisión ya tomada. "
        "NO reconsideres la acción, NO cambies ningún campo existente, NO cambies recurso, hipótesis, "
        "estado ni intención. Devuelve SOLO un objeto JSON con exactamente los campos faltantes y sus "
        "valores. No incluyas explicaciones. Si falta command, completa el comando coherente con la "
        "intención ya expresada; no inventes una acción distinta.\n\nCONTEXTO:\n"
        + json.dumps(context, ensure_ascii=False)
    )
    debug_event("CONTRACT_REPAIR_ATTEMPT", action=action, missing_fields=missing)
    print(f"[CONTRACT REPAIR] intento 1/1 action={action} missing={','.join(missing)}")
    try:
        rr = call_llm(repair_prompt, 800)
        repair_content = _strip_model_wrappers(rr.get("content", ""))
        repair_candidate = extract_first_json_object(repair_content).strip()
        supplied = json.loads(repair_candidate)
        if not isinstance(supplied, dict):
            raise ValueError("repair response is not an object")
        # Never permit the repair pass to overwrite an existing decision field.
        unexpected = [k for k in supplied if k not in missing]
        if unexpected:
            raise ValueError("repair attempted non-missing fields: " + ", ".join(unexpected))
        still_missing = [k for k in missing if k not in supplied]
        if still_missing:
            raise ValueError("repair omitted fields: " + ", ".join(still_missing))
        for field in missing:
            action_obj[field] = supplied[field]
        debug_event("CONTRACT_REPAIR_MERGED", action=action, repaired_fields=missing)
        llm_event("contract_repair_merged", action=action, repaired_fields=missing)
        print(f"[CONTRACT REPAIR] campos incorporados: {','.join(missing)}; revalidando contrato")
        return parsed, True, "merged"
    except Exception as exc:
        debug_event("CONTRACT_REPAIR_FAILED", action=action, missing_fields=missing, error=str(exc))
        llm_event("contract_repair_failed", action=action, missing_fields=missing, error=str(exc)[:500])
        print(f"[CONTRACT REPAIR] fallo; se conserva SAFE STOP original: {exc}")
        return parsed, True, "failed"

try:
    debug_event("JSON_CANDIDATE", candidate_chars=len(json_candidate), candidate_prefix=json_candidate[:240])
    parse_recovery = "first_try"
    original_parse_error = None
    try:
        parsed = json.loads(json_candidate)
        llm_event("json_valid", recovery="first_try", candidate_chars=len(json_candidate))
    except json.JSONDecodeError as first_parse_error:
        original_parse_error = first_parse_error
        repaired_candidate = _minimal_json_repair(json_candidate)
        if repaired_candidate != json_candidate:
            try:
                parsed = json.loads(repaired_candidate)
                json_candidate = repaired_candidate
                parse_recovery = "deterministic_repair"
                llm_event("json_recovered", error_type="repaired", recovery=parse_recovery, initial_error=str(first_parse_error), candidate_chars=len(json_candidate))
            except json.JSONDecodeError:
                parsed = None
        else:
            parsed = None
        if parsed is None:
            # Reintento compacto y realmente orientado a reparación: incluye la salida defectuosa,
            # no vuelve a enviar todo el prompt operativo ni depende de memoria de conversación.
            retry_prompt = (
                "Repara exclusivamente la sintaxis del siguiente objeto JSON. "
                "No cambies su significado, no agregues explicaciones y devuelve SOLO el objeto JSON completo.\n\n"
                "JSON DEFECTUOSO:\n" + json_candidate[:14000]
            )
            try:
                retry_result = call_llm(retry_prompt, 1800)
            except Exception as retry_transport_error:
                metrics.setdefault("json_recovery", []).append({
                    "mode":"format_retry",
                    "initial_error":str(first_parse_error),
                    "transport_error":str(retry_transport_error)[:1200],
                    "recovered":False,
                })
                METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
                llm_event("json_recovery_transport_failure", initial_error=str(first_parse_error), error=str(retry_transport_error)[:1200], unrecoverable=True)
                failure = safe_decision(
                    "llm_json_recovery_transport_error",
                    "El LLM devolvió JSON inválido y el reintento de reparación no pudo completarse."
                )
                failure["validation_error"] = {
                    "error_type":"json_recovery_transport_error",
                    "initial_parse_error":str(first_parse_error),
                    "retry_transport_error":str(retry_transport_error),
                }
                OUT_FILE.write_text(json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
                print("[SAFE STOP] Falló el transporte durante la reparación JSON.")
                print("[DETAIL]", retry_transport_error)
                sys.exit(0)

            retry_content = _strip_model_wrappers(retry_result.get("content", ""))
            retry_candidate = extract_first_json_object(retry_content).strip()
            metrics.setdefault("json_recovery", []).append({"mode":"format_retry","initial_error":str(first_parse_error),"response_chars":len(retry_content),"recovered":True})
            METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
            RAW_FILE.with_name("last_llm_raw_retry.txt").write_text(retry_content, encoding="utf-8")
            try:
                parsed = json.loads(retry_candidate)
                json_candidate = retry_candidate
                parse_recovery = "format_retry"
                llm_event("json_recovered", error_type="retry_success", recovery=parse_recovery, initial_error=str(first_parse_error), candidate_chars=len(json_candidate))
            except json.JSONDecodeError as retry_parse_error:
                llm_event("json_unrecoverable", error_type="retry_failure", initial_error=str(first_parse_error), retry_error=str(retry_parse_error), candidate_chars=len(retry_candidate))
                raise retry_parse_error from first_parse_error
    debug_event("JSON_PARSED", top_level_keys=sorted(parsed.keys()) if isinstance(parsed,dict) else [], parsed_type=type(parsed).__name__, recovery=parse_recovery)

    # Compatibilidad: algunos modelos devuelven la acción directamente
    if isinstance(parsed, dict) and "action" in parsed and "next_actions" not in parsed:
        parsed = {
            "analysis_summary": parsed.get("verdict", ""),
            "reflection": {"observation":"La respuesta directa no incluyó reflexión estructurada.","interpretation":parsed.get("reason", "Acción propuesta sin reflexión previa."),"hypothesis_effect":"NOT_EVALUATED","learned_fact":"Se convirtió una respuesta legacy al contrato cognitivo.","evidence_candidate":False,"next_requirement":"Continuar con contrato estructurado."},
            "hypotheses": [],
            "needed_context": parsed.get("needed_to_continue", []),
            "cognitive_updates": {"facts": [], "hypotheses": [], "evidence": [], "pending": [], "verdicts": []},
            "state_updates": [],
            "next_actions": [parsed],
            "operator_message": parsed.get("reason", "")
        }

    # ---------- v2.6.0: deterministic contract repair before hard validation ----------
    contract_autofixes = repair_contract(parsed)
    # ---------- NUEVO V1.3 ----------
    valid_schema, schema_msg = validate_decision_schema(parsed)
    if not valid_schema:
        parsed, repair_attempted, repair_status = attempt_contract_field_repair(parsed, schema_msg)
        if repair_attempted and repair_status == "merged":
            valid_schema, repaired_schema_msg = validate_decision_schema(parsed)
            if valid_schema:
                metrics.setdefault("contract_repair", []).append({"attempted":True,"status":"accepted_after_repair","initial_error":schema_msg})
                METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
                debug_event("CONTRACT_REPAIR_ACCEPTED", initial_reason=schema_msg)
                llm_event("contract_repair_accepted", initial_reason=schema_msg)
                print("[CONTRACT REPAIR] ACCEPTED por el contrato normal")
            else:
                metrics.setdefault("contract_repair", []).append({"attempted":True,"status":"rejected_after_repair","initial_error":schema_msg,"final_error":repaired_schema_msg})
                METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
                schema_msg = repaired_schema_msg
        elif repair_attempted:
            metrics.setdefault("contract_repair", []).append({"attempted":True,"status":"repair_failed","initial_error":schema_msg})
            METRICS_FILE.write_text(json.dumps(metrics,indent=2,ensure_ascii=False),encoding="utf-8")
        if not valid_schema:
            debug_event("CONTRACT_REJECTED", reason=schema_msg, top_level_keys=sorted(parsed.keys()) if isinstance(parsed,dict) else [])
            raise ValueError(schema_msg)

    parsed.setdefault("decision_id", str(uuid.uuid4()))
    parsed.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    parsed["contract_autofixes"] = contract_autofixes
    parsed["lab_policy_warnings"] = evaluate_lab_policies(parsed)
    normalize_cognitive_updates(parsed)
    normalize_state_updates(parsed)
    parsed.setdefault("new_knowledge", [])  # compatibilidad legacy
    parsed.setdefault("version", VERSION)
    parsed.setdefault("llm_valid_json", True)
    # -------------------------------


except json.JSONDecodeError as e:
    diagnostic = {
        "error_type": "json_parse_error",
        "message": str(e),
        "line": e.lineno,
        "column": e.colno,
        "position": e.pos,
        "response_chars": len(content),
        "raw_response": content,
    }
    BAD_FILE.write_text(json.dumps(diagnostic, indent=2, ensure_ascii=False), encoding="utf-8")
    failure = safe_decision("llm_json_parse_error", "El LLM devolvió una respuesta que no pudo interpretarse como JSON.")
    failure["validation_error"] = diagnostic
    llm_event("json_parse_rejected", error_type=classify_llm_error(e, phase="json"), message=str(e), line=e.lineno, column=e.colno, unrecoverable=True)
    runtime_event("JSON_PARSE_REJECTED", stage="contract", status="rejected", reason_code="json_parse_error", message=str(e), flags={"json_syntax_valid":False,"executor_reached":False,"mcp_reached":False}, data=diagnostic)
    OUT_FILE.write_text(json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
    print("[SAFE STOP] JSON sintácticamente inválido.")
    print(f"[DETAIL] línea={e.lineno} columna={e.colno}: {e.msg}")
    print("Revisar diagnóstico en:", BAD_FILE)
    sys.exit(0)

except ValueError as e:
    active_resource = ((parsed.get("state_updates") or [{}])[0].get("resource") if isinstance(parsed, dict) and (parsed.get("state_updates") or []) and isinstance((parsed.get("state_updates") or [{}])[0], dict) else None)
    try:
        rejection = record_rejection(
            reason=str(e),
            raw_response=content,
            parsed_response=parsed if isinstance(parsed, dict) else None,
            candidate=json_candidate,
            metrics=metrics,
            active_resource=active_resource,
        )
    except Exception as diagnostics_error:
        # La observabilidad jamás debe derribar el Reasoner.
        rejection = {
            "reason_code": "diagnostics_failure",
            "rejection_id": None,
            "flags": {"json_syntax_valid": isinstance(parsed, dict), "contract_valid": False, "executor_reached": False, "mcp_reached": False},
            "proposed_action": "unknown",
            "active_resource": active_resource,
            "parsed_response": parsed if isinstance(parsed, dict) else None,
        }
        debug_event("DIAGNOSTICS_FAILURE", error=str(diagnostics_error), original_contract_error=str(e))
        llm_event("diagnostics_failure", error=str(diagnostics_error), original_contract_error=str(e))
    diagnostic = {
        "error_type": "contract_validation_error",
        "message": str(e),
        "reason_code": rejection.get("reason_code"),
        "rejection_id": rejection.get("rejection_id"),
        "flags": rejection.get("flags"),
        "response_chars": len(content),
        "parsed_response": parsed if isinstance(parsed, dict) else None,
        "raw_response": content,
    }
    BAD_FILE.write_text(json.dumps(diagnostic, indent=2, ensure_ascii=False), encoding="utf-8")
    failure = safe_decision("llm_contract_validation_error", "El LLM devolvió JSON válido, pero no cumple el contrato operativo.")
    failure["validation_error"] = diagnostic
    llm_event("contract_rejected", error_type=classify_llm_error(e, phase="schema"), reason=str(e), reason_code=rejection.get("reason_code"), action=rejection.get("proposed_action"))
    runtime_event("CONTRACT_REJECTED", stage="contract", status="rejected", rejection_id=rejection.get("rejection_id"), resource=rejection.get("active_resource"), action=rejection.get("proposed_action"), reason_code=rejection.get("reason_code"), message=str(e), flags=rejection.get("flags"), data={"parsed_response":rejection.get("parsed_response")})
    OUT_FILE.write_text(json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
    print("[SAFE STOP] JSON válido, contrato operativo inválido.")
    print("[DETAIL]", str(e))
    print("Revisar diagnóstico en:", BAD_FILE)
    sys.exit(0)


OUT_FILE.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")

# v3.0.1a: telemetría de razonamiento, solo observabilidad.
try:
    trace_path = Path("logs/v3/reasoning_trace.jsonl")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    action_obj = (parsed.get("next_actions") or [{}])[0]
    reflection_obj = parsed.get("reflection") or {}
    trace = {
        "timestamp": parsed.get("timestamp"),
        "decision_id": parsed.get("decision_id"),
        "version": parsed.get("version", VERSION),
        "resource": ((parsed.get("state_updates") or [{}])[0].get("resource") if (parsed.get("state_updates") or []) else None),
        "observation": reflection_obj.get("observation"),
        "interpretation": reflection_obj.get("interpretation"),
        "hypothesis_effect": reflection_obj.get("hypothesis_effect"),
        "learned_fact": reflection_obj.get("learned_fact"),
        "next_requirement": reflection_obj.get("next_requirement"),
        "assessment": reflection_obj.get("assessment"),
        "command_result_saved": reflection_obj.get("command_result_saved"),
        "previous_result_used": reflection_obj.get("previous_result_used"),
        "memory_confirmation": reflection_obj.get("memory_confirmation"),
        "next_attempt_difference": reflection_obj.get("next_attempt_difference"),
        "information_gain": reflection_obj.get("information_gain"),
        "next_action": action_obj.get("action"),
        "next_reason": action_obj.get("reason"),
        "command": action_obj.get("command"),
    }
    with trace_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(trace, ensure_ascii=False) + "\n")
except Exception as trace_error:
    debug_event("REASONING_TRACE_ERROR", error=str(trace_error))

# v3.0.1c: evidencia observable de continuidad entre intentos.
try:
    learning_path = Path("logs/v3/learning_trace.jsonl")
    learning_path.parent.mkdir(parents=True, exist_ok=True)
    action_obj = (parsed.get("next_actions") or [{}])[0]
    reflection_obj = parsed.get("reflection") or {}
    record = {
        "timestamp": parsed.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "decision_id": parsed.get("decision_id"),
        "version": VERSION,
        "resource": ((parsed.get("state_updates") or [{}])[0].get("resource") if (parsed.get("state_updates") or []) else None),
        "command_result_saved": bool(reflection_obj.get("command_result_saved")),
        "previous_result_used": bool(reflection_obj.get("previous_result_used")),
        "memory_confirmation": reflection_obj.get("memory_confirmation"),
        "learned_fact": reflection_obj.get("learned_fact"),
        "information_gain": reflection_obj.get("information_gain"),
        "hypothesis_effect": reflection_obj.get("hypothesis_effect"),
        "next_attempt_difference": reflection_obj.get("next_attempt_difference"),
        "next_action": action_obj.get("action"),
        "next_command": action_obj.get("command"),
    }
    with learning_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
except Exception as learning_error:
    debug_event("LEARNING_TRACE_ERROR", error=str(learning_error))

_cu = parsed.get("cognitive_updates") or {}
_ref = parsed.get("reflection") or {}
_hyp_effect = str(_ref.get("hypothesis_effect") or "NOT_EVALUATED").upper()
llm_event(
    "decision_accepted",
    decision_id=parsed.get("decision_id"),
    action=(parsed.get("next_actions") or [{}])[0].get("action"),
    recovery=locals().get("parse_recovery", "first_try"),
    contract_autofixes=len(parsed.get("contract_autofixes") or []),
    previous_result_used=bool(_ref.get("previous_result_used")),
    memory_used=bool(_ref.get("previous_result_used")) or bool(str(_ref.get("memory_confirmation") or "").strip()),
    strategy_change=bool(str(_ref.get("next_attempt_difference") or "").strip() and "no se describió" not in str(_ref.get("next_attempt_difference") or "").lower()),
    hypotheses_created=len(_cu.get("hypotheses") or []),
    hypotheses_supported=1 if _hyp_effect == "SUPPORTED" else 0,
    hypotheses_weakened=1 if _hyp_effect == "WEAKENED" else 0,
    hypotheses_discarded=1 if _hyp_effect == "REFUTED" else 0,
    confirmations_with_evidence=1 if str(_ref.get("assessment") or "").upper() == "CONFIRMED" and bool(_ref.get("evidence_candidate")) else 0,
)
debug_event("CONTRACT_ACCEPTED", decision_id=parsed.get("decision_id"), action=(parsed.get("next_actions") or [{}])[0].get("action"), reflection_effect=(parsed.get("reflection") or {}).get("hypothesis_effect"))
record_acceptance(decision_id=parsed.get("decision_id"), action=(parsed.get("next_actions") or [{}])[0].get("action"))
runtime_event("CONTRACT_ACCEPTED", stage="contract", status="accepted", decision_id=parsed.get("decision_id"), action=(parsed.get("next_actions") or [{}])[0].get("action"), resource=((parsed.get("state_updates") or [{}])[0].get("resource") if (parsed.get("state_updates") or []) else None), flags={"json_syntax_valid":True,"contract_valid":True})
log_reaction(parsed, selected_cassette())

print("[DONE] Respuesta LLM guardada en:", OUT_FILE)
print(json.dumps(parsed, indent=2, ensure_ascii=False))
