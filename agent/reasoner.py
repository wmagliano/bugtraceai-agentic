#!/usr/bin/env python3
"""
BugTraceAI-Agent v1.6 Reasoner

Responsabilidad:
- Leer data/knowledge.json
- Construir logs/last_llm_prompt.md con contexto compacto
- Proponer una acción automática Nivel 1 como fallback del reasoner clásico

La decisión final del agente la toma reasoner_llm.py leyendo el prompt generado.
"""
import json
from pathlib import Path
from memory_v15 import build_cognitive_memory
from analysis_queue import ensure_schema as ensure_analysis_schema, active_item
from resource_prompt_builder import build_resource_prompt, prompt_metrics
from decision_contract import render_action_contract
from datetime import datetime, timezone
from prompt_builder import build as build_dynamic_prompt
from cassette_manager import selected_cassette, load_cassette, render_prompt_block, log_injection

ROOT = Path(__file__).resolve().parent
KNOWLEDGE = ROOT / "data" / "knowledge.json"
PROMPT_SYSTEM = ROOT / "prompts" / "pentest_system.md"
PROMPT_TEMPLATE = ROOT / "prompts" / "reasoner_template.md"
LLM_PROMPT_OUT = ROOT / "logs" / "last_llm_prompt.md"

VERSION = "3.0.1f-r4b"

ACTIONS = {
    "run_context_builder": "Construir contexto externo del objetivo",
    "run_login": "Crear/validar sesión DVWA low en Kali vía MCP",
    "run_interior": "Mapear URL actual usando Kali vía MCP y guardar contexto incremental",
    "review_forms": "Revisar formularios detectados y parámetros",
    "ask_operator": "Pedir dato faltante al operador",
    "stop_on_error": "Detener por error o ambigüedad",
    "propose_command": "Alias legacy: comando completo enviado a Kali vía MCP con aprobación del operador",
    "propose_mcp_command": "Proponer comando completo para ejecutar en Kali vía MCP",
    "propose_mcp_tool": "Fase 2: fallback con herramienta MCP predefinida",
    "operator_verdict": "Fase 3: informar veredicto asistido al operador"
}


def load():
    if not KNOWLEDGE.exists():
        return {"error": "No existe data/knowledge.json"}
    k = json.loads(KNOWLEDGE.read_text(encoding="utf-8"))
    return ensure_defaults(k)


def ensure_defaults(k):
    """Evita que un reset o fallo temprano deje el ciclo sin claves base."""
    if not isinstance(k, dict):
        k = {}
    scope = k.setdefault("scope", {})
    scope.setdefault("target_base", "http://192.168.0.200")
    scope.setdefault("target_host", "192.168.0.200")
    scope.setdefault("kali_host", "192.168.0.34")
    scope.setdefault("kali_mcp_base", "http://192.168.0.34:9001")
    k.setdefault("visited_urls", [])
    k.setdefault("completed_urls", [])
    k.setdefault("candidate_urls", [])
    ensure_analysis_schema(k)
    k.setdefault("url_context", {})
    k.setdefault("findings", [])
    k.setdefault("errors", [])
    # V1.5.3 CSE: memoria genérica escrita por el LLM como actualizaciones cognitivas.
    # El runtime no interpreta pentesting; solo conserva objetos {kind, resource, text, confidence}.
    k.setdefault("cognitive_knowledge", [])
    k.setdefault("cognitive_updates_history", [])
    # V1.6 CSE: índice operativo por recurso. El LLM decide transiciones; el runtime solo persiste.
    k.setdefault("resource_state", {})
    k.setdefault("resource_state_history", [])
    k.setdefault("resource_errors", {})
    k.setdefault("operator_checkpoints", [])
    k.setdefault("latest_operator_checkpoint", None)
    k.setdefault("resource_goals", {})
    k.setdefault("active_resource", None)
    return k


def _clip(value, limit):
    if value is None:
        return ""
    value = str(value)
    if len(value) <= limit:
        return value
    return value[-limit:]


def _resource_url(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("resource", "url", "endpoint"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return ""


def _items_for_resource(items, resource, limit=4):
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if item.get("resource") in {resource, "global"}:
            out.append(item)
    return out[-limit:]


def compact_context(k):
    """V1.7.4.4: contexto mínimo centrado en el recurso activo.

    No reenvía políticas, esquemas, memoria histórica completa ni artefactos.
    Conserva solo lo necesario para decidir el próximo paso del recurso activo.
    """
    active = _resource_url(k.get("active_resource"))
    if not active:
        visited = [u for u in (k.get("visited_urls") or []) if isinstance(u, str)]
        active = visited[-1] if visited else str((k.get("scope") or {}).get("target_base") or "")

    ctx_all = k.get("url_context") if isinstance(k.get("url_context"), dict) else {}
    ctx = ctx_all.get(active, {}) if isinstance(ctx_all.get(active, {}), dict) else {}
    resource_states = k.get("resource_state") if isinstance(k.get("resource_state"), dict) else {}
    state_obj = resource_states.get(active, {})
    if isinstance(state_obj, str):
        state_obj = {"state": state_obj}
    elif not isinstance(state_obj, dict):
        state_obj = {}

    completed = set()
    completed_summaries = []
    for item in k.get("completed_urls") or []:
        if isinstance(item, str):
            completed.add(item)
            completed_summaries.append({"resource": item, "status": "COMPLETED"})
        elif isinstance(item, dict):
            url = item.get("url") or item.get("resource")
            if isinstance(url, str):
                completed.add(url)
                completed_summaries.append({
                    "resource": url,
                    "status": item.get("state") or item.get("status") or "COMPLETED",
                    "verdict": _clip(item.get("verdict") or item.get("summary") or "", 240),
                })

    candidates = []
    for ai in k.get("analysis_queue") or []:
        url=ai.get("entry_url") if isinstance(ai,dict) else None
        if isinstance(url, str) and url and url != active and url not in completed and str(ai.get("state","NEW")).upper() not in {"COMPLETED","INCONCLUSIVE","FAILED","SKIPPED"} and url not in candidates:
            candidates.append(url)
    candidates = candidates[:8]

    generic = k.get("cognitive_knowledge") or []
    relevant = {
        "facts": _items_for_resource([x for x in generic if isinstance(x, dict) and x.get("kind") in {"fact", "facts", "note"}], active),
        "hypotheses": _items_for_resource([x for x in generic if isinstance(x, dict) and x.get("kind") in {"hypothesis", "hypotheses"}], active),
        "evidence": _items_for_resource([x for x in generic if isinstance(x, dict) and x.get("kind") == "evidence"], active),
        "pending": _items_for_resource([x for x in generic if isinstance(x, dict) and x.get("kind") == "pending"], active),
        "verdicts": _items_for_resource([x for x in generic if isinstance(x, dict) and x.get("kind") in {"verdict", "verdicts"}], active),
    }

    last_commands = []
    for obs in (k.get("mcp_command_observations") or [])[-3:]:
        if not isinstance(obs, dict):
            continue
        command = str(obs.get("command") or "")
        if active and active not in command and _resource_url(obs) not in {active, ""}:
            continue
        last_commands.append({
            "command": _clip(command, 360),
            "ok": obs.get("ok"),
            "returncode": obs.get("returncode"),
            "stdout_preview": _clip(obs.get("stdout_preview") or obs.get("stdout") or "", 700),
            "stderr_preview": _clip(obs.get("stderr_preview") or obs.get("stderr") or "", 240),
        })

    checkpoint = k.get("latest_operator_checkpoint")
    if isinstance(checkpoint, dict) and _resource_url(checkpoint) not in {"", active}:
        checkpoint = None

    # v3.0.1b: memoria de trabajo breve, efímera y específica del recurso.
    # No decide ni interpreta; solo reinyecta al LLM sus propias reflexiones previas
    # y los resultados técnicos asociados para mantener continuidad entre intentos.
    ai = active_item(k) or {}
    cs = ai.get("cognitive_session") if isinstance(ai, dict) else {}
    if not isinstance(cs, dict):
        cs = {}
    short_cycles = []
    history_depth = 3
    try:
        import os
        history_depth = max(1, min(4, int(os.environ.get("BUGTRACEAI_REASONER_HISTORY_DEPTH", "3"))))
    except Exception:
        history_depth = 3
    for cyc in (cs.get("cycles") or [])[-history_depth:]:
        if not isinstance(cyc, dict):
            continue
        action = cyc.get("action") or {}
        result = cyc.get("result") or {}
        reflection = cyc.get("reflection") or {}
        short_cycles.append({
            "cycle_id": cyc.get("cycle_id"),
            "status": cyc.get("status"),
            "command": _clip(action.get("command") or "", 360),
            "reason": _clip(action.get("reason") or "", 240),
            "execution_status": result.get("execution_status"),
            "returncode": result.get("returncode"),
            "stdout_excerpt": _clip(result.get("stdout_excerpt") or "", 700),
            "stderr_excerpt": _clip(result.get("stderr_excerpt") or "", 240),
            "predicate_result": result.get("predicate_result"),
            "reflection": {
                "observation": _clip(reflection.get("observation") or "", 320),
                "interpretation": _clip(reflection.get("interpretation") or "", 400),
                "learned_fact": _clip(reflection.get("learned_fact") or "", 300),
                "hypothesis_effect": reflection.get("hypothesis_effect"),
                "previous_result_used": reflection.get("previous_result_used"),
                "next_attempt_difference": _clip(reflection.get("next_attempt_difference") or "", 280),
            } if reflection else None,
        })
    working_memory = {
        "status": cs.get("status"),
        "active_hypothesis": cs.get("active_hypothesis"),
        "learned_facts": [str(x)[:320] for x in (cs.get("learned_facts") or [])[-8:]],
        "last_reflection": cs.get("last_reflection"),
        "recent_cycles": short_cycles,
        "instruction": "Usa esta memoria para interpretar el último resultado y evita repetir un experimento equivalente salvo que cambie una condición relevante.",
    }

    return {
        "scope": {
            "target_base": (k.get("scope") or {}).get("target_base"),
            "authenticated": (k.get("session") or {}).get("authenticated"),
            "security_level": (k.get("session") or {}).get("dvwa_security"),
            "cookie_jar": (k.get("session") or {}).get("cookie_jar"),
        },
        "analysis_item": ai,
        "cognitive_working_memory": working_memory,
        "active_resource": {
            "url": active,
            "state": state_obj.get("state") or "NEW",
            "resource_goal": (k.get("resource_goals") or {}).get(active),
            "reference_exploit_count": (k.get("reference_exploit_counters") or {}).get(active, 0),
        },
        "current_observation": {
            "status_line": ctx.get("status_line"),
            "title": ctx.get("title"),
            "observation_quality": ctx.get("observation_quality"),
            "forms": (ctx.get("forms") or [])[:3],
            "query_params": ctx.get("query_params") or {},
            "visible_text_excerpt": _clip(ctx.get("visible_text_excerpt") or "", 700),
            "body_indicators": ctx.get("body_indicators") or {},
        },
        "relevant_memory": relevant,
        "latest_command_observations": last_commands,
        "operator_checkpoint": checkpoint,
        "pending_resources_count": len(candidates),
        "scheduler_managed_navigation": True,
        "recent_runtime_feedback": (k.get("runtime_feedback") or [])[-3:],
        "loop_guard": k.get("loop_guard") or {},
        "completed_summaries": completed_summaries[-8:],
    }


def write_llm_prompt(k):
    """V1.7.4.2: usa los dos archivos normalizados como prompt operativo.

    pentest_system.md contiene identidad, límites y contrato JSON.
    reasoner_template.md contiene únicamente tarea y contexto dinámico.
    """
    LLM_PROMPT_OUT.parent.mkdir(parents=True, exist_ok=True)
    system = PROMPT_SYSTEM.read_text(encoding="utf-8") if PROMPT_SYSTEM.exists() else ""
    template = PROMPT_TEMPLATE.read_text(encoding="utf-8") if PROMPT_TEMPLATE.exists() else "{{KNOWLEDGE_JSON}}"
    context = compact_context(k)
    body = template.replace("{{KNOWLEDGE_JSON}}", json.dumps(context, separators=(",", ":"), ensure_ascii=False))
    body = body.replace("{{ACTIONS_JSON}}", json.dumps(ACTIONS, separators=(",", ":"), ensure_ascii=False))
    body = body.replace("{{ACTION_CONTRACT}}", render_action_contract())
    cassette_id = selected_cassette()
    cassette = load_cassette(cassette_id)
    cassette_block, rag_selection = render_prompt_block(cassette, context)
    active = build_dynamic_prompt(system, context, cassette_block, json.dumps(ACTIONS, ensure_ascii=False), "Respete las restricciones reales del entorno y no trate conocimiento como evidencia.", json.dumps(context.get("operator_checkpoint") or {}, ensure_ascii=False), body)
    LLM_PROMPT_OUT.write_text(active, encoding="utf-8")
    active_url = str((context.get("active_resource") or {}).get("url") or "")
    log_injection(cassette, active_url, active, rag_selection)

    # Conserva el resource-focused anterior solo como referencia A/B.
    focused = build_resource_prompt(k, actions=ACTIONS, version=VERSION)
    (ROOT / "logs" / "last_llm_prompt_resource_focused.md").write_text(focused, encoding="utf-8")
    metrics = {
        "version": VERSION,
        "active_clean": prompt_metrics(active),
        "resource_focused_previous": prompt_metrics(focused),
    }
    (ROOT / "logs" / "last_prompt_metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(LLM_PROMPT_OUT)


def decide(k):
    """Decisión automática conservadora Nivel 1. La decisión inteligente final es del LLM."""
    if k.get("error"):
        return [{"action": "stop_on_error", "reason": k["error"]}]
    if not k.get("tool_validation", {}).get("ready"):
        return [{"action": "stop_on_error", "reason": "herramientas.sh no fue ejecutado o faltan herramientas requeridas"}]
    if not k.get("external_context"):
        return [{"action": "run_context_builder", "reason": "No existe contexto externo confirmado"}]
    if not k.get("session", {}).get("authenticated"):
        return [{"action": "run_login", "reason": "No hay sesión DVWA autenticada"}]
    if not k.get("visited_urls"):
        return [{"action": "run_interior", "url": k.get("scope", {}).get("target_base", "http://192.168.0.200") + "/", "reason": "No hay URLs internas mapeadas"}]

    known_links = {x.get("entry_url") for x in k.get("analysis_queue",[]) if isinstance(x,dict) and x.get("entry_url")}
    for ctx in k.get("url_context", {}).values():
        known_links.update(ctx.get("internal_links", []))
        known_links.update(ctx.get("fallback_candidates", []))

    visited = set(k.get("visited_urls", []))
    completed = set()
    for item in k.get("completed_urls", []):
        completed.add(item.get("url") if isinstance(item, dict) else item)
    candidates = [u for u in sorted(known_links) if u not in visited and u not in completed]
    if candidates:
        return [{"action": "run_interior", "url": candidates[0], "reason": "Nueva URL DVWA de vulnerabilidad detectada y aún no mapeada"}]

    form_urls = [u for u, ctx in k.get("url_context", {}).items() if ctx.get("forms")]
    if form_urls:
        return [{
            "action": "review_forms",
            "urls": form_urls,
            "reason": "No quedan módulos nuevos; hay formularios confirmados para análisis guiado"
        }]

    return [{"action": "ask_operator", "reason": "No hay nuevos enlaces internos ni formularios relevantes. Indicar próxima URL o habilitar Nivel 2."}]


def main():
    k = load()
    prompt_path = write_llm_prompt(k) if not k.get("error") else None
    decisions = decide(k)

    if not k.get("error"):
        k["reasoner"] = {
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "llm_prompt_file": prompt_path,
            "next_actions": decisions
        }
        k["next_actions"] = decisions
        KNOWLEDGE.write_text(json.dumps(k, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "version": VERSION,
        "allowed_actions": ACTIONS,
        "llm_prompt_file": prompt_path,
        "decision": decisions
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
