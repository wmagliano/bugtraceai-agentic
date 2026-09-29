#!/usr/bin/env python3
"""
BugTraceAI-CORE v1.7 - Operator Guided Cognitive Pentest

Responsabilidad:
- Convertir knowledge.json cronológico en memoria útil para razonar.
- No decidir estrategia de pentesting.
- No interpretar vulnerabilidades.
- No generar payloads.
- Solo consolidar observaciones, actualizaciones cognitivas y estado operativo escrito por el LLM.
"""
from urllib.parse import urlparse


ALLOWED_RESOURCE_STATES = {
    "UNKNOWN",
    "MAPPED",
    "HYPOTHESIS_ACTIVE",
    "TESTING",
    "EVIDENCE_COLLECTED",
    "CONFIRMED",
    "WAITING_OPERATOR",
    "EXPLOITING",
    "DOCUMENTED",
    "COMPLETED",
    "DONE",
    "INCONCLUSIVE",
}


def build_resource_state(k):
    """Índice operativo por recurso.

    No interpreta vulnerabilidades ni decide transiciones. Solo expone el
    estado que el LLM pidió persistir mediante state_updates.
    """
    out = {}
    raw = k.get("resource_state") or {}
    if not isinstance(raw, dict):
        return out
    for resource, state_obj in raw.items():
        if not resource:
            continue
        if isinstance(state_obj, str):
            state_obj = {"state": state_obj}
        if not isinstance(state_obj, dict):
            continue
        state = str(state_obj.get("state") or "UNKNOWN").upper().strip()
        if state not in ALLOWED_RESOURCE_STATES:
            state = "UNKNOWN"
        out[str(resource)] = {
            "state": state,
            "resource_goal": state_obj.get("resource_goal") or (k.get("resource_goals", {}) or {}).get(str(resource)),
            "updated_at": state_obj.get("updated_at"),
            "updated_by": state_obj.get("updated_by", "llm"),
            "decision_id": state_obj.get("decision_id"),
            "reason": _clip(state_obj.get("reason"), 300),
        }
    return out


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clip(value, limit=500):
    if value is None:
        return None
    value = str(value)
    if len(value) <= limit:
        return value
    return value[:limit] + "...[clipped]"


def _form_summary(forms):
    out = []
    for form in _as_list(forms):
        if not isinstance(form, dict):
            continue
        inputs = []
        for inp in _as_list(form.get("inputs")):
            if isinstance(inp, dict):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                    "value_present": bool(inp.get("value")),
                })
            elif inp:
                inputs.append({"name": str(inp), "type": None})
        out.append({
            "method": form.get("method"),
            "action": form.get("action"),
            "inputs": inputs,
        })
    return out


def _resource_key(url):
    try:
        p = urlparse(url)
        key = p.path or "/"
        if p.query:
            # La query forma parte del recurso observado, pero queda separada.
            key += "?" + p.query
        return key
    except Exception:
        return url


def build_semantic_memory(k):
    """Hechos consolidados por recurso observado."""
    resources = {}
    for url, ctx in (k.get("url_context") or {}).items():
        if not isinstance(ctx, dict):
            continue
        parsed = urlparse(url)
        forms = _form_summary(ctx.get("forms", []))
        query_params = ctx.get("query_params") or {}
        resources[url] = {
            "resource": _resource_key(url),
            "path": parsed.path or "/",
            "has_query": bool(parsed.query),
            "query_params": query_params,
            "status_line": ctx.get("status_line"),
            "title": ctx.get("title"),
            "observation_quality": ctx.get("observation_quality"),
            "forms_count": len(forms),
            "forms": forms,
            "internal_links_count": len(ctx.get("internal_links") or []),
            "body_indicators": ctx.get("body_indicators") or {},
            "artifacts": ctx.get("raw_artifacts") or {},
        }
    return {
        "resources": resources,
        "findings": k.get("findings", []),
    }


def _completed_set(k):
    completed = set()
    for item in k.get("completed_urls", []):
        if isinstance(item, dict) and item.get("url"):
            completed.add(item["url"])
        elif isinstance(item, str):
            completed.add(item)
    return completed


def build_active_memory(k, max_candidates=20):
    """Estado pequeño para decidir el próximo paso."""
    visited = list(k.get("visited_urls", []))
    completed = _completed_set(k)
    candidates = []
    seen = set()
    for url in k.get("candidate_urls", []):
        if not url or url in seen or url in visited or url in completed:
            continue
        seen.add(url)
        candidates.append(url)
        if len(candidates) >= max_candidates:
            break

    blocked = k.get("blocked_actions", [])[-5:]
    errors = k.get("errors", [])[-5:]
    resource_errors = k.get("resource_errors", {})

    current_url = visited[-1] if visited else None
    current_ctx = (k.get("url_context") or {}).get(current_url, {}) if current_url else {}

    waiting_operator = []
    goals = k.get("resource_goals", {}) if isinstance(k.get("resource_goals"), dict) else {}
    for res, st in (k.get("resource_state") or {}).items():
        if isinstance(st, dict) and st.get("state") == "WAITING_OPERATOR":
            waiting_operator.append({
                "resource": res,
                "resource_goal": goals.get(res) or st.get("resource_goal"),
                "reason": st.get("reason"),
            })

    return {
        "goal": "Elegir la próxima acción útil sin repetir trabajo y dentro del alcance autorizado.",
        "session": k.get("session", {}),
        "progress": {
            "visited_count": len(visited),
            "candidate_count": len(candidates),
            "completed_count": len(completed),
            "findings_count": len(k.get("findings", [])),
        },
        "current_resource": {
            "url": current_url,
            "title": current_ctx.get("title"),
            "observation_quality": current_ctx.get("observation_quality"),
            "forms_count": len(current_ctx.get("forms") or []),
            "query_params": current_ctx.get("query_params") or {},
        },
        "pending_candidate_urls": candidates,
        "recent_blocked_actions": blocked,
        "recent_errors": errors,
        "resource_errors": resource_errors,
        "resource_goals": goals,
        "waiting_operator_resources": waiting_operator,
        "active_resource": k.get("active_resource"),
        "latest_operator_checkpoint": k.get("latest_operator_checkpoint"),
        "operator_checkpoints_recent": (k.get("operator_checkpoints") or [])[-5:],
    }


def build_historical_memory(k):
    """Resumen de auditoría, no historial completo."""
    return {
        "visited_urls": k.get("visited_urls", []),
        "completed_urls": k.get("completed_urls", []),
        "last_interior_observations": k.get("mcp_interior_observations", [])[-5:],
        "last_command_observations": k.get("mcp_command_observations", [])[-3:],
    }


def build_generic_knowledge(k, max_items=80):
    """Camino B: objetos genéricos escritos por el LLM.

    El runtime no interpreta SQLi/XSS/API/etc. Solo agrupa y recorta
    memoria para que el LLM no tenga que reconstruirla desde logs.
    """
    items = []
    for item in _as_list(k.get("cognitive_knowledge")):
        if not isinstance(item, dict):
            continue
        kind = item.get("kind") or "note"
        resource = item.get("resource") or "global"
        text = item.get("text")
        if not text:
            continue
        obj = {
            "timestamp": item.get("timestamp"),
            "source": item.get("source", "llm"),
            "decision_id": item.get("decision_id"),
            "kind": str(kind),
            "resource": str(resource),
            "text": _clip(text, 700),
            "confidence": item.get("confidence", "medium"),
        }
        if item.get("status"):
            obj["status"] = item.get("status")
        items.append(obj)
    return items[-max_items:]


def build_knowledge_index(k, max_per_resource=12):
    """Índice liviano por recurso. No interpreta contenido, solo agrupa."""
    index = {}
    for item in build_generic_knowledge(k, max_items=200):
        res = item.get("resource") or "global"
        bucket = index.setdefault(res, [])
        bucket.append({
            "kind": item.get("kind"),
            "text": item.get("text"),
            "confidence": item.get("confidence"),
        })
    for res in list(index):
        index[res] = index[res][-max_per_resource:]
    return index


def build_cognitive_state(k, max_items=80):
    """Estado cognitivo agrupado. No interpreta contenido, solo separa por kind."""
    state = {
        "facts": [],
        "hypotheses": [],
        "evidence": [],
        "pending": [],
        "verdicts": [],
        "notes": [],
    }
    kind_to_section = {
        "fact": "facts",
        "hypothesis": "hypotheses",
        "evidence": "evidence",
        "pending": "pending",
        "verdict": "verdicts",
        "note": "notes",
    }
    for item in build_generic_knowledge(k, max_items=max_items):
        section = kind_to_section.get(item.get("kind"), "notes")
        state[section].append(item)
    return state


def build_cognitive_memory(k):
    return {
        "memory_version": "1.7-operator-guided-cognitive-pentest",
        "resource_state": build_resource_state(k),
        "active_memory": build_active_memory(k),
        "cognitive_state": build_cognitive_state(k),
        "generic_knowledge": build_generic_knowledge(k),
        "knowledge_index_by_resource": build_knowledge_index(k),
        "semantic_memory": build_semantic_memory(k),
        "historical_memory_summary": build_historical_memory(k),
    }
