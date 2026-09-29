#!/usr/bin/env python3
"""Contrato unificado de acciones BugTraceAI v1.7.5.6.

Única fuente de verdad para:
- ejemplos mostrados al LLM,
- campos obligatorios,
- validación runtime,
- pruebas de contrato.
"""
from __future__ import annotations

from copy import deepcopy
from evidence_matcher import validate_expected_evidence

ACTION_SCHEMAS = {
    "run_context_builder": {
        "required": ["action", "reason"],
        "example": {"action": "run_context_builder", "reason": "Construir contexto externo inicial del objetivo autorizado"},
    },
    "run_login": {
        "required": ["action", "reason"],
        "example": {"action": "run_login", "reason": "Crear o validar la sesión requerida por el análisis"},
    },
    "run_interior": {
        "required": ["action", "url", "reason"],
        "example": {"action": "run_interior", "url": "http://objetivo/recurso", "reason": "Mapear la estructura del recurso antes de formular o validar hipótesis"},
    },
    "review_forms": {
        "required": ["action", "reason"],
        "example": {"action": "review_forms", "reason": "Revisar formularios y parámetros ya detectados en el recurso activo"},
    },
    "ask_operator": {
        "required": ["action", "resource", "question"],
        "example": {"action": "ask_operator", "resource": "http://objetivo/recurso", "question": "Vulnerabilidad confirmada. ¿Desea documentar, explotar, enumerar, profundizar o marcar inconclusa?", "context": "Resumen breve de evidencia"},
    },
    "stop_on_error": {
        "required": ["action", "reason"],
        "example": {"action": "stop_on_error", "reason": "No existe contexto suficiente o ocurrió una ambigüedad operativa"},
    },
    "propose_command": {
        "required": ["action", "command", "risk_level", "approval_required", "reason", "expected_evidence"],
        "example": {"action": "propose_command", "command": "COMANDO_COMPLETO", "risk_level": 1, "approval_required": True, "reason": "Validar una hipótesis concreta con evidencia observable", "expected_evidence": {"matcher":"contains", "value":"SEÑAL_ESPERADA", "meaning":"Qué demostraría observar esta señal"}},
    },
    "propose_mcp_command": {
        "required": ["action", "command", "risk_level", "approval_required", "reason", "expected_evidence"],
        "example": {"action": "propose_mcp_command", "command": "COMANDO_COMPLETO", "risk_level": 1, "approval_required": True, "reason": "Validar una hipótesis concreta con evidencia observable", "expected_evidence": {"matcher":"regex", "pattern":"PATRON_OBSERVABLE", "meaning":"Qué demostraría una coincidencia"}},
    },
    "propose_mcp_tool": {
        "required": ["action", "tool", "risk_level", "approval_required", "reason"],
        "example": {"action": "propose_mcp_tool", "tool": "NOMBRE_HERRAMIENTA", "risk_level": 1, "approval_required": True, "reason": "Usar una herramienta disponible para validar la hipótesis activa"},
    },
    "operator_verdict": {
        "required": ["action", "url", "verdict", "evidence", "impact", "recommendation", "reason"],
        "example": {"action": "operator_verdict", "url": "http://objetivo/recurso", "verdict": "Hallazgo confirmado", "evidence": ["Evidencia técnica concreta"], "impact": "Impacto técnico", "recommendation": "Recomendación defensiva", "reason": "La evidencia confirma el hallazgo y el operador decidió documentar"},
    },
    "finalize_analysis": {
        "required": ["action", "reason"],
        "example": {"action": "finalize_analysis", "reason": "La reflexión ya emitió un assessment terminal sustentado por la evidencia del Analysis Item"},
    },
    "submit_benign_upload": {
        "required": ["action", "resource", "reason", "expected_evidence"],
        "example": {"action": "submit_benign_upload", "resource": "http://objetivo/vulnerabilities/upload/", "reason": "Enviar el artefacto benigno preinstalado mediante el formulario identificado", "expected_evidence": {"matcher":"contains", "value":"succesfully uploaded!", "meaning":"La respuesta del mismo POST confirma que el servidor aceptó la carga del archivo benigno"}},
    },
}


ALLOWED_RESOURCE_STATES = {
    "NEW", "UNKNOWN", "MAPPED", "HYPOTHESIS_ACTIVE", "TESTING",
    "EVIDENCE_COLLECTED", "CONFIRMED", "WAITING_OPERATOR",
    "EXPLOITING", "EXPLOITABLE", "DOCUMENTED", "COMPLETED", "DONE", "INCONCLUSIVE",
}

ACTION_REQUIRED_FIELDS = {name: list(spec["required"]) for name, spec in ACTION_SCHEMAS.items()}
ALLOWED_ACTIONS = set(ACTION_SCHEMAS)


def get_action_example(action: str) -> dict:
    return deepcopy(ACTION_SCHEMAS[action]["example"])


def render_action_contract() -> str:
    lines = [
        "CONTRATO UNIFICADO DE ACCIONES",
        "Elige exactamente UNA de las siguientes formas para next_actions[0].",
        "Copia todos los campos requeridos de la forma elegida y reemplaza sus valores.",
    ]
    for action, spec in ACTION_SCHEMAS.items():
        import json
        lines.append(f"- {action}: {json.dumps(spec['example'], ensure_ascii=False, separators=(',', ':'))}")
    lines += [
        "REGLAS DEL CONTRATO:",
        "- run_interior.url debe ser una URL absoluta http:// o https://.",
        "- propose_command y propose_mcp_command deben usar approval_required=true y risk_level entero entre 0 y 5.",
        "- operator_verdict.evidence debe ser una lista no vacía.",
        "- No inventes resource_goal durante NEW, MAPPED, HYPOTHESIS_ACTIVE, TESTING ni EVIDENCE_COLLECTED.",
        "- resource_goal solo puede aparecer tras una decisión del operador o en WAITING_OPERATOR/EXPLOITING.",
    ]
    return "\n".join(lines)
