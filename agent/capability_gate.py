#!/usr/bin/env python3
"""BugTraceAI v3.0.3h architecture capability gate.

Authoritative runtime policy.  Architectural capability is NOT decided by the LLM.
The model may reason about the vulnerability, but the runtime independently decides
whether BugTraceAI can autonomously validate the relevant observation domain.

The core is generic: profiles describe observation domains and available instruments.
A deployment adapter may map resources to profiles. Unknown resources fail closed to
REQUIRES_OPERATOR_VALIDATION rather than being silently treated as FULL/SUPPORTED.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlsplit
import re

ARCHITECTURE_CAPABILITIES = {
    "http_requests": True,
    "cli_tools": True,
    "shell_runtime": True,
    "static_source_analysis": True,
    "javascript_source_analysis": True,
    "instrumented_browser": False,
    "dom_runtime_observation": False,
    "browser_javascript_execution_observation": False,
    "browser_csp_enforcement_observation": False,
    "out_of_band_callback": False,
    "manual_gui_interaction": False,
}

VALIDATION_STATUSES = {"SUPPORTED", "REQUIRES_OPERATOR_VALIDATION", "UNSUPPORTED"}

# Observation-domain profiles. These are architectural facts, not LLM opinions.
VALIDATION_PROFILES = {
    "SERVER_HTTP": {
        "required_capabilities": ["http_requests", "cli_tools"],
        "reason": "La condición puede validarse mediante observaciones HTTP/CLI disponibles en BugTraceAI.",
    },
    "SERVER_SIDE_EFFECT": {
        "required_capabilities": ["http_requests", "cli_tools", "shell_runtime"],
        "reason": "La condición puede validarse mediante efectos server-side observables por la arquitectura.",
    },
    "STATIC_CLIENT_FLOW": {
        "required_capabilities": ["http_requests", "javascript_source_analysis"],
        "reason": "BugTraceAI puede demostrar flujo estructural cliente, pero no observar por sí solo el runtime del navegador.",
        "final_runtime_capabilities": ["instrumented_browser", "dom_runtime_observation", "browser_javascript_execution_observation"],
    },
    "BROWSER_CSP": {
        "required_capabilities": ["http_requests", "javascript_source_analysis"],
        "reason": "BugTraceAI puede inspeccionar política y flujo, pero no observar enforcement/ejecución CSP en un navegador instrumentado.",
        "final_runtime_capabilities": ["instrumented_browser", "browser_csp_enforcement_observation", "browser_javascript_execution_observation"],
    },
    "BROWSER_JAVASCRIPT": {
        "required_capabilities": ["http_requests", "javascript_source_analysis"],
        "reason": "La validación final depende de ejecución JavaScript/DOM que la arquitectura actual no observa directamente.",
        "final_runtime_capabilities": ["instrumented_browser", "browser_javascript_execution_observation"],
    },
}

# Deployment policy for the DVWA experimental corpus.  It classifies the observation
# domain only; it does not encode payloads, exploit logic, verdicts or success criteria.
# Unknown resources are intentionally REVIEW_REQUIRED (fail closed).
RESOURCE_PROFILE_RULES = [
    (r"/vulnerabilities/csp(?:/|$)", "BROWSER_CSP"),
    (r"/vulnerabilities/xss_d(?:/|$)", "STATIC_CLIENT_FLOW"),
    (r"/vulnerabilities/xss_r(?:/|$)", "STATIC_CLIENT_FLOW"),
    (r"/vulnerabilities/xss_s(?:/|$)", "STATIC_CLIENT_FLOW"),
    (r"/vulnerabilities/javascript(?:/|$)", "BROWSER_JAVASCRIPT"),
    (r"/vulnerabilities/(?:exec|csrf|fi|upload|sqli|sqli_blind|brute)(?:/|$)", "SERVER_SIDE_EFFECT"),
    (r"/(?:phpinfo\.php|instructions\.php|about\.php)(?:$|\?)", "SERVER_HTTP"),
]


def _resource_path(resource: str | None) -> str:
    try:
        p = urlsplit(str(resource or ""))
        return p.path + (("?" + p.query) if p.query else "")
    except Exception:
        return str(resource or "")


def classify_validation_profile(resource: str | None) -> tuple[str | None, str]:
    path = _resource_path(resource)
    for pattern, profile in RESOURCE_PROFILE_RULES:
        if re.search(pattern, path, flags=re.I):
            return profile, f"architecture_policy:{pattern}"
    return None, "architecture_policy:unclassified"


def evaluate_architecture_validation(resource: str | None, profile: str | None = None) -> dict[str, Any]:
    """Return authoritative architectural validation state for a resource/profile.

    The LLM is deliberately not an input. Missing/unknown classification fails closed.
    """
    policy_source = "explicit_profile"
    if not profile:
        profile, policy_source = classify_validation_profile(resource)
    if not profile or profile not in VALIDATION_PROFILES:
        return {
            "status": "REQUIRES_OPERATOR_VALIDATION",
            "support": "REVIEW_REQUIRED",
            "validation_profile": profile or "UNCLASSIFIED",
            "required_capabilities": [],
            "unavailable_capabilities": [],
            "specialized_validation": True,
            "reason": "El runtime no pudo demostrar que la arquitectura soporte autónomamente el dominio de validación requerido; se aplica cierre conservador.",
            "recommended_validation": "Revisión del operador para clasificar el dominio de validación o usar instrumental especializado.",
            "policy_source": policy_source,
            "authority": "ARCHITECTURE_RUNTIME",
        }

    cfg = VALIDATION_PROFILES[profile]
    base_required = list(cfg.get("required_capabilities") or [])
    final_required = list(cfg.get("final_runtime_capabilities") or [])
    unavailable_base = [c for c in base_required if not ARCHITECTURE_CAPABILITIES.get(c, False)]
    unavailable_final = [c for c in final_required if not ARCHITECTURE_CAPABILITIES.get(c, False)]

    if unavailable_base:
        status = "UNSUPPORTED"
    elif unavailable_final:
        status = "REQUIRES_OPERATOR_VALIDATION"
    else:
        status = "SUPPORTED"

    return {
        "status": status,
        "support": status,
        "validation_profile": profile,
        "required_capabilities": base_required + final_required,
        "unavailable_capabilities": unavailable_base + unavailable_final,
        "specialized_validation": status != "SUPPORTED",
        "reason": cfg.get("reason"),
        "recommended_validation": (
            "Validar el efecto final con instrumental especializado o por el operador."
            if status == "REQUIRES_OPERATOR_VALIDATION" else None
        ),
        "policy_source": policy_source,
        "authority": "ARCHITECTURE_RUNTIME",
    }


def normalize_capability_assessment(raw: Any = None, *, resource: str | None = None) -> dict[str, Any]:
    """Compatibility shim: v3.0.3h ignores LLM capability declarations."""
    return evaluate_architecture_validation(resource)


def gate_exploitation_status(vulnerability_status: str, requested_status: str, capability: dict[str, Any]) -> tuple[str, str | None]:
    vuln = str(vulnerability_status or "UNASSESSED").upper()
    status = str(requested_status or "NOT_CONFIRMED").upper()
    if vuln != "CONFIRMED":
        return "NOT_APPLICABLE", "exploitation_requires_confirmed_vulnerability"
    arch_status = str((capability or {}).get("status") or (capability or {}).get("support") or "REQUIRES_OPERATOR_VALIDATION").upper()
    if arch_status in {"REQUIRES_OPERATOR_VALIDATION", "UNSUPPORTED", "REVIEW_REQUIRED", "UNASSESSED"} and status == "CONFIRMED":
        return "NOT_TESTABLE", "architectural_runtime_validation_unavailable"
    return status, None


# v3.0.3i-ajuste — vulnerability-first hierarchy
# Vulnerability verdict is authoritative over downstream architectural/exploitation states.
def apply_vulnerability_first_hierarchy(vulnerability_status, capability_assessment=None):
    """
    Runtime invariant:
      NO_FINDING   -> architectural validation NOT_REQUIRED; exploitation NOT_APPLICABLE.
      CONFIRMED    -> evaluate/retain authoritative architecture gate.
      INCONCLUSIVE -> architecture gate may terminate as REQUIRES_OPERATOR_VALIDATION,
                      otherwise analysis may continue according to queue policy.
    This function does not allow the LLM to elevate architecture capabilities.
    """
    status = str(vulnerability_status or "").strip().upper()
    cap = dict(capability_assessment or {})

    if status == "NO_FINDING":
        return {
            "support": "NOT_REQUIRED",
            "required_capabilities": [],
            "unavailable_capabilities": [],
            "specialized_validation": False,
            "runtime_effect_observed": bool(cap.get("runtime_effect_observed", False)),
            "reason": "No vulnerability finding: architectural validation is not required.",
            "recommended_validation": None,
            "authority": "runtime_vulnerability_first_hierarchy",
        }

    # For CONFIRMED/INCONCLUSIVE the architecture-owned result is preserved.
    # Unknown/missing capability never becomes FULL/SUPPORTED here.
    if not cap:
        return {
            "support": "REQUIRES_OPERATOR_VALIDATION",
            "required_capabilities": [],
            "unavailable_capabilities": [],
            "specialized_validation": True,
            "runtime_effect_observed": False,
            "reason": "Architecture capability could not be established conservatively.",
            "recommended_validation": "Operator validation required.",
            "authority": "runtime_vulnerability_first_hierarchy",
        }
    return cap


def derive_phase1_exploitation_status(vulnerability_status):
    """Phase 1 invariant for v3.0.3i: exploitation remains disabled."""
    status = str(vulnerability_status or "").strip().upper()
    if status == "NO_FINDING":
        return "NOT_APPLICABLE"
    return "NOT_ATTEMPTED"


def should_terminalize_for_architecture(vulnerability_status, capability_assessment):
    """
    NO_FINDING is always terminal.
    CONFIRMED is terminal after architecture classification.
    INCONCLUSIVE becomes terminal when the architecture boundary requires operator validation.
    """
    status = str(vulnerability_status or "").strip().upper()
    support = str((capability_assessment or {}).get("support") or "").strip().upper()
    if status == "NO_FINDING":
        return True
    if status == "CONFIRMED":
        return True
    if status == "INCONCLUSIVE" and support == "REQUIRES_OPERATOR_VALIDATION":
        return True
    return False
