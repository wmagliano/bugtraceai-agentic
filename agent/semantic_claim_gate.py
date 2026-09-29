#!/usr/bin/env python3
"""BugTraceAI v3.0.4 — semantic claim authority.

This module is intentionally pure: it has no LLM/MCP/runtime side effects and can be
unit-tested independently. It prevents discovery/attack-surface claims from being
promoted into a confirmed vulnerability.
"""
from __future__ import annotations

ALLOWED_HYPOTHESIS_TYPES = {
    "VULNERABILITY",
    "DISCOVERY",
    "ATTACK_SURFACE",
    "INFORMATIONAL",
    "UNCLASSIFIED",
}


def normalize_hypothesis_type(value) -> str:
    t = str(value or "UNCLASSIFIED").upper().strip()
    return t if t in ALLOWED_HYPOTHESIS_TYPES else "UNCLASSIFIED"


def can_confirm_vulnerability(hypothesis_type) -> bool:
    """Only a concrete vulnerability claim may produce Vulnerability=CONFIRMED."""
    return normalize_hypothesis_type(hypothesis_type) == "VULNERABILITY"


def semantic_claim_role(hypothesis_type) -> str:
    t = normalize_hypothesis_type(hypothesis_type)
    if t == "VULNERABILITY":
        return "SECURITY_VERDICT_ELIGIBLE"
    if t in {"DISCOVERY", "ATTACK_SURFACE"}:
        return "MAPPING_ONLY"
    return "NON_VULNERABILITY_CLAIM"
