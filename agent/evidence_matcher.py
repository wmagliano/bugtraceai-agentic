#!/usr/bin/env python3
"""Neutral evidence predicate evaluator for BugTraceAI v2.4.1.

The LLM defines the observable predicate. This module only validates and
mechanically evaluates it against the captured MCP result.
"""
from __future__ import annotations

import re
from typing import Any

ALLOWED_MATCHERS = {"contains", "not_contains", "regex", "returncode"}
MAX_PATTERN_LENGTH = 512
MAX_OUTPUT_SCAN = 2_000_000
MAX_EXCERPT = 320


def validate_expected_evidence(spec: Any) -> tuple[bool, str]:
    if not isinstance(spec, dict):
        return False, "expected_evidence debe ser un objeto"
    matcher = str(spec.get("matcher") or "").strip().lower()
    if matcher not in ALLOWED_MATCHERS:
        return False, f"matcher no permitido: {matcher or '<vacío>'}"
    meaning = spec.get("meaning")
    if not isinstance(meaning, str) or len(meaning.strip()) < 8:
        return False, "expected_evidence.meaning debe explicar el significado técnico"
    if matcher == "returncode":
        if not isinstance(spec.get("value"), int):
            return False, "returncode requiere value entero"
        return True, "ok"
    key = "pattern" if matcher == "regex" else "value"
    value = spec.get(key)
    if not isinstance(value, str) or not value:
        return False, f"{matcher} requiere {key} no vacío"
    if len(value) > MAX_PATTERN_LENGTH:
        return False, f"{key} excede {MAX_PATTERN_LENGTH} caracteres"
    if matcher == "regex":
        # Defensa simple contra patrones propensos a backtracking catastrófico.
        if re.search(r"\([^)]*[+*][^)]*\)[+*]", value):
            return False, "regex potencialmente peligrosa por cuantificadores anidados"
        try:
            re.compile(value)
        except re.error as exc:
            return False, f"regex inválida: {exc}"
    return True, "ok"


def _excerpt(text: str, start: int, end: int) -> str:
    left = max(0, start - 100)
    right = min(len(text), end + 180)
    return text[left:right].replace("\x00", "")[:MAX_EXCERPT]


def classify_experiment_status(result: dict[str, Any]) -> tuple[str, str | None]:
    """Classify infrastructure execution without interpreting vulnerability semantics."""
    if not isinstance(result, dict):
        return "TRANSPORT_ERROR", "resultado MCP ausente o inválido"
    error_type = str(result.get("error_type") or "").upper()
    error = str(result.get("error") or "")
    if error_type == "MCP_VALIDATION" or (result.get("returncode") is None and "bloque" in error.lower()):
        return "NOT_EXECUTED", error or "comando rechazado por validación MCP"
    if error_type == "TIMEOUT" or error.lower() == "timeout":
        return "TRANSPORT_ERROR", "timeout"
    if result.get("returncode") is None:
        return "NOT_EXECUTED", error or "el comando no produjo returncode"
    return "EXECUTED", None


def evaluate_expected_evidence(spec: Any, result: dict[str, Any]) -> dict[str, Any]:
    ok, reason = validate_expected_evidence(spec)
    experiment_status, status_reason = classify_experiment_status(result)
    base = {
        "valid": ok,
        "evaluated": experiment_status == "EXECUTED" and ok,
        "experiment_status": experiment_status,
        "status_reason": status_reason,
        "matcher": spec.get("matcher") if isinstance(spec, dict) else None,
        "meaning": spec.get("meaning") if isinstance(spec, dict) else None,
        "matched": None if experiment_status != "EXECUTED" else False,
        "match_count": 0,
        "excerpt": None,
        "validation_error": None if ok else reason,
    }
    if not ok or experiment_status != "EXECUTED":
        return base

    matcher = str(spec["matcher"]).lower()
    if matcher == "returncode":
        actual = result.get("returncode")
        base.update({
            "matched": actual == spec.get("value"),
            "match_count": 1 if actual == spec.get("value") else 0,
            "actual": actual,
            "expected": spec.get("value"),
            "excerpt": f"returncode={actual}",
        })
        return base

    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    text = (stdout + ("\n[stderr]\n" + stderr if stderr else ""))[:MAX_OUTPUT_SCAN]

    if matcher == "contains":
        needle = spec["value"]
        positions = []
        pos = 0
        while len(positions) < 20:
            idx = text.find(needle, pos)
            if idx < 0: break
            positions.append(idx); pos = idx + max(1, len(needle))
        if positions:
            base.update({"matched": True, "match_count": len(positions), "excerpt": _excerpt(text, positions[0], positions[0] + len(needle))})
        return base

    if matcher == "not_contains":
        needle = spec["value"]
        idx = text.find(needle)
        matched = idx < 0
        base.update({"matched": matched, "match_count": 1 if matched else 0, "excerpt": "Valor ausente en la salida capturada" if matched else _excerpt(text, idx, idx + len(needle))})
        return base

    rx = re.compile(spec["pattern"], re.MULTILINE)
    matches=[]
    for match in rx.finditer(text):
        matches.append(match)
        if len(matches)>=20: break
    if matches:
        first=matches[0]
        base.update({"matched":True,"match_count":len(matches),"excerpt":_excerpt(text,first.start(),first.end())})
    return base

