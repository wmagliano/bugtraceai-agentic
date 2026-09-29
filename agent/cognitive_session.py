#!/usr/bin/env python3
"""BugTraceAI v2.4.0a: memoria cognitiva aislada por Analysis Item."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_item_session(item: dict[str, Any]) -> dict[str, Any]:
    session = item.setdefault("cognitive_session", {})
    session.setdefault("schema_version", "1.0")
    session.setdefault("status", "OPEN")
    session.setdefault("initial_observation", None)
    session.setdefault("active_hypothesis", None)
    session.setdefault("learned_facts", [])
    session.setdefault("cycles", [])
    session.setdefault("last_reflection", None)
    session.setdefault("summary", None)
    session.setdefault("updated_at", utc_now())
    return session


def attach_command_result(item: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    """Create/update one experiment cycle from an MCP command result."""
    session = ensure_item_session(item)
    command_id = command.get("command_id")
    decision_id = command.get("decision_id")
    cycle = None
    for existing in session["cycles"]:
        if command_id and existing.get("command_id") == command_id:
            cycle = existing
            break
        if decision_id and existing.get("action_decision_id") == decision_id:
            cycle = existing
            break
    if cycle is None:
        cycle = {
            "cycle_id": f"CYCLE-{len(session['cycles']) + 1:04d}",
            "created_at": utc_now(),
            "action_decision_id": decision_id,
            "command_id": command_id,
            "hypothesis_before": session.get("active_hypothesis"),
            "action": {
                "reason": command.get("reason"),
                "command": command.get("command"),
                "tested_url": command.get("tested_url"),
            },
            "result": {},
            "reflection": None,
            "status": "AWAITING_REFLECTION",
        }
        session["cycles"].append(cycle)
    cycle["result"] = {
        "execution_status": command.get("execution_status"),
        "ok": command.get("ok"),
        "returncode": command.get("returncode"),
        "stdout_excerpt": command.get("stdout_preview"),
        "stderr_excerpt": command.get("stderr_preview"),
        "stdout_sha256": command.get("stdout_sha256"),
        "stderr_sha256": command.get("stderr_sha256"),
        "verified_evidence": command.get("verified_evidence") or [],
        "expected_evidence": command.get("expected_evidence"),
        "predicate_result": command.get("predicate_result"),
    }
    cycle["status"] = "AWAITING_REFLECTION"
    cycle["updated_at"] = utc_now()
    session["updated_at"] = utc_now()
    return cycle


def apply_reflection(item: dict[str, Any], reflection: dict[str, Any], decision_id: str | None = None) -> dict[str, Any]:
    session = ensure_item_session(item)
    pending = next((x for x in reversed(session["cycles"]) if x.get("status") == "AWAITING_REFLECTION"), None)
    normalized = {
        "decision_id": decision_id,
        "timestamp": utc_now(),
        "observation": reflection.get("observation"),
        "interpretation": reflection.get("interpretation"),
        "hypothesis_effect": str(reflection.get("hypothesis_effect") or "NOT_EVALUATED").upper(),
        "learned_fact": reflection.get("learned_fact"),
        "evidence_candidate": bool(reflection.get("evidence_candidate", False)),
        "next_requirement": reflection.get("next_requirement"),
        "assessment": str(reflection.get("assessment") or "CONTINUE").upper(),
        "confidence": str(reflection.get("confidence") or "MEDIUM").upper(),
        "evidence_reason": reflection.get("evidence_reason"),
        "command_result_saved": bool(reflection.get("command_result_saved", False)),
        "previous_result_used": bool(reflection.get("previous_result_used", False)),
        "memory_confirmation": reflection.get("memory_confirmation"),
        "next_attempt_difference": reflection.get("next_attempt_difference"),
        "information_gain": str(reflection.get("information_gain") or "NONE").upper(),
    }
    if pending is None:
        pending = {
            "cycle_id": f"CYCLE-{len(session['cycles']) + 1:04d}",
            "created_at": utc_now(),
            "action_decision_id": None,
            "command_id": None,
            "hypothesis_before": session.get("active_hypothesis"),
            "action": None,
            "result": None,
        }
        session["cycles"].append(pending)
    pending["reflection"] = normalized
    pending["status"] = "REFLECTED"
    pending["updated_at"] = utc_now()
    session["last_reflection"] = normalized
    learned = normalized.get("learned_fact")
    if isinstance(learned, str) and learned.strip() and learned not in session["learned_facts"]:
        session["learned_facts"].append(learned.strip())
    session["updated_at"] = utc_now()
    return normalized


def close_session(item: dict[str, Any]) -> None:
    session = ensure_item_session(item)
    session["status"] = "CLOSED"
    session["summary"] = {
        "final_state": item.get("state"),
        "verdict": item.get("vulnerability_verdict"),
        "exploitation": item.get("exploitation"),
        "evidence_ids": [x.get("evidence_id") for x in item.get("evidence", []) if isinstance(x, dict)],
        "learned_facts": session.get("learned_facts", []),
        "cycles": len(session.get("cycles", [])),
    }
    session["updated_at"] = utc_now()
