#!/usr/bin/env python3
"""BugTraceAI v2.6.0 policy separation and contract repair telemetry."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
AUTOFIX_FILE = LOG_DIR / "contract_autofixes.jsonl"
WARNINGS_FILE = LOG_DIR / "policy_warnings.jsonl"

TERMINAL_ASSESSMENTS = {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "NO_FINDING"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _append(path: Path, record: dict):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def record_autofix(*, fix_code: str, before, after, resource=None, decision_id=None, detail=None):
    rec = {
        "timestamp": utc_now(), "event_type": "contract_autofix", "fix_code": fix_code,
        "decision_id": decision_id, "resource": resource, "before": before, "after": after,
        "detail": detail or "",
    }
    _append(AUTOFIX_FILE, rec)
    return rec


def record_policy_warning(*, policy_code: str, message: str, action=None, command=None, resource=None, decision_id=None):
    rec = {
        "timestamp": utc_now(), "event_type": "lab_policy_warning", "policy_code": policy_code,
        "message": message, "decision_id": decision_id, "resource": resource,
        "action": action, "command": command,
        "blocking": False, "policy_layer": "laboratory",
    }
    _append(WARNINGS_FILE, rec)
    return rec


def infer_terminal_assessment(parsed: dict) -> str:
    ref = parsed.get("reflection") if isinstance(parsed.get("reflection"), dict) else {}
    if ref.get("evidence_candidate"):
        return "CONFIRMED"
    effect = str(ref.get("hypothesis_effect") or "").upper()
    if effect == "REFUTED":
        return "NOT_CONFIRMED"
    state_updates = parsed.get("state_updates") or []
    states = {str(x.get("state") or "").upper() for x in state_updates if isinstance(x, dict)}
    if "INCONCLUSIVE" in states:
        return "INCONCLUSIVE"
    return "NO_FINDING"


def repair_contract(parsed: dict) -> list[dict]:
    """Apply deterministic, low-risk structural repairs before validation."""
    fixes = []
    if not isinstance(parsed, dict):
        return fixes

    # Legacy/completion response without next_actions.
    actions = parsed.get("next_actions")
    status = str(parsed.get("status") or "").upper()
    if (not isinstance(actions, list) or not actions) and status in {"COMPLETED", "DONE", "INCONCLUSIVE"}:
        reason = str(parsed.get("reason") or parsed.get("verdict") or "Finalizar el análisis según el estado terminal informado.")
        parsed["next_actions"] = [{"action": "finalize_analysis", "reason": reason}]
        fixes.append(record_autofix(fix_code="synthesize_finalize_action", before=actions, after=parsed["next_actions"], detail="Se sintetizó finalize_analysis desde status terminal."))

    actions = parsed.get("next_actions") or []
    action = actions[0].get("action") if len(actions) == 1 and isinstance(actions[0], dict) else None
    if action == "finalize_analysis":
        ref = parsed.get("reflection")
        if not isinstance(ref, dict):
            ref = {}
            parsed["reflection"] = ref
        assessment = str(ref.get("assessment") or "CONTINUE").upper()
        if assessment not in TERMINAL_ASSESSMENTS:
            inferred = infer_terminal_assessment(parsed)
            ref["assessment"] = inferred
            fixes.append(record_autofix(fix_code="normalize_terminal_assessment", before=assessment, after=inferred, detail="Assessment terminal inferido para finalize_analysis."))
        if ref.get("assessment") == "CONFIRMED" and not bool(ref.get("evidence_candidate")):
            # Do not fabricate confirmation; downgrade to inconclusive.
            ref["assessment"] = "INCONCLUSIVE"
            fixes.append(record_autofix(fix_code="downgrade_unsubstantiated_confirmation", before="CONFIRMED", after="INCONCLUSIVE", detail="CONFIRMED sin evidence_candidate no se acepta como confirmación."))
    return fixes


def evaluate_lab_policies(parsed: dict) -> list[dict]:
    """Non-blocking DVWA/lab preferences. Security rules remain elsewhere."""
    warnings = []
    if not isinstance(parsed, dict):
        return warnings
    actions = parsed.get("next_actions") or []
    if len(actions) != 1 or not isinstance(actions[0], dict):
        return warnings
    action_obj = actions[0]
    action = action_obj.get("action")
    if action not in {"propose_mcp_command", "propose_command"}:
        return warnings
    command = str(action_obj.get("command") or "")
    low = command.lower()
    common = {"action": action, "command": command, "decision_id": parsed.get("decision_id")}

    if "/vulnerabilities/brute/" in low and not ("admin" in low and "password" in low):
        warnings.append(record_policy_warning(policy_code="brute_fixed_credentials_preference", message="La política DVWA requiere usar exclusivamente admin/password para Brute Force.", **common))
    if "/vulnerabilities/csrf/" in low and any(x in low for x in ("password_new=", "password_conf=", "new_password=")) and "password" not in low:
        warnings.append(record_policy_warning(policy_code="csrf_fixed_credentials_preference", message="La política DVWA requiere conservar admin/password durante CSRF.", **common))
    if "/vulnerabilities/captcha/" in low and any(x in low for x in ("password_new=", "password_conf=", "new_password=")) and "password" not in low:
        warnings.append(record_policy_warning(policy_code="captcha_fixed_credentials_preference", message="La política DVWA requiere conservar admin/password durante CAPTCHA.", **common))
    is_upload = "/vulnerabilities/upload/" in low and any(token in low for token in (" -f ", " -f'", ' -f"', "--form", "uploaded=@"))
    if is_upload and "assets/benign_phpinfo.php" not in command:
        warnings.append(record_policy_warning(policy_code="benign_upload_artifact_preference", message="La política DVWA recomienda el artefacto benigno preinstalado; se conserva la propuesta para diagnóstico.", **common))
    return warnings


def classify_rejection_layer(reason_code: str) -> tuple[str, str]:
    technical = {"missing_required_field", "invalid_action", "invalid_action_count", "invalid_reason", "placeholder_detected", "invalid_command", "invalid_approval", "invalid_risk", "invalid_url", "invalid_reflection", "invalid_cognitive_update", "invalid_state_update", "invalid_operator_verdict"}
    consistency = {"invalid_finalization"}
    laboratory = {"upload_policy", "brute_wordlist_policy", "csrf_policy"}
    security = {"session_policy", "lab_mutation_policy"}
    if reason_code in technical: return "technical_contract", "error"
    if reason_code in consistency: return "contract_consistency", "error"
    if reason_code in laboratory: return "laboratory_policy", "warning"
    if reason_code in security: return "security_policy", "critical"
    return "unclassified", "error"
