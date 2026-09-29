#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parent
KNOWLEDGE = ROOT / 'data' / 'knowledge.json'
RAW_VERDICT_STATUSES = {'UNASSESSED','SUSPECTED','CONFIRMED','NOT_CONFIRMED','NO_FINDING','INCONCLUSIVE'}
RAW_EXPLOIT_STATUSES = {'CONFIRMED','LIMITED','NOT_CONFIRMED','NOT_TESTABLE','NOT_APPLICABLE','NOT_ATTEMPTED','ATTEMPTED','PARTIAL','FAILED','INCOMPLETE'}
EVIDENCE_LEVELS = {
    0:'E0_NONE', 1:'E1_INDICATOR', 2:'E2_DIFFERENTIAL',
    3:'E3_REPRODUCIBLE_CONFIRMATION', 4:'E4_IMPACT_DEMONSTRATED',
    5:'E5_CONTROLLED_EXPLOITATION'
}
NO_FINDING_MIN_COVERAGE = 0.90


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_knowledge() -> dict[str, Any]:
    try:
        return json.loads(KNOWLEDGE.read_text(encoding='utf-8'))
    except Exception:
        return {}


def _items(k: dict[str, Any]) -> list[dict[str, Any]]:
    q = k.get('analysis_queue') or k.get('analysis_items') or []
    if isinstance(q, dict):
        q = list(q.values())
    return [x for x in q if isinstance(x, dict)]


def _resource(item: dict[str, Any]) -> str:
    return item.get('entry_url') or item.get('resource') or item.get('url') or 'unknown'


def _valid_evidence(item: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in item.get('evidence') or []:
        if not isinstance(e, dict):
            continue
        source = str(e.get('source') or '').lower()
        kind = str(e.get('kind') or '').lower()
        specific = bool(e.get('excerpt') or e.get('predicate') or e.get('stdout_sha256') or e.get('text'))
        if specific and ('verified' in source or 'promotion' in source or 'predicate' in kind or e.get('confidence')):
            out.append(e)
    return out


def _has_assessment_activity(item: dict[str, Any]) -> bool:
    state = str(item.get('state') or 'NEW').upper()
    return bool(
        state not in {'NEW', 'UNKNOWN'}
        or item.get('commands')
        or item.get('actions')
        or item.get('evidence')
        or item.get('hypothesis_history')
    )


def _no_finding_gate(verdict: dict[str, Any], item: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    """Accept NO_FINDING only with explicit, machine-checkable negative basis.

    The gate is generic: it does not encode vulnerability playbooks. The LLM or
    operator must provide the coverage basis, while runtime facts verify that
    execution was stable and free from unresolved limitations.
    """
    basis = verdict.get('no_finding_basis') or item.get('no_finding_basis') or {}
    if not isinstance(basis, dict):
        basis = {}
    coverage = float(basis.get('coverage', 0.0) or 0.0)
    reproducible = bool(basis.get('reproducible'))
    preconditions = bool(basis.get('preconditions_verified'))
    alternatives = int(basis.get('unresolved_alternatives', 1) or 0)
    contradictions = int(basis.get('contradictions', 0) or 0)
    commands = [x for x in (item.get('commands') or []) if isinstance(x, dict)]
    execution_errors = sum(
        str(x.get('execution_status') or '').upper() in {'FAILED','TIMEOUT','TRANSPORT_ERROR','UNKNOWN_RESULT'}
        or x.get('ok') is False
        for x in commands
    )
    limitations = verdict.get('limitations') or item.get('limitations') or []
    if not isinstance(limitations, list):
        limitations = [str(limitations)]

    failures: list[str] = []
    if coverage < NO_FINDING_MIN_COVERAGE:
        failures.append('INSUFFICIENT_NEGATIVE_COVERAGE')
    if not reproducible:
        failures.append('NEGATIVE_RESULT_NOT_REPRODUCIBLE')
    if not preconditions:
        failures.append('PRECONDITIONS_NOT_VERIFIED')
    if alternatives > 0:
        failures.append('UNRESOLVED_ALTERNATIVES_REMAIN')
    if contradictions > 0:
        failures.append('NEGATIVE_EVIDENCE_CONTRADICTIONS')
    if execution_errors > 0:
        failures.append('EXECUTION_ERRORS_PRESENT')
    if limitations:
        failures.append('UNRESOLVED_VALIDATION_LIMITATIONS')
    if len(commands) < 2:
        failures.append('INSUFFICIENT_TEST_REPETITION')

    normalized = {
        'coverage': coverage,
        'minimum_coverage': NO_FINDING_MIN_COVERAGE,
        'reproducible': reproducible,
        'preconditions_verified': preconditions,
        'unresolved_alternatives': alternatives,
        'contradictions': contradictions,
        'execution_errors': execution_errors,
        'test_count': len(commands),
        'limitations': limitations,
    }
    return not failures, failures, normalized


def _validation_capability(item: dict[str, Any], verdict: dict[str, Any]) -> tuple[str, list[str], Any]:
    limitations = verdict.get('limitations') or item.get('validation_limitations') or item.get('limitations') or []
    if isinstance(limitations, str):
        limitations = [limitations]
    limitations = [str(x) for x in limitations if x]
    handoff = verdict.get('operator_handoff') or item.get('operator_handoff')
    if handoff or limitations:
        capability = 'SUPPORTED_WITH_OPERATOR' if handoff else 'LIMITED_AUTOMATION'
    else:
        capability = 'SUPPORTED_AUTOMATICALLY'
    return capability, limitations, handoff


def classify(item: dict[str, Any]) -> dict[str, Any]:
    verdict = item.get('vulnerability_verdict') or {}
    exploitation = item.get('exploitation') or {}
    raw_status = str(verdict.get('status') or 'UNASSESSED').upper()
    raw_exp = str(exploitation.get('status') or 'NOT_CONFIRMED').upper()
    if raw_status not in RAW_VERDICT_STATUSES:
        raw_status = 'UNASSESSED'
    if raw_exp not in RAW_EXPLOIT_STATUSES:
        raw_exp = 'NOT_CONFIRMED'

    assessed = _has_assessment_activity(item)
    assessment_status = 'ASSESSED' if assessed else 'UNASSESSED'
    evidence = _valid_evidence(item)
    operator = bool(item.get('operator_verdict') or item.get('operator_approval'))
    version_only = bool(verdict.get('cve') or verdict.get('version_match')) and not evidence
    contradictions: list[str] = []

    # Vulnerability axis: only four public states.
    if not assessed:
        vulnerability_status = 'UNASSESSED'
    elif raw_status == 'CONFIRMED':
        vulnerability_status = 'CONFIRMED'
    elif raw_status == 'NO_FINDING':
        accepted, gate_failures, no_finding_basis = _no_finding_gate(verdict, item)
        vulnerability_status = 'NO_FINDING' if accepted else 'INCONCLUSIVE'
        if not accepted:
            contradictions.extend(['NO_FINDING_GATE_REJECTED', *gate_failures])
    else:
        # UNASSESSED, SUSPECTED, NOT_CONFIRMED and explicit INCONCLUSIVE remain conservatively open.
        vulnerability_status = 'INCONCLUSIVE'
        no_finding_basis = None

    if raw_status != 'NO_FINDING':
        no_finding_basis = None
    if vulnerability_status == 'CONFIRMED' and not evidence:
        contradictions.append('CONFIRMED_WITHOUT_VERIFIED_EVIDENCE')
    if version_only and vulnerability_status == 'CONFIRMED':
        contradictions.append('VERSION_OR_CVE_ONLY_IS_NOT_CONFIRMATION')
    if contradictions and vulnerability_status == 'CONFIRMED':
        vulnerability_status = 'INCONCLUSIVE'

    # Exploitability axis is only meaningful after vulnerability confirmation.
    if vulnerability_status != 'CONFIRMED':
        exploitability_status = 'NOT_APPLICABLE'
    elif raw_exp == 'CONFIRMED':
        exploitability_status = 'CONFIRMED'
    elif raw_exp in {'LIMITED','PARTIAL'}:
        exploitability_status = 'LIMITED'
    elif raw_exp == 'NOT_TESTABLE':
        exploitability_status = 'NOT_TESTABLE'
    else:
        exploitability_status = 'NOT_CONFIRMED'

    if raw_exp == 'CONFIRMED' and vulnerability_status != 'CONFIRMED':
        contradictions.append('EXPLOITATION_CONFIRMED_WITHOUT_VULNERABILITY_CONFIRMATION')
        exploitability_status = 'NOT_APPLICABLE'

    if exploitability_status == 'CONFIRMED':
        level = 5
    elif vulnerability_status == 'CONFIRMED' and exploitability_status == 'LIMITED':
        level = 4
    elif vulnerability_status == 'CONFIRMED' and evidence:
        level = 3
    elif evidence:
        level = 2
    elif raw_status == 'SUSPECTED' or version_only:
        level = 1
    else:
        level = 0

    capability, limitations, handoff = _validation_capability(item, verdict)
    return {
        'resource': _resource(item),
        'analysis_id': item.get('analysis_id'),
        'process_state': str(item.get('state') or 'UNKNOWN').upper(),
        'assessment_status': assessment_status,
        'vulnerability_status': vulnerability_status,
        'exploitability_status': exploitability_status,
        'raw_vulnerability_status': raw_status,
        'raw_exploitation_status': raw_exp,
        'evidence_level': EVIDENCE_LEVELS[level],
        'evidence_score': level,
        'verified_evidence_count': len(evidence),
        'evidence_ids': [e.get('evidence_id') for e in evidence if e.get('evidence_id')],
        'operator_supported': operator,
        'validation_capability': capability,
        'validation_limitations': limitations,
        'operator_handoff': handoff,
        'summary': verdict.get('summary'),
        'no_finding_basis': no_finding_basis,
        'contradictions': list(dict.fromkeys(contradictions)),
        'next_requirement': ((item.get('cognitive_session') or {}).get('latest_reflection') or {}).get('next_requirement')
            if isinstance(item.get('cognitive_session'), dict) else None,
    }


def build(k: dict[str, Any] | None = None) -> dict[str, Any]:
    k = k or load_knowledge()
    rows = [classify(x) for x in _items(k)]
    vulnerability_counts: dict[str, int] = {}
    exploitability_counts: dict[str, int] = {}
    for r in rows:
        vulnerability_counts[r['vulnerability_status']] = vulnerability_counts.get(r['vulnerability_status'], 0) + 1
        exploitability_counts[r['exploitability_status']] = exploitability_counts.get(r['exploitability_status'], 0) + 1
    return {
        'generated_at': now(),
        'model': 'v2.6.2-conservative-dual-axis',
        'resources': rows,
        'summary': {
            'total': len(rows),
            'unassessed': sum(r['assessment_status'] == 'UNASSESSED' for r in rows),
            'assessed': sum(r['assessment_status'] == 'ASSESSED' for r in rows),
            'vulnerability': vulnerability_counts,
            'exploitability': exploitability_counts,
            'confirmed_vulnerabilities': sum(r['vulnerability_status'] == 'CONFIRMED' for r in rows),
            'confirmed_exploitability': sum(r['exploitability_status'] == 'EXPLOITABLE' for r in rows),
            'no_finding': sum(r['vulnerability_status'] == 'NO_FINDING' for r in rows),
            'inconclusive': sum(r['vulnerability_status'] == 'INCONCLUSIVE' for r in rows),
            'operator_handoffs': sum(bool(r['operator_handoff']) for r in rows),
            'consistency_warnings': sum(bool(r['contradictions']) for r in rows),
        },
    }


if __name__ == '__main__':
    print(json.dumps(build(), indent=2, ensure_ascii=False))
