#!/usr/bin/env python3
import json, hashlib, sys
from pathlib import Path
from datetime import datetime, timezone
from policy_engine_v260 import classify_rejection_layer

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
REPORT_DIR = ROOT / "reports" / "contract_diagnostics"
EVENTS_FILE = LOG_DIR / "contract_rejections.jsonl"
COUNTERS_FILE = LOG_DIR / "contract_rejection_counters.json"
LATEST_FILE = LOG_DIR / "last_contract_rejection.json"
REPORT_JSON = REPORT_DIR / "contract_diagnostics_report.json"
REPORT_MD = REPORT_DIR / "contract_diagnostics_report.md"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _read_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, type(default)) else default
    except Exception:
        return default


def _counter_key(value, default="unknown"):
    """Always return a stable, hashable and compact key for diagnostic counters."""
    if value is None or value == "":
        return default
    if isinstance(value, str):
        return value[:240]
    if isinstance(value, dict):
        nested = value.get("action") or value.get("type") or value.get("name")
        if isinstance(nested, str) and nested:
            return f"malformed_object:{nested[:200]}"
        return "malformed_action_object"
    if isinstance(value, (list, tuple, set)):
        return f"malformed_{type(value).__name__}"
    try:
        return str(value)[:240]
    except Exception:
        return default


def classify_reason(reason: str):
    low=(reason or '').lower()
    rules=[
      ('missing_required_field','campos faltantes'),
      ('invalid_action','acción no permitida'),('invalid_action','accion no permitida'),
      ('nested_action_object','campo action válido'),
      ('invalid_action_count','exactamente una acción'),('invalid_action_count','exactamente una accion'),
      ('invalid_reason','reason técnico'),('placeholder_detected','placeholder'),
      ('invalid_command','requiere command'),('invalid_approval','approval_required'),('invalid_risk','risk_level'),
      ('invalid_url','url absoluta'),('invalid_finalization','finalize_analysis'),
      ('upload_policy','upload requiere'),('upload_policy','webshell'),
      ('brute_wordlist_policy','brute force requiere usar assets/brute.txt'),('csrf_policy','csrf debe cambiar'),
      ('session_policy','no inventar cookie'),('lab_mutation_policy','acción mutable del laboratorio'),
      ('lab_mutation_policy','accion mutable del laboratorio'),('invalid_cognitive_update','cognitive_updates'),
      ('invalid_state_update','state_updates'),('invalid_reflection','reflection.'),('invalid_operator_verdict','operator_verdict'),
    ]
    for code, marker in rules:
        if marker in low:
            return code
    return 'other_contract_rejection'


def _safe_write_json(path, value):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return True
    except Exception as exc:
        print(f"[WARN] diagnóstico no pudo escribir {path}: {exc}", file=sys.stderr)
        return False


def record_rejection(*, reason, raw_response, parsed_response=None, candidate=None, metrics=None, active_resource=None):
    """Best-effort telemetry: returns a record even if every diagnostic write fails."""
    rid='CR-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    action=None
    try:
        if isinstance(parsed_response,dict):
            acts=parsed_response.get('next_actions') or []
            if acts and isinstance(acts[0],dict):
                action=acts[0].get('action')
    except Exception:
        action=None
    action_key=_counter_key(action)
    resource_key=_counter_key(active_resource)
    reason_code=classify_reason(str(reason))
    try:
        policy_layer,severity=classify_rejection_layer(reason_code)
    except Exception:
        policy_layer,severity='diagnostics','warning'
    record={
      'rejection_id':rid,'timestamp':utc_now(),'type':'contract_validation_error',
      'reason_code':reason_code,'policy_layer':policy_layer,'severity':severity,'reason':str(reason),'active_resource':active_resource,
      'proposed_action':action_key,'proposed_action_raw':action,'raw_response_chars':len(raw_response or ''),
      'json_candidate_chars':len(candidate or ''),'raw_sha256':hashlib.sha256((raw_response or '').encode()).hexdigest(),
      'parsed_response':parsed_response if isinstance(parsed_response,dict) else None,'raw_response':raw_response,'metrics':metrics or {},
      'flags':{'json_syntax_valid':isinstance(parsed_response,dict),'contract_valid':False,'executor_reached':False,'mcp_reached':False}
    }
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True); REPORT_DIR.mkdir(parents=True, exist_ok=True)
        with EVENTS_FILE.open('a',encoding='utf-8') as f:
            f.write(json.dumps(record,ensure_ascii=False,default=str)+'\n')
        _safe_write_json(LATEST_FILE, record)
        counters=_read_json(COUNTERS_FILE,{'total':0,'by_reason_code':{},'by_resource':{},'by_action':{}})
        counters['total']=int(counters.get('total',0))+1
        for bucket,key in [('by_reason_code',_counter_key(reason_code)),('by_resource',resource_key),('by_action',action_key)]:
            d=counters.setdefault(bucket,{})
            if not isinstance(d,dict): d={}; counters[bucket]=d
            d[key]=int(d.get(key,0))+1
        counters['last_rejection_id']=rid; counters['updated_at']=utc_now()
        _safe_write_json(COUNTERS_FILE,counters)
        try: generate_report()
        except Exception as exc: print(f"[WARN] reporte diagnóstico no disponible: {exc}",file=sys.stderr)
    except Exception as exc:
        print(f"[WARN] record_rejection degradado: {exc}", file=sys.stderr)
    return record


def record_acceptance(*, decision_id=None, action=None, active_resource=None):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        rec={'timestamp':utc_now(),'decision_id':decision_id,'action':_counter_key(action),'active_resource':active_resource,
             'flags':{'json_syntax_valid':True,'contract_valid':True,'executor_reached':None,'mcp_reached':None}}
        with (LOG_DIR/'contract_acceptances.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps(rec,ensure_ascii=False,default=str)+'\n')
    except Exception as exc:
        print(f"[WARN] aceptación contractual no registrada: {exc}",file=sys.stderr)


def generate_report():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    events=[]
    if EVENTS_FILE.exists():
        for line in EVENTS_FILE.read_text(encoding='utf-8',errors='replace').splitlines():
            try: events.append(json.loads(line))
            except Exception: pass
    counters=_read_json(COUNTERS_FILE,{})
    report={'generated_at':utc_now(),'summary':counters,'rejections':events}
    _safe_write_json(REPORT_JSON,report)
    lines=['# Contract Diagnostics Report','',f"Generated: {report['generated_at']}",'',f"Total rejections: {counters.get('total',0)}",'','## By reason']
    for k,v in sorted((counters.get('by_reason_code') or {}).items(), key=lambda x:(-int(x[1]),str(x[0]))): lines.append(f'- {k}: {v}')
    lines += ['','## By resource']
    for k,v in sorted((counters.get('by_resource') or {}).items(), key=lambda x:(-int(x[1]),str(x[0]))): lines.append(f'- {k}: {v}')
    lines += ['','## Rejections']
    for e in events[-100:]:
        lines += ['',f"### {e.get('rejection_id')}",f"- Timestamp: {e.get('timestamp')}",f"- Resource: {e.get('active_resource')}",f"- Action: {e.get('proposed_action')}",f"- Code: {e.get('reason_code')}",f"- Reason: {e.get('reason')}",f"- Raw SHA256: {e.get('raw_sha256')}"]
    try: REPORT_MD.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    except Exception as exc: print(f"[WARN] markdown diagnóstico no disponible: {exc}",file=sys.stderr)
    return report

if __name__=='__main__':
    generate_report(); print(REPORT_JSON)
