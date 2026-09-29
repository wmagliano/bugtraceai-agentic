#!/usr/bin/env python3
"""BugTraceAI v2.5.6e - observabilidad transversal.

Registra eventos JSONL sin alterar la lógica operativa. Nunca debe bloquear el flujo.
"""
from __future__ import annotations
import json, os, hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from correlation_context import resolve as resolve_context

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / 'logs'
REPORT_DIR = ROOT / 'reports' / 'runtime_diagnostics'
EVENTS_FILE = LOG_DIR / 'runtime_events.jsonl'
LATEST_FILE = LOG_DIR / 'last_runtime_event.json'
COUNTERS_FILE = LOG_DIR / 'runtime_event_counters.json'
REPORT_JSON = REPORT_DIR / 'runtime_diagnostics_report.json'
REPORT_MD = REPORT_DIR / 'runtime_diagnostics_report.md'
ENABLED = os.environ.get('BUGTRACEAI_RUNTIME_DIAGNOSTICS','1') != '0'


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe(value, limit=12000):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f'...<truncated:{len(value)-limit}>'
    if isinstance(value, dict):
        return {str(k): _safe(v, limit) for k,v in value.items()}
    if isinstance(value, list):
        return [_safe(v, limit) for v in value]
    return value


def emit(event_type: str, *, stage: str, status: str='info', decision_id=None,
         rejection_id=None, resource=None, action=None, reason_code=None,
         message=None, flags=None, data=None, analysis_id=None, trace_id=None,
         contract_id=None, executor_id=None, mcp_execution_id=None, evidence_id=None):
    if not ENABLED:
        return None
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        ctx=resolve_context(decision_id=decision_id, analysis_id=analysis_id, resource=resource, trace_id=trace_id)
        record = {
            'event_id': 'EV-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'),
            'timestamp': utc_now(), 'event_type': event_type, 'stage': stage,
            'status': status, 'run_id': ctx['run_id'], 'trace_id': ctx['trace_id'],
            'decision_id': ctx['decision_id'], 'analysis_id': ctx['analysis_id'], 'rejection_id': rejection_id,
            'resource': ctx['resource'], 'contract_id': contract_id, 'executor_id': executor_id,
            'mcp_execution_id': mcp_execution_id, 'evidence_id': evidence_id, 'action': action, 'reason_code': reason_code,
            'message': message, 'flags': flags or {}, 'data': _safe(data or {}),
        }
        canonical=json.dumps(record,ensure_ascii=False,sort_keys=True,default=str)
        record['event_sha256']=hashlib.sha256(canonical.encode()).hexdigest()
        with EVENTS_FILE.open('a',encoding='utf-8') as f:
            f.write(json.dumps(record,ensure_ascii=False,default=str)+'\n')
        LATEST_FILE.write_text(json.dumps(record,indent=2,ensure_ascii=False),encoding='utf-8')
        _update_counters(record)
        return record
    except Exception:
        return None


def _update_counters(record):
    counters={'total':0,'by_stage':{},'by_type':{},'by_status':{},'by_reason_code':{},'by_resource':{}}
    try:
        if COUNTERS_FILE.exists(): counters=json.loads(COUNTERS_FILE.read_text(encoding='utf-8'))
    except Exception: pass
    counters['total']=int(counters.get('total',0))+1
    for bucket,key in [('by_stage',record.get('stage')),('by_type',record.get('event_type')),
                       ('by_status',record.get('status')),('by_reason_code',record.get('reason_code')),
                       ('by_resource',record.get('resource'))]:
        if key:
            d=counters.setdefault(bucket,{})
            d[str(key)]=int(d.get(str(key),0))+1
    counters['updated_at']=utc_now()
    COUNTERS_FILE.write_text(json.dumps(counters,indent=2,ensure_ascii=False),encoding='utf-8')


def generate_report():
    REPORT_DIR.mkdir(parents=True,exist_ok=True)
    events=[]
    if EVENTS_FILE.exists():
        for line in EVENTS_FILE.read_text(encoding='utf-8',errors='replace').splitlines():
            try: events.append(json.loads(line))
            except Exception: pass
    by_decision=defaultdict(list)
    for e in events:
        key=e.get('decision_id') or e.get('rejection_id') or 'unlinked'
        by_decision[key].append(e)
    stalled=[]
    for key, items in by_decision.items():
        stages={i.get('stage') for i in items}
        if 'reasoner' in stages and not ({'executor','mcp'} & stages):
            stalled.append({'correlation_id':key,'last_event':items[-1],'event_count':len(items)})
    report={
      'generated_at':utc_now(), 'event_count':len(events),
      'stage_counts':dict(Counter(e.get('stage') for e in events)),
      'status_counts':dict(Counter(e.get('status') for e in events)),
      'reason_counts':dict(Counter(e.get('reason_code') for e in events if e.get('reason_code'))),
      'decisions_observed':len(by_decision), 'reasoner_only_flows':stalled,
      'events':events[-1000:],
    }
    REPORT_JSON.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    lines=['# Runtime Diagnostics Report','',f"Generated: {report['generated_at']}",
           f"Events: {report['event_count']}",f"Correlated flows: {report['decisions_observed']}",'',
           '## Events by stage']
    for k,v in sorted(report['stage_counts'].items(),key=lambda x:(-x[1],str(x[0]))): lines.append(f'- {k}: {v}')
    lines += ['','## Events by status']
    for k,v in sorted(report['status_counts'].items(),key=lambda x:(-x[1],str(x[0]))): lines.append(f'- {k}: {v}')
    lines += ['','## Reasoner flows that never reached Executor/MCP']
    for item in stalled[-100:]:
        last=item['last_event']; lines.append(f"- {item['correlation_id']}: {last.get('event_type')} / {last.get('reason_code') or last.get('status')}")
    REPORT_MD.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return report

if __name__=='__main__':
    out=generate_report(); print(REPORT_JSON); print(json.dumps({k:v for k,v in out.items() if k!='events'},indent=2,ensure_ascii=False))
