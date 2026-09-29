#!/usr/bin/env python3
import json
import os
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

EVENTS = Path('logs/v3/llm_events.jsonl')
OUT = Path('reports/llm-performance-summary.json')
RUN_OUT = Path(os.environ.get('BUGTRACEAI_RUN_DIR', '.')) / 'reports/llm-performance-summary.json'

def load_jsonl(path):
    rows=[]
    if not path.exists(): return rows
    for line in path.read_text(errors='ignore').splitlines():
        try: rows.append(json.loads(line))
        except Exception: pass
    return rows

def total(rows, key):
    return sum(int(r.get(key) or 0) for r in rows)

rows=load_jsonl(EVENTS)
events=Counter(r.get('event') for r in rows)
error_types=Counter(r.get('error_type') for r in rows if r.get('error_type'))
accepted=[r for r in rows if r.get('event')=='decision_accepted']
recovery=Counter(r.get('recovery','unknown') for r in accepted)
actions=Counter(r.get('action','unknown') for r in accepted)
responses=events['response_received']
final_errors=events['json_parse_rejected']+events['contract_rejected']+sum(1 for r in rows if r.get('event')=='transport_failure' and r.get('unrecoverable'))
summary={
  'version':'3.0.1f-r2',
  'generated_at':datetime.now(timezone.utc).isoformat(),
  'llm_events_total':len(rows),
  'responses_valid_first_attempt':recovery['first_try'],
  'responses_repaired':recovery['deterministic_repair'],
  'responses_recovered':recovery['format_retry'],
  'final_errors':final_errors,
  'transport_success':events['transport_success'],
  'transport_failure':events['transport_failure'],
  'responses_received':responses,
  'decisions_executed':len(accepted),
  'strategy_changes':sum(bool(r.get('strategy_change')) for r in accepted),
  'memory_usage':sum(bool(r.get('memory_used')) for r in accepted),
  'previous_results_used':sum(bool(r.get('previous_result_used')) for r in accepted),
  'hypotheses_created':total(accepted,'hypotheses_created'),
  'hypotheses_supported':total(accepted,'hypotheses_supported'),
  'hypotheses_weakened':total(accepted,'hypotheses_weakened'),
  'hypotheses_discarded':total(accepted,'hypotheses_discarded'),
  'confirmations_with_evidence':total(accepted,'confirmations_with_evidence'),
  'contract_autofixes_total':total(accepted,'contract_autofixes'),
  'valid_first_attempt_rate':round(recovery['first_try']/responses,4) if responses else None,
  'eventual_valid_rate':round(len(accepted)/responses,4) if responses else None,
  'accepted_actions':dict(actions),
  'error_classification':dict(error_types),
  'event_counts':dict(events),
  'error_domains':{
      'model_errors':sum(error_types[k] for k in ('invalid_json','schema_error','missing_field','timeout','connection','model_error','retry_failure')),
      'cognitive_errors':events['contract_rejected'],
      'runtime_errors':sum(1 for r in rows if r.get('event') in ('diagnostics_failure',)),
  },
}
for target in {OUT, RUN_OUT}:
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(summary,indent=2,ensure_ascii=False))
print('[LLM SUMMARY]', OUT)
