#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parent
TRACE=ROOT/'logs'/'decision-execution-flow.jsonl'

def now(): return datetime.now(timezone.utc).isoformat()
def sha(v:str)->str: return hashlib.sha256(v.encode('utf-8','replace')).hexdigest()
def clip(v:Any,n:int=4000)->str:
    s=str(v or '')
    return s if len(s)<=n else s[:n]+f'...<truncated:{len(s)-n}>'
def emit(stage:str, **data:Any)->None:
    TRACE.parent.mkdir(parents=True,exist_ok=True)
    event={'timestamp':now(),'stage':stage,'run_id':os.environ.get('BUGTRACEAI_RUN_ID')}
    event.update(data)
    with TRACE.open('a',encoding='utf-8') as f:
        f.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')

def snapshot_decision(active:str='')->None:
    p=ROOT/'logs'/'last_llm_decision.json'
    try: d=json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        emit('DECISION_SNAPSHOT_ERROR',active_resource=active,error=repr(e)); return
    a=(d.get('next_actions') or [{}])[0]
    command=str(a.get('command') or '')
    emit('LLM_DECISION_ACCEPTED',active_resource=active,decision_id=d.get('decision_id'),
         action=a.get('action'),command=clip(command),command_sha256=sha(command) if command else None,
         reason=clip(a.get('reason'),1000),expected_evidence=a.get('expected_evidence'),
         assessment=((d.get('reflection') or {}).get('assessment') if isinstance(d.get('reflection'),dict) else None))

def executor_event(stage:str, **data:Any)->None: emit(stage,**data)

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('mode',choices=['decision']); ap.add_argument('--active',default='')
    ns=ap.parse_args(); snapshot_decision(ns.active)
