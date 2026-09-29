#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parent
TRACE_DIR=ROOT/'logs'/'lifecycle'
TRACE_FILE=TRACE_DIR/'analysis-lifecycle.jsonl'
SNAP_DIR=TRACE_DIR/'snapshots'

def utc_now(): return datetime.now(timezone.utc).isoformat()

def enabled()->bool:
    return os.environ.get('BUGTRACEAI_LIFECYCLE_TRACE','1').strip().lower() not in {'0','false','no','off'}

def _safe(v:Any)->Any:
    try: json.dumps(v); return v
    except Exception: return str(v)

def emit(event_type:str, *, analysis_id:str|None=None, resource:str|None=None, component:str='runtime', **data:Any)->None:
    if not enabled(): return
    TRACE_DIR.mkdir(parents=True,exist_ok=True)
    event={'timestamp':utc_now(),'event':str(event_type).upper(),'component':component,'analysis_id':analysis_id,'resource':resource}
    event.update({k:_safe(v) for k,v in data.items()})
    with TRACE_FILE.open('a',encoding='utf-8') as f:
        f.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')

def queue_summary(k:dict[str,Any])->dict[str,Any]:
    q=k.get('analysis_queue') or []
    states={}
    ids=[]
    for item in q:
        if not isinstance(item,dict): continue
        state=str(item.get('state') or 'UNKNOWN').upper(); states[state]=states.get(state,0)+1
        if item.get('analysis_id'): ids.append(item.get('analysis_id'))
    return {'analysis_items':len(ids),'analysis_ids':ids,'states':states,'active_analysis_id':k.get('active_analysis_id'),'candidate_urls':len(k.get('candidate_urls') or [])}

def persist_snapshot(k:dict[str,Any], *, component:str, path:str|None=None)->None:
    if not enabled(): return
    summary=queue_summary(k)
    raw=json.dumps(k,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8','replace')
    digest=hashlib.sha256(raw).hexdigest()
    emit('PERSIST',component=component,path=path,sha256=digest,**summary)
    if os.environ.get('BUGTRACEAI_LIFECYCLE_SNAPSHOTS','0').strip().lower() in {'1','true','yes','on'}:
        SNAP_DIR.mkdir(parents=True,exist_ok=True)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        (SNAP_DIR/f'{stamp}-{component.replace("/","_")}.json').write_text(json.dumps(k,ensure_ascii=False,indent=2),encoding='utf-8')
