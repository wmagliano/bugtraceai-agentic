#!/usr/bin/env python3
from __future__ import annotations
import json, os, uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
ROOT=Path(__file__).resolve().parent
DECISION=ROOT/'logs'/'last_llm_decision.json'
KNOWLEDGE=ROOT/'data'/'knowledge.json'

def _read(path:Path)->dict[str,Any]:
    try:
        x=json.loads(path.read_text(encoding='utf-8'))
        return x if isinstance(x,dict) else {}
    except Exception:return {}

def current_run_id()->str:
    return os.environ.get('BUGTRACEAI_RUN_ID') or 'legacy-unscoped'

def resolve(*, decision_id=None, analysis_id=None, resource=None, trace_id=None)->dict[str,Any]:
    d=_read(DECISION); k=_read(KNOWLEDGE)
    did=decision_id or d.get('decision_id')
    aid=analysis_id or k.get('active_analysis_id')
    active=k.get('active_resource')
    if isinstance(active,dict): active=active.get('resource')
    res=resource or active
    tid=trace_id or (f"TR-{did}" if did else f"TR-{uuid.uuid4()}")
    return {'run_id':current_run_id(),'decision_id':did,'analysis_id':aid,'resource':res,'trace_id':tid}
