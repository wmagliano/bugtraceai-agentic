#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
from adaptive_rag import load_units,retrieve,render_selection
from config_env import load_env,as_bool,as_int
load_env(); ROOT=Path(__file__).resolve().parent; CASSETTES=ROOT/'cassettes'; LOG=ROOT/'logs/v3'; CACHE={}
def now():return datetime.now(timezone.utc).isoformat()
def write_json(name,data):LOG.mkdir(parents=True,exist_ok=True);(LOG/name).write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')
def append(name,data):LOG.mkdir(parents=True,exist_ok=True);open(LOG/name,'a',encoding='utf-8').write(json.dumps({'ts':now(),**data},ensure_ascii=False)+'\n')
def available_cassettes():return sorted(p.name for p in CASSETTES.iterdir() if p.is_dir() and (p/'manifest.json').exists())
def selected_cassette(config=None):return os.getenv('BUGTRACEAI_CASSETTE','web-vulnerabilities-2026').strip() or 'web-vulnerabilities-2026'
def load_cassette(cid):
 b=CASSETTES/cid
 if not b.is_dir():raise ValueError(f'cassette inexistente: {cid}')
 m=json.loads((b/'manifest.json').read_text()); units=load_units(b); text='\n'.join(u.text for u in units)
 return {'id':cid,'base':b,'manifest':m,'units':units,'chars':len(text),'estimated_tokens':round(len(text)/4),'sha256':hashlib.sha256(text.encode()).hexdigest()}
def rag_settings(config=None):return {'enabled':as_bool('BUGTRACEAI_RAG_ENABLED',True),'cache':as_bool('BUGTRACEAI_RAG_CACHE',True),'max_documents':as_int('BUGTRACEAI_RAG_MAX_DOCS',12),'max_tokens':as_int('BUGTRACEAI_RAG_MAX_TOKENS',4500)}
def render_prompt_block(cassette,context=None,config=None):
 s=rag_settings(config); cache=CACHE if s['cache'] else None
 if s['enabled'] and context is not None:sel=retrieve(cassette['units'],context,max_documents=s['max_documents'],max_tokens=s['max_tokens'],cache=cache)
 else:sel={'candidate_documents':0,'selected_documents':[],'discarded_documents':[],'selected_count':0,'discarded_count':0,'selected_estimated_tokens':0,'strategy':'disabled','cache_hit':False}
 return render_selection(sel),sel
def log_injection(cassette,active_resource,full_prompt,selection=None):
 s=selection or {}; docs=[{k:v for k,v in d.items() if k!='text'} for d in s.get('selected_documents',[])]; discarded=s.get('discarded_documents',[])
 event={'ts':now(),'cassette':cassette['id'],'resource':active_resource,'strategy':s.get('strategy'),'cache_hit':s.get('cache_hit',False),'cache_miss':not s.get('cache_hit',False),'candidate_documents':s.get('candidate_documents',0),'selected_count':s.get('selected_count',0),'discarded_count':s.get('discarded_count',0),'knowledge_tokens':s.get('selected_estimated_tokens',0),'prompt_tokens':round(len(full_prompt)/4),'retrieval_ms':s.get('retrieval_ms',0)}
 write_json('rag_statistics.json',event);write_json('rag_selection.json',{'ts':now(),'selected':docs,'discarded':discarded});write_json('rag_reason.json',{'ts':now(),'resource':active_resource,'signals':s.get('signals',{}),'documents':[{'id':d.get('id'),'score':d.get('score'),'reason':d.get('reason',[])} for d in docs]});append('rag_history.jsonl',event)
def log_reaction(parsed,cassette_id):
 actions=parsed.get('next_actions') or [];action=actions[0] if actions and isinstance(actions[0],dict) else {}; ref=parsed.get('reflection') or {}; hyps=parsed.get('hypotheses') or []
 prev={}
 p=LOG/'cognitive_progress.json'
 if p.exists():
  try:prev=json.loads(p.read_text())
  except:pass
 data={'ts':now(),'cassette':cassette_id,'decision_id':parsed.get('decision_id'),'previous_hypothesis':prev.get('new_hypothesis'),'new_hypothesis':hyps[0] if hyps else ref.get('interpretation'),'new_information':ref.get('learned_fact') or parsed.get('analysis_summary'),'strategy_change':action.get('action'),'reason':action.get('reason') or ref.get('next_requirement'),'learned_this_cycle':bool(ref.get('learned_fact') or (parsed.get('cognitive_updates') or {}).get('facts'))}
 write_json('cognitive_progress.json',data);append('cognitive_progress_history.jsonl',data)
