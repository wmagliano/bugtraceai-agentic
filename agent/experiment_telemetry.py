#!/usr/bin/env python3
import json, os, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone

def load(p, default):
    try: return json.loads(Path(p).read_text())
    except Exception: return default

def dump(p, obj):
    p=Path(p); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(obj, indent=2, ensure_ascii=False))

def now(): return datetime.now(timezone.utc).isoformat()

def compact_state():
    k=load('data/knowledge.json', {})
    rs=k.get('resource_state') or {}
    counts={}
    for v in rs.values():
        s=v.get('state') if isinstance(v,dict) else str(v)
        counts[s]=counts.get(s,0)+1
    return {
      'resources_total':len(rs), 'states':counts,
      'completed_urls':len(k.get('completed_urls') or []),
      'candidate_urls':len(k.get('candidate_urls') or []),
      'cognitive_facts':len(k.get('cognitive_knowledge') or []),
      'mcp_observations':len(k.get('mcp_command_observations') or []),
      'contract_errors':len(k.get('llm_contract_validation_errors') or {}),
    }

def main():
    mode=sys.argv[1]
    run_dir=Path(os.environ['BUGTRACEAI_RUN_DIR'])
    project_id=os.environ.get('BUGTRACEAI_PROJECT_ID','default-project')
    cycle=int(os.environ.get('BUGTRACEAI_PROJECT_CYCLE','1'))
    meta={'version':'3.0.1e','project_id':project_id,'project_cycle':cycle,'run_id':os.environ.get('BUGTRACEAI_RUN_ID'),'timestamp':now()}
    if mode=='start':
        meta['phase']='start'; meta['state']=compact_state(); dump(run_dir/'experiment/start.json',meta)
    elif mode=='end':
        meta['phase']='end'; meta['state']=compact_state();
        start=load(run_dir/'experiment/start.json',{})
        meta['delta']={k:meta['state'].get(k,0)-start.get('state',{}).get(k,0) for k in ['resources_total','completed_urls','candidate_urls','cognitive_facts','mcp_observations','contract_errors']}
        dump(run_dir/'experiment/end.json',meta)
        project_dir=Path(os.environ.get('BUGTRACEAI_PROJECTS_DIR','projects'))/project_id
        project_dir.mkdir(parents=True,exist_ok=True)
        timeline=load(project_dir/'challenge_resolution_curve.json',{'project_id':project_id,'cycles':[]})
        timeline['cycles']=[x for x in timeline.get('cycles',[]) if x.get('project_cycle')!=cycle]
        timeline['cycles'].append(meta); timeline['cycles'].sort(key=lambda x:x.get('project_cycle',0))
        dump(project_dir/'challenge_resolution_curve.json',timeline)
        dump(run_dir/'experiment/challenge_progress.json',timeline)
    else: raise SystemExit('usage: experiment_telemetry.py start|end')
if __name__=='__main__': main()
