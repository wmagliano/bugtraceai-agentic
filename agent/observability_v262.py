#!/usr/bin/env python3
from __future__ import annotations
import json,re,hashlib,argparse
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter,defaultdict
from verdict_engine_v262 import build as build_verdicts, load_knowledge
ROOT=Path(__file__).resolve().parent; LOG=ROOT/'logs'; REPORT=ROOT/'reports'
def now(): return datetime.now(timezone.utc).isoformat()
def load_jsonl(p):
 out=[]
 if not p.exists(): return out
 for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
  try:
   x=json.loads(line)
   if isinstance(x,dict): out.append(x)
  except: pass
 return out
def dump(p,o): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(o,indent=2,ensure_ascii=False,default=str)+'\n',encoding='utf-8')
def resource(e): return e.get('resource') or (e.get('data') or {}).get('resource') or 'unknown'
def flow(e): return e.get('trace_id') or e.get('decision_id') or e.get('rejection_id') or e.get('event_id') or 'unlinked'
def action(e):
 d=e.get('data') or {}; return e.get('action') or d.get('action') or d.get('command') or ''
def generate(run_id=None,all_runs=False):
 events=load_jsonl(LOG/'runtime_events.jsonl')
 selected=events if all_runs else [e for e in events if (e.get('run_id') or 'legacy-unscoped')==(run_id or __import__('os').environ.get('BUGTRACEAI_RUN_ID') or 'legacy-unscoped')]
 selected.sort(key=lambda e:e.get('timestamp','')); effective_run='all-runs' if all_runs else (run_id or __import__('os').environ.get('BUGTRACEAI_RUN_ID') or 'legacy-unscoped')
 outdir=REPORT/('runs/'+effective_run if not all_runs else 'all-runs'); outdir.mkdir(parents=True,exist_ok=True)
 grouped=defaultdict(list)
 for e in selected: grouped[flow(e)].append(e)
 # timeline
 with (outdir/'decision_timeline.jsonl').open('w',encoding='utf-8') as f:
  for fid,items in grouped.items(): f.write(json.dumps({'run_id':effective_run,'correlation_id':fid,'decision_id':next((x.get('decision_id') for x in items if x.get('decision_id')),None),'analysis_id':next((x.get('analysis_id') for x in items if x.get('analysis_id')),None),'resource':next((resource(x) for x in items if resource(x)!='unknown'),'unknown'),'event_count':len(items),'stages':[{'timestamp':x.get('timestamp'),'stage':x.get('stage'),'event_type':x.get('event_type'),'status':x.get('status'),'event_id':x.get('event_id'),'executor_id':x.get('executor_id'),'mcp_execution_id':x.get('mcp_execution_id'),'evidence_id':x.get('evidence_id')} for x in items]},ensure_ascii=False)+'\n')
 # resources and state inference
 R=defaultdict(lambda:{'events':0,'flows':set(),'stages':Counter(),'mcp_commands':0,'mcp_ok':0,'executor_events':0,'evidence_events':0,'accepted':0,'rejected':0,'signals':Counter(),'first':None,'last':None})
 for e in selected:
  r=resource(e); x=R[r]; x['events']+=1;x['flows'].add(flow(e));x['stages'][str(e.get('stage'))]+=1;x['first']=x['first'] or e.get('timestamp');x['last']=e.get('timestamp')
  st=str(e.get('stage')); et=str(e.get('event_type','')).upper(); status=str(e.get('status','')).upper(); blob=json.dumps(e,ensure_ascii=False).upper()
  if st=='mcp': x['mcp_commands']+=1; x['mcp_ok']+= status=='OK'
  if st=='executor': x['executor_events']+=1
  if st=='evidence': x['evidence_events']+=1
  if 'ACCEPTED' in et or status=='ACCEPTED': x['accepted']+=1
  if 'REJECT' in et or status=='REJECTED': x['rejected']+=1
  for sig in ('CONFIRMED','COMPLETED','NO_FINDING','INCONCLUSIVE'):
   if sig in blob: x['signals'][sig]+=1
 scoreboard={}
 rank=['CONFIRMED','COMPLETED','NO_FINDING','INCONCLUSIVE']
 for r,x in R.items():
  state=next((s for s in rank if x['signals'][s]),'ACTIVE')
  scoreboard[r]={'status':state,'events':x['events'],'flows':len(x['flows']),'stages':dict(x['stages']),'mcp_commands':x['mcp_commands'],'mcp_ok':x['mcp_ok'],'executor_events':x['executor_events'],'evidence_events':x['evidence_events'],'contract_accepted':x['accepted'],'contract_rejected':x['rejected'],'state_signals':dict(x['signals']),'first_timestamp':x['first'],'last_timestamp':x['last']}
 dump(outdir/'resource_scoreboard.json',{'generated_at':now(),'run_id':effective_run,'resources':scoreboard})
 # pipeline
 stages=['reasoner','contract','executor','mcp','evidence','scheduler']; total=max(1,len(grouped)); reached={s:sum(any(e.get('stage')==s for e in items) for items in grouped.values()) for s in stages}
 lines=['# Pipeline Heatmap','',f'Run: {effective_run}',f'Generated: {now()}','',f'Correlated flows: {len(grouped)}','']
 for s in stages:
  pct=round(100*reached[s]/total); blocks=round(pct/6.25);lines.append(f"{s.capitalize():12} {('█'*blocks)+('░'*(16-blocks))} {pct}% ({reached[s]}/{len(grouped)})")
 (outdir/'pipeline_heatmap.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 # health
 accepted=sum(x['accepted'] for x in R.values()); rejected=sum(x['rejected'] for x in R.values()); mcp=sum(x['mcp_commands'] for x in R.values()); mcpok=sum(x['mcp_ok'] for x in R.values())
 scores={'reasoner':round(100*reached['reasoner']/total),'contract':round(100*accepted/max(1,accepted+rejected)),'executor':round(100*reached['executor']/total),'mcp':round(100*mcpok/max(1,mcp)),'evidence':round(100*reached['evidence']/total),'correlation':round(100*sum(1 for e in selected if e.get('run_id') and e.get('trace_id') and e.get('decision_id'))/max(1,len(selected)))};scores['overall']=round(sum(scores.values())/len(scores))
 dump(outdir/'health_score.json',{'generated_at':now(),'run_id':effective_run,'scores':scores,'note':'Operational observability indicator; not a security assurance.'})
 dump(outdir/'version_metrics.json',{'generated_at':now(),'run_id':effective_run,'version':(ROOT/'VERSION').read_text().strip(),'events':len(selected),'flows':len(grouped),'resources':len(R),'mcp_commands':mcp,'mcp_success':mcpok,'executor_events':sum(x['executor_events'] for x in R.values()),'evidence_events':sum(x['evidence_events'] for x in R.values()),'unknown_resource_events':sum(resource(e)=='unknown' for e in selected)})
 # replay
 rep=['# Campaign Replay','',f'Run: {effective_run}',f'Generated: {now()}','']
 for fid,items in grouped.items():
  rep += [f'## Trace {fid}',f'- Decision: `{next((x.get("decision_id") for x in items if x.get("decision_id")),"unknown")}`',f'- Analysis: `{next((x.get("analysis_id") for x in items if x.get("analysis_id")),"unknown")}`',f'- Resource: `{next((resource(x) for x in items if resource(x)!="unknown"),"unknown")}`']
  for e in items: rep.append(f"- {e.get('timestamp')} | {e.get('stage')} | {e.get('event_type')} | {e.get('status')}")
  rep.append('')
 (outdir/'campaign_replay.md').write_text('\n'.join(rep)+'\n',encoding='utf-8')
 # verdict-centered diagnostics v2.6.0c
 verdicts=build_verdicts(load_knowledge())
 verdicts['run_id']=effective_run
 dump(outdir/'security_verdicts.json',verdicts)
 v=verdicts.get('summary') or {}
 dump(outdir/'run_summary.json',{
  'generated_at':now(),'run_id':effective_run,'version':(ROOT/'VERSION').read_text().strip(),
  'events':len(selected),'flows':len(grouped),'resources':len(R),
  'mcp_commands':mcp,'mcp_success':mcpok,
  'assessment':{'unassessed':v.get('unassessed',0),'assessed':v.get('assessed',0)},
  'vulnerability':v.get('vulnerability',{}),
  'exploitability':v.get('exploitability',{}),
  'confirmed_vulnerabilities':v.get('confirmed_vulnerabilities',0),
  'confirmed_exploitability':v.get('confirmed_exploitability',0),
  'no_finding':v.get('no_finding',0),'inconclusive':v.get('inconclusive',0),
  'operator_handoffs':v.get('operator_handoffs',0),
  'consistency_warnings':v.get('consistency_warnings',0),
  'health':scores})
 # compatibility copies for latest/default, only for a valid scoped campaign
 if not all_runs:
  if effective_run.upper().startswith('SELFTEST'):
   raise RuntimeError(f'refusing to publish selftest diagnostics as campaign reports: {effective_run}')
  for name in ('resource_scoreboard.json','pipeline_heatmap.md','health_score.json','version_metrics.json','campaign_replay.md','security_verdicts.json','run_summary.json'):
   (REPORT/name).write_bytes((outdir/name).read_bytes())
  (LOG/'decision_timeline.jsonl').write_bytes((outdir/'decision_timeline.jsonl').read_bytes())
 return {'run_id':effective_run,'events':len(selected),'flows':len(grouped),'output_dir':str(outdir),'health':scores}
if __name__=='__main__':
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group();g.add_argument('--run-id');g.add_argument('--all-runs',action='store_true');a=ap.parse_args();print(json.dumps(generate(a.run_id,a.all_runs),indent=2,ensure_ascii=False))
