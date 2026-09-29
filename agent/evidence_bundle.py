#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from lifecycle_trace import emit

ROOT=Path(__file__).resolve().parent
DATA=ROOT/'data'/'knowledge.json'
OUT=ROOT/'reports'/'evidence'
TERMINAL={'COMPLETED','INCONCLUSIVE','FAILED','SKIPPED'}

def utc_now(): return datetime.now(timezone.utc).isoformat()
def sha256_text(value: Any)->str:
    return hashlib.sha256(str(value or '').encode('utf-8','replace')).hexdigest()
def safe_name(value:str)->str:
    return re.sub(r'[^A-Za-z0-9_.-]+','_',value or 'UNKNOWN')
def load(path=DATA):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except Exception: return {}
def write(path:Path,obj:Any):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
def command_record(cmd:dict,index:int)->dict:
    stdout=cmd.get('stdout_preview') or ''
    stderr=cmd.get('stderr_preview') or ''
    return {
      'command_id':cmd.get('command_id') or f'CMD-{index:04d}',
      'decision_id':cmd.get('decision_id'),
      'requested_by':'LLM',
      'requested_at':cmd.get('timestamp'),
      'action':cmd.get('action') or cmd.get('source_action') or 'propose_mcp_command',
      'reason':cmd.get('reason'),
      'command':cmd.get('command'),
      'tested_url':cmd.get('tested_url'),
      'risk_level':cmd.get('risk_level'),
      'approved':cmd.get('approved',True),
      'executed':cmd.get('executed',True),
      'ok':cmd.get('ok'),
      'returncode':cmd.get('returncode'),
      'stdout_preview':stdout,
      'stderr_preview':stderr,
      'stdout_sha256':cmd.get('stdout_sha256') or sha256_text(stdout),
      'stderr_sha256':cmd.get('stderr_sha256') or sha256_text(stderr),
      'evidence_hint':cmd.get('evidence_hint'),
      'verified_evidence':cmd.get('verified_evidence') or [],
      'execution_status':cmd.get('execution_status') or ('SUCCEEDED' if cmd.get('ok') is True else 'FAILED' if cmd.get('returncode') is not None else 'UNKNOWN_RESULT'),
    }
def timeline(item:dict)->list[dict]:
    events=[]
    for key,kind in [('observations','observation'),('hypotheses','hypothesis'),('actions','action'),('commands','command'),('evidence','evidence'),('state_history','state')]:
        for obj in item.get(key) or []:
            if not isinstance(obj,dict): continue
            events.append({'timestamp':obj.get('timestamp') or obj.get('updated_at') or '', 'type':kind, 'data':obj})
    events.sort(key=lambda x:x.get('timestamp') or '')
    return events
def bundle_for(item:dict)->dict:
    commands=[command_record(x,i) for i,x in enumerate(item.get('commands') or [],1) if isinstance(x,dict)]
    return {
      'schema_version':'2.2.3.3',
      'generated_at':utc_now(),
      'analysis_id':item.get('analysis_id'),
      'entry_url':item.get('entry_url'),
      'state':item.get('state'),
      'created_at':item.get('created_at'),
      'started_at':item.get('started_at'),
      'finished_at':item.get('finished_at'),
      'closure':item.get('closure'),
      'vulnerability_verdict':item.get('vulnerability_verdict') or {'status':'UNKNOWN'},
      'exploitation':item.get('exploitation') or {'status':'NOT_ATTEMPTED'},
      'operator_assessment':item.get('operator_assessment'),
      'observations':item.get('observations') or [],
      'hypotheses':item.get('hypotheses') or [],
      'actions':item.get('actions') or [],
      'commands':commands,
      'evidence':item.get('evidence') or [],
      'timeline':timeline(item),
      'report':item.get('report'),
    }
def md_for(bundle:dict)->str:
    lines=[f"# Evidence Bundle — {bundle.get('analysis_id')}",'',f"- URL: `{bundle.get('entry_url')}`",f"- Estado: **{bundle.get('state')}**",f"- Inicio: `{bundle.get('started_at') or 'N/D'}`",f"- Fin: `{bundle.get('finished_at') or 'N/D'}`",'']
    lines += ['## Resultado del análisis','',json.dumps(bundle.get('closure'),ensure_ascii=False,indent=2) if bundle.get('closure') else 'Sin cierre registrado.','', '## Veredicto de vulnerabilidad','', json.dumps(bundle.get('vulnerability_verdict'),ensure_ascii=False,indent=2), '', '## Estado de explotación','', json.dumps(bundle.get('exploitation'),ensure_ascii=False,indent=2), '']
    for title,key in [('Observaciones','observations'),('Hipótesis','hypotheses'),('Evidencias','evidence')]:
        lines += [f'## {title}','']
        vals=bundle.get(key) or []
        if not vals: lines.append('- Sin registros.')
        for x in vals:
            if isinstance(x,dict): lines.append(f"- {x.get('text') or x.get('content') or json.dumps(x,ensure_ascii=False)}")
            else: lines.append(f'- {x}')
        lines.append('')
    lines += ['## Validation Timeline','']
    cmds=bundle.get('commands') or []
    if not cmds:
        lines.append('- No se realizaron intentos de validación.')
    for i,c in enumerate(cmds,1):
        evidence_state='sí' if c.get('verified_evidence') else 'no'
        lines += [f'### Intento {i}',f'- URL probada: `{c.get("tested_url") or "N/D"}`',f'- Estado: **{c.get("execution_status")}**',f'- Return code: `{c.get("returncode")}`',f'- Evidencia verificada: **{evidence_state}**',f'- Motivo: {c.get("reason") or "N/D"}','']
    lines += ['## Bitácora de comandos solicitados por el LLM','']
    cmds=bundle.get('commands') or []
    if not cmds: lines.append('- No se solicitaron comandos MCP.')
    for i,c in enumerate(cmds,1):
        lines += [f'### {i}. {c.get("command_id")}',f'- Solicitado: `{c.get("requested_at") or "N/D"}`',f'- Acción: `{c.get("action")}`',f'- Motivo: {c.get("reason") or "N/D"}',f'- URL probada: `{c.get("tested_url") or "N/D"}`',f'- Estado de ejecución: **{c.get("execution_status")}**',f'- Ejecutado: **{c.get("executed")}**',f'- OK: **{c.get("ok")}**',f'- Return code: `{c.get("returncode")}`','', '```bash',str(c.get('command') or ''),'```','',f'- SHA-256 stdout: `{c.get("stdout_sha256")}`',f'- SHA-256 stderr: `{c.get("stderr_sha256")}`']
        if c.get('verified_evidence'): lines.append(f'- Evidencia verificada: {json.dumps(c.get("verified_evidence"),ensure_ascii=False)}')
        if c.get('stdout_preview'): lines += ['','Salida resumida:','```text',str(c.get('stdout_preview')),'```']
        if c.get('stderr_preview'): lines += ['','Error resumido:','```text',str(c.get('stderr_preview')),'```']
        lines.append('')
    return '\n'.join(lines)
def generate(k:dict|None=None)->list[Path]:
    k=k or load(); OUT.mkdir(parents=True,exist_ok=True); created=[]
    for item in k.get('analysis_queue') or []:
        if not isinstance(item,dict): continue
        aid=safe_name(str(item.get('analysis_id') or 'UNKNOWN')); d=OUT/aid; d.mkdir(parents=True,exist_ok=True)
        bundle=bundle_for(item)
        write(d/'summary.json',{x:bundle.get(x) for x in ('schema_version','generated_at','analysis_id','entry_url','state','created_at','started_at','finished_at','closure','report')})
        write(d/'commands.json',bundle['commands']); write(d/'assessment.json',{'vulnerability_verdict':bundle['vulnerability_verdict'],'exploitation':bundle['exploitation'],'operator_assessment':bundle['operator_assessment']}); write(d/'evidence.json',bundle['evidence']); write(d/'timeline.json',bundle['timeline']); write(d/'bundle.json',bundle)
        (d/'report.md').write_text(md_for(bundle),encoding='utf-8'); created.append(d)
        emit('REPORT_EXPORT',analysis_id=item.get('analysis_id'),resource=item.get('entry_url'),component='evidence_bundle',state=item.get('state'),output=str(d))
    return created
if __name__=='__main__':
    paths=generate(); print(f'[EVIDENCE] {len(paths)} bundle(s) generados en reports/evidence')
