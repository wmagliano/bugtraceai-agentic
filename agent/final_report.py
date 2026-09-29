#!/usr/bin/env python3
from __future__ import annotations
import html,json
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from evidence_bundle import generate as generate_evidence
from capability_gate import evaluate_architecture_validation
ROOT=Path(__file__).resolve().parent; K=ROOT/'data'/'knowledge.json'; OUT=ROOT/'reports'
def load():
    try:return json.loads(K.read_text(encoding='utf-8'))
    except Exception:return {}
def txt(x):
    if isinstance(x,dict): return x.get('text') or x.get('content') or x.get('finding') or json.dumps(x,ensure_ascii=False)
    return str(x)
def main():
    k=load(); OUT.mkdir(parents=True,exist_ok=True); items=[x for x in k.get('analysis_queue') or [] if isinstance(x,dict)]
    states=Counter(str(x.get('state') or 'NEW').upper() for x in items); verdicts=Counter(('UNASSESSED' if str((x.get('state') or 'NEW')).upper() in {'NEW','MAPPED'} else 'INCONCLUSIVE') if str((x.get('vulnerability_verdict') or {}).get('status') or 'UNASSESSED').upper() in {'UNKNOWN','UNASSESSED'} else str((x.get('vulnerability_verdict') or {}).get('status')).upper() for x in items); exploits=Counter(str((x.get('exploitation') or {}).get('status') or 'NOT_ATTEMPTED').upper() for x in items); now=datetime.now(timezone.utc).isoformat(); generate_evidence(k)
    lines=['# BugTraceAI — Reporte final auditable','',f'- Generado: `{now}`',f'- Analysis Items: **{len(items)}**',f'- Evidence Bundles: **{len(items)}**','', '## Resumen de estados','']
    for st,n in sorted(states.items()): lines.append(f'- {st}: **{n}**')
    lines += ['', '## Resumen de veredictos de vulnerabilidad','']
    for st,n in sorted(verdicts.items()): lines.append(f'- {st}: **{n}**')
    lines += ['', '## Resumen de explotación','']
    for st,n in sorted(exploits.items()): lines.append(f'- {st}: **{n}**')
    lines += ['', '## Resultados por Analysis Item','']
    findings=[]
    for idx,item in enumerate(items,1):
        aid=item.get('analysis_id') or f'A-{idx:04d}'; url=item.get('entry_url') or ''; state=str(item.get('state') or 'NEW').upper(); closure=item.get('closure') or {}; report=item.get('report') or {}
        conclusion=(report.get('finding') if isinstance(report,dict) else None) or closure.get('reason') or 'Sin conclusión registrada.'
        commands=item.get('commands') or []; evidence=item.get('evidence') or []; hypotheses=item.get('hypotheses') or []; observations=item.get('observations') or []; vulnerability=dict(item.get('vulnerability_verdict') or {'status':'UNASSESSED'})
        if str(vulnerability.get('status') or '').upper()=='UNKNOWN':
            vulnerability['status']='UNASSESSED' if state in {'NEW','MAPPED'} else 'INCONCLUSIVE'
        exploitation=item.get('exploitation') or {'status':'NOT_ATTEMPTED'}
        capability=evaluate_architecture_validation(item.get('entry_url'))
        classification=item.get('finding_classification') or {'type':'VULNERABILITY'}
        findings.append({'analysis_id':aid,'url':url,'state':state,'vulnerability_verdict':vulnerability,'exploitation':exploitation,'capability_assessment':capability,'finding_classification':classification,'conclusion':conclusion,'command_count':len(commands),'evidence_count':len(evidence),'bundle':f'evidence/{aid}/report.md'})
        lines += [f'### {idx}. {aid} — {url}',f'- Estado del análisis: **{state}**',f'- Vulnerabilidad: **{vulnerability.get("status","UNASSESSED")}** — confianza: **{vulnerability.get("confidence") or "N/D"}**',f'- Explotación: **{exploitation.get("status","NOT_ATTEMPTED")}**',f'- Tipo de hallazgo: **{classification.get("type","VULNERABILITY")}**',f'- Validación arquitectónica: **{capability.get("status","REQUIRES_OPERATOR_VALIDATION")}**',f'- Conclusión operativa: {conclusion}',f'- Resumen de vulnerabilidad: {vulnerability.get("summary") or "Sin resumen explícito."}',f'- Resumen de explotación: {exploitation.get("summary") or "Sin resumen explícito."}',f'- Observaciones: **{len(observations)}**',f'- Hipótesis: **{len(hypotheses)}**',f'- Comandos MCP solicitados por el LLM: **{len(commands)}**',f'- Evidencias: **{len(evidence)}**',f'- Expediente: `reports/evidence/{aid}/report.md`','']
        if commands:
            lines += ['#### Bitácora de comandos','']
            for i,c in enumerate(commands,1):
                lines += [f'{i}. `{c.get("timestamp") or "N/D"}` — {c.get("reason") or "Sin motivo"}','```bash',str(c.get('command') or ''),'```',f'   - Estado: `{c.get("execution_status") or "UNKNOWN_RESULT"}` | Ejecutado: `{c.get("executed",True)}` | OK: `{c.get("ok")}` | Return code: `{c.get("returncode")}`',f'   - SHA-256 stdout: `{c.get("stdout_sha256") or "N/D"}`','']
        if evidence:
            lines += ['#### Evidencia usada en el cierre','']+[f'- {txt(e)}' for e in evidence]+['']
    specialized=[]
    for item in items:
        cap=item.get('capability_assessment') or {}
        if str(cap.get('status') or '').upper() == 'REQUIRES_OPERATOR_VALIDATION':
            specialized.append((item,cap))
    if specialized:
        lines += ['', '## Hallazgos que requieren validación del operador','', 'El LLM puede conservar su conclusión de vulnerabilidad, pero la arquitectura marca independientemente los hallazgos cuyo dominio de validación final requiere instrumental no disponible.','']
        for item,cap in specialized:
            aid=item.get('analysis_id') or 'N/D'; url=item.get('entry_url') or ''; vv=item.get('vulnerability_verdict') or {}; ex=item.get('exploitation') or {}
            lines += [f'### {aid} — {url}',f'- Vulnerabilidad: **{vv.get("status","UNASSESSED")}**',f'- Explotación: **{ex.get("status","NOT_ATTEMPTED")}**',f'- Capacidades no disponibles: `{", ".join(cap.get("unavailable_capabilities") or []) or "N/D"}`',f'- Motivo: {cap.get("reason") or "La validación final requiere una capacidad no disponible en la arquitectura actual."}',f'- Recomendación: {cap.get("recommended_validation") or "Validar con una herramienta especializada adecuada al runtime requerido."}','']
    md='\n'.join(lines); (OUT/'bugtraceai-final-report.md').write_text(md,encoding='utf-8')
    page='<!doctype html><html lang="es"><head><meta charset="utf-8"><title>BugTraceAI Reporte Final</title><style>body{font-family:system-ui;margin:2rem;max-width:1200px}pre{white-space:pre-wrap;line-height:1.45}</style></head><body><pre>'+html.escape(md)+'</pre></body></html>'
    (OUT/'bugtraceai-final-report.html').write_text(page,encoding='utf-8')
    payload={'schema_version':'2.2.3.3','generated_at':now,'state_counts':dict(states),'vulnerability_verdict_counts':dict(verdicts),'exploitation_counts':dict(exploits),'analysis_items':findings,'evidence_root':'reports/evidence'}
    (OUT/'bugtraceai-final-report.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
    print('[REPORT] reports/bugtraceai-final-report.md'); print('[REPORT] reports/bugtraceai-final-report.html'); print('[REPORT] reports/bugtraceai-final-report.json'); print(f'[EVIDENCE] {len(items)} expediente(s) en reports/evidence')
if __name__=='__main__':main()
