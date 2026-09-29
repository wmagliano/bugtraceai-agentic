#!/usr/bin/env python3
import json

def build(system,context,knowledge,tools,constraints,operator_context,task):
 ar=context.get('active_resource') or {}
 sections=[('SYSTEM',system),('MISSION','Analizar el recurso autorizado mediante hipótesis, evidencia y veredictos técnicamente justificados.'),('CURRENT RESOURCE',json.dumps(ar,ensure_ascii=False,indent=2)),('KNOWN FACTS',json.dumps({'observation':context.get('current_observation'),'memory':context.get('relevant_memory')},ensure_ascii=False,indent=2)),('RELEVANT KNOWLEDGE',knowledge),('AVAILABLE TOOLS',tools),('CONSTRAINTS',constraints),('OPERATOR CONTEXT',operator_context),('TASK',task)]
 return '\n\n'.join(f'## {k}\n{v.strip() if isinstance(v,str) else v}' for k,v in sections if v)
