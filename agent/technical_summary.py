#!/usr/bin/env python3
import json,re,sys
from pathlib import Path
run=Path(sys.argv[1]); log=run/'logs'/'autonomous-run.log'
text=log.read_text(encoding='utf-8',errors='replace') if log.exists() else ''
patterns={
 'llm_errors':r'\[LLM ERROR\]|\[SAFE STOP\]',
 'mcp_errors':r'\[MCP ERROR\]|\[ERROR\].*MCP|returncode": [1-9]',
 'dedup':r'\[DEDUP\]',
 'loops':r'\[LOOP ESCAPE\]|3 loops detectados',
 'inconclusive':r'INCONCLUSIVE',
 'completed':r'\[AUTONOMOUS COMPLETED\]|\[OPERATOR VERDICT\]'
}
summary={k:len(re.findall(v,text,re.I)) for k,v in patterns.items()}
summary['run_id']=run.name
(run/'logs'/'run-summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
md=['# Resumen técnico de ejecución','',f'- Run ID: `{run.name}`']+[f'- {k}: **{v}**' for k,v in summary.items() if k!='run_id']
(run/'logs'/'run-summary.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
print('[LOG SUMMARY]',run/'logs'/'run-summary.json')
