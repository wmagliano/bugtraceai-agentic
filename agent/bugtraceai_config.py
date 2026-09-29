#!/usr/bin/env python3
from __future__ import annotations
import json, os, shlex, sys
from pathlib import Path

def load(path: str):
    p=Path(path)
    data=json.loads(p.read_text(encoding='utf-8'))
    required=['target','authentication','http','scheduler','reporting','discovery']
    missing=[x for x in required if x not in data]
    if missing: raise SystemExit(f"Config inválida; faltan: {', '.join(missing)}")
    return data

def emit_shell(c):
    t=c['target']; a=c['authentication']; h=c['http']; s=c['scheduler']; r=c['reporting']; d=c['discovery']; sc=c.get('scope',{})
    vals={
      'BUGTRACEAI_CONFIG_PROFILE':c.get('profile','custom'),
      'BUGTRACEAI_CASSETTE':(c.get('cassette',{}).get('id','dvwa-lab') if isinstance(c.get('cassette'),dict) else c.get('cassette','dvwa-lab')),
      'BUGTRACEAI_TARGET_BASE':t['base_url'].rstrip('/'),
      'BUGTRACEAI_TARGET_HOST':t.get('target_host',''),
      'BUGTRACEAI_KALI_HOST':t.get('kali_host',''),
      'BUGTRACEAI_MCP_BASE':t.get('kali_mcp_base',''),
      'BUGTRACEAI_AUTH_TYPE':a.get('type','none'),
      'BUGTRACEAI_USERNAME':a.get('username',''),
      'BUGTRACEAI_PASSWORD':a.get('password',''),
      'BUGTRACEAI_DVWA_SECURITY':a.get('security','low'),
      'BUGTRACEAI_LOGIN_URL':a.get('login_url',''),
      'BUGTRACEAI_COOKIE_JAR':a.get('cookie_jar',''),
      'BUGTRACEAI_USER_AGENT':h.get('user_agent','BugTraceAI'),
      'BUGTRACEAI_HTTP_HEADERS_JSON':json.dumps(h.get('headers',{}),ensure_ascii=False),
      'BUGTRACEAI_HTTP_TIMEOUT':str(h.get('timeout',20)),
      'BUGTRACEAI_AUTONOMOUS':'1' if s.get('autonomous',True) else '0',
      'BUGTRACEAI_MAX_MCP_COMMANDS':str(s.get('max_mcp_commands_per_resource',4)),
      'BUGTRACEAI_MAX_RESOURCE_ITERATIONS':str(s.get('max_resource_iterations_per_analysis',20)),
      'BUGTRACEAI_SPECIALIZED_LAST_ATTEMPT':'1' if s.get('specialized_last_attempt',True) else '0',
      'BUGTRACEAI_MAX_ERRORS':str(s.get('max_errors_per_resource',3)),
      'BUGTRACEAI_MAX_CYCLES':str(s.get('max_cycles',500)),
      'BUGTRACEAI_RUNS_DIR':r.get('run_directory','runs'),
      'BUGTRACEAI_DISCOVERY_MODE':d.get('mode','auto'),
      'BUGTRACEAI_DISCOVERY_SAME_ORIGIN':'1' if d.get('same_origin_only',True) else '0',
      'BUGTRACEAI_DISCOVERY_MAX_URLS':str(d.get('max_urls',500)),
      'BUGTRACEAI_DISCOVERY_STATIC_POLICY':d.get('static_resource_policy','ignore'),
      'BUGTRACEAI_DISCOVERY_STATIC_EXTENSIONS_JSON':json.dumps(d.get('static_extensions',[]),ensure_ascii=False),
      'BUGTRACEAI_DISCOVERY_FRAGMENT_POLICY':d.get('fragment_policy','discard'),
      'BUGTRACEAI_URL_BLACKLIST_JSON':json.dumps(sc.get('url_blacklist',[]),ensure_ascii=False),
      'BUGTRACEAI_VULN_BLACKLIST_JSON':json.dumps(sc.get('vulnerability_blacklist',{}),ensure_ascii=False)
    }
    for k,v in vals.items(): print(f'export {k}={shlex.quote(str(v))}')

if __name__=='__main__':
    if len(sys.argv)<3 or sys.argv[1] != '--shell': raise SystemExit('uso: bugtraceai_config.py --shell config.json')
    emit_shell(load(sys.argv[2]))
