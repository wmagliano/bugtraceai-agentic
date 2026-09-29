#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

SITE="${1:-}"
if [[ -z "$SITE" ]]; then
  echo "BugTraceAI R0-v2 - Web Target Setup"
  echo "  1) DVWA"
  echo "  2) bWAPP"
  read -r -p "Seleccione [1/2]: " choice
  case "$choice" in 1) SITE=dvwa;; 2) SITE=bwapp;; *) echo "Selección inválida" >&2; exit 2;; esac
fi
SITE="${SITE,,}"
TEMPLATE="config/sites/${SITE}.json"
[[ -f "$TEMPLATE" ]] || { echo "Perfil no soportado: $SITE" >&2; exit 3; }

python3 - "$SITE" "$TEMPLATE" <<'PYSETUP'
import json,sys,ipaddress
from pathlib import Path
from urllib.parse import urlsplit
site,template=sys.argv[1:3]
cfg=json.loads(Path(template).read_text(encoding='utf-8'))
def ask(label,default):
    try: v=input(f"{label} [{default}]: ").strip()
    except EOFError: v=''
    return v or str(default)
base=ask('Base URL',cfg['target']['base_url']).rstrip('/')
host_default=urlsplit(base).hostname or cfg['target'].get('target_host','')
host=ask('Target host/IP',host_default)
mcp=ask('Kali MCP base',cfg['target']['kali_mcp_base']).rstrip('/')
kali=ask('Kali host',urlsplit(mcp).hostname or cfg['target'].get('kali_host',''))
user=ask('Usuario',cfg['authentication'].get('username',''))
pwd=ask('Password',cfg['authentication'].get('password',''))
security=ask('Nivel de seguridad',cfg['authentication'].get('security','low')).lower()
cfg['target'].update(base_url=base,target_host=host,kali_host=kali,kali_mcp_base=mcp)
cfg['authentication']['username']=user; cfg['authentication']['password']=pwd; cfg['authentication']['security']=security
cfg['authentication']['login_url']=base+'/login.php'
cfg['cassette']={'id':'web-vulnerabilities-2026'}
Path('config/site.json').write_text(json.dumps(cfg,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print('\n[OK] config/site.json generado')
print('[SITE]',site)
print('[TARGET]',base)
print('[CASSETTE] web-vulnerabilities-2026')
if site=='bwapp':
    print('[NOTE] El perfil bWAPP queda generado. R0-v2 conserva todavía el Session Guard DVWA; validar/adaptar autenticación bWAPP en la fase bWAPP antes del ensayo completo.')
PYSETUP

# deterministic schema/preflight
python3 bugtraceai_config.py --shell config/site.json >/dev/null
[[ -f cassettes/web-vulnerabilities-2026/manifest.json ]] || { echo "Cassette faltante" >&2; exit 4; }
echo "[VALIDATION] configuración y cassette: OK"
echo "Prueba sugerida DVWA: python3 bugtraceai-runner.py --ciclos 2 --bucles 500 --config config/site.json --cassette web-vulnerabilities-2026"
