#!/usr/bin/env bash
set -euo pipefail
DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"; IP="${2:-}"
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Uso: $0 [DIR] IP"; exit 2; }
python3 - "$DIR/kali_mcp_server.py" "$IP" <<'PY'
from pathlib import Path
import re,sys,ipaddress
p=Path(sys.argv[1]); ip=str(ipaddress.ip_address(sys.argv[2])); s=p.read_text()
n,c=re.subn(r'^TARGET_HOST\s*=\s*["\'][^"\']+["\']',f'TARGET_HOST = "{ip}"',s,count=1,flags=re.M)
if c!=1: raise SystemExit("TARGET_HOST no encontrado")
p.with_suffix('.py.bak').write_text(s); p.write_text(n); print("[UPDATED]",ip)
PY
python3 -m py_compile "$DIR/kali_mcp_server.py"
"$DIR/install_kali_assets.sh"
echo "[INFO] Reinicie Uvicorn y ejecute: $DIR/validate_bugtraceai_mcp.sh $IP"
