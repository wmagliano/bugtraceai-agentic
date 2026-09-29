#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/config.env"
mkdir -p "$LOG_DIR" "$ROOT_DIR/data"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$LOG_DIR/context_builder-$TS"
mkdir -p "$OUT"

printf '[+] Construyendo contexto externo para %s\n' "$TARGET_BASE"

curl -ksS -m 10 -D "$OUT/http_headers.txt" "$TARGET_BASE/" -o "$OUT/index.html" || true
nmap -Pn -sV --top-ports 100 "$TARGET_HOST" -oN "$OUT/nmap_top100.txt" >/dev/null 2>&1 || true

if command -v whatweb >/dev/null 2>&1; then
  whatweb "$TARGET_BASE" > "$OUT/whatweb.txt" 2>&1 || true
fi

python3 - "$KNOWLEDGE_FILE" "$OUT" "$TARGET_BASE" "$TARGET_HOST" <<'PY'
import json, sys, pathlib
from datetime import datetime, timezone
import re
kf=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])
target_base=sys.argv[3]; target_host=sys.argv[4]
data=json.loads(kf.read_text())
headers=(out/'http_headers.txt').read_text(errors='ignore') if (out/'http_headers.txt').exists() else ''
index=(out/'index.html').read_text(errors='ignore') if (out/'index.html').exists() else ''
nmap=(out/'nmap_top100.txt').read_text(errors='ignore') if (out/'nmap_top100.txt').exists() else ''
whatweb=(out/'whatweb.txt').read_text(errors='ignore') if (out/'whatweb.txt').exists() else ''
ports=[]
for line in nmap.splitlines():
    m=re.match(r'^(\d+/tcp)\s+open\s+([^\s]+)\s*(.*)$', line)
    if m: ports.append({'port':m.group(1),'service':m.group(2),'detail':m.group(3).strip()})
data['external_context']={
  'timestamp': datetime.now(timezone.utc).isoformat(),
  'target_base': target_base,
  'target_host': target_host,
  'output_dir': str(out),
  'http_headers_preview': headers[:2000],
  'index_title': (re.search(r'<title>(.*?)</title>', index, re.I|re.S).group(1).strip() if re.search(r'<title>(.*?)</title>', index, re.I|re.S) else None),
  'open_ports': ports,
  'whatweb_preview': whatweb[:2000]
}
kf.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PY
printf '[DONE] Contexto externo guardado en %s\n' "$OUT"
