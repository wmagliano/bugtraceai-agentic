#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/config.env"
mkdir -p "$LOG_DIR" "$ROOT_DIR/data"
LOG="$LOG_DIR/herramientas.log"
: > "$LOG"

required=(bash curl jq python3 grep sed awk tee nmap)
optional=(whatweb nikto gobuster ffuf feroxbuster sqlmap)
missing_required=()
missing_optional=()

printf '[+] Validando laboratorio Kali\n' | tee -a "$LOG"
for bin in "${required[@]}"; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf '[OK] %s\n' "$bin" | tee -a "$LOG"
  else
    printf '[ERROR] Falta requerido: %s\n' "$bin" | tee -a "$LOG"
    missing_required+=("$bin")
  fi
done

for bin in "${optional[@]}"; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf '[OK] opcional %s\n' "$bin" | tee -a "$LOG"
  else
    printf '[WARN] Falta opcional: %s\n' "$bin" | tee -a "$LOG"
    missing_optional+=("$bin")
  fi
done

printf '[+] Validando conectividad con TARGET_HOST=%s\n' "$TARGET_HOST" | tee -a "$LOG"
if ping -c 1 -W 2 "$TARGET_HOST" >/dev/null 2>&1; then
  printf '[OK] Ping responde %s\n' "$TARGET_HOST" | tee -a "$LOG"
else
  printf '[WARN] Ping no responde. Se probará HTTP igualmente.\n' | tee -a "$LOG"
fi

if curl -ks --max-time 5 "$TARGET_BASE/" >/dev/null; then
  printf '[OK] HTTP responde %s\n' "$TARGET_BASE" | tee -a "$LOG"
else
  printf '[ERROR] No responde HTTP: %s\n' "$TARGET_BASE" | tee -a "$LOG"
fi

python3 - "$KNOWLEDGE_FILE" "$LOG" "${missing_required[*]}" "${missing_optional[*]}" <<'PY'
import json, sys, pathlib
from datetime import datetime, timezone
kf=pathlib.Path(sys.argv[1]); log=sys.argv[2]
missing_required=sys.argv[3].split() if len(sys.argv)>3 and sys.argv[3] else []
missing_optional=sys.argv[4].split() if len(sys.argv)>4 and sys.argv[4] else []
data=json.loads(kf.read_text())
data.setdefault('tool_validation', {})
data['tool_validation']={
  'timestamp': datetime.now(timezone.utc).isoformat(),
  'log': log,
  'missing_required': missing_required,
  'missing_optional': missing_optional,
  'ready': not missing_required
}
kf.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PY

if ((${#missing_required[@]})); then
  printf '[FAIL] Faltan herramientas requeridas. Corregir antes de continuar.\n' | tee -a "$LOG"
  exit 1
fi
printf '[DONE] Validación terminada.\n' | tee -a "$LOG"
