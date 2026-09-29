#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${1:-$PWD}"
NEW_IP="${2:-192.168.0.200}"
OLD_IP="${3:-}"

die(){ echo "[ERROR] $*" >&2; exit 1; }
info(){ echo "[+] $*"; }
ok(){ echo "[OK] $*"; }

valid_ip(){ python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.ip_address(sys.argv[1])
except ValueError: raise SystemExit(1)
PY
}

[[ -d "$PROJECT_DIR" ]] || die "No existe: $PROJECT_DIR"
valid_ip "$NEW_IP" || die "IP inválida: $NEW_IP"
[[ -z "$OLD_IP" ]] || valid_ip "$OLD_IP" || die "IP anterior inválida: $OLD_IP"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$PROJECT_DIR/backup-ip-$STAMP"
mkdir -p "$BACKUP"

if [[ -n "$OLD_IP" ]]; then OLD_IPS=("$OLD_IP"); else OLD_IPS=("192.168.0.200" "192.168.0.200"); fi

info "Actualizando BugTraceAI Agent a DVWA $NEW_IP"
mapfile -d '' FILES < <(find "$PROJECT_DIR" -type f \
  \( -name '*.py' -o -name '*.sh' -o -name '*.json' -o -name '*.md' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml' -o -name '*.env' -o -name '*.ini' -o -name '*.conf' \) \
  ! -path "$PROJECT_DIR/.git/*" ! -path "$PROJECT_DIR/venv/*" ! -path "$PROJECT_DIR/.venv/*" \
  ! -path "$PROJECT_DIR/runs/*" ! -path "$PROJECT_DIR/logs/*" ! -path "$PROJECT_DIR/backup-ip-*/*" -print0)

changed=0
for f in "${FILES[@]}"; do
  hit=0
  for old in "${OLD_IPS[@]}"; do grep -Fq "$old" "$f" && hit=1 && break; done
  (( hit == 1 )) || continue
  rel="${f#$PROJECT_DIR/}"; mkdir -p "$BACKUP/$(dirname "$rel")"; cp -a "$f" "$BACKUP/$rel"
  for old in "${OLD_IPS[@]}"; do sed -i "s/${old//./\\.}/${NEW_IP//./\\.}/g" "$f"; done
  echo "[UPDATED] $rel"; ((changed+=1))
done

info "Limpiando cookies, logs y artefactos anteriores"
find "$PROJECT_DIR" -type f \( -iname '*cookie*.txt' -o -iname '*.cookie' -o -iname 'cookies.txt' -o -iname 'session_guard.json' -o -iname 'last_llm_*' \) ! -path "$PROJECT_DIR/backup-ip-*/*" -delete 2>/dev/null || true
for d in "$PROJECT_DIR/runs" "$PROJECT_DIR/logs/pages" "$PROJECT_DIR/tmp"; do [[ -d "$d" ]] && find "$d" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; done
[[ -d "$PROJECT_DIR/logs" ]] && find "$PROJECT_DIR/logs" -maxdepth 1 -type f -delete 2>/dev/null || true

info "Validando sintaxis"
while IFS= read -r -d '' f; do bash -n "$f" || die "Shell inválido: $f"; done < <(find "$PROJECT_DIR" -type f -name '*.sh' ! -path '*/venv/*' ! -path '*/.venv/*' ! -path '*/backup-ip-*/*' -print0)
python3 - "$PROJECT_DIR" <<'PY'
import json,pathlib,py_compile,sys
root=pathlib.Path(sys.argv[1]); bad=[]
for p in root.rglob('*.json'):
    if any(x in p.parts for x in ('.git','venv','.venv','runs','logs')) or any(x.startswith('backup-ip-') for x in p.parts): continue
    try: json.loads(p.read_text(encoding='utf-8'))
    except Exception as e: bad.append(f'JSON {p}: {e}')
for p in root.rglob('*.py'):
    if any(x in p.parts for x in ('.git','venv','.venv','runs','logs')) or any(x.startswith('backup-ip-') for x in p.parts): continue
    try: py_compile.compile(str(p),doraise=True)
    except Exception as e: bad.append(f'PY {p}: {e}')
if bad: print('\n'.join(bad),file=sys.stderr); raise SystemExit(1)
PY

grep -RIlF --exclude-dir=.git --exclude-dir=venv --exclude-dir=.venv --exclude-dir=runs --exclude-dir=logs "$NEW_IP" "$PROJECT_DIR" >/tmp/bugtraceai-agent-ip-files.txt || die "La nueva IP no quedó aplicada"

if curl -fsS --max-time 8 "http://$NEW_IP/login.php" | grep -qiE 'DVWA|Damn Vulnerable'; then ok "DVWA responde en $NEW_IP"; else echo "[WARN] No se pudo validar DVWA en $NEW_IP"; fi
ok "Agent actualizado. Archivos modificados: $changed"
echo "Respaldo: $BACKUP"
