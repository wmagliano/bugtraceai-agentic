#!/usr/bin/env bash
set -Eeuo pipefail

# Reconfigura BugTraceAI MCP para una nueva IP de DVWA.
# Reinstala primero, actualiza después, reemplaza el wrapper de login,
# limpia cookies/artefactos y valida health + login + security LOW.
#
# Uso:
#   sudo ./update_bugtraceai_mcp_ip_v2.sh /ruta/al/proyecto NUEVA_IP [IP_ANTERIOR]
#
# Ejemplo:
#   sudo ./update_bugtraceai_mcp_ip_v2.sh "$PWD" 192.168.0.200 192.168.0.19

PROJECT_DIR="${1:-$PWD}"
NEW_IP="${2:-}"
OLD_IP="${3:-}"

INSTALL_DIR="/opt/bugtraceai-mcp"
SERVICE_NAME="bugtraceai-mcp"
COOKIE_DIR="/tmp/bugtraceai-session"
ARTIFACT_DIR="/tmp/bugtraceai-artifacts"
WRAPPER_PATH="/usr/local/bin/bugtraceai_dvwa_login"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[+] $*"; }
ok()   { echo "[OK] $*"; }
warn() { echo "[WARN] $*" >&2; }

[[ $EUID -eq 0 ]] || die "Ejecutá este script con sudo."
[[ -n "$NEW_IP" ]] || die "Falta NUEVA_IP. Ejemplo: sudo $0 \"$PWD\" 192.168.0.200 192.168.0.19"
[[ -d "$PROJECT_DIR" ]] || die "No existe el proyecto: $PROJECT_DIR"

python3 - "$NEW_IP" <<'PY' || die "IP nueva inválida: $NEW_IP"
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY

if [[ -n "$OLD_IP" ]]; then
  python3 - "$OLD_IP" <<'PY' || die "IP anterior inválida: $OLD_IP"
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
fi

PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$PROJECT_DIR/backup-mcp-ip-$STAMP"
mkdir -p "$BACKUP_DIR"

# Incluye IPs históricas conocidas. Esto corrige el caso 192.168.0.19 -> .200
# aunque el tercer argumento no se haya proporcionado.
OLD_IPS=("192.168.0.11" "192.168.0.19" "192.168.0.33")
[[ -z "$OLD_IP" ]] || OLD_IPS=("$OLD_IP" "${OLD_IPS[@]}")

# Elimina duplicados sin alterar el orden.
mapfile -t OLD_IPS < <(printf '%s\n' "${OLD_IPS[@]}" | awk '!seen[$0]++')

info "Proyecto MCP : $PROJECT_DIR"
info "Nueva IP DVWA: $NEW_IP"
[[ -z "$OLD_IP" ]] || info "IP anterior   : $OLD_IP"
info "Respaldo      : $BACKUP_DIR"

systemctl stop "$SERVICE_NAME" 2>/dev/null || true

# Reinstala primero. Algunos instaladores copian nuevamente archivos con la IP vieja.
info "Reinstalando componentes MCP antes de aplicar el cambio definitivo..."
if [[ -x "$PROJECT_DIR/install_clean.sh" ]]; then
  "$PROJECT_DIR/install_clean.sh" || die "Falló install_clean.sh"
elif [[ -x "$PROJECT_DIR/install_kali_assets.sh" ]]; then
  "$PROJECT_DIR/install_kali_assets.sh" || die "Falló install_kali_assets.sh"
elif [[ -x "$PROJECT_DIR/kali_mcp/install_kali_assets.sh" ]]; then
  "$PROJECT_DIR/kali_mcp/install_kali_assets.sh" || die "Falló kali_mcp/install_kali_assets.sh"
else
  warn "No se encontró instalador; se modificará la instalación existente."
fi

update_tree() {
  local root="$1"
  local backup_root="$2"

  [[ -d "$root" ]] || return 0

  while IFS= read -r -d '' file; do
    # No modifica el propio actualizador ni respaldos.
    [[ "$(basename "$file")" == "$(basename "$0")" ]] && continue

    local hit=0
    for old in "${OLD_IPS[@]}"; do
      if [[ "$old" != "$NEW_IP" ]] && grep -Fq "$old" "$file"; then
        hit=1
        break
      fi
    done
    (( hit == 1 )) || continue

    local rel="${file#$root/}"
    mkdir -p "$backup_root/$(dirname "$rel")"
    cp -a "$file" "$backup_root/$rel"

    for old in "${OLD_IPS[@]}"; do
      [[ "$old" == "$NEW_IP" ]] && continue
      sed -i "s/${old//./\\.}/${NEW_IP//./\\.}/g" "$file"
    done

    echo "[UPDATED] $root/$rel"
  done < <(
    find "$root" -type f \
      \( -name '*.py' -o -name '*.sh' -o -name '*.json' -o -name '*.md' \
         -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml' -o -name '*.env' \
         -o -name '*.ini' -o -name '*.conf' -o -name '*.service' \) \
      ! -path '*/venv/*' \
      ! -path '*/.venv/*' \
      ! -path '*/backup-mcp-ip-*/*' \
      -print0
  )
}

info "Actualizando archivos del proyecto..."
update_tree "$PROJECT_DIR" "$BACKUP_DIR/project"

info "Actualizando instalación activa..."
update_tree "$INSTALL_DIR" "$BACKUP_DIR/installed"

# Instala un wrapper autocontenido y robusto. Usa HTMLParser, por lo que admite
# comillas simples/dobles y atributos HTML en cualquier orden.
if [[ -e "$WRAPPER_PATH" ]]; then
  cp -aL "$WRAPPER_PATH" "$BACKUP_DIR/bugtraceai_dvwa_login.previous" 2>/dev/null || true
fi

cat > "$WRAPPER_PATH" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-}"
USERNAME="${2:-admin}"
PASSWORD="${3:-password}"
SECURITY="${4:-low}"
COOKIE_JAR="${5:-/tmp/bugtraceai-session/dvwa_cookie.txt}"

die(){ echo "[ERROR] $*" >&2; exit 1; }

[[ -n "$TARGET" ]] || die "Uso: bugtraceai_dvwa_login URL usuario contraseña nivel cookie_jar"
TARGET="${TARGET%/}"

mkdir -p "$(dirname "$COOKIE_JAR")"
rm -f "$COOKIE_JAR"

TMPDIR="$(mktemp -d /tmp/bugtraceai-login.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_token() {
  local html_file="$1"
  python3 - "$html_file" <<'PY'
from html.parser import HTMLParser
import sys

class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        values = {str(k).lower(): (v or "") for k, v in attrs}
        if values.get("name") == "user_token":
            self.token = values.get("value", "")

p = Parser()
with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
    p.feed(fh.read())
print(p.token)
PY
}

echo "[+] Kali login DVWA target=$TARGET security=$SECURITY cookie=$COOKIE_JAR"

curl -ksS --max-time 15 \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$TARGET/login.php" \
  -o "$TMPDIR/login.html"

grep -qiE 'DVWA|Damn Vulnerable Web Application' "$TMPDIR/login.html" \
  || die "La URL no parece ser DVWA: $TARGET/login.php"

LOGIN_TOKEN="$(extract_token "$TMPDIR/login.html")"
[[ -n "$LOGIN_TOKEN" ]] || {
  echo "[DEBUG] Primeras coincidencias del formulario:" >&2
  grep -nEi 'form|username|password|user_token|error|warning|fatal' "$TMPDIR/login.html" | head -30 >&2 || true
  die "No se encontró user_token en login.php"
}

curl -ksS -L --max-time 20 \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=$LOGIN_TOKEN" \
  "$TARGET/login.php" \
  -o "$TMPDIR/login-result.html"

if grep -qiE '<title>Login|name=.username.|Login failed|incorrect' "$TMPDIR/login-result.html"; then
  die "Login DVWA rechazado para el usuario $USERNAME"
fi

curl -ksS --max-time 15 \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$TARGET/security.php" \
  -o "$TMPDIR/security.html"

SECURITY_TOKEN="$(extract_token "$TMPDIR/security.html")"

POST_ARGS=(
  --data-urlencode "security=$SECURITY"
  --data-urlencode "seclev_submit=Submit"
)
[[ -z "$SECURITY_TOKEN" ]] || POST_ARGS+=(--data-urlencode "user_token=$SECURITY_TOKEN")

curl -ksS -L --max-time 20 \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "${POST_ARGS[@]}" \
  "$TARGET/security.php" \
  -o "$TMPDIR/security-result.html"

curl -ksS --max-time 15 \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$TARGET/vulnerabilities/sqli/" \
  -o "$TMPDIR/effective.html"

if grep -qiE "Security Level[^A-Za-z0-9]+${SECURITY}\b" "$TMPDIR/effective.html"; then
  echo "[DONE] Login DVWA confirmado en Kali. security=$SECURITY cookie=$COOKIE_JAR bytes=$(wc -c < "$COOKIE_JAR")"
  exit 0
fi

echo "[DEBUG] Nivel observado:" >&2
grep -niE 'Security Level|login|error|warning|fatal' "$TMPDIR/effective.html" | tail -20 >&2 || true
die "Security level no confirmado. solicitado=$SECURITY"
WRAPPER

chmod 0755 "$WRAPPER_PATH"

# Si el proyecto contiene el wrapper fuente, lo reemplaza para evitar que
# futuras reinstalaciones recuperen el parser defectuoso.
for candidate in \
  "$PROJECT_DIR/bugtraceai_dvwa_login.sh" \
  "$PROJECT_DIR/kali_mcp/bugtraceai_dvwa_login.sh" \
  "$INSTALL_DIR/bugtraceai_dvwa_login.sh"
do
  if [[ -e "$candidate" ]]; then
    cp -a "$candidate" "$BACKUP_DIR/$(echo "$candidate" | tr '/' '_').previous" 2>/dev/null || true
    cp -a "$WRAPPER_PATH" "$candidate"
    chmod 0755 "$candidate"
    echo "[REPLACED] $candidate"
  fi
done

info "Limpiando cookies, sesiones y artefactos anteriores..."
rm -rf -- "$COOKIE_DIR" "$ARTIFACT_DIR"
install -d -m 0770 "$COOKIE_DIR" "$ARTIFACT_DIR"

find "$PROJECT_DIR" "$INSTALL_DIR" -type f \
  \( -iname '*cookie*.txt' -o -iname '*.cookie' -o -iname 'cookies.txt' \
     -o -iname '*.log' -o -iname 'last_*.json' \) \
  ! -path '*/backup-mcp-ip-*/*' \
  -delete 2>/dev/null || true

info "Validando sintaxis..."
bash -n "$WRAPPER_PATH" || die "Wrapper generado con error de sintaxis"

while IFS= read -r -d '' file; do
  bash -n "$file" || die "Error de sintaxis shell: $file"
done < <(
  find "$PROJECT_DIR" "$INSTALL_DIR" -type f -name '*.sh' 2>/dev/null \
    ! -path '*/venv/*' \
    ! -path '*/.venv/*' \
    ! -path '*/backup-mcp-ip-*/*' \
    -print0
)

python3 - "$PROJECT_DIR" "$INSTALL_DIR" <<'PY'
import pathlib
import py_compile
import sys

errors = []
for raw in sys.argv[1:]:
    root = pathlib.Path(raw)
    if not root.exists():
        continue
    for path in root.rglob("*.py"):
        if any(part in {"venv", ".venv"} or part.startswith("backup-mcp-ip-")
               for part in path.parts):
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            errors.append(f"{path}: {exc}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
PY

info "Validando que no queden referencias activas a IPs anteriores..."
for root in "$PROJECT_DIR" "$INSTALL_DIR"; do
  [[ -d "$root" ]] || continue
  for old in "${OLD_IPS[@]}"; do
    [[ "$old" == "$NEW_IP" ]] && continue
    leftovers="$(
      grep -RIlF \
        --exclude-dir=.git \
        --exclude-dir=venv \
        --exclude-dir=.venv \
        --exclude-dir="$(basename "$BACKUP_DIR")" \
        "$old" "$root" 2>/dev/null || true
    )"
    if [[ -n "$leftovers" ]]; then
      warn "Quedaron referencias a $old:"
      echo "$leftovers" >&2
    fi
  done
done

curl -fsS --max-time 10 "http://$NEW_IP/login.php" \
  | grep -qiE 'DVWA|Damn Vulnerable Web Application' \
  || die "DVWA no responde correctamente en http://$NEW_IP/login.php"
ok "DVWA accesible en $NEW_IP"

systemctl daemon-reload
systemctl restart "$SERVICE_NAME" 2>/dev/null || true
sleep 2

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
  systemctl is-active --quiet "$SERVICE_NAME" \
    || die "El servicio $SERVICE_NAME no quedó activo."
  ok "Servicio $SERVICE_NAME activo."
fi

HEALTH_FILE="/tmp/bugtraceai-mcp-health.json"
curl -fsS --max-time 8 "http://127.0.0.1:9001/health" -o "$HEALTH_FILE" \
  || die "MCP /health no responde."

cat "$HEALTH_FILE"
echo

python3 - "$HEALTH_FILE" "$NEW_IP" <<'PY' || die "El endpoint /health todavía anuncia una IP diferente."
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
actual = str(data.get("target_host", ""))
if actual != expected:
    print(f"[ERROR] target_host actual={actual!r}, esperado={expected!r}", file=sys.stderr)
    raise SystemExit(1)
PY
ok "MCP anuncia target_host=$NEW_IP"

info "Validando login, cookie y security LOW..."
"$WRAPPER_PATH" \
  "http://$NEW_IP" \
  admin \
  password \
  low \
  "$COOKIE_DIR/dvwa_cookie.txt"

[[ -s "$COOKIE_DIR/dvwa_cookie.txt" ]] \
  || die "No se generó el cookie jar."

curl -ksS --max-time 10 \
  -b "$COOKIE_DIR/dvwa_cookie.txt" \
  "http://$NEW_IP/vulnerabilities/sqli/" \
  | grep -qiE 'Security Level[^A-Za-z0-9]+low\b' \
  || die "No se confirmó el nivel LOW en una página vulnerable."

ok "Login, cookie y nivel LOW confirmados."
echo
ok "Actualización del MCP completada correctamente."
echo "Nueva IP DVWA: $NEW_IP"
echo "Respaldo: $BACKUP_DIR"
