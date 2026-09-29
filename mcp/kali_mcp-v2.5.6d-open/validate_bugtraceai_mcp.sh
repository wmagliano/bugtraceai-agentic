#!/usr/bin/env bash
set -uo pipefail
IP="${1:-}"; BASE="${MCP_BASE:-http://127.0.0.1:9001}"; FAIL=0
ok(){ echo "[OK] $*"; }; fail(){ echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Uso: $0 IP_DVWA"; exit 2; }
echo "=== MCP ==="
PIDS="$(pgrep -f 'uvicorn.*kali_mcp_server:app' || true)"
[[ -n "$PIDS" ]] && { ok "Uvicorn activo: $PIDS"; ps -o pid,user,%cpu,rss,vsz,etime,cmd -p $(echo "$PIDS"|tr '\n' ' ') || true; } || fail "Uvicorn inactivo"
H="$(curl -fsS -m 5 "$BASE/health" 2>/dev/null || true)"
if [[ -n "$H" ]]; then
  ok "/health"
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$H" | jq . 2>/dev/null || printf '%s\n' "$H"
  else
    printf '%s\n' "$H"
  fi
else
  fail "/health no responde"
fi

# Python forma parte del runtime del MCP y evita depender de jq.
OBS="$(printf '%s' "$H" | python3 -c 'import json,sys
try:
    value=json.load(sys.stdin).get("target_host", "")
    print(value if value is not None else "")
except Exception:
    print("")' 2>/dev/null || true)"

# Fallback adicional para entornos mínimos.
if [[ -z "$OBS" ]]; then
  OBS="$(printf '%s' "$H" | sed -n 's/.*"target_host"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
fi

[[ "$OBS" == "$IP" ]] && ok "TARGET_HOST=$OBS" || fail "TARGET_HOST=${OBS:-<vacío>} esperado=$IP"
echo "=== Wrapper/tmp ==="
[[ -x /usr/local/bin/bugtraceai_dvwa_login ]] && ok "wrapper" || fail "wrapper"
bash -n /usr/local/bin/bugtraceai_dvwa_login 2>/dev/null && ok "sintaxis wrapper" || fail "sintaxis wrapper"
for X in /tmp/bugtraceai-session:700 /tmp/bugtraceai-artifacts:750; do D="${X%%:*}"; M="${X##*:}"; [[ -d "$D" ]] || { fail "$D ausente"; continue; }; [[ "$(stat -c %a "$D")" == "$M" ]] && ok "$D modo=$M" || fail "$D modo=$(stat -c %a "$D")"; done
echo "=== Regresión 500 ==="
HTTP="$(curl -sS -o /tmp/mcp-reg.json -w '%{http_code}' -X POST "$BASE/tools/exec" -H 'Content-Type: application/json' -d '{"command":"printf \"\\304\"","timeout":20}' 2>/dev/null || true)"
[[ "$HTTP" == 200 ]] && ok "HTTP 200 con byte no UTF-8" || fail "HTTP=$HTTP"
echo "=== DVWA ==="
curl -ksS -m 10 "http://$IP/login.php"|grep -qiE 'DVWA|Damn Vulnerable' && ok "DVWA accesible" || fail "DVWA"
if /usr/local/bin/bugtraceai_dvwa_login "http://$IP" admin password low /tmp/bugtraceai-session/dvwa_cookie.txt; then ok "login+low+cookie"; else fail "login"; fi
((FAIL==0)) && { echo "[RESULT] ENTORNO MCP VALIDADO"; exit 0; } || { echo "[RESULT] $FAIL fallo(s)"; exit 1; }
