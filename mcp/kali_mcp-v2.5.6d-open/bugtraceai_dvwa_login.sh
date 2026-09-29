#!/usr/bin/env bash
set -euo pipefail

TARGET_BASE="${1:-http://192.168.0.200}"
# Tolerate accidental Markdown link text copied from chat.
if [[ "$TARGET_BASE" == \[*\]\(*\) ]]; then
  TARGET_BASE="${TARGET_BASE#\[}"
  TARGET_BASE="${TARGET_BASE%%\]*}"
fi
DVWA_USER="${2:-admin}"
DVWA_PASS="${3:-password}"
DVWA_SECURITY="${4:-low}"
COOKIE_JAR="${5:-/tmp/bugtraceai-session/dvwa_cookie.txt}"

SESSION_DIR="$(dirname "$COOKIE_JAR")"
mkdir -p "$SESSION_DIR"
chmod 700 "$SESSION_DIR" 2>/dev/null || true
rm -f "$COOKIE_JAR"
touch "$COOKIE_JAR"
chmod 600 "$COOKIE_JAR" 2>/dev/null || true

LOGIN_URL="${TARGET_BASE%/}/login.php"
SEC_URL="${TARGET_BASE%/}/security.php"
INDEX_URL="${TARGET_BASE%/}/index.php"
VERIFY_URL="${TARGET_BASE%/}/vulnerabilities/sqli/"

extract_token() {
  python3 -c '
import re
import sys

html = sys.stdin.read()

for tag in re.findall(r"<input\b[^>]*>", html, flags=re.I | re.S):
    attrs = dict(
        (key.lower(), value)
        for key, value in re.findall(
            r"([:\w-]+)\s*=\s*[\"\x27]([^\"\x27]*)[\"\x27]",
            tag
        )
    )

    if attrs.get("name") == "user_token":
        print(attrs.get("value", ""))
        break
'
}

current_level() {
  python3 -c '
import re
import sys

html = sys.stdin.read()

match = re.search(
    r"<em>\s*Security\s+Level:\s*</em>\s*(low|medium|high|impossible)",
    html,
    flags=re.I | re.S
)

print(match.group(1).lower() if match else "")
'
}

printf '[+] Kali login DVWA target=%s security=%s cookie=%s\n' \
  "$TARGET_BASE" "$DVWA_SECURITY" "$COOKIE_JAR"

LOGIN_HTML="$(
  curl -ksS \
    -L \
    -c "$COOKIE_JAR" \
    -b "$COOKIE_JAR" \
    "$LOGIN_URL"
)"

printf '%s' "$LOGIN_HTML" > "$SESSION_DIR/login_page.html"

TOKEN="$(printf '%s' "$LOGIN_HTML" | extract_token)"

if [[ -z "$TOKEN" ]]; then
  printf '[ERROR] No se encontró user_token en login.php\n' >&2
  printf '[DEBUG] HTML guardado en %s\n' \
    "$SESSION_DIR/login_page.html" >&2
  exit 10
fi

printf '[OK] user_token obtenido: %s...\n' "${TOKEN:0:8}"

curl -ksS \
  -L \
  -b "$COOKIE_JAR" \
  -c "$COOKIE_JAR" \
  --data-urlencode "username=$DVWA_USER" \
  --data-urlencode "password=$DVWA_PASS" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=$TOKEN" \
  "$LOGIN_URL" \
  -o "$SESSION_DIR/login_response.html"

INDEX_HTML="$(
  curl -ksS \
    -L \
    -b "$COOKIE_JAR" \
    -c "$COOKIE_JAR" \
    "$INDEX_URL"
)"

if printf '%s' "$INDEX_HTML" |
  grep -Eiq '<title>[^<]*login|name=["'\'']username["'\'']'
then
  printf '[ERROR] Login no confirmado: DVWA devolvió la página de login.\n' >&2
  printf '[DEBUG] Respuesta guardada en %s\n' \
    "$SESSION_DIR/login_response.html" >&2
  exit 11
fi

SEC_HTML="$(
  curl -ksS \
    -L \
    -b "$COOKIE_JAR" \
    -c "$COOKIE_JAR" \
    "$SEC_URL"
)"

printf '%s' "$SEC_HTML" > "$SESSION_DIR/security_page.html"

SEC_TOKEN="$(printf '%s' "$SEC_HTML" | extract_token)"

if [[ -z "$SEC_TOKEN" ]]; then
  printf '[ERROR] No se encontró user_token en security.php\n' >&2
  printf '[DEBUG] HTML guardado en %s\n' \
    "$SESSION_DIR/security_page.html" >&2
  exit 12
fi

curl -ksS \
  -L \
  -b "$COOKIE_JAR" \
  -c "$COOKIE_JAR" \
  --data-urlencode "security=$DVWA_SECURITY" \
  --data-urlencode "seclev_submit=Submit" \
  --data-urlencode "user_token=$SEC_TOKEN" \
  "$SEC_URL" \
  -o "$SESSION_DIR/security_response.html"

VERIFY_HTML="$(
  curl -ksS \
    -L \
    -b "$COOKIE_JAR" \
    -c "$COOKIE_JAR" \
    "$VERIFY_URL"
)"

ACTUAL_LEVEL="$(printf '%s' "$VERIFY_HTML" | current_level)"

if [[ "$ACTUAL_LEVEL" != "${DVWA_SECURITY,,}" ]]; then
  printf '[ERROR] Security level efectivo no aplicado. solicitado=%s actual=%s\n' \
    "$DVWA_SECURITY" "${ACTUAL_LEVEL:-unknown}" >&2
  exit 13
fi

BYTES="$(wc -c < "$COOKIE_JAR" | tr -d ' ')"

printf '[DONE] Login DVWA confirmado en Kali. security=%s cookie_jar=%s bytes=%s\n' \
  "$ACTUAL_LEVEL" "$COOKIE_JAR" "$BYTES"
