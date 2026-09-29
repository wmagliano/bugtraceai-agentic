#!/usr/bin/env bash
set -euo pipefail
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DST_DIR="${BUGTRACEAI_MCP_DIR:-/opt/bugtraceai-mcp}"
"$SRC_DIR/scripts/create_assets.sh"
sudo mkdir -p "$DST_DIR/assets"
sudo cp "$SRC_DIR/kali_mcp_server.py" "$DST_DIR/kali_mcp_server.py"
sudo cp "$SRC_DIR/bugtraceai_dvwa_login.sh" "$DST_DIR/bugtraceai_dvwa_login.sh"
sudo cp "$SRC_DIR/requirements.txt" "$DST_DIR/requirements.txt" 2>/dev/null || true
sudo cp "$SRC_DIR/assets/brute.txt" "$DST_DIR/assets/brute.txt"
sudo cp "$SRC_DIR/assets/benign_phpinfo.php" "$DST_DIR/assets/benign_phpinfo.php"
sudo chmod 0755 "$DST_DIR/bugtraceai_dvwa_login.sh"
sudo chmod 0644 "$DST_DIR/kali_mcp_server.py" "$DST_DIR/assets/brute.txt" "$DST_DIR/assets/benign_phpinfo.php"
sudo ln -sf "$DST_DIR/bugtraceai_dvwa_login.sh" /usr/local/bin/bugtraceai_dvwa_login
echo "[OK] MCP instalado/actualizado en $DST_DIR"
echo "[OK] Assets activos en $DST_DIR/assets"
ls -l "$DST_DIR/assets"

# r4b-open: repair stale root-owned BugTraceAI temp directories after sudo tests.
RUN_USER="${SUDO_USER:-${USER:-}}"
if [[ -n "$RUN_USER" && "$RUN_USER" != "root" ]]; then
  sudo mkdir -p /tmp/bugtraceai-session /tmp/bugtraceai-artifacts
  sudo chown -R "$RUN_USER":"$(id -gn "$RUN_USER")" /tmp/bugtraceai-session /tmp/bugtraceai-artifacts
  sudo chmod 700 /tmp/bugtraceai-session /tmp/bugtraceai-artifacts
  echo "[OK] Directorios temporales preparados para usuario $RUN_USER"
fi
