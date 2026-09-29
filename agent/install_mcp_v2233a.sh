#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-$HOME/Downloads/bugtraceai-mcp-kali/kali_mcp_server.py}"
SRC="$(cd "$(dirname "$0")" && pwd)/kali_mcp/kali_mcp_server.py"
mkdir -p "$(dirname "$DEST")"
if [[ -f "$DEST" ]]; then cp -a "$DEST" "${DEST}.bak.$(date +%Y%m%d-%H%M%S)"; fi
cp "$SRC" "$DEST"
chmod +x "$DEST"
echo "[OK] MCP v2.2.3.3a instalado en $DEST"
echo "[NEXT] Reiniciá uvicorn para aplicar el cambio."
