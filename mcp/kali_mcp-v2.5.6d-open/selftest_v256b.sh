#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$BASE_DIR/scripts/create_assets.sh"
test -s "$BASE_DIR/assets/brute.txt"
grep -qx 'password' "$BASE_DIR/assets/brute.txt"
grep -q 'phpinfo();' "$BASE_DIR/assets/benign_phpinfo.php"
python3 -m py_compile "$BASE_DIR/kali_mcp_server.py"
echo '[OK] Kali MCP v2.5.6b assets y sintaxis'
