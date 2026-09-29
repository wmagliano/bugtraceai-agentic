#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
"$BASE_DIR/scripts/create_assets.sh"
test -s "$BASE_DIR/assets/brute.txt"
grep -qx password "$BASE_DIR/assets/brute.txt"
grep -q '"hydra"' "$BASE_DIR/kali_mcp_server.py"
python3 -m py_compile "$BASE_DIR/kali_mcp_server.py"
python3 - <<'PY' "$BASE_DIR"
import importlib.util, pathlib, sys
base=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location("mcp", base/"kali_mcp_server.py")
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert "hydra" in m.ALLOWED_BINARIES
ok,_=m.validate_command("echo $(printf test | md5sum)")
assert ok
print("[OK] MCP v2.5.6c hydra + command substitution")
PY
