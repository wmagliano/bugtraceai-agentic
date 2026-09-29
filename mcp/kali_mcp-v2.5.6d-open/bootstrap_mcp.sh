#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$BASE_DIR/scripts/create_assets.sh"
"$BASE_DIR/install_kali_assets.sh"
if [[ -x "$BASE_DIR/validate_bugtraceai_mcp.sh" ]]; then "$BASE_DIR/validate_bugtraceai_mcp.sh" || true; fi
