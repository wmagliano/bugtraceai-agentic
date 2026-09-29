#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -x .venv-tui/bin/python ]]; then
  echo '[ERROR] Ejecute primero: ./install_tui.sh' >&2
  exit 2
fi
exec .venv-tui/bin/python bugtraceai_tui.py
