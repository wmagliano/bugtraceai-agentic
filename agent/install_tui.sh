#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv-tui
. .venv-tui/bin/activate
python -m pip install --upgrade pip
python -m pip install 'textual>=0.75,<2'
echo '[OK] TUI instalada. Ejecute ./run_tui.sh'
