#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./scripts/herramientas.sh
./scripts/context_builder.sh
./scripts/login.sh
./reset_v14_lab.sh
python3 reasoner.py
