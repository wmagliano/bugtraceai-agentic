#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# BugTraceAI - Reset consolidado
# R0-FINAL-C1-FIX
#
# Consolida la cadena histórica:
#
# reset_v254_sessioncheck.sh
#   -> reset_v254_blacklist.sh
#   -> reset_v2233b.sh
#   -> reset_v2232.sh
#   -> reset_v222.sh
#   -> reset_v220.sh
#   -> reset_v201.sh
#   -> reset_v200.sh
#   -> reset_v183.sh
#   -> reset_v14_lab.sh
#
# Objetivo:
#   Mantener el comportamiento funcional de la cadena
#   eliminando wrappers históricos.
# ============================================================

cd "$(dirname "$0")"

CONFIG_FILE="${1:-${BUGTRACEAI_CONFIG:-config/site.json}}"

# ------------------------------------------------------------
# 1. Estado de sesión
# ------------------------------------------------------------

rm -f data/session_guard.json
rm -f data/session_rotation.json

# La cadena histórica terminaba sobrescribiendo
# 2.5.4-sessioncheck con 2.5.4-blacklist.
# Se conserva el valor efectivo para equivalencia experimental.
export BUGTRACEAI_VERSION="2.5.4-blacklist"

# ------------------------------------------------------------
# 2. Evidencias de ejecución anterior
# ------------------------------------------------------------

rm -rf reports/evidence

# ------------------------------------------------------------
# 3. Carga de configuración
#    Equivalente a reset_v183.sh
# ------------------------------------------------------------

eval "$(python3 bugtraceai_config.py --shell "$CONFIG_FILE")"

export BUGTRACEAI_CONFIG="$CONFIG_FILE"

echo "[CONFIG] Usando $CONFIG_FILE ($BUGTRACEAI_CONFIG_PROFILE)"

# ------------------------------------------------------------
# 4. Backup previo al reset
# ------------------------------------------------------------

echo "[+] BugTraceAI reset consolidado R0-FINAL-C1-FIX"

mkdir -p backups/reset
cp -a data logs backups/reset/ 2>/dev/null || true

# ------------------------------------------------------------
# 5. Limpieza de memoria operativa
# ------------------------------------------------------------

echo "[+] Limpiando memoria operativa"

python3 - <<'PY'
import json
import os
from pathlib import Path

p = Path("data/knowledge.json")

if not p.exists():
    print("[ERROR] No existe data/knowledge.json")
    raise SystemExit(1)

k = json.loads(p.read_text(encoding="utf-8"))

# Defaults mínimos para que un fallo temprano de MCP
# no deje al reasoner sin scope.
k.setdefault("scope", {})

k["scope"]["target_base"] = os.environ.get(
    "BUGTRACEAI_TARGET_BASE",
    "http://192.168.0.200"
)

k["scope"]["target_host"] = os.environ.get(
    "BUGTRACEAI_TARGET_HOST",
    "192.168.0.200"
)

k["scope"]["kali_host"] = os.environ.get(
    "BUGTRACEAI_KALI_HOST",
    "192.168.0.34"
)

k["scope"]["kali_mcp_base"] = os.environ.get(
    "BUGTRACEAI_MCP_BASE",
    "http://192.168.0.34:9001"
)

# ------------------------------------------------------------
# Estado operativo
# ------------------------------------------------------------

k["visited_urls"] = []
k["url_context"] = {}
k["findings"] = []
k["errors"] = []
k["next_actions"] = []
k["completed_urls"] = []
k["candidate_urls"] = []
k["analysis_queue"] = []
k["active_analysis_id"] = None

# ------------------------------------------------------------
# Descubrimiento
# ------------------------------------------------------------

k["url_discovery"] = {
    "mode": os.environ.get("BUGTRACEAI_DISCOVERY_MODE", "auto"),
    "decisions": {},
    "events": [],
    "approved_count": 0,
    "rejected_count": 0
}

# ------------------------------------------------------------
# Primer Analysis Item
# ------------------------------------------------------------

from analysis_queue import add_item

initial_url = k["scope"]["target_base"].rstrip("/") + "/"

item, _ = add_item(
    k,
    initial_url,
    "reset_initial_target"
)

# ------------------------------------------------------------
# Memoria cognitiva / scheduler
# ------------------------------------------------------------

k["cognitive_knowledge"] = []
k["cognitive_updates_history"] = []

k["resource_state"] = {}
k["resource_state_history"] = []
k["resource_errors"] = {}

k["operator_checkpoints"] = []
k["latest_operator_checkpoint"] = None

k["active_resource"] = None

k["scheduler"] = {
    "version": "1.9",
    "queue": {},
    "events": [],
    "loop_limit": 3,
    "error_limit": 3,
    "operator_override": None,
    "final_report_ready": False
}

# ------------------------------------------------------------
# Información que no debe sobrevivir al reset
# ------------------------------------------------------------

for key in [
    "reasoner",
    "command_observations",
    "mcp_observations",
    "mcp_interior_observations",
    "mcp_command_observations",
    "loop_guard",
    "loop_skipped_urls",
    "runtime_feedback",
    "recommended_next_url",
    "autonomous_resource_counters",
    "reference_exploit_counters",
    "reference_exploitation"
]:
    k.pop(key, None)

p.write_text(
    json.dumps(k, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print("[OK] knowledge.json limpiado")
PY

# ------------------------------------------------------------
# 6. Logs temporales
# ------------------------------------------------------------

echo "[+] Limpiando logs temporales"

rm -f logs/last_llm_prompt.md
rm -f logs/last_llm_raw.txt
rm -f logs/last_llm_decision.json
rm -f logs/last_llm_invalid.json
rm -f logs/llm_contract_debug.jsonl
rm -f logs/last_mcp_result.json
rm -f logs/executor_state.json

rm -rf logs/pages
mkdir -p logs/pages

# ------------------------------------------------------------
# 7. Herramientas / contexto
# ------------------------------------------------------------

echo "[+] Validando herramientas/contexto base si faltan"

python3 - <<'PYCHK'
import json
from pathlib import Path

k = json.loads(
    Path("data/knowledge.json").read_text(encoding="utf-8")
)

print(
    "RUN_HERRAMIENTAS=1"
    if not k.get("tool_validation")
    else "RUN_HERRAMIENTAS=0"
)

print(
    "RUN_CONTEXT=1"
    if not k.get("external_context")
    else "RUN_CONTEXT=0"
)
PYCHK

if ! python3 - <<'PYCHK2'
import json
from pathlib import Path

k = json.loads(
    Path("data/knowledge.json").read_text(encoding="utf-8")
)

raise SystemExit(
    0 if k.get("tool_validation") else 1
)
PYCHK2
then
    ./scripts/herramientas.sh
fi

if ! python3 - <<'PYCHK3'
import json
from pathlib import Path

k = json.loads(
    Path("data/knowledge.json").read_text(encoding="utf-8")
)

raise SystemExit(
    0 if k.get("external_context") else 1
)
PYCHK3
then
    ./scripts/context_builder.sh
fi

# ------------------------------------------------------------
# 8. Login remoto DVWA vía MCP
# ------------------------------------------------------------

echo "[+] Ejecutando login remoto en Kali vía MCP"

python3 - <<'PYLOGIN'
import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

p = Path("logs/last_llm_decision.json")
p.parent.mkdir(parents=True, exist_ok=True)

p.write_text(
    json.dumps({
        "decision_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.4-kali-session",
        "llm_valid_json": True,

        "analysis_summary":
            "Inicialización de sesión DVWA dentro de Kali.",

        "hypotheses": [],
        "needed_context": [],

        "next_actions": [{
            "action": "run_login",

            "url":
                os.environ.get(
                    "BUGTRACEAI_TARGET_BASE",
                    "http://192.168.0.200"
                ).rstrip("/") + "/",

            "reason":
                "Crear sesión DVWA low en Kali para que "
                "curl/sqlmap reutilicen la misma cookie local."
        }],

        "operator_message":
            "Login ejecutado desde Kali/MCP."

    }, indent=2, ensure_ascii=False),

    encoding="utf-8"
)
PYLOGIN

python3 executor_mcp.py

# ------------------------------------------------------------
# 9. Interior inicial vía MCP
# ------------------------------------------------------------

echo "[+] Ejecutando interior inicial vía Kali/MCP"

python3 - <<'PY2'
import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

p = Path("logs/last_llm_decision.json")
p.parent.mkdir(parents=True, exist_ok=True)

p.write_text(
    json.dumps({
        "decision_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.4-kali-session",
        "llm_valid_json": True,

        "analysis_summary":
            "Inicialización de contexto interno desde Kali/MCP.",

        "hypotheses": [],
        "needed_context": [],

        "next_actions": [{
            "action": "run_interior",

            "url":
                os.environ.get(
                    "BUGTRACEAI_TARGET_BASE",
                    "http://192.168.0.200"
                ).rstrip("/") + "/",

            "reason":
                "Contexto inicial post-login remoto en Kali"
        }],

        "operator_message":
            "Mapeo inicial ejecutado desde Kali/MCP."

    }, indent=2, ensure_ascii=False),

    encoding="utf-8"
)
PY2

python3 executor_mcp.py

# ------------------------------------------------------------
# 10. Estado inicial
# ------------------------------------------------------------

echo "[+] Estado inicial"

jq \
    '.session,
     .visited_urls,
     .completed_urls,
     .command_observations,
     .mcp_interior_observations,
     .mcp_command_observations' \
    data/knowledge.json

# ------------------------------------------------------------
# 11. Discovery + Scheduler
#     Equivalente a la parte final de reset_v183.sh
# ------------------------------------------------------------

echo "[+] Ejecutando discovery inicial"

python3 discovery_manager.py

echo "[+] Inicializando scheduler"

python3 resource_scheduler.py init >/dev/null

echo "[DISCOVERY] modo=$BUGTRACEAI_DISCOVERY_MODE"

echo
echo "[DONE] Reset consolidado R0-FINAL-C1-FIX completado"
echo "[CONFIG] $BUGTRACEAI_CONFIG"
echo "[VERSION] $BUGTRACEAI_VERSION"

