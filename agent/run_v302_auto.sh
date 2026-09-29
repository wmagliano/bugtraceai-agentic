#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export BUGTRACEAI_AUTONOMOUS=1
export BUGTRACEAI_VERSION="3.0.3a"
export BUGTRACEAI_CONFIG="${BUGTRACEAI_CONFIG:-config/site.json}"
export BUGTRACEAI_REASONER_HISTORY_DEPTH="${BUGTRACEAI_REASONER_HISTORY_DEPTH:-3}"
TUI_CASSETTE="${BUGTRACEAI_CASSETTE:-}"

# R0-FINAL-C1: explicit configuration precedence.
# Values explicitly supplied by the operator/runtime before profile loading win
# over config JSON. This is intentionally limited to configuration resolution;
# Discovery, URL exploration, blacklist and scheduler navigation are untouched.
_R0_C1_KEYS=(
  BUGTRACEAI_CASSETTE BUGTRACEAI_TARGET_BASE BUGTRACEAI_TARGET_HOST BUGTRACEAI_KALI_HOST
  BUGTRACEAI_MCP_BASE BUGTRACEAI_AUTH_TYPE BUGTRACEAI_USERNAME BUGTRACEAI_PASSWORD
  BUGTRACEAI_DVWA_SECURITY BUGTRACEAI_LOGIN_URL BUGTRACEAI_COOKIE_JAR BUGTRACEAI_USER_AGENT
  BUGTRACEAI_HTTP_HEADERS_JSON BUGTRACEAI_HTTP_TIMEOUT BUGTRACEAI_AUTONOMOUS
  BUGTRACEAI_MAX_MCP_COMMANDS BUGTRACEAI_MAX_RESOURCE_ITERATIONS BUGTRACEAI_SPECIALIZED_LAST_ATTEMPT BUGTRACEAI_MAX_ERRORS
  BUGTRACEAI_MAX_CYCLES BUGTRACEAI_RUNS_DIR BUGTRACEAI_DISCOVERY_MODE
  BUGTRACEAI_DISCOVERY_SAME_ORIGIN BUGTRACEAI_DISCOVERY_MAX_URLS
  BUGTRACEAI_DISCOVERY_STATIC_POLICY BUGTRACEAI_DISCOVERY_STATIC_EXTENSIONS_JSON
  BUGTRACEAI_DISCOVERY_FRAGMENT_POLICY BUGTRACEAI_URL_BLACKLIST_JSON BUGTRACEAI_VULN_BLACKLIST_JSON
)
declare -A _R0_C1_ENV=()
for _k in "${_R0_C1_KEYS[@]}"; do
  if [[ -v "$_k" ]]; then _R0_C1_ENV["$_k"]="${!_k}"; fi
done

required=(
  bugtraceai_config.py run_v263b_scheduler.sh reasoner.py reasoner_llm.py
  executor_mcp.py resource_prompt_builder.py adaptive_rag.py session_guard.py
)
for f in "${required[@]}"; do
  [[ -f "$f" ]] || { echo "[PREFLIGHT ERROR] Falta $f" >&2; exit 20; }
done
[[ -f "$BUGTRACEAI_CONFIG" ]] || { echo "[PREFLIGHT ERROR] Config inexistente: $BUGTRACEAI_CONFIG" >&2; exit 21; }

eval "$(python3 bugtraceai_config.py --shell "$BUGTRACEAI_CONFIG")"
for _k in "${!_R0_C1_ENV[@]}"; do export "$_k=${_R0_C1_ENV[$_k]}"; done
if [[ -n "$TUI_CASSETTE" ]]; then export BUGTRACEAI_CASSETTE="$TUI_CASSETTE"; fi
export BUGTRACEAI_CASSETTE="${BUGTRACEAI_CASSETTE:-dvwa-lab}"
[[ -f "cassettes/$BUGTRACEAI_CASSETTE/manifest.json" ]] || {
  echo "[PREFLIGHT ERROR] Cassette inválido: $BUGTRACEAI_CASSETTE" >&2; exit 22;
}

python3 -m py_compile bugtraceai_tui.py reasoner.py reasoner_llm.py resource_prompt_builder.py adaptive_rag.py session_guard.py
if [[ "${BUGTRACEAI_PREFLIGHT_ONLY:-0}" == "1" ]]; then
  echo "[PREFLIGHT OK] BugTraceAI v3.0.3b config=$BUGTRACEAI_CONFIG cassette=$BUGTRACEAI_CASSETTE"
  exit 0
fi

MAX_CYCLES="${1:-$BUGTRACEAI_MAX_CYCLES}"
RUN_ID="${BUGTRACEAI_RUN_ID:-$(date -u +%Y%m%d-%H%M%S)-$$}"
RUN_DIR="${BUGTRACEAI_RUNS_DIR}/${RUN_ID}"
export BUGTRACEAI_RUN_ID="$RUN_ID" BUGTRACEAI_RUN_DIR="$RUN_DIR"
mkdir -p "$RUN_DIR/logs/v3" "$RUN_DIR/reports" "$RUN_DIR/data" logs/v3
export BUGTRACEAI_PROJECT_ID="${BUGTRACEAI_PROJECT_ID:-dvwa-low-validation}"
export BUGTRACEAI_PROJECT_CYCLE="${BUGTRACEAI_PROJECT_CYCLE:-1}"
export BUGTRACEAI_PROJECTS_DIR="${BUGTRACEAI_PROJECTS_DIR:-projects}"
cp "$BUGTRACEAI_CONFIG" "$RUN_DIR/config.snapshot.json"
cp -a "cassettes/$BUGTRACEAI_CASSETTE" "$RUN_DIR/cassette.snapshot" 2>/dev/null || true
printf '%s\n' \
  "run_id=$RUN_ID" \
  "version=3.0.3a" \
  "scheduler=2.6.3b" \
  "config=$BUGTRACEAI_CONFIG" \
  "cassette=$BUGTRACEAI_CASSETTE" \
  "reasoner_history_depth=$BUGTRACEAI_REASONER_HISTORY_DEPTH" \
  > "$RUN_DIR/runtime_context.env"

python3 experiment_telemetry.py start || true
echo "[AUTONOMOUS] BugTraceAI v3.0.3b"
echo "[PROJECT] $BUGTRACEAI_PROJECT_ID cycle=$BUGTRACEAI_PROJECT_CYCLE"
echo "[CONFIG] $BUGTRACEAI_CONFIG ($BUGTRACEAI_CONFIG_PROFILE)"
echo "[R0-C1] precedence=explicit-runtime-env>config-profile>internal-default"
echo "[R0-C1-FIX] max_cycles=$BUGTRACEAI_MAX_CYCLES max_resource_iterations=${BUGTRACEAI_MAX_RESOURCE_ITERATIONS:-20} max_mcp=$BUGTRACEAI_MAX_MCP_COMMANDS max_errors=$BUGTRACEAI_MAX_ERRORS"
echo "[CASSETTE] $BUGTRACEAI_CASSETTE"
echo "[RAG] Adaptive RAG + explicit result-to-learning continuity"
echo "[TARGET] $BUGTRACEAI_TARGET_BASE"
set +e
./run_v263b_scheduler.sh "$MAX_CYCLES" 2>&1 | tee "$RUN_DIR/logs/autonomous-run.log"
RC=${PIPESTATUS[0]}
set -e
python3 - "$RC" <<'PYTERM'
import json,sys,os
from pathlib import Path
rc=int(sys.argv[1])
p=Path('data/knowledge.json')
try: k=json.loads(p.read_text(encoding='utf-8'))
except Exception: k={}
q=[x for x in k.get('analysis_queue',[]) if isinstance(x,dict)]
terminal={'COMPLETED','INCONCLUSIVE','FAILED','SKIPPED'}
all_terminal=bool(q) and all(str(x.get('state') or '').upper() in terminal for x in q)
if all_terminal: reason='ALL_RESOURCES_TERMINAL'
elif rc==2: reason='GLOBAL_ITERATION_LIMIT'
elif rc==130: reason='OPERATOR_STOP'
elif rc!=0: reason='FATAL_OR_RUNTIME_ERROR'
else: reason='NORMAL_EXIT'
k.setdefault('run_summary',{})['termination_reason']=reason
k['run_summary']['runner_returncode']=rc
k['run_summary']['terminal_resources']=sum(str(x.get('state') or '').upper() in terminal for x in q)
k['run_summary']['total_resources']=len(q)
p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(k,indent=2,ensure_ascii=False),encoding='utf-8')
print(f'[TERMINATION] {reason}')
PYTERM
python3 evidence_bundle.py || true
python3 final_report.py || true
python3 summarize_llm_performance.py || true
cp -a logs/v3/. "$RUN_DIR/logs/v3/" 2>/dev/null || true
cp -a reports/. "$RUN_DIR/reports/" 2>/dev/null || true
cp data/knowledge.json "$RUN_DIR/data/knowledge.final.json" 2>/dev/null || true
cp data/session_guard.json "$RUN_DIR/data/session_guard.final.json" 2>/dev/null || true
python3 technical_summary.py "$RUN_DIR" || true
python3 experiment_telemetry.py end || true
echo "[OUTPUT] $RUN_DIR"
exit "$RC"
