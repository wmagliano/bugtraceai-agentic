#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
MAX_CYCLES="${1:-100}"
DBG=(python3 debug_flow_v263b.py)
"${DBG[@]}" scheduler_start --note "max_cycles=$MAX_CYCLES"
for i in $(seq 1 "$MAX_CYCLES"); do
  echo; echo "============================================================"; echo "[SCHEDULER] BugTraceAI v2.6.3b cycle $i/$MAX_CYCLES"; echo "============================================================"
  "${DBG[@]}" cycle_start --cycle "$i"
  python3 resource_scheduler.py reconcile >/dev/null; RC=$?; "${DBG[@]}" after_reconcile_pre --cycle "$i" --rc "$RC"
  PREPARE_OUTPUT="$(python3 resource_scheduler.py prepare 2>&1)"; PREPARE_RC=$?; echo "$PREPARE_OUTPUT"
  "${DBG[@]}" after_prepare --cycle "$i" --rc "$PREPARE_RC" --note "$PREPARE_OUTPUT"

  if [[ $PREPARE_RC -ne 10 && $PREPARE_RC -ne 1 ]]; then
    ACTIVE_META="$(python3 - <<'PY'
from resource_scheduler import ResourceScheduler
s=ResourceScheduler(); url=s.active() or ''; item=(s.queue().get(url) or {}) if url else {}; print((item.get('analysis_id') or '')+'|'+url)
PY
)"
    ACTIVE_ID="${ACTIVE_META%%|*}"; ACTIVE_URL="${ACTIVE_META#*|}"
    LAST_ROTATED_ID="$(python3 - <<'PY'
import json
from pathlib import Path
try: print(json.loads(Path('data/session_rotation.json').read_text()).get('analysis_id') or '')
except Exception: print('')
PY
)"
    "${DBG[@]}" session_rotation_check --cycle "$i" --active "$ACTIVE_URL" --note "active_id=$ACTIVE_ID previous=$LAST_ROTATED_ID"
    if [[ -n "$ACTIVE_ID" && "$ACTIVE_ID" != "$LAST_ROTATED_ID" ]]; then
      echo "[SESSION ROTATION] Cambio de Analysis Item: ${LAST_ROTATED_ID:-NONE} -> $ACTIVE_ID"
      python3 session_guard.py --config "${BUGTRACEAI_CONFIG:-config/site.json}" --attempts 3 --rotate --analysis-id "$ACTIVE_ID"; SG_RC=$?
      "${DBG[@]}" after_session_rotate --cycle "$i" --active "$ACTIVE_URL" --rc "$SG_RC"
      if [[ $SG_RC -ne 0 ]]; then exit 31; fi
      python3 - "$ACTIVE_ID" "$ACTIVE_URL" <<'PY'
import json,sys
from datetime import datetime,timezone
from pathlib import Path
p=Path('data/session_rotation.json'); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps({'version':'2.6.3b','analysis_id':sys.argv[1],'resource':sys.argv[2],'rotated_at':datetime.now(timezone.utc).isoformat()},indent=2))
PY
    fi
  fi

  if [[ $PREPARE_RC -eq 10 ]]; then
    "${DBG[@]}" queue_exhausted --cycle "$i"; python3 resource_scheduler.py status; python3 final_report.py; exit 0
  elif [[ $PREPARE_RC -eq 20 ]]; then
    RESOURCE="$(python3 - <<'PY'
import json
from pathlib import Path
x=json.loads(Path('logs/last_llm_decision.json').read_text()); print((x.get('next_actions') or [{}])[0].get('url') or '')
PY
)"
    "${DBG[@]}" before_interior --cycle "$i" --active "$RESOURCE"
    python3 executor_mcp.py; EXEC_INT_RC=$?; "${DBG[@]}" after_interior --cycle "$i" --active "$RESOURCE" --rc "$EXEC_INT_RC"
    if [[ $EXEC_INT_RC -ne 0 ]]; then python3 resource_scheduler.py reconcile >/dev/null || true; continue; fi
    python3 resource_scheduler.py reconcile >/dev/null; "${DBG[@]}" after_reconcile_interior --cycle "$i" --active "$RESOURCE"
    if python3 - "$RESOURCE" <<'PY'
import json,sys
from pathlib import Path
k=json.loads(Path('data/knowledge.json').read_text()); raise SystemExit(0 if sys.argv[1] in (k.get('url_context') or {}) else 1)
PY
    then python3 - "$RESOURCE" <<'PY'
from resource_scheduler import ResourceScheduler
import sys
ResourceScheduler().mark_mapped(sys.argv[1])
PY
    else python3 - "$RESOURCE" <<'PY'
from resource_scheduler import ResourceScheduler
import sys
s=ResourceScheduler(); n=s.register_error(sys.argv[1],'run_interior no produjo url_context'); print(f'[SCHEDULER] error_count={n}');
if n >= int(s.k['scheduler'].get('error_limit',3)): s.mark_inconclusive(sys.argv[1],f"{int(s.k['scheduler'].get('error_limit',3))} errores de preparación/interior")
PY
      "${DBG[@]}" interior_without_context --cycle "$i" --active "$RESOURCE"; continue
    fi
  elif [[ $PREPARE_RC -ne 0 ]]; then "${DBG[@]}" prepare_error --cycle "$i" --rc "$PREPARE_RC"; exit 1; fi

  ACTIVE="$(python3 - <<'PY'
from resource_scheduler import ResourceScheduler
print(ResourceScheduler().active() or '')
PY
)"
  "${DBG[@]}" active_selected --cycle "$i" --active "$ACTIVE"
  [[ -z "$ACTIVE" ]] && continue

  "${DBG[@]}" before_session_guard --cycle "$i" --active "$ACTIVE"
  # v3.0.2-archivo: tolerate a temporary MCP/network outage without losing the run.
  # The failed cycle remains on the same Analysis Item; no verdict/state is changed.
  SG_TRANSIENT_RETRIES="${BUGTRACEAI_SG_TRANSIENT_RETRIES:-5}"
  SG_TRANSIENT_SLEEP="${BUGTRACEAI_SG_TRANSIENT_SLEEP:-20}"
  SG_TRY=0
  while true; do
    python3 session_guard.py --config "${BUGTRACEAI_CONFIG:-config/site.json}" --attempts 3; SG_RC=$?
    "${DBG[@]}" after_session_guard --cycle "$i" --active "$ACTIVE" --rc "$SG_RC"
    [[ $SG_RC -eq 0 ]] && break

    SG_FAILURE="$(python3 - <<'PYSG'
import json
from pathlib import Path
p=Path('data/session_guard.json')
try:
    d=json.loads(p.read_text())
    classes={str(x.get('failure_class') or '') for x in d.get('history',[]) if isinstance(x,dict)}
    errors=' '.join(str(x.get('error') or '') for x in d.get('history',[]) if isinstance(x,dict)).lower()
    transient=bool(classes & {'no_route_to_host','connection_refused','connection_reset','timeout','transport_error'}) or any(x in errors for x in ('no route to host','connection refused','timed out','connection reset'))
    print('TRANSIENT' if transient else 'NONTRANSIENT')
except Exception:
    print('NONTRANSIENT')
PYSG
)"
    if [[ "$SG_FAILURE" != "TRANSIENT" ]]; then exit 31; fi
    SG_TRY=$((SG_TRY + 1))
    if (( SG_TRY > SG_TRANSIENT_RETRIES )); then
      echo "[SESSION GUARD] Infraestructura sigue inaccesible tras ${SG_TRANSIENT_RETRIES} reintentos transitorios."
      exit 31
    fi
    echo "[SESSION GUARD] Fallo transitorio de infraestructura; conservando estado y reintentando ${SG_TRY}/${SG_TRANSIENT_RETRIES} en ${SG_TRANSIENT_SLEEP}s."
    sleep "$SG_TRANSIENT_SLEEP"
  done

  "${DBG[@]}" before_reasoner --cycle "$i" --active "$ACTIVE"; python3 reasoner.py; R_RC=$?; "${DBG[@]}" after_reasoner --cycle "$i" --active "$ACTIVE" --rc "$R_RC"; [[ $R_RC -ne 0 ]] && exit 1
  "${DBG[@]}" before_reasoner_llm --cycle "$i" --active "$ACTIVE"; python3 reasoner_llm.py; L_RC=$?; "${DBG[@]}" after_reasoner_llm --cycle "$i" --active "$ACTIVE" --rc "$L_RC"; [[ $L_RC -ne 0 ]] && exit 1
  python3 flow_trace.py decision --active "$ACTIVE" || true
  if command -v jq >/dev/null 2>&1; then jq '{decision_id,analysis_summary,next_actions,state_updates,operator_message}' logs/last_llm_decision.json; else cat logs/last_llm_decision.json; fi

  ACTION="$(python3 - <<'PY'
import json
from pathlib import Path
x=json.loads(Path('logs/last_llm_decision.json').read_text()); print(((x.get('next_actions') or [{}])[0]).get('action') or '')
PY
)"
  PAYLOAD="$(python3 - <<'PY'
import json
from pathlib import Path
x=json.loads(Path('logs/last_llm_decision.json').read_text()); a=(x.get('next_actions') or [{}])[0]; print(a.get('command') or a.get('url') or a.get('reason') or '')
PY
)"
  "${DBG[@]}" decision_parsed --cycle "$i" --active "$ACTIVE" --note "action=$ACTION" --command "$PAYLOAD"
  LOOP_COUNT="$(python3 - "$ACTIVE" "$ACTION" "$PAYLOAD" <<'PY'
from resource_scheduler import ResourceScheduler
import sys
print(ResourceScheduler().register_action(sys.argv[1],sys.argv[2],sys.argv[3]))
PY
)"
  "${DBG[@]}" loop_registered --cycle "$i" --active "$ACTIVE" --note "loop_count=$LOOP_COUNT action=$ACTION"
  # R0-FINAL-C1-fix: register_action() owns the real same-action loop limit
  # (persisted scheduler.loop_limit, baseline default=10). The historical shell
  # guard at >=3 only skipped execution and printed a false INCONCLUSIVE message.
  LOOP_STATE="$(python3 - "$ACTIVE" <<'PY'
from resource_scheduler import ResourceScheduler,state_name
import sys
s=ResourceScheduler(); print(state_name((s.queue().get(sys.argv[1]) or {}).get('state')))
PY
)"
  if [[ "$LOOP_STATE" == "INCONCLUSIVE" || "$LOOP_STATE" == "COMPLETED" || "$LOOP_STATE" == "FAILED" ]]; then
    echo "[SCHEDULER] Same-action guard alcanzado (loop_count=$LOOP_COUNT). Estado persistido: $LOOP_STATE; avanzando."
    continue
  fi

  "${DBG[@]}" before_executor --cycle "$i" --active "$ACTIVE" --command "$PAYLOAD"
  python3 executor_mcp.py; EXEC_RC=$?
  "${DBG[@]}" after_executor --cycle "$i" --active "$ACTIVE" --rc "$EXEC_RC" --command "$PAYLOAD"
  python3 resource_scheduler.py reconcile >/dev/null || true; "${DBG[@]}" after_reconcile_post --cycle "$i" --active "$ACTIVE"
  POST_STATE="$(python3 - "$ACTIVE" <<'PY'
from resource_scheduler import ResourceScheduler,state_name
import sys
s=ResourceScheduler(); print(state_name((s.queue().get(sys.argv[1]) or {}).get('state')))
PY
)"
  echo "[SCHEDULER] Estado posterior: $POST_STATE"; "${DBG[@]}" post_state --cycle "$i" --active "$ACTIVE" --note "$POST_STATE"
  if [[ "$POST_STATE" == "COMPLETED" || "$POST_STATE" == "INCONCLUSIVE" || "$POST_STATE" == "FAILED" ]]; then continue; fi
  if [[ $EXEC_RC -ne 0 ]]; then
    ERR_COUNT="$(python3 - "$ACTIVE" <<'PY'
from resource_scheduler import ResourceScheduler
import sys
print(ResourceScheduler().register_error(sys.argv[1],'executor_mcp returncode no cero'))
PY
)"; ERROR_LIMIT="${BUGTRACEAI_MAX_ERRORS:-3}"; echo "[SCHEDULER] Error operativo $ERR_COUNT/$ERROR_LIMIT"; "${DBG[@]}" executor_error_registered --cycle "$i" --active "$ACTIVE" --note "$ERR_COUNT/$ERROR_LIMIT"
    if [[ "$ERR_COUNT" =~ ^[0-9]+$ ]] && (( ERR_COUNT >= ERROR_LIMIT )); then python3 resource_scheduler.py mark "$ACTIVE" INCONCLUSIVE --reason "$ERROR_LIMIT errores operativos del executor" >/dev/null; fi
  fi
done
"${DBG[@]}" max_cycles_reached --cycle "$MAX_CYCLES"; python3 resource_scheduler.py status; exit 2
