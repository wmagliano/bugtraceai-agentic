#!/usr/bin/env python3
import argparse,json
from contract_diagnostics import generate_report as contract_report
from runtime_diagnostics import generate_report as runtime_report
from observability_v262 import generate
ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(); g.add_argument('--run-id'); g.add_argument('--all-runs',action='store_true'); a=ap.parse_args()
print('[+] Diagnóstico de contratos'); contract_report()
print('[+] Diagnóstico transversal'); runtime_report()
print('[+] Observabilidad extendida v2.6.2'); print(json.dumps(generate(a.run_id,a.all_runs),indent=2,ensure_ascii=False))
print('[DONE] Reportes generados en reports/runs/<run_id> o reports/all-runs')
