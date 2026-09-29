#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

JSON_REPORTS = (
    'resource_scoreboard.json','health_score.json','version_metrics.json',
    'security_verdicts.json','run_summary.json',
)

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--report-dir', required=True)
    args=ap.parse_args()
    run_id=args.run_id
    report_dir=Path(args.report_dir)
    errors=[]
    if run_id.upper().startswith('SELFTEST'):
        errors.append('operational run_id cannot begin with SELFTEST')
    for name in JSON_REPORTS:
        path=report_dir/name
        if not path.exists():
            errors.append(f'missing report: {name}')
            continue
        try:
            data=json.loads(path.read_text(encoding='utf-8'))
        except Exception as exc:
            errors.append(f'invalid JSON {name}: {exc}')
            continue
        actual=str(data.get('run_id') or '')
        if actual != run_id:
            errors.append(f'{name}: run_id={actual!r}, expected={run_id!r}')
        if actual.upper().startswith('SELFTEST'):
            errors.append(f'{name}: selftest report contamination')
    if errors:
        print('[REPORT VALIDATION] FAILED', file=sys.stderr)
        for e in errors: print(f' - {e}', file=sys.stderr)
        return 31
    print(f'[REPORT VALIDATION] OK run_id={run_id}')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
