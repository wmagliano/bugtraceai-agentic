#!/usr/bin/env python3
"""
BugTraceAI v3.0.4a - Multi-Cycle Experiment Runner

Peripheral orchestration only:
- executes N independent BugTraceAI cycles
- resets state before each cycle
- pauses between cycles for operator control
- preserves cycle artifacts
- aggregates normalized states without reinterpreting verdicts
"""
from __future__ import annotations
import argparse, csv, datetime as dt, hashlib, json, os, shlex, shutil, subprocess, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = "3.0.4a"

def utcstamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")

def sha256_file(p: Path):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024), b""): h.update(b)
    return h.hexdigest()

def run_cmd(cmd, env=None):
    print("+", " ".join(shlex.quote(str(x)) for x in cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=env).returncode

def load_report(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def item_key(item):
    # URL is stable across independent cycles; classification helps disambiguate.
    return (str(item.get("url") or ""), str((item.get("finding_classification") or {}).get("type") or ""))

def aggregate(cycle_records, outdir: Path, requested: int, loops: int):
    valid=[x for x in cycle_records if x["status"]=="VALID"]
    failed=[x for x in cycle_records if x["status"]!="VALID"]
    resources=defaultdict(lambda:{
        "states":Counter(), "vulnerability":Counter(),
        "capability":Counter(), "exploitation":Counter(), "cycles":0
    })
    for rec in valid:
        rep=load_report(Path(rec["report"]))
        if not rep: continue
        for item in rep.get("analysis_items",[]):
            k=item_key(item); r=resources[k]; r["cycles"]+=1
            r["states"][str(item.get("state") or "UNKNOWN")]+=1
            r["vulnerability"][str((item.get("vulnerability_verdict") or {}).get("status") or "UNASSESSED")]+=1
            r["capability"][str((item.get("capability_assessment") or {}).get("status") or "UNASSESSED")]+=1
            r["exploitation"][str((item.get("exploitation") or {}).get("status") or "UNASSESSED")]+=1

    summary={
      "schema_version":"3.0.4a-multicycle-1",
      "version":VERSION,
      "generated_at":dt.datetime.now(dt.timezone.utc).isoformat(),
      "requested_cycles":requested,
      "valid_cycles":len(valid),
      "failed_or_aborted_cycles":len(failed),
      "loops_per_cycle":loops,
      "invariant":"Aggregator counts persisted per-cycle states and never reinterprets verdicts.",
      "cycles":cycle_records,
      "resources":[]
    }
    for (url,ft),r in sorted(resources.items()):
        summary["resources"].append({
          "url":url, "finding_type":ft, "observed_valid_cycles":r["cycles"],
          "states":dict(r["states"]), "vulnerability_verdicts":dict(r["vulnerability"]),
          "capability_assessments":dict(r["capability"]), "exploitation":dict(r["exploitation"])
        })
    (outdir/"summary.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")

    md=[
      "# BugTraceAI v3.0.4a — Multi-Cycle Summary","",
      f"- Requested cycles: **{requested}**",
      f"- Valid cycles: **{len(valid)}**",
      f"- RUN_FAILED/aborted: **{len(failed)}**",
      f"- Loops per cycle: **{loops}**","",
      "> The aggregator only counts persisted states. It never promotes, demotes, or reinterprets a cycle verdict.","",
      "| Resource | Valid observations | COMPLETED | CONFIRMED | REQUIRES_OPERATOR_VALIDATION | INCONCLUSIVE |",
      "|---|---:|---:|---:|---:|---:|"
    ]
    for x in summary["resources"]:
        n=x["observed_valid_cycles"]
        completed=x["states"].get("COMPLETED",0)
        confirmed=x["vulnerability_verdicts"].get("CONFIRMED",0)
        rov=x["capability_assessments"].get("REQUIRES_OPERATOR_VALIDATION",0)
        incon=x["states"].get("INCONCLUSIVE",0)+x["vulnerability_verdicts"].get("INCONCLUSIVE",0)
        md.append(f"| {x['url']} | {n} | {completed}/{n} | {confirmed}/{n} | {rov}/{n} | {incon}/{n} |")
    (outdir/"report.md").write_text("\n".join(md)+"\n",encoding="utf-8")

    with (outdir/"summary.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["resource","valid_observations","completed","confirmed","requires_operator_validation","state_inconclusive","verdict_inconclusive"])
        for x in summary["resources"]:
            w.writerow([x["url"],x["observed_valid_cycles"],x["states"].get("COMPLETED",0),
                        x["vulnerability_verdicts"].get("CONFIRMED",0),
                        x["capability_assessments"].get("REQUIRES_OPERATOR_VALIDATION",0),
                        x["states"].get("INCONCLUSIVE",0),x["vulnerability_verdicts"].get("INCONCLUSIVE",0)])
    return summary

def main():
    ap=argparse.ArgumentParser(description="BugTraceAI v3.0.4a multi-cycle experiment runner")
    ap.add_argument("--ciclos",type=int,default=10)
    ap.add_argument("--bucles",type=int,default=500)
    ap.add_argument("--config",default="config/site.json")
    ap.add_argument("--cassette",default=None)
    ap.add_argument("--command",default="./run_v302_auto.sh",help="BugTraceAI single-cycle entry point")
    ap.add_argument("--reset-command",default="./reset_v254_sessioncheck.sh",help="reset command executed before every cycle")
    ap.add_argument("--sin-pausa",action="store_true",help="continue automatically between cycles")
    args=ap.parse_args()
    if args.ciclos < 1 or args.bucles < 1: ap.error("--ciclos and --bucles must be >= 1")

    exp_id=f"{utcstamp()}-{os.getpid()}"
    base=ROOT/"runs"/"multicycle"/exp_id
    cycles_dir=base/"cycles"; aggregate_dir=base/"aggregate"
    cycles_dir.mkdir(parents=True,exist_ok=True); aggregate_dir.mkdir(parents=True,exist_ok=True)

    manifest={
      "version":VERSION,"experiment_id":exp_id,"started_at":dt.datetime.now(dt.timezone.utc).isoformat(),
      "cycles":args.ciclos,"loops":args.bucles,"config":args.config,"cassette":args.cassette,
      "command":args.command,"reset_command":args.reset_command
    }
    cfg=ROOT/args.config
    if cfg.exists(): manifest["config_sha256"]=sha256_file(cfg)
    (base/"experiment.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding="utf-8")

    records=[]
    for i in range(1,args.ciclos+1):
        while True:
            print(f"\n=== BugTraceAI cycle {i}/{args.ciclos} ===")
            cdir=cycles_dir/f"cycle-{i:03d}"; cdir.mkdir(parents=True,exist_ok=True)
            reset=shlex.split(args.reset_command)+[args.config]
            rrc=run_cmd(reset)
            if rrc:
                rec={"cycle":i,"status":"RUN_FAILED","stage":"reset","returncode":rrc}
            else:
                env=os.environ.copy()
                env["BUGTRACEAI_CONFIG"]=args.config
                env["BUGTRACEAI_PROJECT_CYCLE"]=str(i)
                env["BUGTRACEAI_RUN_ID"]=f"{exp_id}-cycle-{i:03d}"
                if args.cassette: env["BUGTRACEAI_CASSETTE"]=args.cassette
                cmd=shlex.split(args.command)+[str(args.bucles)]
                rc=run_cmd(cmd,env)
                report=ROOT/"runs"/env["BUGTRACEAI_RUN_ID"]/"reports"/"bugtraceai-final-report.json"
                if rc==0 and report.exists() and load_report(report):
                    shutil.copy2(report,cdir/"bugtraceai-final-report.json")
                    md=report.with_suffix(".md")
                    if md.exists(): shutil.copy2(md,cdir/"bugtraceai-final-report.md")
                    rec={"cycle":i,"status":"VALID","returncode":rc,"report":str(cdir/"bugtraceai-final-report.json")}
                else:
                    rec={"cycle":i,"status":"RUN_FAILED","stage":"agent","returncode":rc,"report_found":report.exists()}
            print("Cycle result:",rec["status"])
            if rec["status"]=="VALID":
                records.append(rec); break
            if args.sin_pausa:
                records.append(rec); break
            choice=input("[R]epeat cycle / [C]ontinue counting as RUN_FAILED / [A]bort: ").strip().lower()
            if choice.startswith("r"): continue
            records.append(rec)
            if choice.startswith("a"):
                aggregate(records,aggregate_dir,args.ciclos,args.bucles)
                print("Aborted. Partial report:",aggregate_dir/"report.md")
                return 130
            break
        if i < args.ciclos and not args.sin_pausa:
            choice=input(f"Cycle {i}/{args.ciclos} finished. ENTER=continue / R=repeat last valid cycle / A=abort: ").strip().lower()
            if choice.startswith("a"):
                aggregate(records,aggregate_dir,args.ciclos,args.bucles); return 130
            if choice.startswith("r"):
                # Remove the valid observation and rerun the same numbered cycle.
                records.pop()
                # intentionally rerun via a compact loop
                while True:
                    print("Repeat requested; restarting current cycle.")
                    rrc=run_cmd(shlex.split(args.reset_command)+[args.config])
                    env=os.environ.copy(); env["BUGTRACEAI_CONFIG"]=args.config; env["BUGTRACEAI_PROJECT_CYCLE"]=str(i)
                    env["BUGTRACEAI_RUN_ID"]=f"{exp_id}-cycle-{i:03d}-repeat-{utcstamp()}"
                    if args.cassette: env["BUGTRACEAI_CASSETTE"]=args.cassette
                    rc=run_cmd(shlex.split(args.command)+[str(args.bucles)],env) if rrc==0 else rrc
                    report=ROOT/"runs"/env["BUGTRACEAI_RUN_ID"]/"reports"/"bugtraceai-final-report.json"
                    if rc==0 and report.exists() and load_report(report):
                        cdir=cycles_dir/f"cycle-{i:03d}"; shutil.copy2(report,cdir/"bugtraceai-final-report.json")
                        records.append({"cycle":i,"status":"VALID","returncode":0,"report":str(cdir/"bugtraceai-final-report.json")}); break
                    ch=input("Repeat failed. [R]etry / [C]ontinue / [A]bort: ").strip().lower()
                    if ch.startswith("r"): continue
                    records.append({"cycle":i,"status":"RUN_FAILED","stage":"repeat","returncode":rc})
                    if ch.startswith("a"): aggregate(records,aggregate_dir,args.ciclos,args.bucles); return 130
                    break

    aggregate(records,aggregate_dir,args.ciclos,args.bucles)
    print("\n[OK] Multi-cycle experiment complete")
    print("Report:",aggregate_dir/"report.md")
    print("JSON:",aggregate_dir/"summary.json")
    print("CSV:",aggregate_dir/"summary.csv")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
