#!/usr/bin/env python3
"""Raw execution-flow recorder for BugTraceAI v2.6.3a.

Creates an append-only JSONL timeline plus per-event snapshots of the mutable
files that connect Scheduler, Reasoner, Executor and reporting. It observes the
existing architecture; it does not change decisions or execution policy.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRACKED = [
    "config/dvwa.json",
    "data/knowledge.json",
    "data/session_guard.json",
    "data/session_rotation.json",
    "data/analysis_queue.json",
    "data/resource_state.json",
    "logs/last_reasoner_result.json",
    "logs/last_llm_decision.json",
    "logs/executor_state.json",
    "logs/executor_mcp.log",
    "logs/runtime_capabilities.json",
    "logs/flow_trace.jsonl",
    "logs/lifecycle_trace.jsonl",
    "logs/runtime_diagnostics.jsonl",
]

def now(): return datetime.now(timezone.utc).isoformat()
def sha256(p: Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

def safe_json(p: Path):
    try: return json.loads(p.read_text(encoding='utf-8'))
    except Exception as e: return {"_parse_error": str(e)}

def run_dir() -> Path:
    p=os.environ.get("BUGTRACEAI_RUN_DIR")
    return (ROOT / p if p and not Path(p).is_absolute() else Path(p)) if p else ROOT / "runs" / "manual-debug"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("phase")
    ap.add_argument("--cycle", type=int)
    ap.add_argument("--rc", type=int)
    ap.add_argument("--active", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--command", default="")
    args=ap.parse_args()
    base=run_dir()/"debug_raw"
    events=base/"events"; events.mkdir(parents=True,exist_ok=True)
    seqfile=base/"sequence.txt"
    try: seq=int(seqfile.read_text())+1
    except Exception: seq=1
    seqfile.write_text(str(seq))
    event_id=f"{seq:06d}_{args.phase.replace('/','_').replace(' ','_')}"
    snap=events/event_id; snap.mkdir(parents=True,exist_ok=True)
    files=[]
    for rel in TRACKED:
        src=ROOT/rel
        if not src.exists():
            files.append({"path":rel,"exists":False}); continue
        dst=snap/rel; dst.parent.mkdir(parents=True,exist_ok=True)
        try: shutil.copy2(src,dst)
        except Exception as e:
            files.append({"path":rel,"exists":True,"copy_error":str(e)}); continue
        info={"path":rel,"exists":True,"size":src.stat().st_size,"sha256":sha256(src)}
        if src.suffix=='.json': info["json"]=safe_json(src)
        files.append(info)
    env_keys=[k for k in os.environ if k.startswith("BUGTRACEAI_")]
    event={
      "event_id":event_id,"timestamp":now(),"phase":args.phase,"cycle":args.cycle,
      "returncode":args.rc,"active":args.active,"note":args.note,"command":args.command,
      "pid":os.getpid(),"ppid":os.getppid(),
      "environment":{k:os.environ.get(k) for k in sorted(env_keys)},"files":files,
    }
    (snap/"event.json").write_text(json.dumps(event,indent=2,ensure_ascii=False),encoding='utf-8')
    with (base/"flow.jsonl").open('a',encoding='utf-8') as f: f.write(json.dumps(event,ensure_ascii=False)+"\n")
    print(f"[RAW DEBUG] {event_id} active={args.active or '-'} rc={args.rc if args.rc is not None else '-'}")
if __name__=='__main__': main()
