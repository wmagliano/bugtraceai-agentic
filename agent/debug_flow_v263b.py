#!/usr/bin/env python3
"""BugTraceAI v2.6.3b forensic flight recorder.

Observes the orchestrator at explicit boundaries and writes:
- debug_raw/flow.jsonl: complete event snapshots
- debug_raw/full_execution_trace.jsonl: compact unified timeline
- debug_raw/file_changes.jsonl: observed file changes and JSON field diffs
- debug_raw/events/<event>/...: immutable per-event copies

This recorder does not alter Reasoner, Executor, scheduler decisions, MCP policy,
or attempt limits. READ/WRITE labels are observational: a changed file between
boundaries is an observed write; unchanged tracked files are observed snapshots,
not proof that a process opened them at OS level.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    "logs/decision-execution-flow.jsonl",
    "logs/llm_contract_debug.jsonl",
    "logs/lifecycle/analysis-lifecycle.jsonl",
]

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def safe_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_parse_error": str(exc)}

def run_dir() -> Path:
    value = os.environ.get("BUGTRACEAI_RUN_DIR")
    if not value:
        return ROOT / "runs" / "manual-debug"
    p = Path(value)
    return p if p.is_absolute() else ROOT / p

def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(item, name))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            name = f"{prefix}[{idx}]"
            out.update(flatten(item, name))
    else:
        out[prefix or "$value"] = value
    return out

def json_diff(before: Any, after: Any, limit: int = 500) -> list[dict[str, Any]]:
    a, b = flatten(before), flatten(after)
    changes: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            changes.append({"field": key, "before": a.get(key), "after": b.get(key)})
            if len(changes) >= limit:
                changes.append({"field": "_truncated", "before": None, "after": f">={limit} changes"})
                break
    return changes

def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

def load_previous(base: Path) -> dict[str, Any]:
    p = base / "last_snapshot.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def compact_decision() -> dict[str, Any]:
    p = ROOT / "logs/last_llm_decision.json"
    if not p.exists():
        return {}
    x = safe_json(p)
    if not isinstance(x, dict):
        return {}
    action = ((x.get("next_actions") or [{}])[0]) if isinstance(x.get("next_actions"), list) else {}
    return {
        "decision_id": x.get("decision_id"),
        "analysis_summary": x.get("analysis_summary"),
        "action": action.get("action") if isinstance(action, dict) else None,
        "command": action.get("command") if isinstance(action, dict) else None,
        "url": action.get("url") if isinstance(action, dict) else None,
        "reason": action.get("reason") if isinstance(action, dict) else None,
        "state_updates": x.get("state_updates"),
    }

def main() -> None:
    # v3.0.2: raw forensic snapshots are opt-in. Structured operational
    # telemetry remains enabled elsewhere.
    if str(os.environ.get("BUGTRACEAI_DEBUG_RAW", "0")).strip().lower() not in {"1","true","yes","on"}:
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("phase")
    ap.add_argument("--cycle", type=int)
    ap.add_argument("--rc", type=int)
    ap.add_argument("--active", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--command", default="")
    ap.add_argument("--component", default="")
    args = ap.parse_args()

    base = run_dir() / "debug_raw"
    events = base / "events"
    events.mkdir(parents=True, exist_ok=True)
    seqfile = base / "sequence.txt"
    try:
        seq = int(seqfile.read_text(encoding="utf-8")) + 1
    except Exception:
        seq = 1
    seqfile.write_text(str(seq), encoding="utf-8")
    event_id = f"{seq:06d}_{args.phase.replace('/', '_').replace(' ', '_')}"
    snap = events / event_id
    snap.mkdir(parents=True, exist_ok=True)

    previous = load_previous(base)
    current: dict[str, Any] = {}
    files: list[dict[str, Any]] = []
    observed_changes: list[dict[str, Any]] = []

    for rel in TRACKED:
        src = ROOT / rel
        if not src.exists():
            meta = {"path": rel, "exists": False}
            files.append(meta)
            current[rel] = meta
            old = previous.get(rel)
            if old and old.get("exists"):
                observed_changes.append({"path": rel, "change": "deleted", "before_sha256": old.get("sha256")})
            continue

        dst = snap / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
        except Exception as exc:
            meta = {"path": rel, "exists": True, "copy_error": str(exc)}
            files.append(meta)
            current[rel] = meta
            continue

        meta: dict[str, Any] = {
            "path": rel,
            "exists": True,
            "size": src.stat().st_size,
            "mtime_ns": src.stat().st_mtime_ns,
            "sha256": sha256(src),
        }
        if src.suffix == ".json":
            meta["json"] = safe_json(src)
        files.append(meta)
        current[rel] = meta

        old = previous.get(rel)
        if not old or not old.get("exists"):
            observed_changes.append({"path": rel, "change": "created", "after_sha256": meta.get("sha256")})
        elif old.get("sha256") != meta.get("sha256"):
            change: dict[str, Any] = {
                "path": rel,
                "change": "modified",
                "before_sha256": old.get("sha256"),
                "after_sha256": meta.get("sha256"),
                "before_size": old.get("size"),
                "after_size": meta.get("size"),
            }
            if "json" in old and "json" in meta:
                change["json_diff"] = json_diff(old.get("json"), meta.get("json"))
            observed_changes.append(change)

    (base / "last_snapshot.json").write_text(json.dumps(current, ensure_ascii=False, default=str), encoding="utf-8")

    env_keys = [k for k in os.environ if k.startswith("BUGTRACEAI_")]
    component = args.component or args.phase.split("_", 1)[-1]
    event = {
        "event_id": event_id,
        "timestamp": now(),
        "phase": args.phase,
        "component": component,
        "cycle": args.cycle,
        "returncode": args.rc,
        "active": args.active,
        "note": args.note,
        "command": args.command,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "environment": {k: os.environ.get(k) for k in sorted(env_keys)},
        "observed_changes": observed_changes,
        "files": files,
    }
    (snap / "event.json").write_text(json.dumps(event, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    append_jsonl(base / "flow.jsonl", event)

    decision = compact_decision()
    unified = {
        "event_id": event_id,
        "timestamp": event["timestamp"],
        "cycle": args.cycle,
        "phase": args.phase,
        "component": component,
        "active_resource": args.active,
        "returncode": args.rc,
        "note": args.note,
        "submitted_command": args.command,
        "decision": decision,
        "changed_files": [x.get("path") for x in observed_changes],
        "change_count": len(observed_changes),
        "knowledge_sha256": (current.get("data/knowledge.json") or {}).get("sha256"),
    }
    append_jsonl(base / "full_execution_trace.jsonl", unified)
    for change in observed_changes:
        append_jsonl(base / "file_changes.jsonl", {
            "event_id": event_id,
            "timestamp": event["timestamp"],
            "cycle": args.cycle,
            "phase": args.phase,
            "component_boundary": component,
            **change,
        })

    print(f"[FORENSIC] {event_id} active={args.active or '-'} rc={args.rc if args.rc is not None else '-'} changes={len(observed_changes)}")

if __name__ == "__main__":
    main()
