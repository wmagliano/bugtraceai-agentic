#!/usr/bin/env python3
"""BugTraceAI v2.2.3 - Analysis Item scheduler.

The scheduler owns global navigation. It never interprets vulnerabilities.
It only normalizes the resource queue, selects one pending resource, tracks
visits/errors/loops and prepares deterministic run_interior actions.
"""
from __future__ import annotations

import argparse
import os
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from analysis_queue import ensure_schema as ensure_analysis_schema, find_item, add_item, set_state as set_analysis_state, set_active as set_active_analysis, sync_runtime
from lifecycle_trace import emit, persist_snapshot

ROOT = Path(__file__).resolve().parent
KNOWLEDGE = ROOT / "data" / "knowledge.json"
DECISION = ROOT / "logs" / "last_llm_decision.json"

TERMINAL_STATES = {"COMPLETED", "INCONCLUSIVE", "FAILED"}
PENDING_STATES = {"NEW", "MAPPED", "HYPOTHESIS_ACTIVE", "CONFIRMED", "EXPLOITING", "EXPLOITABLE"}
VALID_STATES = PENDING_STATES | TERMINAL_STATES | {"PAUSED", "WAITING_OPERATOR", "EXPLOITING", "EXPLOITABLE", "DOCUMENTED", "DONE", "FINISHED", "CLOSED"}
DEFAULT_LOOP_LIMIT = 10
DEFAULT_ERROR_LIMIT = 3
DEFAULT_RESOURCE_ITERATION_LIMIT = 20



def autonomous_mode_enabled() -> bool:
    return str(os.environ.get("BUGTRACEAI_AUTONOMOUS", "0")).strip().lower() in {"1", "true", "yes", "on"}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def resource_url(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("resource", "url", "endpoint"):
            v = value.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def normalize_url(url: str | None) -> str | None:
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip().split("#", 1)[0]
    if not url.startswith(("http://", "https://")):
        return url
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def canonical_key(url: str | None) -> str | None:
    """Queue identity preserves meaningful query strings such as FI page=."""
    return normalize_url(url)


def completed_urls(k: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for item in k.get("completed_urls") or []:
        url = normalize_url(resource_url(item))
        if url:
            out.add(url)
    return out


def _norm_path(path: str) -> str:
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def state_name(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("state")
    value = str(value or "NEW").upper().strip()
    aliases = {"DOCUMENTED": "COMPLETED", "DONE": "COMPLETED", "FINISHED": "COMPLETED", "CLOSED": "COMPLETED"}
    value = aliases.get(value, value)
    return value if value in (PENDING_STATES | TERMINAL_STATES | {"PAUSED", "WAITING_OPERATOR", "EXPLOITING", "EXPLOITABLE"}) else "NEW"


def infer_priority(url: str, index: int) -> int:
    # Prioridad neutral: conserva el orden de descubrimiento. No infiere
    # vulnerabilidad, función ni importancia a partir del path.
    return 100000 - index


@dataclass
class Selection:
    resource: str
    state: str
    reason: str


class ResourceScheduler:
    def __init__(self, knowledge_path: Path = KNOWLEDGE):
        self.path = knowledge_path
        self.k: dict[str, Any] = load_json(self.path, {})
        if not isinstance(self.k, dict):
            self.k = {}
        self.ensure_schema()

    def save(self) -> None:
        self.k["scheduler"]["updated_at"] = utc_now()
        sync_runtime(self.k)
        save_json(self.path, self.k)
        persist_snapshot(self.k,component='resource_scheduler.save',path=str(self.path))

    def ensure_schema(self) -> None:
        k = self.k
        k.setdefault("candidate_urls", [])
        k.setdefault("visited_urls", [])
        k.setdefault("completed_urls", [])
        k.setdefault("resource_state", {})
        k.setdefault("resource_state_history", [])
        k.setdefault("resource_errors", {})
        k.setdefault("active_resource", None)
        scheduler = k.setdefault("scheduler", {})
        scheduler["version"] = "2.2.3-query-continuity-scheduler"
        scheduler.setdefault("queue", {})
        scheduler.setdefault("events", [])
        scheduler.setdefault("loop_limit", DEFAULT_LOOP_LIMIT)
        # r4b-open: old persisted r4/r4b values must not keep the limit at 3.
        try:
            if int(scheduler.get("loop_limit") or 0) < DEFAULT_LOOP_LIMIT:
                scheduler["loop_limit"] = DEFAULT_LOOP_LIMIT
        except (TypeError, ValueError):
            scheduler["loop_limit"] = DEFAULT_LOOP_LIMIT
        scheduler["error_limit"] = max(1, int(os.environ.get("BUGTRACEAI_MAX_ERRORS", scheduler.get("error_limit", DEFAULT_ERROR_LIMIT))))
        scheduler["resource_iteration_limit"] = max(1, int(os.environ.get("BUGTRACEAI_MAX_RESOURCE_ITERATIONS", scheduler.get("resource_iteration_limit", DEFAULT_RESOURCE_ITERATION_LIMIT))))
        scheduler.setdefault("operator_override", None)
        scheduler.setdefault("final_report_ready", False)

        ensure_analysis_schema(k)
        candidates=[x.get("entry_url") for x in k.get("analysis_queue",[]) if isinstance(x,dict) and x.get("entry_url")]
        k["candidate_urls"] = list(candidates)

        done = completed_urls(k)
        states = k.get("resource_state") if isinstance(k.get("resource_state"), dict) else {}
        queue = scheduler["queue"]
        if not isinstance(queue, dict):
            queue = {}
            scheduler["queue"] = queue

        visited = {normalize_url(x) for x in k.get("visited_urls") or [] if normalize_url(x)}
        for index, url in enumerate(candidates):
            entry = queue.setdefault(url, {})
            if not isinstance(entry, dict):
                entry = {}
                queue[url] = entry
            explicit = state_name(states.get(url))
            if url in done:
                explicit = "INCONCLUSIVE" if self._completed_is_inconclusive(url) else "COMPLETED"
            elif explicit == "NEW" and url in visited:
                explicit = "MAPPED"
            entry.setdefault("resource", url)
            entry["state"] = explicit
            entry.setdefault("visit_count", 1 if url in visited else 0)
            entry.setdefault("error_count", 0)
            entry.setdefault("loop_count", 0)
            entry.setdefault("resource_iteration_count", 0)
            entry.setdefault("last_action", None)
            entry.setdefault("last_action_fingerprint", None)
            entry.setdefault("priority", infer_priority(url, index))
            entry.setdefault("operator_override", False)
            entry.setdefault("created_at", utc_now())
            entry["updated_at"] = utc_now()

        # Keep queue resources discovered earlier even if candidate_urls was compacted.
        for url, entry in list(queue.items()):
            if not isinstance(entry, dict):
                queue[url] = {"resource": url, "state": "NEW", "priority": 0,
                              "visit_count": 0, "error_count": 0, "loop_count": 0, "resource_iteration_count": 0,
                              "last_action": None, "last_action_fingerprint": None,
                              "operator_override": False, "created_at": utc_now(),
                              "updated_at": utc_now()}

        self.reconcile(save=False)

    def _completed_is_inconclusive(self, url: str) -> bool:
        for item in self.k.get("completed_urls") or []:
            if normalize_url(resource_url(item)) != url or not isinstance(item, dict):
                continue
            status = str(item.get("status") or item.get("state") or "").lower()
            if "inconclusive" in status:
                return True
        return False

    def queue(self) -> dict[str, dict[str, Any]]:
        return self.k["scheduler"]["queue"]

    def active(self) -> str | None:
        return normalize_url(resource_url(self.k.get("active_resource")))

    def set_active(self, url: str | None, source: str) -> None:
        url = normalize_url(url)
        self.k["active_resource"] = ({"resource": url, "source": source, "timestamp": utc_now()}
                                     if url else None)
        self.k["scheduler"]["active_resource"] = url
        set_active_analysis(self.k, url)

    def event(self, event_type: str, resource: str | None = None, **extra: Any) -> None:
        event = {"timestamp": utc_now(), "type": event_type, "resource": resource}
        event.update(extra)
        events = self.k["scheduler"].setdefault("events", [])
        events.append(event)
        self.k["scheduler"]["events"] = events[-100:]
        emit('SCHEDULER_EVENT',resource=resource,component='resource_scheduler',scheduler_event=event_type,details=extra)

    def reconcile(self, save: bool = True) -> None:
        """Mirror authoritative runtime state into the scheduler queue."""
        done = completed_urls(self.k)
        states = self.k.get("resource_state") or {}
        visited = {normalize_url(x) for x in self.k.get("visited_urls") or [] if normalize_url(x)}
        for url, entry in self.queue().items():
            previous = state_name(entry.get("state"))
            new = state_name(states.get(url))
            # v2.2.2 containment: AUTO mode cannot remain blocked waiting for
            # a human operator. Re-open the confirmed item so the runtime can
            # apply AUTO-YES and complete/document it.
            if autonomous_mode_enabled() and new == "WAITING_OPERATOR":
                new = "CONFIRMED"
                self.k.setdefault("resource_state", {})[url] = {
                    "state": "CONFIRMED", "updated_at": utc_now(),
                    "updated_by": "auto_yes_containment",
                    "reason": "AUTO-YES: WAITING_OPERATOR resuelto automáticamente."
                }
                set_analysis_state(self.k, url, "CONFIRMED",
                                   "AUTO-YES: WAITING_OPERATOR resuelto automáticamente.",
                                   "auto_yes_containment")
            if url in done:
                new = "INCONCLUSIVE" if self._completed_is_inconclusive(url) else "COMPLETED"
            elif new == "NEW" and url in visited:
                new = "MAPPED"
            # Never downgrade terminal scheduler state without explicit override.
            if previous in TERMINAL_STATES and not entry.get("operator_override"):
                new = previous
            entry["state"] = new
            if url in visited:
                entry["visit_count"] = max(1, int(entry.get("visit_count") or 0))
            err = (self.k.get("resource_errors") or {}).get(url) or {}
            entry["error_count"] = max(int(entry.get("error_count") or 0), int(err.get("error_count") or 0))
            entry["updated_at"] = utc_now()

        active = self.active()
        if active:
            entry = self.queue().get(active)
            if not entry or state_name(entry.get("state")) in TERMINAL_STATES:
                self.event("active_released", active, reason="terminal_or_missing")
                self.set_active(None, "scheduler_reconcile")
        self.k["scheduler"]["final_report_ready"] = not self.has_pending_resources()
        if save:
            self.save()

    def _eligible(self, entry: dict[str, Any]) -> bool:
        state = state_name(entry.get("state"))
        if entry.get("operator_override"):
            return True
        return state in PENDING_STATES

    def has_pending_resources(self) -> bool:
        return any(self._eligible(e) for e in self.queue().values())

    def resource_iteration_limit(self) -> int:
        return max(1, int(self.k["scheduler"].get("resource_iteration_limit") or DEFAULT_RESOURCE_ITERATION_LIMIT))

    def register_resource_iteration(self, url: str) -> tuple[int, int, str | None]:
        """Count absolute scheduler selections for one Analysis Item/resource.

        This is deliberately non-cognitive: it does not interpret progress, actions,
        vulnerabilities or MCP output. It is a final fuse against any unforeseen loop.
        """
        url = normalize_url(url)
        if not url or url not in self.queue():
            return 0, self.resource_iteration_limit(), None
        e = self.queue()[url]
        e["resource_iteration_count"] = int(e.get("resource_iteration_count") or 0) + 1
        item = find_item(self.k, url=url)
        analysis_id = item.get("analysis_id") if isinstance(item, dict) else None
        if isinstance(item, dict):
            item["resource_iteration_count"] = e["resource_iteration_count"]
            item["resource_iteration_limit"] = self.resource_iteration_limit()
        e["updated_at"] = utc_now()
        self.event("resource_iteration_registered", url, analysis_id=analysis_id, count=e["resource_iteration_count"], limit=self.resource_iteration_limit())
        self.save()
        return e["resource_iteration_count"], self.resource_iteration_limit(), analysis_id

    def next_pending_resource(self) -> Selection | None:
        override = normalize_url(resource_url(self.k["scheduler"].get("operator_override")))
        if override and override in self.queue():
            e = self.queue()[override]
            return Selection(override, state_name(e.get("state")), "operator_override")

        active = self.active()
        if active and active in self.queue() and self._eligible(self.queue()[active]):
            e = self.queue()[active]
            return Selection(active, state_name(e.get("state")), "continue_active")

        eligible = [(url, e) for url, e in self.queue().items() if self._eligible(e)]
        if not eligible:
            return None
        # NEW first, then mapped/active states; highest priority; stable URL tie-break.
        state_rank = {"NEW": 0, "MAPPED": 1, "HYPOTHESIS_ACTIVE": 2, "CONFIRMED": 3, "EXPLOITING": 4, "EXPLOITABLE": 5, "PAUSED": 9}
        eligible.sort(key=lambda pair: (state_rank.get(state_name(pair[1].get("state")), 8),
                                        -int(pair[1].get("priority") or 0), pair[0]))
        url, entry = eligible[0]
        return Selection(url, state_name(entry.get("state")), "next_pending")

    def select(self) -> Selection | None:
        self.reconcile(save=False)
        while True:
            selection = self.next_pending_resource()
            if not selection:
                self.set_active(None, "resource_scheduler")
                self.k["scheduler"]["final_report_ready"] = True
                self.event("queue_exhausted")
                self.save()
                return None

            self.set_active(selection.resource, "resource_scheduler")
            count, limit, analysis_id = self.register_resource_iteration(selection.resource)
            print(f"[RESOURCE BUDGET] {analysis_id or '-'} {count}/{limit} para {selection.resource}", file=sys.stderr)
            if count >= limit:
                reason = f"RESOURCE_ITERATION_LIMIT: {count}/{limit} selecciones del Analysis Item"
                self.mark_inconclusive(selection.resource, reason)
                self.event("resource_iteration_limit_reached", selection.resource, analysis_id=analysis_id, count=count, limit=limit)
                print(f"[RESOURCE LIMIT] {analysis_id or '-'} {count}/{limit}. Recurso INCONCLUSIVE; avanzando.", file=sys.stderr)
                self.reconcile(save=False)
                continue

            self.event("resource_selected", selection.resource, state=selection.state, reason=selection.reason, analysis_id=analysis_id, resource_iteration=count, resource_iteration_limit=limit)
            self.save()
            return selection

    def needs_mapping(self, url: str) -> bool:
        entry = self.queue()[url]
        return state_name(entry.get("state")) == "NEW" or url not in (self.k.get("url_context") or {})

    def build_interior_decision(self, url: str) -> dict[str, Any]:
        return {
            "decision_id": str(uuid.uuid4()),
            "timestamp": utc_now(),
            "version": "2.2.3-analysis-item-scheduler",
            "llm_valid_json": True,
            "analysis_summary": "Scheduler prepara el recurso activo antes del análisis cognitivo.",
            "hypotheses": [],
            "needed_context": [],
            "cognitive_updates": {},
            "state_updates": [],
            "next_actions": [{
                "action": "run_interior",
                "url": url,
                "reason": "Mapeo determinístico del recurso seleccionado por resource_scheduler.py"
            }],
            "operator_message": "El scheduler seleccionó y mapeó el recurso activo."
        }

    def write_interior_decision(self, url: str, path: Path = DECISION) -> None:
        save_json(path, self.build_interior_decision(url))
        entry = self.queue()[url]
        entry["last_action"] = "run_interior"
        entry["last_action_fingerprint"] = self.fingerprint(url, "run_interior", url)
        entry["updated_at"] = utc_now()
        self.event("interior_requested", url)
        self.save()

    def mark_mapped(self, url: str) -> None:
        url = normalize_url(url)
        if not url or url not in self.queue():
            return
        e = self.queue()[url]
        if state_name(e.get("state")) == "NEW":
            e["state"] = "MAPPED"
        e["visit_count"] = int(e.get("visit_count") or 0) + 1
        e["error_count"] = 0
        self.k.setdefault("resource_state", {})[url] = {
            "state": e["state"], "updated_at": utc_now(), "updated_by": "scheduler",
            "reason": "run_interior completado antes del análisis cognitivo"
        }
        self.event("resource_mapped", url, visit_count=e["visit_count"])

        # v3.0.3a: the configured target root is a discovery seed, not an
        # Analysis Item that should consume cognitive cycles after its interior
        # mapping has already produced child candidates.  Leaving it MAPPED
        # caused the LLM to keep reasoning on "/" and propose a discovered
        # child URL while the exact-path scope guard correctly blocked it.
        # Close only the target root, and only when same-host child candidates
        # were actually discovered.  Child Analysis Items retain normal scope.
        try:
            from urllib.parse import urlparse
            target_base = normalize_url(os.environ.get("BUGTRACEAI_TARGET_BASE") or self.k.get("target_base") or "")
            up = urlparse(url)
            tp = urlparse(target_base) if target_base else None
            is_target_root = bool(tp and up.scheme == tp.scheme and up.netloc == tp.netloc and _norm_path(up.path) == _norm_path(tp.path))
            child_candidates = [
                normalize_url(x) for x in (self.k.get("candidate_urls") or [])
                if normalize_url(x) and normalize_url(x) != url
                and urlparse(normalize_url(x)).scheme == up.scheme
                and urlparse(normalize_url(x)).netloc == up.netloc
            ]
            if is_target_root and child_candidates:
                e["state"] = "COMPLETED"
                e["updated_at"] = utc_now()
                self.k.setdefault("resource_state", {})[url] = {
                    "state": "COMPLETED", "updated_at": utc_now(), "updated_by": "scheduler",
                    "reason": "discovery seed mapped; child Analysis Items discovered"
                }
                self.event("discovery_seed_completed", url, discovered_children=len(child_candidates))
        except Exception as exc:
            self.event("discovery_seed_completion_skipped", url, reason=str(exc))
        self.save()

    def mark(self, url: str, state: str, reason: str, source: str = "scheduler") -> None:
        url = normalize_url(url)
        state = state.upper()
        if not url or state not in VALID_STATES:
            raise ValueError("resource/state inválido")
        if url not in self.queue():
            self.queue()[url] = {"resource": url, "priority": 0, "visit_count": 0,
                                 "error_count": 0, "loop_count": 0, "resource_iteration_count": 0, "last_action": None,
                                 "last_action_fingerprint": None, "operator_override": False,
                                 "created_at": utc_now()}
        previous = state_name(self.queue()[url].get("state"))
        if previous in TERMINAL_STATES and state not in TERMINAL_STATES and not self.queue()[url].get("operator_override"):
            return
        self.queue()[url]["state"] = state
        self.queue()[url]["updated_at"] = utc_now()
        self.k.setdefault("resource_state", {})[url] = {
            "state": state, "updated_at": utc_now(), "updated_by": source, "reason": reason
        }
        set_analysis_state(self.k, url, state, reason, source)
        self.k.setdefault("resource_state_history", []).append({
            "timestamp": utc_now(), "resource": url, "state": state, "reason": reason,
            "updated_by": source
        })
        if state in TERMINAL_STATES and self.active() == url:
            self.set_active(None, f"mark_{state.lower()}")
        self.event("state_changed", url, state=state, reason=reason)
        self.save()

    def mark_completed(self, url: str, reason: str = "completed") -> None:
        self.mark(url, "COMPLETED", reason)

    def mark_inconclusive(self, url: str, reason: str = "inconclusive") -> None:
        self.mark(url, "INCONCLUSIVE", reason)

    def mark_failed(self, url: str, reason: str = "failed") -> None:
        self.mark(url, "FAILED", reason)

    def register_error(self, url: str, reason: str) -> int:
        url = normalize_url(url)
        if not url or url not in self.queue():
            return 0
        e = self.queue()[url]
        e["error_count"] = int(e.get("error_count") or 0) + 1
        e["last_error"] = reason
        e["updated_at"] = utc_now()
        self.event("resource_error", url, count=e["error_count"], reason=reason)
        self.save()
        return e["error_count"]

    @staticmethod
    def fingerprint(url: str, action: str, payload: str = "") -> str:
        normalized = " ".join(str(payload).split())
        return hashlib.sha256(f"{normalize_url(url)}|{action}|{normalized}".encode()).hexdigest()

    def register_action(self, url: str, action: str, payload: str = "") -> int:
        url = normalize_url(url)
        if not url or url not in self.queue():
            return 0
        e = self.queue()[url]
        # v2.5.4: an autonomous operator checkpoint is a control-plane action,
        # not a failed technical retry. The executor resolves it atomically.
        if autonomous_mode_enabled() and action == "ask_operator":
            e["loop_count"] = 0
            e["last_action"] = action
            e["last_action_fingerprint"] = None
            e["updated_at"] = utc_now()
            self.event("autonomous_checkpoint_registered", url, action=action, loop_count=0)
            self.save()
            return 0
        fp = self.fingerprint(url, action, payload)
        if e.get("last_action_fingerprint") == fp:
            e["loop_count"] = int(e.get("loop_count") or 0) + 1
        else:
            e["loop_count"] = 1
        e["last_action"] = action
        e["last_action_fingerprint"] = fp
        e["updated_at"] = utc_now()
        self.event("action_registered", url, action=action, loop_count=e["loop_count"])
        if e["loop_count"] >= int(self.k["scheduler"].get("loop_limit") or DEFAULT_LOOP_LIMIT):
            self.mark_inconclusive(url, f"Scheduler: misma acción repetida {e['loop_count']} veces")
            return e["loop_count"]
        self.save()
        return e["loop_count"]

    def reopen(self, url: str) -> None:
        url = normalize_url(url)
        if not url:
            raise ValueError("URL inválida")
        if url not in self.queue():
            add_item(self.k, url, "operator_reopen")
            self.ensure_schema()
        e = self.queue()[url]
        e["state"] = "NEW"
        e["operator_override"] = True
        e["error_count"] = 0
        e["loop_count"] = 0
        e["resource_iteration_count"] = 0
        self.k.setdefault("resource_state", {})[url] = {
            "state": "NEW", "updated_at": utc_now(), "updated_by": "operator_reopen",
            "reason": "Reapertura explícita del operador"
        }
        set_analysis_state(self.k, url, "NEW", "Reapertura explícita del operador", "operator_reopen")
        self.k["scheduler"]["operator_override"] = url
        self.set_active(url, "operator_reopen")
        self.event("resource_reopened", url)
        self.save()

    def status(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for e in self.queue().values():
            s = state_name(e.get("state"))
            counts[s] = counts.get(s, 0) + 1
        return {
            "version": self.k["scheduler"].get("version"),
            "active_resource": self.active(),
            "counts": counts,
            "pending": self.has_pending_resources(),
            "final_report_ready": self.k["scheduler"].get("final_report_ready"),
            "next": (self.next_pending_resource().__dict__ if self.next_pending_resource() else None),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="BugTraceAI v2.0 Analysis Item scheduler")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("status")
    sub.add_parser("select")
    sub.add_parser("reconcile")
    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--decision-file", default=str(DECISION))
    p_mark = sub.add_parser("mark")
    p_mark.add_argument("resource")
    p_mark.add_argument("state", choices=sorted(VALID_STATES))
    p_mark.add_argument("--reason", default="operator/scheduler")
    p_reopen = sub.add_parser("reopen")
    p_reopen.add_argument("resource")
    args = parser.parse_args()

    s = ResourceScheduler()
    if args.command == "init":
        s.save()
        print(json.dumps(s.status(), indent=2, ensure_ascii=False))
    elif args.command == "status":
        print(json.dumps(s.status(), indent=2, ensure_ascii=False))
    elif args.command == "reconcile":
        s.reconcile()
        print(json.dumps(s.status(), indent=2, ensure_ascii=False))
    elif args.command == "select":
        sel = s.select()
        print(json.dumps(sel.__dict__ if sel else {"resource": None, "queue_exhausted": True}, indent=2, ensure_ascii=False))
    elif args.command == "prepare":
        sel = s.select()
        if not sel:
            print(json.dumps({"status": "DONE", "resource": None, "final_report_ready": True}))
            return 10
        if s.needs_mapping(sel.resource):
            s.write_interior_decision(sel.resource, Path(args.decision_file))
            print(json.dumps({"status": "MAP_REQUIRED", "resource": sel.resource, "state": sel.state}))
            return 20
        print(json.dumps({"status": "READY", "resource": sel.resource, "state": sel.state}))
    elif args.command == "mark":
        s.mark(args.resource, args.state, args.reason, source="operator_cli")
        print(json.dumps(s.status(), indent=2, ensure_ascii=False))
    elif args.command == "reopen":
        s.reopen(args.resource)
        print(json.dumps(s.status(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
