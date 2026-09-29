#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime, timezone
from lifecycle_trace import persist_snapshot

KNOWLEDGE_FILE = Path("data/knowledge.json")
EXEC_STATE_FILE = Path("logs/executor_state.json")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_knowledge():
    if KNOWLEDGE_FILE.exists():
        try:
            return json.loads(KNOWLEDGE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_knowledge(k):
    KNOWLEDGE_FILE.write_text(json.dumps(k, indent=2, ensure_ascii=False),encoding='utf-8')
    persist_snapshot(k,component='memory.save_knowledge',path=str(KNOWLEDGE_FILE))


def mark_decision_executed(decision_id):
    if not decision_id:
        return

    EXEC_STATE_FILE.write_text(
        json.dumps(
            {
                "last_executed_decision_id": decision_id,
                "last_executed_timestamp": utc_now()
            },
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def get_last_executed_decision_id():
    if not EXEC_STATE_FILE.exists():
        return None

    try:
        state = json.loads(EXEC_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None

    return state.get("last_executed_decision_id")
