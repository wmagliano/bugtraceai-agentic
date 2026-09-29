#!/usr/bin/env python3
"""Resume formularios detectados en knowledge.json para revisión guiada Nivel 1."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "data" / "knowledge.json"

def main():
    k = json.loads(KNOWLEDGE.read_text())
    found = []
    for url, ctx in k.get("url_context", {}).items():
        forms = ctx.get("forms") or []
        if not forms:
            continue
        found.append({
            "url": url,
            "title": ctx.get("title"),
            "forms": forms,
            "query_params": ctx.get("query_params", {}),
            "indicators": ctx.get("body_indicators", {})
        })
    print(json.dumps({"forms_detected": found}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
