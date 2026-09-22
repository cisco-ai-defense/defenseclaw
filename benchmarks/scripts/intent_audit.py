"""How much of our corpus actually carries user intent? DefenseClaw's core mechanism
(compare tool calls against the last user prompt) cannot be evaluated without it.
"""

import json
from pathlib import Path

from benchmark_inventory_system_one_sources import read_jsonl, truth_grade

BASE = Path("/home/ubuntu/.system-one-data/outputs")
CORPORA = {
    "s1-1000": BASE / "s1-n1000/cases.jsonl",
    "screen-200": BASE / "s1-n1000/screen-cases.jsonl",
    "terminalbench-40": BASE / "s1-n1000/terminalbench-context-cases.jsonl",
    "tb-dev-with-context": BASE / "terminalbench/development-with-context.jsonl",
}

for name, path in CORPORA.items():
    if not path.exists():
        print(f"{name:22} MISSING {path}")
        continue
    total = with_intent = multi_event = 0
    intent_by_grade: dict[str, int] = {}
    total_by_grade: dict[str, int] = {}
    intent_chars = []
    for row in read_jsonl(path):
        total += 1
        g = truth_grade(row)
        total_by_grade[g] = total_by_grade.get(g, 0) + 1
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        content = payload.get("content") or ""
        events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
        if len(events) > 1:
            multi_event += 1
        if isinstance(content, str) and content.strip():
            with_intent += 1
            intent_by_grade[g] = intent_by_grade.get(g, 0) + 1
            intent_chars.append(len(content))
    pct = 100.0 * with_intent / total if total else 0.0
    print(f"{name:22} total={total:<6} with_intent={with_intent:<6} ({pct:5.1f}%)  multi_event={multi_event}")
    print(f"{'':22} grades={dict(sorted(total_by_grade.items()))}")
    if with_intent:
        print(f"{'':22} intent_by_grade={dict(sorted(intent_by_grade.items()))} "
              f"median_intent_chars={sorted(intent_chars)[len(intent_chars)//2]}")
    print()
