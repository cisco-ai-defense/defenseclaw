"""What is in the `smoke` split? It is the only source of production-scale benign volume,
so S2/S3 operational lanes depend on it. Confirm it is real agent traffic, not fixtures.
"""

import json
from collections import defaultdict
from pathlib import Path

from benchmark_inventory_system_one_sources import family_authority, read_jsonl, truth_grade

BASE = Path("/home/ubuntu/.system-one-data/outputs")
catalog = json.loads((BASE / "source-catalog-v2.json").read_text())

per = defaultdict(lambda: defaultdict(int))
fams = defaultdict(set)
surfaces = defaultdict(lambda: defaultdict(int))
events = defaultdict(list)

for corpus in catalog["corpora"]:
    path = Path(corpus["path"])
    if not path.exists():
        continue
    name = path.parent.name
    for row in read_jsonl(path):
        if str(row.get("split", "")) != "smoke":
            continue
        g = truth_grade(row)
        per[name][g] += 1
        fams[name].add(family_authority(row)[1])
        surfaces[name][str(row.get("surface", "?"))] += 1
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        ev = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
        events[name].append(len(ev))

print("SMOKE SPLIT COMPOSITION")
for name in sorted(per, key=lambda n: -sum(per[n].values())):
    counts = dict(sorted(per[name].items()))
    total = sum(counts.values())
    ev = events[name]
    mean_ev = sum(ev) / len(ev) if ev else 0
    print(f"\n  {name}")
    print(f"    rows={total:,}  families={len(fams[name]):,}  grades={counts}")
    print(f"    surfaces={dict(sorted(surfaces[name].items()))}  mean_events/case={mean_ev:.1f}")
