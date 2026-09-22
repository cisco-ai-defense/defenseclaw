"""Exact S2 availability per corpus after excluding all 1,000 S1 families.

Also identifies which corpora can supply a production-weighted benign lane, since the S1
benign lane understated per-event FPR by ~5x.
"""

import json
from collections import defaultdict
from pathlib import Path

from benchmark_inventory_system_one_sources import family_authority, read_jsonl, truth_grade

BASE = Path("/home/ubuntu/.system-one-data/outputs")
catalog = json.loads((BASE / "source-catalog-v2.json").read_text())

s1_families = set()
for row in read_jsonl(BASE / "s1-n1000/cases.jsonl"):
    s1_families.add(family_authority(row)[1])
print(f"S1 families to exclude: {len(s1_families)}")
print()

# per corpus: grade x split counts, excluding S1 families
per = defaultdict(lambda: defaultdict(int))
totals = defaultdict(int)
for corpus in catalog["corpora"]:
    path = Path(corpus["path"])
    if not path.exists():
        continue
    name = path.parent.name
    for row in read_jsonl(path):
        fam = family_authority(row)[1]
        if fam in s1_families:
            continue
        g = truth_grade(row)
        s = str(row.get("split", "missing"))
        if g == "E":
            continue
        per[name][f"{g}:{s}"] += 1
        totals[f"{g}:{s}"] += 1

print("AVAILABLE AFTER S1 EXCLUSION (grade:split -> count), E omitted")
for k in sorted(totals):
    print(f"  {k:24} {totals[k]:>8,}")
print()
print("TOP CORPORA BY development-D (production benign lane candidates)")
rows = sorted(per.items(), key=lambda kv: -kv[1].get("D:development", 0))
for name, counts in rows[:12]:
    d_dev = counts.get("D:development", 0)
    if not d_dev:
        continue
    print(f"  {d_dev:>8,}  {name}")
print()
print("CORPORA WITH development B or C (contextual/diagnostic lanes)")
for name, counts in sorted(per.items(), key=lambda kv: -(kv[1].get("B:development", 0) + kv[1].get("C:development", 0)))[:10]:
    b = counts.get("B:development", 0)
    c = counts.get("C:development", 0)
    if not (b or c):
        continue
    print(f"  B={b:<6} C={c:<6} {name}")
print()
print("CORPORA WITH any grade A (exact lane, scarce)")
for name, counts in per.items():
    a = {k: v for k, v in counts.items() if k.startswith("A:")}
    if a:
        print(f"  {dict(sorted(a.items()))}  {name}")
