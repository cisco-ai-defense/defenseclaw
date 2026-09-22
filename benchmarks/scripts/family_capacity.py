"""Family-deduplicated capacity, which is what actually limits stage selection.

benchmark_prepare_system_one.py picks at most one case per family, so row counts overstate
availability wherever families are large (Nemotron: 195,768 rows across 630 families).
"""

import json
from collections import defaultdict
from pathlib import Path

from benchmark_inventory_system_one_sources import family_authority, read_jsonl, truth_grade

BASE = Path("/home/ubuntu/.system-one-data/outputs")
catalog = json.loads((BASE / "source-catalog-v2.json").read_text())

s1_families = {family_authority(r)[1] for r in read_jsonl(BASE / "s1-n1000/cases.jsonl")}

# family -> best (grade, split) it can contribute; a family is consumed once
fam_grade_split = {}
for corpus in catalog["corpora"]:
    path = Path(corpus["path"])
    if not path.exists():
        continue
    for row in read_jsonl(path):
        fam = family_authority(row)[1]
        if fam in s1_families:
            continue
        g = truth_grade(row)
        if g == "E":
            continue
        s = str(row.get("split", "missing"))
        prev = fam_grade_split.get(fam)
        # prefer the most authoritative grade available in the family
        rank = {"A": 0, "B": 1, "C": 2, "D": 3}
        if prev is None or rank[g] < rank[prev[0]]:
            fam_grade_split[fam] = (g, s)

by = defaultdict(int)
by_grade = defaultdict(int)
by_split = defaultdict(int)
for g, s in fam_grade_split.values():
    by[f"{g}:{s}"] += 1
    by_grade[g] += 1
    by_split[s] += 1

print(f"TOTAL SELECTABLE FAMILIES (S1 excluded, E dropped): {len(fam_grade_split):,}")
print()
print("by grade:split")
for k in sorted(by):
    print(f"  {k:22} {by[k]:>7,}")
print()
print("by grade:", dict(sorted(by_grade.items())))
print("by split:", dict(sorted(by_split.items())))
print()
dev = sum(v for k, v in by.items() if k.endswith(":development"))
val = sum(v for k, v in by.items() if k.endswith(":validation"))
test = sum(v for k, v in by.items() if k.endswith(":test"))
smoke = sum(v for k, v in by.items() if k.endswith(":smoke"))
print(f"development families : {dev:,}")
print(f"validation families  : {val:,}")
print(f"test families        : {test:,}")
print(f"smoke families       : {smoke:,}")
print(f"GRAND TOTAL          : {dev+val+test+smoke:,}")
print()
print("S2 target 8,000 dev + 2,000 val  ->", "FEASIBLE" if dev >= 8000 and val >= 2000 else "NOT FEASIBLE")
print("S3 target 100,000 families       ->", "FEASIBLE" if dev+val+test+smoke >= 100000 else "NOT FEASIBLE")
