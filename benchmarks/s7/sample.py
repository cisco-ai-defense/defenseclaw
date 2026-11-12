#!/usr/bin/env python3
"""Stratified sample of s2+s3 cases for the model-layer run. Strata = corpus x label(unsafe) x dataset.
Writes ids.txt, weights.json (case -> population weight within its corpus), plan.json. Seeded."""
import json, random, collections, sys
OUT = sys.argv[1]
targets = {("s3", True): None, ("s3", False): 700, ("s2", True): 500, ("s2", False): 500}
FLOOR = 60
rnd = random.Random(741983)
plan = {}; ids = []; weights = {}; decisions = 0
for corpus in ("s3", "s2"):
    strata = collections.defaultdict(list)
    for l in open(f"/home/ubuntu/.system-one-data/outputs/{corpus}/cases.jsonl"):
        r = json.loads(l)
        u = r["truth"].get("source_truth") in ("malicious", "sensitive")
        n = len(r["payload"].get("events") or [1])
        strata[(u, r["source"]["dataset"])].append((r["id"], n))
    for u in (True, False):
        group = {k: v for k, v in strata.items() if k[0] == u}
        total = sum(len(v) for v in group.values())
        T = targets[(corpus, u)]
        alloc = {}
        if T is None or T >= total:
            alloc = {k: len(v) for k, v in group.items()}
        else:
            base = {k: min(len(v), FLOOR) for k, v in group.items()}
            rest = T - sum(base.values())
            restpool = {k: len(v) - base[k] for k, v in group.items()}
            rp = sum(restpool.values())
            alloc = {k: base[k] + (int(round(rest * restpool[k] / rp)) if rp and rest > 0 else 0) for k in group}
        for k, v in group.items():
            a = min(alloc[k], len(v))
            pick = rnd.sample(v, a)
            w = len(v) / a if a else 0
            plan[f"{corpus}|{'unsafe' if u else 'benign'}|{k[1]}"] = {"population": len(v), "sampled": a, "weight": w,
                "decisions": sum(n for _, n in pick)}
            for cid, n in pick:
                ids.append(cid); weights[cid] = w; decisions += n
json.dump(plan, open(f"{OUT}/plan.json", "w"), indent=1)
json.dump(weights, open(f"{OUT}/weights.json", "w"))
open(f"{OUT}/ids.txt", "w").write("\n".join(ids) + "\n")
for corpus in ("s3", "s2"):
    print(corpus, "cases", sum(v["sampled"] for k, v in plan.items() if k.startswith(corpus)), "decisions", sum(v["decisions"] for k, v in plan.items() if k.startswith(corpus)))
print("total cases", len(ids), "decisions", decisions)
for k, v in sorted(plan.items()): print(k, v)
