#!/usr/bin/env python3
"""Stratified judge sample for the s7-gate rules+judge configuration.

  judge_sample.py --corpora corpora_all.json --out DIR [--keep s2,s3=CASCADE_DIR] [--labels OVERLAY.jsonl] [--seed N]

Writes DIR/corpora_judge.json: the corpora of --corpora, each with an "ids" file (the sampled
cases) and a "meta" file ({"id", "weight"} per line: population / sampled within its stratum),
so precision and false-positive rates can be reported at corpus prevalence. DIR/plan.json lists
every stratum (population, sampled, weight, tool calls).

Strata are corpus x label (attack, benign) x dataset. Small corpora are taken whole. --keep
reuses the seeded cascade sample (BENCH-cascade.md: every s2/s3 positive, 700 s3 and 500 s2
benign cases) for the named corpora, so the Gemma 4 numbers stay comparable with the bake-off.
--labels applies a label overlay ({"id", "source_truth"} per line, e.g. labels/agentdojo-security-flip.jsonl,
rel-1-0-10:GAP-0120) before stratifying, so the weights follow the corrected labels; score with the same overlay
(s7gate.py --reviews). Seeded; no corpus text is printed.
"""
import argparse, collections, json, os, random, sys

# cases per (corpus, label); None = all of them. Chosen from the judge cost per tool call (about
# USD 0.27 per 1,000 calls with Gemma 4 31B) so one fresh rules+judge pass stays near USD 10.
TARGETS = {
    "agent-transcripts-sample": {"benign": 1500, "attack": None},
    "extra-public": {"benign": 300, "attack": None},
    "public-surfaces": {"benign": 600, "attack": 800},
    "agent-transcripts-small": {"benign": 0, "attack": 0},
}
FLOOR = 40

ap = argparse.ArgumentParser()
ap.add_argument("--corpora", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--keep", default="", help="corpus[,corpus]=DIR with ids.txt and weights.json from sample_cascade.py")
ap.add_argument("--labels", default="", help="label overlay jsonl applied before stratifying")
ap.add_argument("--seed", type=int, default=741983)
a = ap.parse_args()
rnd = random.Random(a.seed)
os.makedirs(a.out, exist_ok=True)
keep_names, keep_dir = set(), None
if a.keep:
    names, _, keep_dir = a.keep.partition("=")
    keep_names = set(names.split(","))
    kw = json.load(open(os.path.join(keep_dir, "weights.json")))
overlay = {}
if a.labels:
    for line in open(a.labels):
        if line.strip():
            o = json.loads(line)
            overlay[o["id"]] = o["source_truth"]
cfgs = json.load(open(a.corpora))
out_cfg, plan = {}, {}
for name, cfg in cfgs.items():
    strata = collections.defaultdict(list)
    for f in cfg["files"]:
        for line in open(f):
            r = json.loads(line)
            t = r["truth"]
            if t.get("applicability", "in_scope") != "in_scope":
                continue
            st = overlay.get(r["id"], t.get("source_truth"))
            lab = "benign" if st == "benign" else "attack" if st in ("malicious", "sensitive") else None
            if lab is None:
                continue
            n = len(r["payload"].get("events") or [1])
            strata[(lab, r["source"]["dataset"])].append((r["id"], n))
    picked = {}
    if name in keep_names:
        ids_all = {cid: n for v in strata.values() for cid, n in v}
        for cid, w in kw.items():
            if cid in ids_all:
                picked[cid] = w
        for (lab, ds), v in strata.items():
            sel = [(c, n) for c, n in v if c in picked]
            plan[f"{name}|{lab}|{ds}"] = {"population": len(v), "sampled": len(sel), "weight": (len(v) / len(sel)) if sel else 0,
                                           "calls": sum(n for _, n in sel), "source": "cascade sample"}
    else:
        tg = TARGETS.get(name, {})
        for lab in ("attack", "benign"):
            group = {k: v for k, v in strata.items() if k[0] == lab}
            total = sum(len(v) for v in group.values())
            T = tg.get(lab)
            if T is None or T >= total:
                alloc = {k: len(v) for k, v in group.items()}
            else:
                base = {k: min(len(v), FLOOR, T) for k, v in group.items()}
                rest = max(0, T - sum(base.values()))
                pool = {k: len(v) - base[k] for k, v in group.items()}
                rp = sum(pool.values())
                alloc = {k: base[k] + (int(round(rest * pool[k] / rp)) if rp else 0) for k in group}
            for k, v in sorted(group.items()):
                n = min(alloc[k], len(v))
                sel = rnd.sample(sorted(v), n)
                w = len(v) / n if n else 0
                for cid, _ in sel:
                    picked[cid] = w
                plan[f"{name}|{lab}|{k[1]}"] = {"population": len(v), "sampled": n, "weight": w, "calls": sum(c for _, c in sel)}
    if not picked:
        continue
    idf = os.path.join(a.out, f"{name}.ids.txt")
    mf = os.path.join(a.out, f"{name}.meta.jsonl")
    with open(idf, "w") as o:
        o.write("\n".join(sorted(picked)) + "\n")
    with open(mf, "w") as o:
        for cid in sorted(picked):
            o.write(json.dumps({"id": cid, "weight": picked[cid]}) + "\n")
    out_cfg[name] = {"files": cfg["files"], "ids": idf, "meta": [mf]}
json.dump(out_cfg, open(os.path.join(a.out, "corpora_judge.json"), "w"), indent=1)
json.dump(plan, open(os.path.join(a.out, "plan.json"), "w"), indent=1)
tot = collections.Counter()
for k, v in plan.items():
    c = k.split("|")[0]
    tot[(c, "cases")] += v["sampled"]
    tot[(c, "calls")] += v["calls"]
for c in out_cfg:
    print(f"{c}: {tot[(c, 'cases')]} cases, {tot[(c, 'calls')]} tool calls")
print(f"total: {sum(v for (c, k), v in tot.items() if k == 'cases')} cases, {sum(v for (c, k), v in tot.items() if k == 'calls')} tool calls")
