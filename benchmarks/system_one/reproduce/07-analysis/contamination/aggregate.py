"""Task C aggregation over the union of all LSH passes."""
from __future__ import annotations
import glob, json, os, sys, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
DOCS = ROOT + "/work/docs"
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
THRESH = [0.9, 0.7, 0.5]
TOPN = 20

case_ds = {}
for st in STAGES:
    d = json.load(open(ROOT + "/work/case_index__" + st + ".json"))
    for k, v in d.items(): case_ds[(st, k)] = v["ds"]

def parse_corpus_id(s):
    p = s.split("|")
    return p[0], p[1], p[-1]

def subcorpus(tdoc):
    """dc-security-suite|regex:secret/aws-access-key|content -> regex"""
    p = tdoc.split("|")
    return p[1].split(":", 1)[0] if len(p) > 2 else "?"

best = {}                      # (group, stage, view, case) -> max j
best_sub = {}                  # (group, sub, stage, case) -> max j
tops = collections.defaultdict(list)
tops_sub = collections.defaultdict(list)
n_rows = 0
files = sorted(glob.glob(ROOT + "/work/pairs__*.jsonl"))
for p in files:
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        d = json.loads(line); n_rows += 1
        stage, case, view = parse_corpus_id(d["cdoc"])
        j = d["j"]
        for g in d["tgroups"]:
            k = (g, stage, view, case)
            if j > best.get(k, -1): best[k] = j
            lst = tops[(g, stage)]
            lst.append((j, d["cdoc"], d["tdoc"]))
            if len(lst) > 5000:
                lst.sort(key=lambda x: -x[0]); del lst[TOPN * 3:]
            if g in ("dc-security-suite", "dc-benchmark-fixtures"):
                sub = subcorpus(d["tdoc"])
                ks = (g, sub, stage, case)
                if j > best_sub.get(ks, -1): best_sub[ks] = j
                l2 = tops_sub[(g, sub, stage)]
                l2.append((j, d["cdoc"], d["tdoc"]))
                if len(l2) > 2000:
                    l2.sort(key=lambda x: -x[0]); del l2[TOPN * 3:]
    print("read", os.path.basename(p), n_rows, flush=True)

# collapse views -> per-case max
best_case = {}
for (g, stage, view, case), j in best.items():
    k = (g, stage, case)
    if j > best_case.get(k, -1): best_case[k] = j

def counts_from(d, keyfn):
    out = collections.defaultdict(lambda: {"ge_0.9": 0, "ge_0.7": 0, "ge_0.5": 0,
                                           "n_cases_with_any_pair_ge_0.3": 0, "max_jaccard": 0.0})
    for k, j in d.items():
        c = out[keyfn(k)]
        c["n_cases_with_any_pair_ge_0.3"] += 1
        for th in THRESH:
            if j >= th: c["ge_" + str(th)] += 1
        if j > c["max_jaccard"]: c["max_jaccard"] = round(j, 6)
    return dict(out)

by_src_stage = counts_from(best_case, lambda k: (k[0], k[1]))
by_src_stage_view = counts_from(best, lambda k: (k[0], k[1], k[2]))
by_sub = counts_from(best_sub, lambda k: (k[0], k[1], k[2]))
best_ds = {}
for (g, stage, case), j in best_case.items():
    k = (g, stage, case_ds.get((stage, case), "?"))
    kk = (g, stage, case_ds.get((stage, case), "?"), case)
    best_ds[kk] = j
by_src_stage_ds = counts_from(best_ds, lambda k: (k[0], k[1], k[2]))

need = set()
tops_out = {}
for k, lst in tops.items():
    lst.sort(key=lambda x: -x[0]); tops_out[k] = lst[:TOPN]
    for j, cd, td in tops_out[k]: need.add(cd); need.add(td)
tops_sub_out = {}
for k, lst in tops_sub.items():
    lst.sort(key=lambda x: -x[0]); tops_sub_out[k] = lst[:TOPN]
    for j, cd, td in tops_sub_out[k]: need.add(cd); need.add(td)
texts = {}
for p in [DOCS + "/corpus__" + s + ".jsonl" for s in STAGES] + sorted(glob.glob(DOCS + "/train__*.jsonl")):
    for d in L.read_docs(p):
        if d["id"] in need: texts[d["id"]] = d["t"]
print("fetched texts", len(texts), "of", len(need), flush=True)

def fmt(lst):
    return [{"jaccard": round(j, 6), "corpus_doc_id": cd, "train_doc_id": td,
             "corpus_text_200": texts.get(cd, "")[:200], "train_text_200": texts.get(td, "")[:200]}
            for j, cd, td in lst]

res = {
    "pairs_files": [os.path.basename(f) for f in files],
    "pair_rows_read": n_rows,
    "distinct_corpus_case_x_source_pairs_ge_0.3": len(best_case),
    "by_source_x_stage": {" || ".join(k): v for k, v in sorted(by_src_stage.items())},
    "by_source_x_stage_x_view": {" || ".join(k): v for k, v in sorted(by_src_stage_view.items())},
    "by_source_x_stage_x_corpus_source_dataset": {" || ".join(k): v for k, v in sorted(by_src_stage_ds.items())},
    "defenseclaw_by_subcorpus_x_stage": {" || ".join(k): v for k, v in sorted(by_sub.items())},
    "top_pairs_per_source_x_stage": {" || ".join(k): fmt(v) for k, v in sorted(tops_out.items())},
    "top_pairs_defenseclaw_subcorpus_x_stage": {" || ".join(k): fmt(v) for k, v in sorted(tops_sub_out.items())},
}
json.dump(res, open(ROOT + "/work/aggregate.json", "w"), indent=2)
print("WROTE work/aggregate.json")
for k, v in sorted(by_src_stage.items()):
    print("%-70s %s" % (" || ".join(k), {x: v[x] for x in ["ge_0.9", "ge_0.7", "ge_0.5", "max_jaccard"]}))
