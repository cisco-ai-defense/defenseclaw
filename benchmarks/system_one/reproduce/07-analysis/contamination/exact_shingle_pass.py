"""Task C/D/E cross-check: EXACT full-shingle inverted index for the small,
highest-risk training/eval sources (no MinHash approximation at all).

For every corpus doc we count how many of its character-5-grams fall in each
small-source doc, which gives the exact intersection size (up to the small set
of shingles dropped by the posting cap), then recompute the exact Jaccard from
the full shingle sets held in memory.
"""
from __future__ import annotations
import json, os, sys, time, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
DOCS = ROOT + "/work/docs"
CAP2 = int(os.environ.get("CAP2", "300"))
MIN_INTER = int(os.environ.get("MIN_INTER", "3"))
KEEP_MIN = float(os.environ.get("KEEP_MIN", "0.30"))
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
GROUPS = ["dc-security-suite", "dc-benchmark-fixtures",
          "rogue-security__coding-agent-security-benchmark",
          "deepset__prompt-injections",
          "3nesdeniz__agentic-prompt-injection-boundary-pairs",
          "nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"]
t0 = time.time()

t_ids = []; t_sh = []; t_txt = []
for g in GROUPS:
    for d in L.read_docs(DOCS + "/train__" + g + ".jsonl"):
        h = L.shingle_hashes(d["t"])
        if h.size == 0: continue
        t_ids.append(d["id"]); t_sh.append(h); t_txt.append(d["t"])
N_T = len(t_ids)
print("small-source docs", N_T, "total shingles", sum(x.size for x in t_sh), flush=True)

allsh = np.concatenate(t_sh)
own = np.repeat(np.arange(N_T, dtype=np.int32), [x.size for x in t_sh])
o = np.argsort(allsh, kind="stable"); allsh = allsh[o]; own = own[o]
dh, st, ct = np.unique(allsh, return_index=True, return_counts=True)
over = ct > CAP2
n_over = int(over.sum()); post_over = int(ct[over].sum())
sel = ~over
dh_f = dh[sel]; st_f = st[sel]; ct_f = ct[sel]
off = np.empty(dh_f.size + 1, dtype=np.int64); off[0] = 0; np.cumsum(ct_f, out=off[1:])
gi = np.repeat(st_f, ct_f) + (np.arange(off[-1]) - np.repeat(off[:-1], ct_f))
postings = own[gi]
del allsh, own, o, gi
print("distinct shingles", dh.size, "indexed", dh_f.size, "dropped_over_cap", n_over,
      "dropped_postings", post_over, flush=True)

# coverage: fraction of each small-source doc's shingles that remain indexable
indexable = np.zeros(N_T, dtype=np.int64)
np.add.at(indexable, postings, 1)
tot_sh = np.array([x.size for x in t_sh], dtype=np.int64)
frac = indexable / np.maximum(tot_sh, 1)
cov = {"min_indexable_fraction": float(frac.min()), "p01": float(np.quantile(frac, 0.01)),
       "median": float(np.median(frac)), "mean": float(frac.mean()),
       "n_docs_with_zero_indexable": int((indexable == 0).sum())}
print("coverage", json.dumps(cov), flush=True)

out = open(ROOT + "/work/exact_pass_pairs.jsonl", "w", encoding="utf-8")
nkept = 0; nseen = 0; gathered = 0
cbase = 0
corpus_offsets = {}
for stage in STAGES:
    corpus_offsets[stage] = cbase
    for d in L.read_docs(DOCS + "/corpus__" + stage + ".jsonl"):
        gidx = cbase; cbase += 1; nseen += 1
        h = L.shingle_hashes(d["t"])
        if h.size == 0: continue
        pos = np.searchsorted(dh_f, h)
        posc = np.minimum(pos, dh_f.size - 1)
        ok = dh_f[posc] == h
        pos = posc[ok]
        if pos.size == 0: continue
        lens = (off[pos + 1] - off[pos]).astype(np.int64)
        tot = int(lens.sum())
        if tot == 0: continue
        gathered += tot
        cum = np.cumsum(lens) - lens
        g2 = np.repeat(off[pos], lens) + (np.arange(tot) - np.repeat(cum, lens))
        cand = postings[g2]
        tid, cnt = np.unique(cand, return_counts=True)
        m = cnt >= MIN_INTER
        if not m.any(): continue
        for ti in tid[m]:
            ti = int(ti)
            j = L.exact_jaccard(h, t_sh[ti])
            if j < KEEP_MIN: continue
            out.write(json.dumps({"c_gidx": gidx, "c_id": d["id"], "c_stage": stage,
                                  "c_case": d["cid"], "c_view": d["view"], "c_ds": d["ds"],
                                  "t_id": t_ids[ti], "j": round(j, 6)}) + "\n")
            nkept += 1
        if nseen % 50000 == 0:
            print("scanned", nseen, "kept", nkept, "gathered", gathered,
                  round(time.time() - t0, 1), flush=True)
out.close()
meta = {"method": "exact full character-5-gram inverted index (no MinHash)",
        "groups": GROUPS, "n_small_source_docs": N_T, "posting_cap": CAP2,
        "min_intersection_for_candidate": MIN_INTER, "keep_min_exact_jaccard": KEEP_MIN,
        "distinct_shingles": int(dh.size), "indexed_shingles": int(dh_f.size),
        "dropped_over_cap_shingles": n_over, "dropped_over_cap_postings": post_over,
        "indexable_coverage": cov, "corpus_docs_scanned": nseen,
        "total_postings_gathered": gathered, "pairs_kept": nkept,
        "corpus_global_offsets": corpus_offsets, "seconds": round(time.time() - t0, 1)}
json.dump(meta, open(ROOT + "/work/exact_pass_meta.json", "w"), indent=2)
print("DONE", json.dumps(meta), flush=True)
