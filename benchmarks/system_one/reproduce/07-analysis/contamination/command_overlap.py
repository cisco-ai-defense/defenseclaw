"""Targeted: do the raw COMMAND STRINGS in our corpora appear in SecJudge training sources?

Our corpora wrap commands as {"command": "..."}, which costs ~10 Jaccard points against a
training row holding the bare string.  This pass compares bare string to bare string using an
EXACT full character-5-gram inverted index -- no MinHash.

Candidate pruning is provably safe for the reported J>=0.5 threshold: J(A,B)>=0.5 implies
|A n B| >= (|A|+|B|)/3 >= (2/3)*min(|A|,|B|), so requiring |A n B| >= 0.5*min(|A|,|B|)
(slack for shingles dropped by the posting cap) cannot discard a pair with J>=0.5.
"""
from __future__ import annotations
import json, os, sys, time, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
DOCS = ROOT + "/work/docs"; BASE = "$WORK/.system-one-data/outputs"
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
CAP = 4000
MIN_LEN = int(os.environ.get("MIN_LEN", "0"))
SUF = os.environ.get("SUF", "")
t0 = time.time()

WANT = {
    "dc-security-suite": ("command", "content"),
    "dc-benchmark-fixtures": ("content",),
    "infraset__infraset": ("command",),
    "AnishJoshi__nl2bash-custom": ("bash_code",),
    "rogue-security__coding-agent-security-benchmark": ("content",),
}
t_ids = []; t_sh = []; t_txt = []; t_sha = {}
for g, views in WANT.items():
    for d in L.read_docs(DOCS + "/train__" + g + ".jsonl"):
        if d["id"].rsplit("|", 1)[-1] not in views: continue
        if len(d["t"]) < MIN_LEN: continue
        h = L.shingle_hashes(d["t"])
        if h.size == 0: continue
        t_sha.setdefault(d["sha"], []).append(d["id"])
        t_ids.append(d["id"]); t_sh.append(h); t_txt.append(d["t"])

FIXT = "$WORK/defenseclaw-system-one/benchmarks/fixtures"
FIX = ["smoke", "cloud-production-conformance-v1", "database-destruction-conformance-v1",
       "kubernetes-production-conformance-v1", "infrastructure-destruction-conformance-v1",
       "postgresql-copy-program-v1", "sql-command-udf-atomic-v1"]
for name in FIX:
    for line in open(FIXT + "/" + name + ".jsonl", encoding="utf-8"):
        line = line.strip()
        if not line: continue
        case = json.loads(line)
        pl = case.get("payload") or {}
        evs = pl.get("events") if isinstance(pl.get("events"), list) else [pl]
        for ei, ev in enumerate(evs):
            if not isinstance(ev, dict): continue
            v = ev.get("command")
            if isinstance(v, str) and v.strip():
                t = L.normalize(v)
                if len(t) < MIN_LEN: continue
                h = L.shingle_hashes(t)
                if h.size == 0: continue
                did = "dc-benchmark-fixtures|" + name + ":" + str(case.get("id")) + ":e" + str(ei) + "|cmdstr"
                t_sha.setdefault(L.sha256_text(t), []).append(did)
                t_ids.append(did); t_sh.append(h); t_txt.append(t)
N_T = len(t_ids)
tot_sh = np.array([x.size for x in t_sh], dtype=np.int64)
print("train command/content docs", N_T, "shingles", int(tot_sh.sum()), flush=True)

allsh = np.concatenate(t_sh)
own = np.repeat(np.arange(N_T, dtype=np.int32), tot_sh)
o = np.argsort(allsh, kind="stable"); allsh = allsh[o]; own = own[o]
dh, st, ct = np.unique(allsh, return_index=True, return_counts=True)
over = ct > CAP
sel = ~over
dh_f = dh[sel]; st_f = st[sel]; ct_f = ct[sel]
off = np.empty(dh_f.size + 1, dtype=np.int64); off[0] = 0; np.cumsum(ct_f, out=off[1:])
gi = np.repeat(st_f, ct_f) + (np.arange(off[-1]) - np.repeat(off[:-1], ct_f))
postings = own[gi]
indexable = np.zeros(N_T, dtype=np.int64); np.add.at(indexable, postings, 1)
frac = indexable / np.maximum(tot_sh, 1)
n_dropped = int(over.sum())
print("distinct", dh.size, "indexed", dh_f.size, "dropped", n_dropped,
      "coverage min", round(float(frac.min()), 4), "median", round(float(np.median(frac)), 4),
      "zero", int((indexable == 0).sum()), flush=True)

def cmd_strings(case):
    pl = case.get("payload") if isinstance(case.get("payload"), dict) else {}
    evs = pl.get("events") if isinstance(pl.get("events"), list) else [pl]
    got = []
    for ei, ev in enumerate(evs):
        if not isinstance(ev, dict): continue
        v = ev.get("command")
        if isinstance(v, str) and v.strip(): got.append((ei, "command", v))
        a = ev.get("args")
        if isinstance(a, dict):
            for k in ("command", "cmd", "script", "shell_command", "code"):
                vv = a.get(k)
                if isinstance(vv, str) and vv.strip(): got.append((ei, "args." + k, vv))
    if isinstance(pl.get("content"), str) and pl["content"].strip():
        got.append((-1, "payload.content", pl["content"]))
    return got

exact = collections.Counter(); exact_cases = collections.defaultdict(set); exact_ex = []
near = {}; tops = collections.defaultdict(list)
n_cmd = collections.Counter(); n_cases = collections.Counter(); n_jacc = 0
for stage in STAGES:
    for line in open(BASE + "/" + stage + "/cases.jsonl", encoding="utf-8"):
        line = line.strip()
        if not line: continue
        case = json.loads(line); cid = str(case.get("id")); n_cases[stage] += 1
        ds = str((case.get("source") or {}).get("dataset"))
        for ei, field, raw in cmd_strings(case):
            t = L.normalize(raw)
            if not t or len(t) < MIN_LEN: continue
            n_cmd[stage] += 1
            if n_cmd[stage] % 5000 == 0:
                print("  ", stage, n_cmd[stage], "jacc", n_jacc, round(time.time() - t0, 1), flush=True)
            shv = L.sha256_text(t)
            if shv in t_sha:
                for tid in t_sha[shv]:
                    g = tid.split("|", 1)[0]
                    exact[(g, stage, field)] += 1
                    exact_cases[(g, stage)].add(cid)
                    if len(exact_ex) < 300:
                        exact_ex.append({"train_group": g, "train_doc_id": tid, "stage": stage,
                                         "case_id": cid, "corpus_source_dataset": ds,
                                         "field": field, "text_200": t[:200]})
            h = L.shingle_hashes(t)
            pos = np.searchsorted(dh_f, h)
            pos = np.minimum(pos, max(dh_f.size - 1, 0))
            pos = pos[dh_f[pos] == h]
            if pos.size == 0: continue
            lens = (off[pos + 1] - off[pos]).astype(np.int64)
            tot = int(lens.sum())
            if tot == 0: continue
            cum = np.cumsum(lens) - lens
            g2 = np.repeat(off[pos], lens) + (np.arange(tot) - np.repeat(cum, lens))
            tid_arr, cnt = np.unique(postings[g2], return_counts=True)
            need = np.maximum(0.5 * np.minimum(h.size, tot_sh[tid_arr]), 3.0)
            for ti in tid_arr[cnt >= need]:
                ti = int(ti); n_jacc += 1
                j = L.exact_jaccard(h, t_sh[ti])
                if j < 0.5: continue
                g = t_ids[ti].split("|", 1)[0]
                k = (g, stage, cid)
                if j > near.get(k, -1.0): near[k] = j
                lst = tops[(g, stage)]
                lst.append((j, stage + "|" + cid + "|e" + str(ei) + "|" + field, t_ids[ti], t[:200], t_txt[ti][:200]))
                if len(lst) > 3000:
                    lst.sort(key=lambda x: -x[0]); del lst[60:]
    print("scanned", stage, n_cmd[stage], "jacc calls", n_jacc, round(time.time() - t0, 1), flush=True)

counts = collections.defaultdict(lambda: {"ge_1.0_exact": 0, "ge_0.9": 0, "ge_0.7": 0, "ge_0.5": 0, "max_jaccard": 0.0})
for (g, stage, cid), j in near.items():
    c = counts[(g, stage)]
    if j >= 0.999: c["ge_1.0_exact"] += 1
    for th in [0.9, 0.7, 0.5]:
        if j >= th: c["ge_" + str(th)] += 1
    if j > c["max_jaccard"]: c["max_jaccard"] = round(j, 6)
res = {
    "min_normalised_chars_both_sides": MIN_LEN,
    "method": "bare command-string comparison, exact full character-5-gram inverted index (no MinHash)",
    "candidate_pruning": "require |A n B| >= max(3, 0.5*min(|A|,|B|)); provably cannot discard a pair with J>=0.5",
    "posting_cap": CAP, "shingles_dropped_over_cap": n_dropped,
    "indexable_coverage": {"min": float(frac.min()), "median": float(np.median(frac)),
                           "n_train_docs_zero_indexable": int((indexable == 0).sum())},
    "train_side_docs": N_T, "train_side_views": {k: list(v) for k, v in WANT.items()},
    "corpus_command_strings_extracted": dict(n_cmd), "corpus_cases_scanned": dict(n_cases),
    "exact_jaccard_computations": n_jacc,
    "exact_string_collisions_by_group_stage_field": {" || ".join(k): v for k, v in sorted(exact.items())},
    "exact_distinct_corpus_cases_by_group_stage": {" || ".join(k): len(v) for k, v in sorted(exact_cases.items())},
    "exact_examples": exact_ex,
    "near_dup_cases_by_group_x_stage": {" || ".join(k): v for k, v in sorted(counts.items())},
    "top_pairs": {" || ".join(k): [{"jaccard": round(j, 6), "corpus": cd, "train": td,
                                   "corpus_text_200": ct, "train_text_200": tt}
                                  for j, cd, td, ct, tt in sorted(v, key=lambda x: -x[0])[:20]]
                  for k, v in sorted(tops.items())},
    "seconds": round(time.time() - t0, 1),
}
json.dump(res, open(ROOT + "/work/command_overlap" + SUF + ".json", "w"), indent=2)
print(json.dumps(res["exact_string_collisions_by_group_stage_field"], indent=1))
print(json.dumps(res["near_dup_cases_by_group_x_stage"], indent=1))
print("WROTE work/command_overlap" + SUF + ".json")
