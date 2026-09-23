"""Task C pass 1: LSH-free bottom-k candidate generation.

Inverted index over every training-side sketch value (frequency-capped);
queried with every corpus-side sketch value.  Emits candidate pairs with the
number of shared sketch values, which is a high-recall proxy for Jaccard.
"""
from __future__ import annotations
import glob, json, os, sys, time
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
SK = ROOT + "/work/sk"
CAP = int(os.environ.get("CAP", "2000"))          # max training docs per sketch value
MIN_SHARED = int(os.environ.get("MIN_SHARED", "4"))
TOPC = int(os.environ.get("TOPC", "40"))          # keep at most this many train cands per corpus doc
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
UMAX = L.UINT64_MAX
t0 = time.time()

def load(name):
    sk = np.load(SK + "/" + name + ".sk.npy")
    nsh = np.load(SK + "/" + name + ".nsh.npy")
    ids = open(SK + "/" + name + ".ids.txt", encoding="utf-8").read().split("\n")
    assert len(ids) == sk.shape[0] == nsh.shape[0], (name, len(ids), sk.shape, nsh.shape)
    return sk, nsh, ids

# ---------------- training side ----------------
train_names = sorted(os.path.basename(p)[:-len(".meta.json")] for p in glob.glob(SK + "/train__*.meta.json"))
tr_sk = []; tr_nsh = []; tr_ids = []; tr_file = []; offs = {}
cur = 0
for nm in train_names:
    sk, nsh, ids = load(nm)
    offs[nm] = (cur, cur + sk.shape[0]); cur += sk.shape[0]
    tr_sk.append(sk); tr_nsh.append(nsh); tr_ids.extend(ids); tr_file.extend([nm] * sk.shape[0])
    print("train", nm, sk.shape, flush=True)
tr_sk = np.concatenate(tr_sk, axis=0)
tr_nsh = np.concatenate(tr_nsh, axis=0)
N_TRAIN = tr_sk.shape[0]
print("N_TRAIN docs", N_TRAIN, "elapsed", round(time.time() - t0, 1), flush=True)

flat = tr_sk.reshape(-1)
owner = np.repeat(np.arange(N_TRAIN, dtype=np.int64), L.SKETCH_K)
keep = flat != UMAX
flat = flat[keep]; owner = owner[keep]
order = np.argsort(flat, kind="stable")
flat = flat[order]; owner = owner[order]
dh, starts, counts = np.unique(flat, return_index=True, return_counts=True)
print("distinct train sketch values", dh.size, "postings", flat.size, flush=True)
over = counts > CAP
n_over = int(over.sum()); post_over = int(counts[over].sum())
sel = ~over
dh_f = dh[sel]; st_f = starts[sel]; ct_f = counts[sel]
off_f = np.empty(dh_f.size + 1, dtype=np.int64)
off_f[0] = 0; np.cumsum(ct_f, out=off_f[1:])
# compact postings for the kept hashes
gidx = np.repeat(st_f, ct_f) + (np.arange(off_f[-1]) - np.repeat(off_f[:-1], ct_f))
postings = owner[gidx].astype(np.int32)
del flat, owner, order, gidx
print("indexed hashes", dh_f.size, "postings", postings.size,
      "dropped_over_cap_hashes", n_over, "dropped_postings", post_over,
      "elapsed", round(time.time() - t0, 1), flush=True)

# training docs with zero indexable sketch value (recall caveat)
has_rare = np.zeros(N_TRAIN, dtype=bool)
has_rare[np.unique(postings)] = True
n_no_rare = int((~has_rare).sum())
print("train docs with no indexable sketch value:", n_no_rare, flush=True)

# ---------------- corpus side ----------------
out_c = []; out_t = []; out_s = []
corpus_meta = []
cbase = 0
B = 4000
for stage in STAGES:
    nm = "corpus__" + stage
    sk, nsh, ids = load(nm)
    n = sk.shape[0]
    corpus_meta.append({"stage": stage, "name": nm, "offset": cbase, "n": n})
    for s in range(0, n, B):
        e = min(s + B, n)
        blk = sk[s:e]
        hs = blk.reshape(-1)
        own = np.repeat(np.arange(s, e, dtype=np.int64), L.SKETCH_K)
        m = hs != UMAX
        hs = hs[m]; own = own[m]
        pos = np.searchsorted(dh_f, hs)
        pos_c = np.minimum(pos, dh_f.size - 1)
        ok = dh_f[pos_c] == hs
        pos = pos[ok]; own = own[ok]
        if pos.size == 0: continue
        lens = (off_f[pos + 1] - off_f[pos]).astype(np.int64)
        tot = int(lens.sum())
        if tot == 0: continue
        cum = np.cumsum(lens) - lens
        gi = np.repeat(off_f[pos], lens) + (np.arange(tot) - np.repeat(cum, lens))
        tr = postings[gi].astype(np.int64)
        ow = np.repeat(own, lens)
        key = ow * N_TRAIN + tr
        key.sort()
        uk, uc = np.unique(key, return_counts=True)
        sel2 = uc >= MIN_SHARED
        uk = uk[sel2]; uc = uc[sel2]
        if uk.size == 0: continue
        cown = uk // N_TRAIN; ctr = uk % N_TRAIN
        # cap candidates per corpus doc
        ordr = np.lexsort((-uc, cown))
        cown = cown[ordr]; ctr = ctr[ordr]; uc = uc[ordr]
        rank = np.arange(cown.size) - np.repeat(
            np.searchsorted(cown, np.unique(cown)), np.unique(cown, return_counts=True)[1])
        km = rank < TOPC
        out_c.append((cown[km] + cbase).astype(np.int64))
        out_t.append(ctr[km].astype(np.int32))
        out_s.append(uc[km].astype(np.int32))
    cbase += n
    print("corpus", stage, n, "cand so far", sum(a.size for a in out_c),
          "elapsed", round(time.time() - t0, 1), flush=True)

c = np.concatenate(out_c) if out_c else np.zeros(0, np.int64)
t = np.concatenate(out_t) if out_t else np.zeros(0, np.int32)
s = np.concatenate(out_s) if out_s else np.zeros(0, np.int32)
np.savez(ROOT + "/work/cand_pairs.npz", corpus_idx=c, train_idx=t, shared=s)
with open(ROOT + "/work/train_global_ids.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(tr_ids))
meta = {"n_train_docs": N_TRAIN, "train_files": train_names, "train_offsets": offs,
        "corpus_meta": corpus_meta, "cap_postings_per_sketch_value": CAP,
        "min_shared_sketch_values": MIN_SHARED, "top_candidates_per_corpus_doc": TOPC,
        "distinct_train_sketch_values": int(dh.size),
        "indexed_train_sketch_values": int(dh_f.size),
        "dropped_over_cap_sketch_values": n_over,
        "dropped_over_cap_postings": post_over,
        "train_docs_with_no_indexable_sketch_value": n_no_rare,
        "n_candidate_pairs": int(c.size), "seconds": round(time.time() - t0, 1)}
json.dump(meta, open(ROOT + "/work/cand_meta.json", "w"), indent=2)
print("CANDIDATES", c.size, json.dumps(meta)[:600], flush=True)
print("DONE")
