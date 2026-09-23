"""Task C: MinHash LSH candidate generation + exact-Jaccard verification.

128 permutations.  Banding is parameterised: rows-per-band R, bands b=128//R,
detection probability 1-(1-J^R)^b.  Both sides are first deduplicated on the
sha256 of the normalised text.  Candidates are pre-screened on signature
agreement, then EVERY survivor gets an exact Jaccard from the full
character-5-gram sets.  Output pairs are written with resolved doc ids.
"""
from __future__ import annotations
import glob, json, os, sys, time, collections
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
MH = ROOT + "/work/mh"; SK = ROOT + "/work/sk"; DOCS = ROOT + "/work/docs"
R = int(os.environ.get("R", "4"))
TAG = os.environ.get("TAG", "r" + str(R))
GROUP_FILTER = [g for g in os.environ.get("GROUPS", "").split(",") if g]
BUCKET_CAP = int(os.environ.get("BUCKET_CAP", "20000"))
SIG_MIN = float(os.environ.get("SIG_MIN", "0.20"))
KEEP_MIN = float(os.environ.get("KEEP_MIN", "0.30"))
STAGES = ["s2", "s3", "intent-real", "toolcall-labels"]
NPERM = 128; NB = NPERM // R
t0 = time.time()

def band_keys(sig):
    n = sig.shape[0]
    out = np.empty((n, NB), dtype=np.uint64)
    off = np.uint64(14695981039346656037); prm = np.uint64(1099511628211)
    mix = np.uint64(0x9E3779B97F4A7C15)
    with np.errstate(over="ignore"):
        for j in range(NB):
            h = np.full(n, off, dtype=np.uint64)
            for t in range(R):
                h = (h ^ sig[:, j * R + t]) * prm
            out[:, j] = h ^ (np.uint64(j) * mix)
    return out

def read_lines(p): return open(p, encoding="utf-8").read().split("\n")

# ---------------- training side ----------------
train_names = sorted(os.path.basename(p)[:-len(".meta.json")] for p in glob.glob(MH + "/train__*.meta.json"))
if GROUP_FILTER:
    train_names = [n for n in train_names if any(n == "train__" + g for g in GROUP_FILTER)]
    assert train_names, GROUP_FILTER
tsig = []; tids = []; tshas = []
for nm in train_names:
    s = np.load(MH + "/" + nm + ".sig.npy"); tsig.append(s)
    tids.extend(read_lines(SK + "/" + nm + ".ids.txt"))
    tshas.extend(read_lines(SK + "/" + nm + ".shas.txt"))
tsig = np.concatenate(tsig, axis=0)
assert len(tids) == len(tshas) == tsig.shape[0]
print("train files", train_names, "docs", tsig.shape[0], flush=True)

def dedupe(shas):
    seen = {}; rep_of = np.empty(len(shas), dtype=np.int64); reps = []
    for i, sh in enumerate(shas):
        j = seen.get(sh)
        if j is None:
            j = len(reps); seen[sh] = j; reps.append(i)
        rep_of[i] = j
    return np.array(reps, dtype=np.int64), rep_of

t_reps, t_rep_of = dedupe(tshas)
tsig_u = tsig[t_reps]; N_T = t_reps.size
t_members = collections.defaultdict(list)
for i, r in enumerate(t_rep_of): t_members[int(r)].append(i)
print("train distinct norm texts", N_T, round(time.time() - t0, 1), flush=True)

tk = band_keys(tsig_u).reshape(-1)
town = np.repeat(np.arange(N_T, dtype=np.int64), NB)
o = np.argsort(tk, kind="stable"); tk = tk[o]; town = town[o]
uk, ustart, ucount = np.unique(tk, return_index=True, return_counts=True)
del tk, o
print("band buckets", uk.size, "max bucket", int(ucount.max()), round(time.time() - t0, 1), flush=True)

# ---------------- corpus side ----------------
csig = []; cids = []; cshas = []
for stage in STAGES:
    nm = "corpus__" + stage
    csig.append(np.load(MH + "/" + nm + ".sig.npy"))
    cids.extend(read_lines(SK + "/" + nm + ".ids.txt"))
    cshas.extend(read_lines(SK + "/" + nm + ".shas.txt"))
csig = np.concatenate(csig, axis=0)
assert len(cids) == len(cshas) == csig.shape[0]
c_reps, c_rep_of = dedupe(cshas)
csig_u = csig[c_reps]; N_C = c_reps.size
c_members = collections.defaultdict(list)
for i, r in enumerate(c_rep_of): c_members[int(r)].append(i)
print("corpus docs", csig.shape[0], "distinct", N_C, round(time.time() - t0, 1), flush=True)

pairs_c = []; pairs_t = []
n_raw = 0; n_capped = 0; n_capped_post = 0
BATCH = 3000
for s0 in range(0, N_C, BATCH):
    s1 = min(s0 + BATCH, N_C)
    ck = band_keys(csig_u[s0:s1]).reshape(-1)
    cown = np.repeat(np.arange(s0, s1, dtype=np.int64), NB)
    pos = np.minimum(np.searchsorted(uk, ck), uk.size - 1)
    ok = uk[pos] == ck
    pos = pos[ok]; cown = cown[ok]
    if pos.size == 0: continue
    lens = ucount[pos].astype(np.int64)
    big = lens > BUCKET_CAP
    if big.any():
        n_capped += int(big.sum()); n_capped_post += int(lens[big].sum())
        pos = pos[~big]; cown = cown[~big]; lens = lens[~big]
    if pos.size == 0: continue
    tot = int(lens.sum())
    if tot == 0: continue
    n_raw += tot
    cum = np.cumsum(lens) - lens
    gi = np.repeat(ustart[pos], lens) + (np.arange(tot) - np.repeat(cum, lens))
    key = np.unique(np.repeat(cown, lens) * N_T + town[gi])
    cc = key // N_T; tt = key % N_T
    est = (csig_u[cc] == tsig_u[tt]).sum(axis=1) / NPERM
    m = est >= SIG_MIN
    if m.any():
        pairs_c.append(cc[m]); pairs_t.append(tt[m])
    if (s0 // BATCH) % 25 == 0:
        print("q", s0, "/", N_C, "raw", n_raw, "kept", sum(a.size for a in pairs_c),
              round(time.time() - t0, 1), flush=True)

pc = np.concatenate(pairs_c) if pairs_c else np.zeros(0, np.int64)
pt = np.concatenate(pairs_t) if pairs_t else np.zeros(0, np.int64)
print("prescreened pairs", pc.size, "raw", n_raw, "capped buckets", n_capped, round(time.time() - t0, 1), flush=True)

# ---------------- exact verification ----------------
need_c = {int(c_reps[i]): int(i) for i in np.unique(pc)}
need_t = {int(t_reps[i]): int(i) for i in np.unique(pt)}
print("need shingles corpus", len(need_c), "train", len(need_t), flush=True)

def load_sh(files, need):
    got = {}; base = 0
    for p, n in files:
        for k, d in enumerate(L.read_docs(p)):
            r = need.get(base + k)
            if r is not None: got[r] = L.shingle_hashes(d["t"])
        base += n
    return got

cfiles = [(DOCS + "/corpus__" + s + ".jsonl", int(np.load(MH + "/corpus__" + s + ".nsh.npy").shape[0])) for s in STAGES]
tfiles = [(DOCS + "/" + nm + ".jsonl", int(np.load(MH + "/" + nm + ".nsh.npy").shape[0])) for nm in train_names]
cs = load_sh(cfiles, need_c); print("corpus shingles loaded", len(cs), round(time.time() - t0, 1), flush=True)
ts = load_sh(tfiles, need_t); print("train shingles loaded", len(ts), round(time.time() - t0, 1), flush=True)

outp = ROOT + "/work/pairs__" + TAG + ".jsonl"
out = open(outp, "w", encoding="utf-8")
nv = 0; nrows = 0
for i in range(pc.size):
    ci = int(pc[i]); ti = int(pt[i])
    a = cs.get(ci); b = ts.get(ti)
    if a is None or b is None: continue
    j = L.exact_jaccard(a, b)
    if j < KEEP_MIN: continue
    nv += 1
    tg = sorted({tids[k].split("|", 1)[0] for k in t_members[ti]})
    trep = tids[int(t_reps[ti])]
    for k in c_members[ci]:
        out.write(json.dumps({"cdoc": cids[k], "tdoc": trep, "tgroups": tg, "j": round(j, 6)}) + "\n")
        nrows += 1
out.close()
meta = {"tag": TAG, "n_perm": NPERM, "rows_per_band": R, "n_bands": NB,
        "group_filter": GROUP_FILTER or "ALL",
        "detection_prob": {str(x): round(1 - (1 - x ** R) ** NB, 6) for x in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]},
        "bucket_cap": BUCKET_CAP, "sig_prescreen_min": SIG_MIN, "keep_min_exact_jaccard": KEEP_MIN,
        "train_docs": int(tsig.shape[0]), "train_distinct": N_T,
        "corpus_docs": int(csig.shape[0]), "corpus_distinct": N_C,
        "raw_candidate_postings": n_raw, "pairs_after_prescreen": int(pc.size),
        "capped_buckets": n_capped, "capped_postings": n_capped_post,
        "verified_rep_pairs": nv, "expanded_rows": nrows,
        "pairs_path": outp, "seconds": round(time.time() - t0, 1)}
json.dump(meta, open(ROOT + "/work/lsh_meta__" + TAG + ".json", "w"), indent=2)
with open(ROOT + "/work/corpus_global_ids.txt", "w", encoding="utf-8") as fh: fh.write("\n".join(cids))
print("DONE", json.dumps(meta), flush=True)
