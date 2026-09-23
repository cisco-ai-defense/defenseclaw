"""128-permutation MinHash signatures for one doc file (universal hashing, uint64 wraparound)."""
from __future__ import annotations
import json, os, sys, time
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

NPERM = 128
SEED = 20260922
rng = np.random.default_rng(SEED)
A = (rng.integers(1, 2**63, size=NPERM, dtype=np.uint64) * np.uint64(2) + np.uint64(1))  # odd
B = rng.integers(0, 2**63, size=NPERM, dtype=np.uint64)
A = A.astype(np.uint64); B = B.astype(np.uint64)

path = sys.argv[1]
ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
MH = ROOT + "/work/mh"
os.makedirs(MH, exist_ok=True)
name = os.path.basename(path)[:-len(".jsonl")]
t0 = time.time()
EMPTY = np.full(NPERM, L.UINT64_MAX, dtype=np.uint64)

CH = 20000
buf = np.empty((CH, NPERM), dtype=np.uint64)
chunks = []; nsh = []; i = 0
with np.errstate(over="ignore"):
    for d in L.read_docs(path):
        h = L.shingle_hashes(d["t"])
        if h.size == 0:
            buf[i % CH] = EMPTY
        else:
            m = (h[None, :] * A[:, None]) + B[:, None]
            buf[i % CH] = m.min(axis=1)
        nsh.append(int(h.size)); i += 1
        if i % CH == 0:
            chunks.append(buf.copy())
        if i % 50000 == 0:
            print(name, i, round(time.time() - t0, 1), "s", flush=True)
rem = i % CH
if rem: chunks.append(buf[:rem].copy())
sig = np.concatenate(chunks, axis=0) if chunks else np.zeros((0, NPERM), dtype=np.uint64)
assert sig.shape[0] == i
np.save(MH + "/" + name + ".sig.npy", sig)
np.save(MH + "/" + name + ".nsh.npy", np.array(nsh, dtype=np.int64))
meta = {"name": name, "n_docs": i, "n_perm": NPERM, "seed": SEED,
        "shingle_n": L.SHINGLE_N, "total_unique_shingles": int(sum(nsh)),
        "max_unique_shingles": int(max(nsh) if nsh else 0), "seconds": round(time.time() - t0, 1)}
json.dump(meta, open(MH + "/" + name + ".meta.json", "w"), indent=2)
print("DONE", json.dumps(meta), flush=True)
