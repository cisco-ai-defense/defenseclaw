"""Build character-5-gram bottom-k (KMV, k=128) sketches for one doc file."""
from __future__ import annotations
import json, os, sys, time
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/contamination/work")
import contam_lib as L
import numpy as np

path = sys.argv[1]
ROOT = "$WORK/.system-one-data/outputs/secjudge/contamination"
SK = ROOT + "/work/sk"
name = os.path.basename(path)[:-6]
t0 = time.time()

ids = []; sks = []; nsh = []; shas = []
CH = 20000
buf = np.empty((CH, L.SKETCH_K), dtype=np.uint64)
chunks = []
i = 0
maxsh = 0; totsh = 0
for d in L.read_docs(path):
    h = L.shingle_hashes(d["t"])
    sk, n, complete = L.kmv_sketch(h)
    buf[i % CH] = sk
    nsh.append(n); ids.append(d["id"]); shas.append(d["sha"])
    totsh += n
    if n > maxsh: maxsh = n
    i += 1
    if i % CH == 0:
        chunks.append(buf.copy())
    if i % 100000 == 0:
        print(name, i, round(time.time() - t0, 1), "s", flush=True)
rem = i % CH
if rem: chunks.append(buf[:rem].copy())
sk_all = np.concatenate(chunks, axis=0) if chunks else np.zeros((0, L.SKETCH_K), dtype=np.uint64)
assert sk_all.shape[0] == i, (sk_all.shape, i)
np.save(SK + "/" + name + ".sk.npy", sk_all)
np.save(SK + "/" + name + ".nsh.npy", np.array(nsh, dtype=np.int64))
with open(SK + "/" + name + ".ids.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(ids))
with open(SK + "/" + name + ".shas.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(shas))
meta = {"name": name, "docs_path": path, "n_docs": i, "sketch_k": L.SKETCH_K,
        "shingle_n": L.SHINGLE_N, "max_unique_shingles": maxsh,
        "total_unique_shingles": totsh,
        "n_docs_with_complete_sketch": int(np.sum(np.array(nsh) <= L.SKETCH_K)),
        "seconds": round(time.time() - t0, 1)}
json.dump(meta, open(SK + "/" + name + ".meta.json", "w"), indent=2)
print("DONE", json.dumps(meta), flush=True)
