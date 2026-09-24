"""Build the chunk table for the nimble s3 reshard.

Slices are whole-case aligned. That is the property that makes this safe: case_jobs()
builds `prior` only from events inside the same case, and build_state() reads nothing
outside the case, so a request body depends only on its own case line. Copying case
lines verbatim into a slice therefore reproduces byte-identical request bodies.

Consumption order is DESCENDING chunk index (from the end of the case file backwards)
while the live shard0 walks forwards from the front. They meet in the middle, so no
boundary has to be committed up front. shard number = CMAX - chunk + 1, which stays
contiguous 1..M because chunks are always consumed in strict descending order.
"""
import json
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
RESHARD = R / "reshard"
TARGET = 1500  # requests per chunk

idx = json.load(open(RESHARD / "case_index.json"))
ids, counts, cum = idx["ids"], idx["counts"], idx["cum"]
ncases = len(ids)
assert cum[-1] == 100001, cum[-1]

# Greedy forward partition into whole-case chunks of ~TARGET requests.
bounds = [0]
acc = 0
for i, c in enumerate(counts):
    acc += c
    if acc >= TARGET and i + 1 < ncases:
        bounds.append(i + 1)
        acc = 0
bounds.append(ncases)

chunks = []
for c in range(len(bounds) - 1):
    a, b = bounds[c], bounds[c + 1]
    chunks.append({"chunk": c, "case_start": a, "case_end": b,
                   "cases": b - a, "req_start": cum[a], "req_end": cum[b],
                   "requests": cum[b] - cum[a]})
cmax = len(chunks) - 1
for ch in chunks:
    ch["shard"] = cmax - ch["chunk"] + 1

# Coverage assertions
assert chunks[0]["case_start"] == 0 and chunks[-1]["case_end"] == ncases
for x, y in zip(chunks, chunks[1:]):
    assert x["case_end"] == y["case_start"]
assert sum(ch["requests"] for ch in chunks) == 100001
shards = [ch["shard"] for ch in chunks]
assert sorted(shards) == list(range(1, len(chunks) + 1))

json.dump({"target_requests_per_chunk": TARGET, "cmax": cmax,
           "n_chunks": len(chunks), "chunks": chunks},
          open(RESHARD / "chunks.json", "w"), indent=1)

rq = [ch["requests"] for ch in chunks]
print(json.dumps({"n_chunks": len(chunks), "cmax": cmax,
                  "requests_min": min(rq), "requests_max": max(rq),
                  "requests_total": sum(rq),
                  "first_chunk_consumed": {"chunk": cmax, "shard": 1,
                                           "case_start": chunks[cmax]["case_start"],
                                           "req_start": chunks[cmax]["req_start"],
                                           "requests": chunks[cmax]["requests"]},
                  "tail_chunks_sample": chunks[-4:]}, indent=2))
