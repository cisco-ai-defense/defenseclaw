"""Progress, aggregate throughput and ETA for the nimble s3 reshard."""
import json, time, os
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
RS = R / "reshard"
RUNDIR = R / "runs/nimble-s3"
table = json.load(open(RS / "chunks.json"))
chunks, cmax = table["chunks"], table["cmax"]
cum = json.load(open(RS / "case_index.json"))["cum"]


def rows(p):
    if not p.exists():
        return 0
    n = 0
    with open(p, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 22), b""):
            n += blk.count(b"\n")
    return n


claimed = sorted(int(p.name) for p in (RS / "claims").iterdir() if p.name.isdigit()) \
    if (RS / "claims").exists() else []
done = {}
if (RS / "done").exists():
    for p in (RS / "done").glob("*.json"):
        rec = json.loads(p.read_text())
        done[rec["chunk"]] = rec.get("status")

s0 = rows(RUNDIR / "bespoke-nimble-9b-shard0.jsonl")
c_min = min(claimed) if claimed else len(chunks)
boundary_req = chunks[c_min]["req_start"] if c_min < len(chunks) else 100001
boundary_case = chunks[c_min]["case_start"] if c_min < len(chunks) else 24476

chunk_rows = 0
per = []
for c in claimed:
    ch = chunks[c]
    n = rows(RUNDIR / f"bespoke-nimble-9b-shard{ch['shard']}.jsonl")
    chunk_rows += n
    per.append({"chunk": c, "shard": ch["shard"], "rows": n, "of": ch["requests"],
                "status": done.get(c, "running")})

kept0 = min(s0, boundary_req)
total_done = kept0 + chunk_rows
snap = RS / "rate.json"
now = time.time()
out = {
    "utc": time.strftime("%H:%M:%SZ", time.gmtime(now)),
    "shard0_rows": s0,
    "shard0_target_boundary_req": boundary_req,
    "shard0_remaining_to_boundary": max(0, boundary_req - s0),
    "boundary_case_index": boundary_case,
    "chunks_claimed": len(claimed),
    "chunks_ok": sum(1 for v in done.values() if v == "ok"),
    "chunks_bad": [c for c, v in done.items() if v != "ok"],
    "chunk_rows": chunk_rows,
    "effective_rows_complete": total_done,
    "effective_remaining": 100001 - total_done,
    "per_chunk": per[-8:],
}
if snap.exists():
    prev = json.loads(snap.read_text())
    dt = now - prev["t"]
    if dt > 30:
        d0 = (s0 - prev["s0"]) / dt * 60
        dc = (chunk_rows - prev["chunk"]) / dt * 60
        agg = d0 + dc
        out["interval_s"] = round(dt, 1)
        out["shard0_rows_per_min"] = round(d0, 1)
        out["chunk_shards_rows_per_min"] = round(dc, 1)
        out["aggregate_rows_per_min"] = round(agg, 1)
        if agg > 0:
            eta_min = (100001 - total_done) / agg
            out["eta_min"] = round(eta_min, 1)
            out["eta_utc"] = time.strftime("%H:%M:%SZ", time.gmtime(now + eta_min * 60))
        snap.write_text(json.dumps({"t": now, "s0": s0, "chunk": chunk_rows}))
else:
    snap.write_text(json.dumps({"t": now, "s0": s0, "chunk": chunk_rows}))
print(json.dumps(out, indent=1))
