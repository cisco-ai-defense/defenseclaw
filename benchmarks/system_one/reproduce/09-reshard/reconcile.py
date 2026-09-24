"""Reconcile reshard state after the studio stop/restart, then verify what survived.

Two hazards this fixes:
  1. claims/ is EMPTY after rehydration -- those were empty directories and object
     storage does not preserve them. Without re-creating claims for the COMPLETED
     chunks, next_chunk.py (which takes min(claimed)-1) would re-claim chunk 66 and
     overwrite a banked, digest-verified shard.
  2. Chunks that were in flight have partial bodies and no meta. Their bodies and
     plan files are deleted so a fresh driver redoes the whole slice in one pass
     ("w" mode), which is a clean re-run rather than a splice.

It also re-verifies every banked shard against its meta, because a crash mid-write
could have left a torn body.
"""
import hashlib, json, sys
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
RS, RUN = R / "reshard", R / "runs/nimble-s3"
table = json.load(open(RS / "chunks.json"))
chunks = {c["chunk"]: c for c in table["chunks"]}


def sha256_file(p):
    d = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            d.update(b)
    return d.hexdigest()


def rows(p):
    n = 0
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 22), b""):
            n += b.count(b"\n")
    return n


ok_chunks, bad = [], []
for p in sorted((RS / "done").glob("*.json")):
    rec = json.loads(p.read_text())
    if rec.get("status") == "ok":
        ok_chunks.append(rec["chunk"])
    else:
        bad.append(rec)
        p.unlink()
        print(f"removed non-ok done record: chunk {rec.get('chunk')} {rec.get('status')}")
ok_chunks.sort()

# --- verify every banked shard still matches its meta exactly ---
print("\n--- verifying banked shards ---")
failed = []
for c in ok_chunks:
    ch = chunks[c]
    n = ch["shard"]
    body = RUN / f"bespoke-nimble-9b-shard{n}.jsonl"
    meta_p = Path(str(body) + ".meta.json")
    if not body.exists() or not meta_p.exists():
        failed.append((c, n, "missing body or meta")); continue
    meta = json.loads(meta_p.read_text())
    disk = sha256_file(body)
    nrows = rows(body)
    problems = []
    if meta.get("complete") is not True:
        problems.append("complete!=true")
    if meta["prediction_sha256"] != disk:
        problems.append(f"digest {meta['prediction_sha256'][:12]}!=disk {disk[:12]}")
    if nrows != ch["requests"]:
        problems.append(f"rows {nrows}!={ch['requests']}")
    if meta["requests"] != ch["requests"]:
        problems.append(f"meta.requests {meta['requests']}!={ch['requests']}")
    status = "OK" if not problems else "FAIL " + "; ".join(problems)
    print(f"  chunk {c} shard{n}: rows={nrows} digest={disk[:16]} {status}")
    if problems:
        failed.append((c, n, problems))

if failed:
    print("\nABORT: banked shards failed verification:", failed)
    sys.exit(1)

# --- re-create claims for completed chunks so they are never re-run ---
(RS / "claims").mkdir(parents=True, exist_ok=True)
made = []
for c in ok_chunks:
    d = RS / "claims" / str(c)
    if not d.exists():
        d.mkdir()
        (d / "completed").write_text(f"chunk {c} completed and digest-verified\n")
        made.append(c)
print(f"\nre-created claims for completed chunks: {made}")

# --- clear partial bodies for chunks with no ok record ---
cleared = []
for c, ch in chunks.items():
    if c in ok_chunks:
        continue
    n = ch["shard"]
    for suffix in ("", ".plan.json", ".meta.json"):
        f = RUN / f"bespoke-nimble-9b-shard{n}.jsonl{suffix}"
        if f.exists():
            f.unlink()
            cleared.append(f.name)
print(f"cleared {len(cleared)} partial file(s): {sorted(cleared)}")

claimed = sorted(int(p.name) for p in (RS / "claims").iterdir() if p.name.isdigit())
c_min = min(claimed) if claimed else len(chunks)
banked = sum(chunks[c]["requests"] for c in ok_chunks)
s0 = rows(RUN / "bespoke-nimble-9b-shard0.jsonl")
print(json.dumps({
    "claims_now": claimed,
    "next_chunk_would_claim": c_min - 1,
    "banked_chunks": ok_chunks,
    "banked_requests": banked,
    "shard0_rows_frozen": s0,
    "pool_must_cover_requests": 100001 - banked,
    "note": ("shard0 is frozen, so the pool eats down until it reaches shard0's "
             "case boundary; shard0's usable prefix is decided at merge time"),
}, indent=2))
