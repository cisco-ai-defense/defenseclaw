"""Atomically claim the next chunk (highest unclaimed, descending) and materialise its slice.

stdout  "<chunk> <shard> <case_start> <req_start> <requests> <slice_path>"  -> claimed
stdout  empty, exit 0                                                      -> met shard0 / exhausted
exit != 0                                                                  -> transient error, caller retries

The meeting guard: the live shard0 only has to cover [0, case_start_of_lowest_claimed_chunk).
Its target in requests is `boundary_req`. If shard0 has already written that many rows it has
met the pool, so another claim would only duplicate rows shard0 already produced -> stop.

The teamspace mount is networked and has been observed to fail an open() transiently, so the
row count retries and a persistent failure exits NONZERO rather than looking like "met".
"""
import json, os, sys, time
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
RS = R / "reshard"
CLAIMS = RS / "claims"
SHARD0 = R / "runs/nimble-s3/bespoke-nimble-9b-shard0.jsonl"
CASES = R / "agree/s3-cases.jsonl"
OUTDIR = R / "runs/nimble-s3"

table = json.load(open(RS / "chunks.json"))
chunks = table["chunks"]
CLAIMS.mkdir(parents=True, exist_ok=True)


def shard0_rows():
    last = None
    for attempt in range(6):
        try:
            n = 0
            with open(SHARD0, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 22), b""):
                    n += block.count(b"\n")
            return n
        except OSError as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    sys.stderr.write(f"could not count shard0 rows after retries: {last}\n")
    sys.exit(3)


def materialise(ch):
    """Copy the chunk's case lines verbatim so request bodies stay byte-identical."""
    path = OUTDIR / f"cases-shard{ch['shard']}.jsonl"
    tmp = Path(str(path) + ".tmp")
    a, b = ch["case_start"], ch["case_end"]
    written = 0
    with open(CASES, "rb") as src, open(tmp, "wb") as out:
        for i, line in enumerate(src):
            if i >= b:
                break
            if i >= a:
                out.write(line)
                written += 1
        out.flush()
        os.fsync(out.fileno())
    if written != ch["cases"]:
        tmp.unlink(missing_ok=True)
        sys.stderr.write(f"slice chunk {ch['chunk']}: wrote {written} cases, want {ch['cases']}\n")
        sys.exit(4)
    os.replace(tmp, path)
    return path


for _ in range(len(chunks) + 2):
    try:
        claimed = {int(p.name) for p in CLAIMS.iterdir() if p.name.isdigit()}
    except OSError as exc:
        sys.stderr.write(f"claims listing failed: {exc}\n")
        sys.exit(5)
    c_min = min(claimed) if claimed else len(chunks)
    boundary_req = chunks[c_min]["req_start"] if c_min < len(chunks) else 100001
    rows = shard0_rows()
    if rows >= boundary_req:
        sys.stderr.write(f"met shard0: rows={rows} >= boundary_req={boundary_req} "
                         f"(lowest claimed chunk {c_min})\n")
        sys.exit(0)
    c = c_min - 1
    if c < 0:
        sys.stderr.write("pool exhausted\n")
        sys.exit(0)
    try:
        (CLAIMS / str(c)).mkdir()
    except FileExistsError:
        continue
    except OSError as exc:
        sys.stderr.write(f"claim mkdir failed: {exc}\n")
        sys.exit(6)
    ch = chunks[c]
    path = materialise(ch)
    print(f"{ch['chunk']} {ch['shard']} {ch['case_start']} {ch['req_start']} "
          f"{ch['requests']} {path}")
    sys.exit(0)
sys.stderr.write("gave up claiming\n")
sys.exit(7)
