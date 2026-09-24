"""Release claims that have no done record and no live driver, so they get re-run.

The studio restart restored some old empty claim directories, leaving chunks claimed with
nobody working them. Those would become a silent coverage gap. A chunk is only considered
live if some running benchmark_run_system_one process names its slice file.
"""
import json, shutil
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
RS, RUN = R / "reshard", R / "runs/nimble-s3"
chunks = {c["chunk"]: c for c in json.load(open(RS / "chunks.json"))["chunks"]}
done = {json.loads(p.read_text())["chunk"] for p in (RS / "done").glob("*.json")}

live = set()
for d in Path("/proc").glob("[0-9]*"):
    try:
        cmd = (d / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace")
    except Exception:
        continue
    if "benchmark_run_system_one" not in cmd:
        continue
    for ch in chunks.values():
        if "cases-shard%d.jsonl" % ch["shard"] in cmd:
            live.add(ch["chunk"])

claimed = sorted(int(p.name) for p in (RS / "claims").iterdir() if p.name.isdigit())
stale = [c for c in claimed if c not in done and c not in live]
for c in stale:
    n = chunks[c]["shard"]
    for suf in ("", ".plan.json", ".meta.json"):
        f = RUN / ("bespoke-nimble-9b-shard%d.jsonl%s" % (n, suf))
        if f.exists():
            f.unlink()
    shutil.rmtree(RS / "claims" / str(c))

after = sorted(int(p.name) for p in (RS / "claims").iterdir() if p.name.isdigit())
print(json.dumps({"claimed_before": claimed, "done_ok": sorted(done),
                  "live_driver_chunks": sorted(live), "released_stale": stale,
                  "claims_after": after}, indent=1))
