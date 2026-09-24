import json, os, subprocess, datetime
p = "/teamspace/studios/this_studio/queue/RESERVATIONS.json"
d = json.load(open(p))
out = subprocess.run(["nvidia-smi", "--query-gpu=index,memory.used", "--format=csv,noheader,nounits"],
                     capture_output=True, text=True).stdout.strip().splitlines()
live = {int(l.split(",")[0]): int(l.split(",")[1]) for l in out}
before = len(d.get("reservations", []))
d["reservations"] = [r for r in d.get("reservations", [])
                     if not (r.get("card") == 3 and "nimble" in str(r.get("what", "")).lower())]
now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
d["updated_utc"] = now
d["_live_memory_mib_at_update"] = {str(k): v for k, v in sorted(live.items())}
d["_released"] = {"at": now, "card": 3, "by": "claude-nimble-reshard",
                  "why": "bespoke-nimble-9b s3 reshard complete and settled; all 5 replicas retired by exact pid"}
tmp = p + ".tmp"
with open(tmp, "w") as fh:
    json.dump(d, fh, indent=2); fh.write("\n"); fh.flush(); os.fsync(fh.fileno())
os.replace(tmp, p)
print("reservations", before, "->", len(d["reservations"]), "live:", live)
