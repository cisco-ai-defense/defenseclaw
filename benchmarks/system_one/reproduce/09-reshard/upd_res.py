import json, os, subprocess, datetime
p="/teamspace/studios/this_studio/queue/RESERVATIONS.json"
d=json.load(open(p))
out=subprocess.run(["nvidia-smi","--query-gpu=index,memory.used","--format=csv,noheader,nounits"],
                   capture_output=True,text=True).stdout.strip().splitlines()
live={int(l.split(",")[0]): int(l.split(",")[1]) for l in out}
now=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
mine=None
for r in d.get("reservations",[]):
    if r.get("card")==3 and "nimble" in str(r.get("what","")).lower():
        mine=r; break
if mine is None:
    mine={"card":3}; d.setdefault("reservations",[]).append(mine)
mine.update({
  "card":3,"owner":"claude-nimble-reshard",
  "what":"bespoke-nimble-9b s3 reshard: 5 nimble_shim replicas ports 8841-8845, one driver each on disjoint whole-case slices",
  "mem_mib":live.get(3,0),
  "expect_free_utc":"2026-09-24T07:00:00Z",
  "contact":"claude-nimble-reshard",
  "note":("measured live. 5 replicas ~19.6 GiB each now, growing to ~24.6 GiB under sustained "
          "load; projected peak ~123,000 MiB of 143,771, leaving ~20 GiB. Ports 8841-8845 are "
          "live model servers: do not bind or restart. Card 3 exclusively; I do not use 0/1/2.")})
d["updated_utc"]=now
d["_live_memory_mib_at_update"]={str(k):v for k,v in sorted(live.items())}
tmp=p+".tmp"
with open(tmp,"w") as fh:
    json.dump(d,fh,indent=2); fh.write("\n"); fh.flush(); os.fsync(fh.fileno())
os.replace(tmp,p)
print("live:",live); print("card3 entry mem_mib:",mine["mem_mib"])
