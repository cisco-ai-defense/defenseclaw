import json, collections
BASE="$WORK/.system-one-data/outputs"
out={}
for st in ["s2","s3"]:
    ex=collections.defaultdict(list)
    ids=collections.defaultdict(set)
    for l in open(f"{BASE}/{st}/cases.jsonl"):
        l=l.strip()
        if not l: continue
        d=json.loads(l); s=d.get("source") or {}
        ds=s.get("dataset")
        if ds in ("rogue-coding-agent-security","nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1"):
            oid=str(s.get("original_id"))
            ids[ds].add(oid)
            if len(ex[ds])<6: ex[ds].append({"case_id":d.get("id"),"original_id":oid,"revision":s.get("revision"),"license":s.get("license"),"surface":d.get("surface"),"truth":d.get("truth")})
    for k in ids:
        print(st,k,"n_cases_with_ds:",len(ids[k]),"distinct_original_ids:",len(ids[k]))
        for e in ex[k]: print("   ", json.dumps(e)[:400])
        out[f"{st}::{k}"]=sorted(ids[k])
json.dump(out, open("$WORK/.system-one-data/outputs/secjudge/contamination/work/our_original_ids.json","w"))
print("WROTE our_original_ids.json")
