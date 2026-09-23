import json, collections, hashlib, os
BASE="$WORK/.system-one-data/outputs"
STAGES=["s2","s3","intent-real","toolcall-labels"]
out={}
for st in STAGES:
    p=f"{BASE}/{st}/cases.jsonl"
    h=hashlib.sha256()
    with open(p,"rb") as fh:
        for c in iter(lambda: fh.read(1<<20), b""): h.update(c)
    cnt=collections.Counter(); lic=collections.Counter(); rev=collections.defaultdict(set)
    n=0; bad=0; srckeys=collections.Counter()
    oid_prefix=collections.Counter()
    with open(p) as fh:
        for line in fh:
            line=line.strip()
            if not line: continue
            n+=1
            try: d=json.loads(line)
            except Exception: bad+=1; continue
            s=d.get("source") or {}
            if isinstance(s,dict):
                for k in s: srckeys[k]+=1
                ds=s.get("dataset")
                cnt[str(ds)]+=1
                lic[str(s.get("license"))]+=1
                rev[str(ds)].add(str(s.get("revision")))
                oid=str(s.get("original_id") or "")
                oid_prefix[(str(ds), oid.split(":")[0].split("/")[0][:40])]+=1
            else:
                cnt["__non_dict_source__"]+=1
    out[st]={"path":p,"sha256":h.hexdigest(),"n_lines":n,"n_unparseable":bad,
             "source_keys_present":dict(srckeys),
             "dataset_counts":dict(sorted(cnt.items(), key=lambda kv:-kv[1])),
             "license_counts":dict(lic),
             "revisions_per_dataset":{k:sorted(v) for k,v in rev.items()},
             "n_distinct_datasets":len(cnt)}
    print(st, n, "datasets:", len(cnt))
    for k,v in sorted(cnt.items(), key=lambda kv:-kv[1]): print("   ", v, k)
json.dump(out, open("$WORK/.system-one-data/outputs/secjudge/contamination/work/source_counts.json","w"), indent=2)
print("WROTE source_counts.json")
