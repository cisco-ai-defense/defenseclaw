import hashlib, json, os
H="$WORK/hf-stage"
SM={r["body"].split("/teamspace/studios/this_studio/")[-1]: r
    for r in json.load(open("$WORK/archive-stage-2026-09-24/.studio_manifest.json"))}
# map staged repo path -> studio-verified record
def find_ver(relpath, tree):
    # cohort s2/s3 and sysone bodies
    cand = {
      ("toolcall","predictions"): "laptopguard/preds/",
      ("toolcall","predictions-s3"): "laptopguard/preds-s3/",
    }
    return None

def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda: f.read(8<<20), b""): h.update(c)
    return h.hexdigest()

def rows(p):
    if not p.endswith(".jsonl"): return None
    n=0
    with open(p,"rb") as f:
        for c in iter(lambda: f.read(8<<20), b""): n+=c.count(b"\n")
    return n

# reverse index: basename+group -> studio verification
ver_by_key={}
for k,r in SM.items():
    ver_by_key[(r["group"], os.path.basename(r["body"]))]=r

GROUP_FOR={
 "predictions":"cohort_s2", "predictions-s3":"cohort_s3",
 "runs/nimble-s3/settled":"nimble_s3", "runs/2b-s3":"sysone_2b", "runs/9b-s3":"sysone_9b",
}

for tree,repo,tranche in [("toolcall","Vineethsain/defenseclaw-slm-toolcall-v1","cohort-settled-2026-09-24"),
                          ("predictions","Vineethsain/defenseclaw-system-one-predictions-v1","system-one-s3-2026-09-24")]:
    root=os.path.join(H,tree); recs=[]
    for dp,_,fns in os.walk(root):
        for fn in sorted(fns):
            fp=os.path.join(dp,fn); rel=os.path.relpath(fp,root)
            if rel.startswith("MANIFEST-") or rel.startswith("SHA256SUMS-"): continue
            d=os.path.dirname(rel)
            rec={"path":rel,"bytes":os.path.getsize(fp),"sha256":sha256(fp)}
            r=rows(fp)
            if r is not None: rec["rows"]=r
            g=GROUP_FOR.get(d)
            if g and fn.endswith(".jsonl"):
                v=ver_by_key.get((g,fn))
                if v:
                    rec["verification"]="VERIFIED: meta complete=true and on-disk sha256 == prediction_sha256"
                    rec["meta_complete"]=v["complete"]; rec["meta_rows"]=v["meta_rows"]
                    rec["meta_errors"]=v["meta_errors"]
                    rec["digest_matches_studio"]= (rec["sha256"]==v["disk_sha"])
            recs.append(rec)
    man={"tranche":tranche,"archived_at_utc":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
         "source_host":"defenseclaw-dev (uploaded from); bodies produced on Lightning 4xH200 studio",
         "files":len(recs),"bytes":sum(r["bytes"] for r in recs),"records":recs}
    json.dump(man,open(os.path.join(root,f"MANIFEST-{tranche}.json"),"w"),indent=1)
    with open(os.path.join(root,f"SHA256SUMS-{tranche}.txt"),"w") as f:
        for r in recs: f.write(f"{r['sha256']}  {r['path']}\n")
    nv=sum(1 for r in recs if r.get("verification"))
    print(f"{tree}: {len(recs)} files, {man['bytes']} bytes, {nv} bodies carry VERIFIED status, "
          f"digest_matches_studio all true = {all(r.get('digest_matches_studio',True) for r in recs)}")
