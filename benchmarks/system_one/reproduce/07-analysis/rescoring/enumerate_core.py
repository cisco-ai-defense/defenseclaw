"""Every settled prediction artifact whose meta pins the 4,277-case core scoring corpus."""
import hashlib, json
from pathlib import Path
DATA = Path("/home/ubuntu/.system-one-data/outputs")
CORE_SHA = "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7"
def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(1<<22), b""): h.update(c)
    return h.hexdigest()
rows=[]
for mp in DATA.rglob("*.jsonl.meta.json"):
    try: m=json.loads(mp.read_text())
    except Exception: continue
    pred=Path(str(mp)[:-len(".meta.json")])
    cs = m.get("cases_sha256")
    if cs != CORE_SHA and m.get("cases") != 4277: continue
    if not pred.exists(): 
        rows.append({"pred":str(pred),"status":"prediction file missing","meta":str(mp)}); continue
    rows.append({"pred":str(pred),"bytes":pred.stat().st_size,"complete":m.get("complete"),
                 "cases":m.get("cases"),"cases_sha_is_core":cs==CORE_SHA,"cases_sha":cs,
                 "model":m.get("model"),"display_name":m.get("display_name"),"run_id":m.get("run_id"),
                 "requests":m.get("requests"),"grid":[m.get("contexts"),m.get("instructions"),m.get("questions")],
                 "meta_sha":m.get("prediction_sha256")})
# also secjudge-style metas that point at a predictions path via "predictions"
for mp in DATA.rglob("*.jsonl.meta.json"):
    try: m=json.loads(mp.read_text())
    except Exception: continue
    if m.get("cases_sha256")==CORE_SHA or m.get("cases")==4277: continue
    if m.get("stage")=="s2" and m.get("requests")==30310:
        pred=Path(str(mp)[:-len(".meta.json")])
        rows.append({"pred":str(pred),"bytes":pred.stat().st_size if pred.exists() else None,
                     "complete":m.get("complete"),"cases":m.get("cases"),"cases_sha_is_core":False,
                     "cases_sha":m.get("cases_sha256"),"model":m.get("model"),"display_name":m.get("display_name"),
                     "run_id":m.get("run_id"),"requests":m.get("requests"),
                     "grid":[m.get("contexts"),m.get("instructions"),m.get("questions")],
                     "meta_sha":m.get("prediction_sha256"),"matched_by":"stage=s2 & requests=30310"})
seen=set(); out=[]
for r in rows:
    if r["pred"] in seen: continue
    seen.add(r["pred"]); out.append(r)
out.sort(key=lambda r: r["pred"])
print(f"TOTAL {len(out)} candidate core-corpus prediction artifacts")
for r in out:
    ok = "?" 
    if r.get("bytes"):
        ok = sha(Path(r["pred"]))==r.get("meta_sha")
    print(f"{str(r.get('complete')):5s} sha_ok={str(ok):5s} req={str(r.get('requests')):6s} core={str(r.get('cases_sha_is_core')):5s} "
          f"grid={r.get('grid')} model={r.get('model')} :: {r['pred'].replace(str(DATA)+'/','')}")
