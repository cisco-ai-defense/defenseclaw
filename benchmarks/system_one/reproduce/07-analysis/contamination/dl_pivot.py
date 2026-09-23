import json, os, hashlib
from huggingface_hub import hf_hub_download
CACHE = "$WORK/.system-one-data/outputs/secjudge/contamination/cache"
repo="nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1"
res={}
for f in ["README.md","atcb_terminal_pivot_release_final_v2.jsonl"]:
    try:
        p=hf_hub_download(repo_id=repo, filename=f, repo_type="dataset", local_dir=os.path.join(CACHE, repo.replace("/","__")))
        h=hashlib.sha256()
        with open(p,"rb") as fh:
            for c in iter(lambda: fh.read(1<<20), b""): h.update(c)
        res[f]={"ok":True,"path":p,"bytes":os.path.getsize(p),"sha256":h.hexdigest()}
        print("OK",f,os.path.getsize(p),flush=True)
    except Exception as e:
        res[f]={"ok":False,"error_type":type(e).__name__,"error":str(e)[:500]}
        print("FAIL",f,type(e).__name__,str(e)[:300],flush=True)
json.dump(res, open("$WORK/.system-one-data/outputs/secjudge/contamination/work/downloads_pivot.json","w"), indent=2)
print("DONE")
