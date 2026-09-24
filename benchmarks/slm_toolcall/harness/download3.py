#!/usr/bin/env python3
"""Download the six newly-unlocked gated models. Uses the studio's cached HF token.
Never prints or copies the token."""
import os, json, time, traceback
t0=time.time()
from huggingface_hub import snapshot_download, HfApi
import huggingface_hub, transformers, torch, numpy
print("imports ok in %.2fs | hub %s tf %s"%(time.time()-t0,huggingface_hub.__version__,
      transformers.__version__), flush=True)
api=HfApi()
try:
    who=api.whoami(); print("authenticated as:", who.get("name"), "| token role:",
        (who.get("auth") or {}).get("accessToken",{}).get("role"), flush=True)
except Exception as e:
    print("WARN whoami failed: %r"%e, flush=True)

W="/teamspace/studios/this_studio/laptopguard"; DEST=os.path.join(W,"weights")
COHORT=["meta-llama/Llama-Guard-3-1B","google/shieldgemma-2b",
        "google/gemma-3-4b-it","meta-llama/Llama-3.2-3B-Instruct",
        "google/gemma-3-1b-it","meta-llama/Llama-3.2-1B-Instruct"]
IGNORE=["*.bin","*.onnx","*.msgpack","*.h5","*.gguf","onnx/*","openvino/*","*.pth",
        "consolidated.safetensors","original/*"]
res=[]
for repo in COHORT:
    try:
        info=api.model_info(repo); rev=info.sha
        lic=(info.cardData or {}).get("license")
        params=(info.safetensors.total if info.safetensors else None)
        local=os.path.join(DEST, repo.replace("/","__"))
        p=snapshot_download(repo_id=repo, revision=rev, local_dir=local,
                            ignore_patterns=IGNORE, max_workers=8)
        n=sum(os.path.getsize(os.path.join(dp,f)) for dp,_,fs in os.walk(p) for f in fs)
        print("OK   %-38s rev=%s params=%s lic=%-10s %.2f GiB"%(
            repo,rev[:12],params,lic,n/2**30), flush=True)
        res.append(dict(repo=repo,revision=rev,licence=lic,params=params,path=p,
                        bytes=n,status="ok"))
    except Exception as e:
        print("FAIL %-38s %s"%(repo,e), flush=True); traceback.print_exc()
        res.append(dict(repo=repo,status="failed",error=str(e)))
open(os.path.join(W,"weights_manifest3.json"),"w").write(json.dumps(res,indent=2)+"\n")
print("DONE %d/%d ok, %.2f GiB"%(sum(1 for r in res if r["status"]=="ok"),len(res),
      sum(r.get("bytes",0) for r in res)/2**30))
