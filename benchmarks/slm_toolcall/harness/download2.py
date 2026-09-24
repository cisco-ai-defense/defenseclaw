#!/usr/bin/env python3
"""Download the revised cohort (post Qwen-drop). Resolves and records each repo sha."""
import os, json, traceback, time, urllib.request
t0=time.time()
from huggingface_hub import snapshot_download
import huggingface_hub, transformers, torch, numpy
print("imports ok in %.2fs | hub %s tf %s torch %s"%(time.time()-t0,
      huggingface_hub.__version__, transformers.__version__, torch.__version__), flush=True)

W="/teamspace/studios/this_studio/laptopguard"; DEST=os.path.join(W,"weights")
os.makedirs(DEST, exist_ok=True)

# (repo, pinned_sha or None -> resolve from API)
COHORT=[
 ("mistralai/Shieldstral-1.0-3B",              "003ec7e2b0bab5f0e6307edbaf186fa5822b76f5"),
 ("allenai/OLMo-2-0425-1B-Instruct",           "48d788eca847d4d7548f375ad03d3c9312f6139e"),
 ("tiiuae/Falcon3-1B-Instruct",                "28ba2251970a01dd1edc7ba7dad2eb71216ccfdf"),
 ("tiiuae/Falcon3-3B-Instruct",                "411bb94318f94f7a5735b77109f456b1e74b42a1"),
 ("HuggingFaceTB/SmolLM3-3B",                  "a07cc9a04f16550a088caea529712d1d335b0ac1"),
 ("ibm-granite/granite-4.0-1b",                None),
 ("ibm-granite/granite-4.0-micro",             None),
 ("answerdotai/ModernBERT-base",               "8949b909ec900327062f0ebf497f51aef5e6f0c8"),
 ("answerdotai/ModernBERT-large",              "45bb4654a4d5aaff24dd11d4781fa46d39bf8c13"),
]
# consolidated.safetensors is Mistral's duplicate of model.safetensors -- skip 7.7 GiB of it.
IGNORE=["*.bin","*.onnx","*.msgpack","*.h5","*.gguf","onnx/*","openvino/*","*.pth",
        "consolidated.safetensors"]

def resolve(rid):
    r=urllib.request.Request("https://huggingface.co/api/models/"+rid,
                             headers={"User-Agent":"curl/8"})
    return json.loads(urllib.request.urlopen(r,timeout=40).read())["sha"]

res=[]
for repo, rev in COHORT:
    try:
        if rev is None:
            rev = resolve(repo); print("   resolved %s -> %s"%(repo,rev), flush=True)
        local=os.path.join(DEST, repo.replace("/","__"))
        p=snapshot_download(repo_id=repo, revision=rev, local_dir=local,
                           ignore_patterns=IGNORE, max_workers=8)
        n=sum(os.path.getsize(os.path.join(dp,f)) for dp,_,fs in os.walk(p) for f in fs)
        print("OK   %-46s rev=%s %.2f GiB"%(repo,rev[:12],n/2**30), flush=True)
        res.append(dict(repo=repo,revision=rev,path=p,bytes=n,status="ok"))
    except Exception as e:
        print("FAIL %-46s %s"%(repo,e), flush=True); traceback.print_exc()
        res.append(dict(repo=repo,revision=rev,status="failed",error=str(e)))
with open(os.path.join(W,"weights_manifest2.json"),"w") as fh: json.dump(res,fh,indent=2)
print("DONE %d/%d ok, %.2f GiB"%(sum(1 for r in res if r["status"]=="ok"),len(res),
      sum(r.get("bytes",0) for r in res)/2**30))
