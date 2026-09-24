#!/usr/bin/env python3
import os, json, time, traceback
from huggingface_hub import snapshot_download, HfApi
import transformers, torch, numpy
print("imports ok", flush=True)
api=HfApi(); W="/teamspace/studios/this_studio/laptopguard"; DEST=os.path.join(W,"weights")
IGNORE=["*.bin","*.onnx","*.msgpack","*.h5","*.gguf","onnx/*","openvino/*","*.pth","original/*"]
res=[]
for repo in ["meta-llama/Llama-Prompt-Guard-2-86M","meta-llama/Llama-Prompt-Guard-2-22M"]:
    try:
        info=api.model_info(repo); rev=info.sha
        lic=(info.cardData or {}).get("license")
        params=(info.safetensors.total if info.safetensors else None)
        p=snapshot_download(repo_id=repo, revision=rev,
                            local_dir=os.path.join(DEST,repo.replace("/","__")),
                            ignore_patterns=IGNORE, max_workers=8)
        n=sum(os.path.getsize(os.path.join(dp,f)) for dp,_,fs in os.walk(p) for f in fs)
        cfg=json.load(open(os.path.join(p,"config.json")))
        print("OK   %-40s rev=%s params=%s lic=%s arch=%s id2label=%s %.3f GiB"%(
            repo,rev[:12],params,lic,cfg.get("architectures"),cfg.get("id2label"),n/2**30), flush=True)
        res.append(dict(repo=repo,revision=rev,licence=lic,params=params,path=p,bytes=n,
                        architectures=cfg.get("architectures"),id2label=cfg.get("id2label"),
                        max_pos=cfg.get("max_position_embeddings"),status="ok"))
    except Exception as e:
        print("FAIL %-40s %s"%(repo,e),flush=True); traceback.print_exc()
        res.append(dict(repo=repo,status="failed",error=str(e)))
open(os.path.join(W,"weights_manifest4.json"),"w").write(json.dumps(res,indent=2)+"\n")
print("DONE")
