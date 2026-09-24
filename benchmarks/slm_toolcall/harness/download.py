#!/usr/bin/env python3
"""Download the accessible cohort, pinned to verified revisions. Skips *.bin/onnx/h5 bloat."""
import os, sys, json, traceback
# Fail fast on imports, per the hydration hazard.
t0 = __import__("time").time()
from huggingface_hub import snapshot_download
import huggingface_hub, transformers, torch, numpy
print("imports ok in %.2fs | hub %s transformers %s torch %s" % (
    __import__("time").time()-t0, huggingface_hub.__version__,
    transformers.__version__, torch.__version__), flush=True)

W = "/teamspace/studios/this_studio/laptopguard"
DEST = os.path.join(W, "weights")
os.makedirs(DEST, exist_ok=True)

COHORT = [
    ("Qwen/Qwen3-0.6B",                               "c1899de289a04d12100db370d81485cdf75e47ca"),
    ("Qwen/Qwen3-1.7B",                               "70d244cc86ccca08cf5af4e1e306ecf908b1ad5e"),
    ("Qwen/Qwen3-4B",                                 "1cfa9a7208912126459214e8b04321603b3df60c"),
    ("ibm-granite/granite-guardian-3.1-2b",           "81145486e85c6c82c01e759c0356d9d6da4d21a5"),
    ("ibm-granite/granite-guardian-3.2-3b-a800m",     "3de033d89b499a18d9a573b5192bf3b967ef48c5"),
    ("microsoft/Phi-4-mini-instruct",                 "cfbefacb99257ffa30c83adab238a50856ac3083"),
    ("HuggingFaceTB/SmolLM2-1.7B-Instruct",           "31b70e2e869a7173562077fd711b654946d38674"),
    ("protectai/deberta-v3-base-prompt-injection-v2", "90c9989b1a342275dd0d1a95aad283c04e075671"),
]
IGNORE = ["*.bin", "*.onnx", "*.msgpack", "*.h5", "*.gguf", "onnx/*", "openvino/*", "*.pth"]

results = []
for repo, rev in COHORT:
    local = os.path.join(DEST, repo.replace("/", "__"))
    try:
        p = snapshot_download(repo_id=repo, revision=rev, local_dir=local,
                              ignore_patterns=IGNORE, max_workers=8)
        n = sum(os.path.getsize(os.path.join(dp, f))
                for dp, _, fs in os.walk(p) for f in fs)
        print("OK   %-48s rev=%s  %.2f GiB" % (repo, rev[:12], n/2**30), flush=True)
        results.append({"repo": repo, "revision": rev, "path": p, "bytes": n, "status": "ok"})
    except Exception as e:
        print("FAIL %-48s %s" % (repo, e), flush=True)
        traceback.print_exc()
        results.append({"repo": repo, "revision": rev, "status": "failed", "error": str(e)})

with open(os.path.join(W, "weights_manifest.json"), "w") as fh:
    json.dump(results, fh, indent=2)
ok = sum(1 for r in results if r["status"] == "ok")
print("DOWNLOAD DONE: %d/%d ok, total %.2f GiB" % (
    ok, len(results), sum(r.get("bytes", 0) for r in results)/2**30))
