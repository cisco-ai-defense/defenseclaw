#!/bin/bash
set -euo pipefail
export HF_HOME=/opt/dlami/nvme/hf
PY=$WORK/sysone/venv/bin/python
CK=/opt/dlami/nvme/checkpoints
mkdir -p "$CK" "$HF_HOME" $WORK/sysone/logs

"$PY" - <<PY
import os, time
from huggingface_hub import snapshot_download
CK = "$CK"
jobs = [
    ("Qwen/Qwen3.5-9B", "c202236235762e1c871ad0ccb60c8ee5ba337b9a", None),
    ("Qwen/Qwen3.5-2B", "15852e8c16360a2fea060d615a32b45270f8a8fc", None),
    ("ZefanCai/Open-Jev-9B", None, CK + "/open-jev-9b"),
    ("ZefanCai/Open-Jev-2B", None, CK + "/open-jev-2b"),
    ("bespokelabs/Bespoke-Nimble-9B", None, CK + "/nimble-9b"),
]
for repo, rev, local in jobs:
    t = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] {repo} rev={rev} -> {local or 'HF cache'}", flush=True)
    p = snapshot_download(repo_id=repo, revision=rev, local_dir=local, max_workers=16)
    print(f"    done in {time.time()-t:.0f}s at {p}", flush=True)
PY

echo "=== DONE ==="
df -h /opt/dlami/nvme / | tail -2
du -sh "$HF_HOME" "$CK"

echo "=== verify published digests ==="
cd "$CK"
sha256sum open-jev-9b/package/checkpoint/adapter/adapter_model.safetensors \
          open-jev-9b/package/checkpoint/head.pt \
          open-jev-2b/package/checkpoint/adapter/adapter_model.safetensors \
          nimble-9b/adapter_model.safetensors \
          nimble-9b/parallel_schema.py
