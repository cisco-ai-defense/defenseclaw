#!/bin/bash
cd /opt/dlami/nvme/kevbench
export HF_HOME=/opt/dlami/nvme/kevbench/hf
export CUDA_VISIBLE_DEVICES=0,2
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export KEV_PREFIX_CACHE=0
export KEV_DATE_FACTS=0
A=/opt/dlami/nvme/kevbench/hf/hub/models--jaredpalmer--kev-9b/snapshots/2629c06a5aeb0feb3b9783bafed17ed8f39ecf5c
exec ./venv/bin/python serve_kev.py \
  --kev-src /opt/dlami/nvme/kevbench/kev-src --adapter-path $A \
  --name kev-9b --repo-id jaredpalmer/kev-9b \
  --repo-revision 2629c06a5aeb0feb3b9783bafed17ed8f39ecf5c \
  --attn eager --max-memory-gib 11 --weights-budget-gib 7.7 --rows-per-forward 1 \
  --host 127.0.0.1 --port 8942 \
  --provenance-out /opt/dlami/nvme/kevbench/work/prov-kev.json
