#!/bin/bash
cd /opt/dlami/nvme/kevbench
export HF_HOME=/opt/dlami/nvme/kevbench/hf
export CUDA_VISIBLE_DEVICES=3
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
D=/opt/dlami/nvme/kevbench/hf/hub/models--Mapika--decider-2b/snapshots/fa996cea58e1c1d8d1ab4d7124154f303b017f95
exec ./venv/bin/python serve_decider.py \
  --model-path $D --name decider-2b \
  --repo-id Mapika/decider-2b --repo-revision fa996cea58e1c1d8d1ab4d7124154f303b017f95 \
  --attn eager --max-memory-gib 12 --max-rows-per-forward 1 \
  --host 127.0.0.1 --port 8941 \
  --provenance-out /opt/dlami/nvme/kevbench/work/prov-decider.json
