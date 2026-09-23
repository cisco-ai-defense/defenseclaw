#!/bin/bash
# Queued after run_holdouts.sh: G2 GPU-vs-CPU adjudication, then Nimble-9B on the same 324.
set -u
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
PY=$WORK/sysone/venv/bin/python

# wait for the holdout chain to finish (max 4h)
for _ in $(seq 1 1440); do
  pgrep -f "[r]un_holdouts.sh" >/dev/null || break
  sleep 10
done
echo "=== $(date -Is) holdout chain clear" >&2

export CUDA_VISIBLE_DEVICES=3
echo "=== $(date -Is) g2d gpu eager" >&2
$PY g2d_logits.py --repo google/gemma-4-26B-A4B-it --device cuda --attn eager --dtype bfloat16 \
  --device-map auto --max-gpu-memory 18GiB --out out/g2d-gpu-eager-bf16.json >> logs/g2d-gpu.log 2>&1
echo "=== $(date -Is) g2d gpu sdpa exit=$?" >&2
$PY g2d_logits.py --repo google/gemma-4-26B-A4B-it --device cuda --attn sdpa --dtype bfloat16 \
  --device-map auto --max-gpu-memory 18GiB --out out/g2d-gpu-sdpa-bf16.json >> logs/g2d-gpu.log 2>&1
echo "=== $(date -Is) g2d done exit=$?" >&2

NIMBLE=/opt/dlami/nvme/hf/hub/models--bespokelabs--Bespoke-Nimble-9B/snapshots/93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c
echo "=== $(date -Is) nimble 324" >&2
$WORK/sysone/venv-ojev/bin/python nimble324.py --checkpoint "$NIMBLE" --device cuda:0 \
  --out-dir out/holdout/nimble-9b >> logs/nimble324.log 2>&1
echo "=== $(date -Is) nimble exit=$?" >&2
echo "=== $(date -Is) CHAIN2 DONE" >&2
