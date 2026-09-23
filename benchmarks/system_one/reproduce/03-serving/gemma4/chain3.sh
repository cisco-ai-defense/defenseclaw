#!/bin/bash
set -u
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export CUDA_VISIBLE_DEVICES=3
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
PY=$WORK/sysone/venv/bin/python
for _ in $(seq 1 1440); do
  pgrep -f "[c]hain2.sh" >/dev/null || break
  sleep 10
done
echo "=== $(date -Is) chain2 clear; jevify cache-free 324" >&2
$PY holdout324.py --repo kushalpatil/jevify-gemma4-26b-a4b --name jevify-gemma4-26b-a4b   --device-map auto --max-gpu-memory 18GiB --no-prefix-cache   --out-dir out/holdout/jevify-nocache >> logs/holdout-jevify-nocache.log 2>&1
echo "=== $(date -Is) exit=$? CHAIN3 DONE" >&2
