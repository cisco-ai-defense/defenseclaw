#!/bin/bash
set -u
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export CUDA_VISIBLE_DEVICES=
export OMP_NUM_THREADS=16
PY=$WORK/sysone/venv/bin/python
$PY g2d_logits.py --repo google/gemma-4-26B-A4B-it --device cpu --attn eager --dtype float32 --out out/g2d-cpu-eager-fp32.json
$PY g2d_logits.py --repo google/gemma-4-26B-A4B-it --device cpu --attn sdpa  --dtype float32 --out out/g2d-cpu-sdpa-fp32.json
echo CPUREF_DONE
