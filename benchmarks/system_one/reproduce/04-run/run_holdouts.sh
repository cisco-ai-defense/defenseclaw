#!/bin/bash
# Phase 0 holdout sweep on the 324-item Nimble/Jev validation set.
# GPU 3 only, bounded to an 18 GiB slice so the neighbouring Open-Jev servers on
# GPUs 0-3 keep their headroom. Eager attention everywhere (G2). Strictly serial.
set -u
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export CUDA_VISIBLE_DEVICES=3
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
PY=$WORK/sysone/venv/bin/python

run() {
  local tag="$1"; shift
  echo "=== $(date -Is) START $tag" >&2
  "$PY" holdout324.py "$@" >> "logs/holdout-$tag.log" 2>&1
  echo "=== $(date -Is) EXIT $? $tag" >&2
}

# E2B fits entirely on one card. This is both the zero-shot Gemma 4 E2B baseline and the
# faithful stand-in for larkooo/gemma-e2b-rlcd, whose shipped checkpoint is an unmodified
# MLX 4-bit conversion of exactly this revision (checkpoint_modified: false, no trained weights).
run e2b-base      --repo google/gemma-4-E2B-it --name gemma-4-e2b-it \
                  --out-dir out/holdout/e2b-base
run e2b-base-rev  --repo google/gemma-4-E2B-it --name gemma-4-e2b-it \
                  --permute reverse --out-dir out/holdout/e2b-base-reverse

# 26B-A4B needs ~52 GB. With one partly-free card the layer tail sits in host memory and
# is streamed per forward: correct, but roughly an order of magnitude slower.
run jevify        --repo kushalpatil/jevify-gemma4-26b-a4b --name jevify-gemma4-26b-a4b \
                  --device-map auto --max-gpu-memory 18GiB --out-dir out/holdout/jevify
run 26b-base      --repo google/gemma-4-26B-A4B-it --name gemma-4-26b-a4b-it \
                  --device-map auto --max-gpu-memory 18GiB --out-dir out/holdout/26b-base
run jevify-rev    --repo kushalpatil/jevify-gemma4-26b-a4b --name jevify-gemma4-26b-a4b \
                  --device-map auto --max-gpu-memory 18GiB --permute reverse \
                  --out-dir out/holdout/jevify-reverse
run 26b-base-rev  --repo google/gemma-4-26B-A4B-it --name gemma-4-26b-a4b-it \
                  --device-map auto --max-gpu-memory 18GiB --permute reverse \
                  --out-dir out/holdout/26b-base-reverse
echo "=== $(date -Is) ALL DONE" >&2
