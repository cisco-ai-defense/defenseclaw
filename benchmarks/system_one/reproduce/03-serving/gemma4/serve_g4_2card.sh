#!/bin/bash
# Serve a Gemma 4 26B-A4B checkpoint resident across TWO L40S, cache-free, eager.
# Usage: ./serve_g4_2card.sh <alias> <port> <cuda_devices> <temperature>
#   e.g. ./serve_g4_2card.sh 26b-base 8921 1,3 5.15516951223468
#        ./serve_g4_2card.sh jevify   8922 0,2 1.0
#
# Phase 0 gates enforced here:
#  G2  --attention eager           (optimised SDPA diverges past the sliding window)
#  G1  template digest asserted inside the shim against TEMPLATE_PINS
#  prefix cache OFF               (--no-prefix-cache; measured 5/324 decision flips)
# Weight digests are NOT recomputed: they are already pinned in
# artifacts/out/holdout/*/results.json, and hashing 51.6 GB twice per load is waste.
set -eu
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
PY=$WORK/sysone/venv/bin/python
HUB=/opt/dlami/nvme/hf/hub

case "${1:?alias}" in
  jevify)   REPO=kushalpatil/jevify-gemma4-26b-a4b; NAME=jevify-gemma4-26b-a4b ;;
  26b-base) REPO=google/gemma-4-26B-A4B-it;         NAME=gemma-4-26b-a4b-it ;;
  *) echo "unknown alias $1" >&2; exit 2 ;;
esac
PORT="${2:?port}"
DEVICES="${3:?cuda devices e.g. 1,3}"
TEMP="${4:?temperature}"

REV=$("$PY" -c "import json;print(json.load(open($WORK/g4j/pins.json))[])")
CKPT="$HUB/models--${REPO//\//--}/snapshots/$REV"
[ -d "$CKPT" ] || { echo "missing checkpoint $CKPT" >&2; exit 3; }

export CUDA_VISIBLE_DEVICES="$DEVICES"
echo "serving $REPO rev=$REV on cuda[$DEVICES] port=$PORT T=$TEMP eager no-prefix-cache"
exec "$PY" gemma4_jev_shim.py \
  --checkpoint "$CKPT" --repo-id "$REPO" --revision "$REV" --name "$NAME" \
  --attention eager --dtype bfloat16 --device-map auto \
  --temperature "$TEMP" --max-input-tokens 8192 --no-prefix-cache \
  --host 127.0.0.1 --port "$PORT"
