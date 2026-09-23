#!/bin/bash
# Serve a Gemma 4 26B-A4B checkpoint resident across N L40S, cache-free, eager.
# Usage: ./serve_g4_multi.sh <alias> <port> <cuda_devices> <temperature> [per_card_cap]
#   e.g. ./serve_g4_multi.sh jevify   8922 1,2,3 1.0 21GiB
#        ./serve_g4_multi.sh 26b-base 8921 0,1   5.15516951223468 22GiB
#
# Phase 0 gates enforced:
#  G2  --attention eager      optimised SDPA diverges from eager past the sliding window
#  G1  template digest asserted inside the shim against TEMPLATE_PINS
#      prefix cache OFF       measured 5/324 decision flips (1.54%) in bf16
# A per-card cap is given when the cards are shared with another agent's resident
# server, so accelerate never tries to claim memory that is already someone else's.
# Weight digests are not recomputed: already pinned in artifacts/out/holdout/*/results.json.
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
DEVICES="${3:?cuda devices e.g. 1,2,3}"
TEMP="${4:?temperature}"
CAP="${5:-}"

REV=$("$PY" -c "import json;print(json.load(open('$WORK/g4j/pins.json'))['$REPO'])")
CKPT="$HUB/models--${REPO//\//--}/snapshots/$REV"
[ -d "$CKPT" ] || { echo "missing checkpoint $CKPT" >&2; exit 3; }

export CUDA_VISIBLE_DEVICES="$DEVICES"
ARGS=(--checkpoint "$CKPT" --repo-id "$REPO" --revision "$REV" --name "$NAME"
      --attention eager --dtype bfloat16 --device-map auto
      --temperature "$TEMP" --max-input-tokens 8192 --no-prefix-cache
      --host 127.0.0.1 --port "$PORT")
[ -n "$CAP" ] && ARGS+=(--max-gpu-memory "$CAP")

echo "serving $REPO rev=$REV cuda[$DEVICES] port=$PORT T=$TEMP cap=${CAP:-none} eager no-prefix-cache"
exec "$PY" gemma4_jev_shim.py "${ARGS[@]}"
