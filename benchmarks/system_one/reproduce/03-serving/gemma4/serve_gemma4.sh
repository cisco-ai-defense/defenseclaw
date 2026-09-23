#!/bin/bash
# Serve a Gemma 4 checkpoint on /v1/systemone for the System One benchmark runner.
#
#   ./serve_gemma4.sh jevify 8911              # two free cards, no offload (preferred)
#   ./serve_gemma4.sh jevify 8911 offload      # one partly-free card + host memory (slow)
#   ./serve_gemma4.sh 26b-base 8912
#   ./serve_gemma4.sh e2b 8913
#
# eager attention is not optional: G2 showed no SDPA path on Gemma 4 reproduces eager
# once a prompt crosses the sliding window (26B-A4B, 18/18 window-crossing prompts,
# up to 1.1e-2 label-probability difference against a bit-identical repeat floor).
set -eu
cd $WORK/g4j
export HF_HOME=/opt/dlami/nvme/hf
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
PY=$WORK/sysone/venv/bin/python
HUB=/opt/dlami/nvme/hf/hub

case "${1:?model alias required}" in
  jevify)   REPO=kushalpatil/jevify-gemma4-26b-a4b; NAME=jevify-gemma4-26b-a4b ;;
  26b-base) REPO=google/gemma-4-26B-A4B-it;         NAME=gemma-4-26b-a4b-it ;;
  e2b)      REPO=google/gemma-4-E2B-it;             NAME=gemma-4-e2b-it ;;
  *) echo "unknown alias $1" >&2; exit 2 ;;
esac
PORT="${2:?port required}"
MODE="${3:-resident}"
REV=$("$PY" -c "import json;print(json.load(open('$WORK/g4j/pins.json'))['$REPO'])")
CKPT="$HUB/models--${REPO//\//--}/snapshots/$REV"

ARGS=(--checkpoint "$CKPT" --repo-id "$REPO" --revision "$REV" --name "$NAME"
      --attention eager --temperature 1.0 --max-input-tokens 8192 --weight-digests
      --host 127.0.0.1 --port "$PORT")
if [ "$MODE" = offload ]; then
  ARGS+=(--device-map auto --max-gpu-memory "${MAX_GPU_MEMORY:-18GiB}")
fi

exec "$PY" gemma4_jev_shim.py "${ARGS[@]}"
