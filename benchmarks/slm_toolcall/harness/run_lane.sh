#!/usr/bin/env bash
# One lane = a sequential list of arms, all pinned to card 0. Lanes run concurrently.
# Card 3 is NOT ours (reserved for the nimble reshard); card 0 only.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
export CUDA_VISIBLE_DEVICES=0
LANE="$1"; BUDGET="$2"; MAXB="$3"; shift 3
for ARM in "$@"; do
  echo "=== [lane $LANE] START $ARM $(date -u +%H:%M:%S) ==="
  "$W/venv-laptop/bin/python" "$W/score_arm.py" \
     --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
     --device cuda --dtype bfloat16 --token-budget "$BUDGET" --max-batch "$MAXB" \
     > "$W/logs/arm-$ARM.log" 2>&1
  echo "=== [lane $LANE] END $ARM rc=$? $(date -u +%H:%M:%S) ==="
done
echo "=== [lane $LANE] COMPLETE ==="
