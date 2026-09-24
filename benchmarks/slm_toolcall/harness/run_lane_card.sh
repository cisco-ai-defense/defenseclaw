#!/usr/bin/env bash
# Lane pinned to an explicit card, with the thread caps that address what broke the box.
# Card 3 is reserved for the nimble reshard and is refused outright.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
CARD="$1"; LANE="$2"; BUDGET="$3"; MAXB="$4"; shift 4
if [ "$CARD" = "3" ]; then echo "REFUSING: card 3 is reserved"; exit 2; fi
export CUDA_VISIBLE_DEVICES="$CARD"
# 19 arms at torch default 48 OMP threads + a Rayon pool sized to all 96 cores exhausted
# the box thread budget and it could no longer fork a login shell. These are GPU-bound.
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4
export TOKENIZERS_PARALLELISM=false
for ARM in "$@"; do
  echo "=== [lane $LANE card $CARD] START $ARM $(date -u +%H:%M:%S) ==="
  "$W/venv-laptop/bin/python" "$W/score_arm.py" \
     --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
     --device cuda --dtype bfloat16 --token-budget "$BUDGET" --max-batch "$MAXB" \
     >> "$W/logs/arm-$ARM.log" 2>&1
  echo "=== [lane $LANE card $CARD] END $ARM rc=$? $(date -u +%H:%M:%S) ==="
done
echo "=== [lane $LANE card $CARD] COMPLETE ==="
