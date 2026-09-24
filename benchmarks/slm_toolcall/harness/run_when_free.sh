#!/usr/bin/env bash
# Start each arm on CARD only once that card has MINFREE MiB free, so we never
# saturate a card another agent is sharing. Card 3 is reserved and refused outright.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
CARD="$1"; MINFREE="$2"; LANE="$3"; shift 3
if [ "$CARD" = "3" ]; then echo "REFUSING: card 3 is reserved"; exit 2; fi
export CUDA_VISIBLE_DEVICES="$CARD"
for ARM in "$@"; do
  while true; do
    USED=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits -i "$CARD")
    TOT=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits -i "$CARD")
    FREE=$(( TOT - USED ))
    if [ "$FREE" -ge "$MINFREE" ]; then break; fi
    echo "[lane $LANE card $CARD] waiting for $MINFREE MiB free (now $FREE) $(date -u +%H:%M:%S)"
    sleep 120
  done
  echo "=== [lane $LANE card $CARD] START $ARM free=${FREE}MiB $(date -u +%H:%M:%S) ==="
  "$W/venv-laptop/bin/python" "$W/score_arm.py" \
     --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
     --device cuda --dtype bfloat16 --token-budget 49152 --max-batch 32 \
     > "$W/logs/arm-$ARM.log" 2>&1
  echo "=== [lane $LANE card $CARD] END $ARM rc=$? $(date -u +%H:%M:%S) ==="
done
echo "=== [lane $LANE card $CARD] COMPLETE ==="
