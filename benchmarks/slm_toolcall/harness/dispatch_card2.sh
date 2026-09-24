#!/usr/bin/env bash
# At most MAXPAR concurrent arms, all on one card. Skips arms already complete (harness guard).
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
CARD="${CARD:-2}"; MAXPAR="${MAXPAR:-3}"
if [ "$CARD" = "3" ]; then echo "REFUSING: card 3 reserved"; exit 2; fi
export CUDA_VISIBLE_DEVICES="$CARD"
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false
ARMS="gemma-3-4b-it llama-3.2-3b-instruct gemma-3-1b-it llama-3.2-1b-instruct \
prompt-guard-2-86m olmo-2-1b-instruct shieldstral-1.0-3b falcon3-1b-instruct \
granite-4.0-1b smollm2-1.7b-instruct granite-guardian-3.2-3b-a800m shieldgemma-2b \
phi-4-mini-instruct smollm3-3b granite-guardian-3.1-2b granite-4.0-micro \
falcon3-3b-instruct llama-guard-3-1b"
for ARM in $ARMS; do
  while [ "$(pgrep -c -f 'score_arm.py --arm' || echo 0)" -ge "$MAXPAR" ]; do sleep 20; done
  echo "=== [card $CARD] START $ARM $(date -u +%H:%M:%S) ==="
  nohup setsid "$W/venv-laptop/bin/python" "$W/score_arm.py" \
    --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
    --device cuda --dtype bfloat16 --token-budget 49152 --max-batch 32 \
    >> "$W/logs/arm-$ARM.log" 2>&1 &
  sleep 25
done
while [ "$(pgrep -c -f 'score_arm.py --arm' || echo 0)" -gt 0 ]; do sleep 30; done
echo "=== [card $CARD] DISPATCHER COMPLETE $(date -u +%H:%M:%S) ==="
