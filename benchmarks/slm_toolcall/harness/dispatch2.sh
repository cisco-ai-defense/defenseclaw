#!/usr/bin/env bash
# At most MAXPAR concurrent scoring arms on one card.
# Counts real python processes via /proc, NOT `pgrep -f`: a bare pattern also matches my own
# monitoring shells (their command lines contain the pattern), which inflates the count and
# stalls the dispatcher. This is the same self-match hazard that makes `pkill -f` dangerous.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
CARD="${CARD:-2}"; MAXPAR="${MAXPAR:-3}"
if [ "$CARD" = "3" ]; then echo "REFUSING: card 3 is reserved"; exit 2; fi
export CUDA_VISIBLE_DEVICES="$CARD"
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false

count_arms () {
  local n=0 p comm
  for p in /proc/[0-9]*; do
    [ -r "$p/comm" ] || continue
    comm=$(cat "$p/comm" 2>/dev/null)
    case "$comm" in python*|venv-laptop*) ;; *) continue ;; esac
    if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q 'score_arm\.py'; then n=$((n+1)); fi
  done
  echo "$n"
}

ARMS="gemma-3-4b-it llama-3.2-3b-instruct gemma-3-1b-it llama-3.2-1b-instruct \
prompt-guard-2-86m olmo-2-1b-instruct shieldstral-1.0-3b falcon3-1b-instruct \
granite-4.0-1b smollm2-1.7b-instruct granite-guardian-3.2-3b-a800m shieldgemma-2b \
phi-4-mini-instruct smollm3-3b granite-guardian-3.1-2b granite-4.0-micro \
falcon3-3b-instruct llama-guard-3-1b"

for ARM in $ARMS; do
  while [ "$(count_arms)" -ge "$MAXPAR" ]; do sleep 20; done
  echo "=== [card $CARD] START $ARM (running=$(count_arms)) $(date -u +%H:%M:%S) ==="
  nohup setsid "$W/venv-laptop/bin/python" "$W/score_arm.py" \
    --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
    --device cuda --dtype bfloat16 --token-budget 49152 --max-batch 32 \
    >> "$W/logs/arm-$ARM.log" 2>&1 &
  sleep 30
done
while [ "$(count_arms)" -gt 0 ]; do sleep 30; done
echo "=== [card $CARD] DISPATCHER COMPLETE $(date -u +%H:%M:%S) ==="
