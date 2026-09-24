#!/usr/bin/env bash
# ONE dispatcher for the whole cohort across all four cards.
# Why one and not four: four dispatchers each counting globally would collectively cap at
# MAXPAR rather than 4xMAXPAR, and four orchestrators racing the same output files is the
# duplicate-writer hazard. One owner, per-card placement, per-arm locks for safety.
#
# Counting walks /proc and matches comm+cmdline. `pgrep -f` is NOT usable here: a monitoring
# shell whose command line contains the pattern is counted too, which stalls the limiter.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
CARDS="${CARDS:-0 1 2 3}"; PERCARD="${PERCARD:-3}"
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false

# echo "<card> <count>" for every card, counting live score_arm processes by their pinning
card_counts () {
  local p comm cl card
  declare -A n
  for c in $CARDS; do n[$c]=0; done
  for p in /proc/[0-9]*; do
    [ -r "$p/comm" ] || continue
    comm=$(cat "$p/comm" 2>/dev/null); case "$comm" in python*) ;; *) continue ;; esac
    cl=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); case "$cl" in *score_arm.py*) ;; *) continue ;; esac
    card=$(tr '\0' '\n' < "$p/environ" 2>/dev/null | sed -n 's/^CUDA_VISIBLE_DEVICES=//p' | head -1)
    [ -n "${card:-}" ] || card=0
    [ -n "${n[$card]+x}" ] && n[$card]=$(( n[$card] + 1 ))
  done
  for c in $CARDS; do echo "$c ${n[$c]}"; done
}

# first card under PERCARD, else empty
pick_card () { card_counts | awk -v m="$PERCARD" '$2 < m {print $1; exit}'; }

# nearest-to-complete first, matching the prefetch order so weights are already warm
ARMS="llama-guard-3-1b shieldstral-1.0-3b olmo-2-1b-instruct prompt-guard-2-86m \
falcon3-1b-instruct granite-4.0-1b smollm2-1.7b-instruct shieldgemma-2b smollm3-3b \
phi-4-mini-instruct granite-guardian-3.2-3b-a800m llama-3.2-3b-instruct gemma-3-4b-it \
llama-3.2-1b-instruct gemma-3-1b-it granite-guardian-3.1-2b granite-4.0-micro \
falcon3-3b-instruct"

for ARM in $ARMS; do
  C=""
  while [ -z "$C" ]; do C=$(pick_card); [ -z "$C" ] && sleep 20; done
  echo "=== START $ARM on card $C  $(date -u +%H:%M:%S) ==="
  card_counts | while read -r c n; do printf "    card %s: %s running\n" "$c" "$n"; done
  CUDA_VISIBLE_DEVICES="$C" setsid nohup "$W/venv-laptop/bin/python" "$W/score_arm.py" \
    --arm "$ARM" --out "$W/preds/$ARM.jsonl" --run-id "lg-s2-$ARM" \
    --device cuda --dtype bfloat16 --token-budget 49152 --max-batch 32 \
    < /dev/null >> "$W/logs/arm-$ARM.log" 2>&1 &
  sleep 20
done
echo "=== all arms dispatched; waiting for completion $(date -u +%H:%M:%S) ==="
while [ "$(card_counts | awk '{s+=$2} END {print s+0}')" -gt 0 ]; do sleep 30; done
echo "=== DISPATCHER COMPLETE $(date -u +%H:%M:%S) ==="
