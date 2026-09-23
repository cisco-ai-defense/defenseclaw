#!/bin/bash
# Drive all three s2 phases back to back with no idle GPU time between them.
# Each phase: wait for the 4 shard runners to exit -> settle+merge+score -> swap the
# 4 replicas to the next model -> launch its 4 shards.
set -uo pipefail
O=$WORK/.system-one-data/outputs
GPU="ssh -i <SSH_KEY> -o StrictHostKeyChecking=no ubuntu@<GPU_HOST>"
LOG=$O/openjev-qwen/drive.log

say() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

wait_for_shards() { # name
  local name=$1
  while pgrep -f "run-id s2-${name}-shard" > /dev/null; do sleep 30; done
  say "all shard runners exited for $name"
}

phase() { # name revision outdir
  local name=$1 rev=$2 outdir=$3
  local started=$(date +%s)
  say "PHASE $name: swapping replicas"
  $GPU "bash $WORK/sysone/phase.sh $name" 2>&1 | tee -a "$LOG"
  bash $WORK/sysone-tunnel.sh 2>&1 | tee -a "$LOG"
  say "PHASE $name: launching 4 shards"
  bash $WORK/sysone-run_s2.sh "$name" "$rev" "$outdir" 2>&1 | tee -a "$LOG"
  sleep 60
  wait_for_shards "$name"
  local elapsed=$(( $(date +%s) - started ))
  say "PHASE $name: wall seconds=$elapsed (gpu seconds=$((elapsed*4)))"
  say "PHASE $name: scoring"
  bash $WORK/sysone-score_s2.sh "$name" "$outdir" 2>&1 | tee -a "$LOG"
  $WORK/.system-one-venv/bin/python $WORK/sysone-capture_provenance.py \
    --name "$name" --out "$outdir/$name.serving.json" --gpu-seconds "$((elapsed*4))" 2>&1 | tee -a "$LOG"
  say "PHASE $name: done"
}

# Phase 1 (open-jev-qwen-9b) is already running; just wait, score, then continue.
say "DRIVER start"
wait_for_shards open-jev-qwen-9b
say "PHASE open-jev-qwen-9b: scoring"
bash $WORK/sysone-score_s2.sh open-jev-qwen-9b "$O/openjev-qwen/s2" 2>&1 | tee -a "$LOG"

phase bespoke-nimble-9b 93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c "$O/nimble/s2"
phase open-jev-qwen-2b  3076462e6356412082e79af909227b39b2863b90def79155ca0821aa506b7ded "$O/openjev-qwen/s2"

say "DRIVER complete; stopping replicas to stop burning GPU"
$GPU "bash $WORK/sysone/phase.sh stop" 2>&1 | tee -a "$LOG"
say "ALL DONE"
