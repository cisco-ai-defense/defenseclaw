#!/usr/bin/env bash
# Detached recorder: one compact status line every 120s into reshard/monitor.log,
# plus card-3 memory so an approaching OOM is visible in hindsight.
# pgrep here only COUNTS workers; nothing in this file kills anything.
set -uo pipefail
R=/teamspace/studios/this_studio/sysone
RS=$R/reshard
while true; do
  if [ -e "$RS/STOP_MONITOR" ]; then echo "monitor stopping"; exit 0; fi
  s0=$(wc -l < "$R/runs/nimble-s3/bespoke-nimble-9b-shard0.jsonl" 2>/dev/null || echo NA)
  crows=0
  for f in "$R"/runs/nimble-s3/bespoke-nimble-9b-shard[1-9]*.jsonl; do
    [ -e "$f" ] || continue
    n=$(wc -l < "$f" 2>/dev/null || echo 0)
    crows=$((crows + n))
  done
  nok=$(ls "$RS"/done/*.json 2>/dev/null | wc -l)
  claims=$(ls "$RS"/claims 2>/dev/null | wc -l)
  m3=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader -i 3 2>/dev/null)
  u3=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader -i 3 2>/dev/null)
  live=$(kill -0 92139 2>/dev/null && echo yes || echo no)
  nw=$(pgrep -fc "reshard/worker.sh" 2>/dev/null || echo 0)
  printf '%s s0=%s chunk_rows=%s done=%s claimed=%s card3=%s util=%s pid92139=%s workers=%s\n' \
    "$(date -u +%H:%M:%SZ)" "$s0" "$crows" "$nok" "$claims" "$m3" "$u3" "$live" "$nw"
  sleep 120
done
