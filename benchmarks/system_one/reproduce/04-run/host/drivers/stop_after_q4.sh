#!/usr/bin/env bash
# Stop driver 5 the moment s2 Q4 lands, so no filler arm runs.
# Removes any partial output the kill leaves behind for the NEXT arm only; never touches
# s2/jev-q0-C7 or s2/jev-q4-C7.
set -uo pipefail
LOG=$WORK/.system-one-data/outputs/jev-drive5.log
D=$WORK/.system-one-data/outputs

for i in $(seq 1 6000); do
  if grep -q "DONE s2/jev-q4-C7" "$LOG" 2>/dev/null; then
    echo "s2 Q4 landed; stopping driver 5"
    screen -S jevd5 -X quit 2>/dev/null
    pkill -f "drive_jev5.py" 2>/dev/null
    sleep 3
    pkill -f "benchmark_run_system_one.py.*intent-real-jev-q" 2>/dev/null
    pkill -f "benchmark_run_system_one.py.*intent-ablation-jev-q" 2>/dev/null
    sleep 2
    # clean up only the filler arms we did not want
    for f in "$D"/intent-real/jev-q0-C7 "$D"/intent-real/jev-q1-C7 "$D"/intent-real/jev-q3-C7 \
             "$D"/intent-ablation/jev-q0-C1 "$D"/intent-ablation/jev-q1-C1 \
             "$D"/intent-ablation/jev-q3-C1; do
      for ext in .jsonl .jsonl.meta.json .jsonl.plan.json .log; do
        if [ -e "${f}${ext}" ]; then echo "removing unwanted filler artifact ${f}${ext}"; rm -f "${f}${ext}"; fi
      done
    done
    echo "STOPPED cleanly after s2 Q4"
    exit 0
  fi
  if grep -qE "STOPPED at|PASS 5 ALL DONE" "$LOG" 2>/dev/null; then
    echo "driver 5 ended on its own"; exit 0
  fi
  sleep 5
done
echo "watcher timed out"
