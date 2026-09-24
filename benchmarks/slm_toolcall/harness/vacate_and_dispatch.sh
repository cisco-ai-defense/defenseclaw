#!/usr/bin/env bash
# Vacate cards 0 and 1 (now the coordinator's), keep card 2, and switch to a dispatcher
# that holds at most 3 concurrent arms on card 2. No pkill: exact PIDs only.
set -uo pipefail
W=/teamspace/studios/this_studio/laptopguard
cd "$W"

echo "=== 1. stop my 9 lane shells by exact PID (so they do not advance to a next arm) ==="
for pid in $(pgrep -f "run_lane_card.sh [012] R[1-9] "); do
  cmd=$(tr "\0" " " < /proc/$pid/cmdline 2>/dev/null)
  case "$cmd" in
    *run_lane_card.sh*) echo "  kill shell $pid : $(echo $cmd | cut -c1-70)"; kill "$pid" 2>/dev/null ;;
  esac
done
sleep 3

echo "=== 2. stop only the score_arm pythons pinned to card 0 or card 1 ==="
for pid in $(pgrep -f "score_arm.py --arm"); do
  [ -r /proc/$pid/environ ] || continue
  card=$(tr "\0" "\n" < /proc/$pid/environ 2>/dev/null | sed -n "s/^CUDA_VISIBLE_DEVICES=//p" | head -1)
  arm=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | grep -A1 -x -- "--arm" | tail -1)
  if [ "$card" = "0" ] || [ "$card" = "1" ]; then
    echo "  kill pid=$pid card=$card arm=$arm (vacating; partial body + resume keeps its rows)"
    kill "$pid" 2>/dev/null
  else
    echo "  KEEP pid=$pid card=$card arm=$arm"
  fi
done
sleep 5
echo "  remaining score_arm procs: $(pgrep -c -f 'score_arm.py --arm' || true)"
# clear locks left by the processes we just stopped, so the dispatcher can reclaim those arms
find preds -name "*.lock" -mmin +0 -print -delete 2>/dev/null | sed "s/^/  cleared lock /"
