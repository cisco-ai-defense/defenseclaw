#!/bin/bash
# Wait for the four s2 runners to finish, then settle/score/publish.
#
# Runs detached on the dev host so the pipeline completes on its own. It only proceeds
# when all four runners have exited AND all four shard files together hold the full
# 30,310 rows; a short count means a runner died and the run needs resuming, which is a
# decision for a human rather than something to paper over, so it reports and stops.
set -uo pipefail
S=$WORK/.system-one-data/outputs/openjev-qwen/s2/shards
NAME=open-jev-qwen-27b
EXPECT=30310

while :; do
  alive=$(pgrep -fc "benchmark_run_system_one.py.*${NAME}-shard" || true)
  total=0
  for i in 0 1 2 3; do
    n=$(wc -l < "$S/${NAME}-shard${i}.jsonl" 2>/dev/null || echo 0)
    total=$((total + n))
  done
  echo "$(date -u +%H:%M:%S) alive=${alive:-0} rows=$total/$EXPECT"
  if [ "${alive:-0}" -eq 0 ]; then
    echo "all runners exited with rows=$total"
    break
  fi
  sleep 120
done

if [ "$total" -ne "$EXPECT" ]; then
  echo "INCOMPLETE: $total of $EXPECT rows. Not scoring. Per-shard counts:"
  for i in 0 1 2 3; do
    printf '  shard%d: %s rows\n' "$i" "$(wc -l < "$S/${NAME}-shard${i}.jsonl" 2>/dev/null || echo 0)"
    tail -3 "$S/${NAME}-shard${i}.log" 2>/dev/null | sed 's/^/     /'
  done
  exit 1
fi

echo "=== all $EXPECT rows present; running finish_27b.sh ==="
bash $WORK/j27/finish_27b.sh
