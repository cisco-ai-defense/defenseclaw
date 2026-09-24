#!/bin/bash
set -u
O=$WORK/.system-one-data/outputs
PY=$WORK/.system-one-venv/bin/python
CASES=$O/s1-n1000/screen-cases.jsonl
cd $WORK/defenseclaw-system-one || exit 1
for tier in default flex; do
  t0=$(date +%s)
  echo "### START $tier $(date -u +%FT%TZ)"
  $PY benchmarks/scripts/benchmark_run_gemma_judge.py \
    --cases "$CASES" \
    --context C7 --instruction I3 --question Q0 \
    --service-tier "$tier" \
    --run-id "flex-gemma4-$tier" \
    --output "$O/flex/gemma4-$tier.jsonl" \
    --concurrency 16
  rc=$?
  t1=$(date +%s)
  echo "### END $tier rc=$rc elapsed_s=$((t1-t0))"
  echo "gemma4 $tier rc=$rc elapsed_s=$((t1-t0))" >> "$O/flex/timing.txt"
done
echo "### DRIVER DONE flex"
