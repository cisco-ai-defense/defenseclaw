#!/bin/bash
set -u
O=$WORK/.system-one-data/outputs
PY=$WORK/.system-one-venv/bin/python
CASES=$O/s1-n1000/screen-cases.jsonl
cd $WORK/defenseclaw-system-one || exit 1
for n in 1 2 3; do
  t0=$(date +%s)
  echo "### START r$n $(date -u +%FT%TZ)"
  $PY benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$CASES" \
    --context C7 --instruction I3 --question Q2 \
    --endpoint http://127.0.0.1:8011/v1/systemone \
    --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
    --instruction-format string \
    --run-id "repeat-diffgemma-r$n" \
    --output "$O/repeat/diffgemma-r$n.jsonl" \
    --concurrency 16 --timeout 300 --retries 2
  rc=$?
  t1=$(date +%s)
  echo "### END r$n rc=$rc elapsed_s=$((t1-t0))"
  echo "diffgemma r$n rc=$rc elapsed_s=$((t1-t0))" >> "$O/repeat/timing.txt"
done
echo "### DRIVER DONE diffgemma"
