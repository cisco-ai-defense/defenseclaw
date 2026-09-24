#!/bin/bash
set -u
O=$WORK/.system-one-data/outputs
PY=$WORK/.system-one-venv/bin/python
CASES=$O/s1-n1000/screen-cases.jsonl
cd $WORK/defenseclaw-system-one || exit 1
set +x
. $WORK/.config/defenseclaw/system-one.env
for n in 1 2 3; do
  t0=$(date +%s)
  echo "### START r$n $(date -u +%FT%TZ)"
  $PY benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$CASES" \
    --context C7 --instruction I3 --question Q2 \
    --endpoint https://api.typesafe.ai/v1/systemone \
    --model jev-1.13.0 --model-revision jev-1.13.0 \
    --instruction-format structured \
    --run-id "repeat-jev-r$n" \
    --output "$O/repeat/jev-r$n.jsonl" \
    --concurrency 16 --timeout 300 --retries 2 \
    --input-usd-per-million 0.042 --max-usd 1
  rc=$?
  t1=$(date +%s)
  echo "### END r$n rc=$rc elapsed_s=$((t1-t0))"
  echo "jev r$n rc=$rc elapsed_s=$((t1-t0))" >> "$O/repeat/timing.txt"
done
echo "### DRIVER DONE jev"
