#!/bin/bash
# Usage: run_load.sh <SHIM_PORT> <LABEL> <CASES_FILE>
# Production workload shape: C7 / I3 / Q2 / structured, concurrency 16.
SHIM_PORT="$1"; LABEL="$2"; CASES="$3"
OUT=$WORK/prefix-unit-test
mkdir -p "$OUT"
cd $WORK/defenseclaw-system-one || exit 1
rm -f "$OUT/$LABEL.jsonl" "$OUT/$LABEL.jsonl.meta.json" "$OUT/$LABEL.jsonl.plan.json"
T0=$(date +%s.%N)
$WORK/.system-one-venv/bin/python benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$CASES" \
  --context C7 --instruction I3 --question Q2 \
  --instruction-format structured \
  --endpoint "http://127.0.0.1:${SHIM_PORT}/v1/systemone" \
  --model openjev \
  --model-revision 5ec9e5fd2f80a6fff386779b1e5ac7e389971889 \
  --run-id "$LABEL" \
  --output "$OUT/$LABEL.jsonl" \
  --concurrency 16 --timeout 300 --retries 2 \
  > "$OUT/$LABEL.log" 2>&1
RC=$?
T1=$(date +%s.%N)
echo "LABEL=$LABEL RC=$RC WALL_SECONDS=$(echo "$T1 - $T0" | bc)"
echo "rows=$(wc -l < "$OUT/$LABEL.jsonl" 2>/dev/null || echo 0)"
tail -3 "$OUT/$LABEL.log"
