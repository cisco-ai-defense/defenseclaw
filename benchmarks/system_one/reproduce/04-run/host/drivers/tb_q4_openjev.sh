#!/bin/bash
# OpenJev counterpart to the TerminalBench Q4 arms, queued behind the ablation Q4
# run on 8768. Gives the Lane B false-positive measurement on real benign coding
# traffic a second backend, which is the standard this project has settled on:
# every claim that survived here survived because it replicated across backends.
set -u
A=$WORK/.system-one-data/outputs/intent-ablation
T=$WORK/.system-one-data/outputs/s1-n1000
O=$WORK/.system-one-data/outputs/terminalbench
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-tb.log
cd $WORK/defenseclaw-system-one || exit 1
mkdir -p "$O"

for _ in $(seq 1 2160); do
  [ -f "$A/openjev-q4-C1.jsonl.meta.json" ] && break
  sleep 10
done
for _ in $(seq 1 60); do
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8768/v1/systemone" && sleep 30 || break
done
for CTX in C7 C1; do
  OUT="$O/openjev-q4-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && continue
  echo "$(date -u +%FT%TZ) launching TB openjev Q4 $CTX on 8768" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$T/terminalbench-context-cases.jsonl" --questions-config "$QCFG" \
    --context "$CTX" --instruction I3 --question Q4 \
    --endpoint "http://127.0.0.1:8768/v1/systemone" \
    --model openjev --model-revision "$REV" --instruction-format structured \
    --run-id "terminalbench-openjev-q4-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 >> "$WORK/tb-oj-q4-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) TB openjev q4 $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) TB openjev Q4 arms finished" >> "$CHAIN"
