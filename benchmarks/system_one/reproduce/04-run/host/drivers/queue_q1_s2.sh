#!/bin/bash
# Queue Q1 at S2 scale behind the running Q3 halves.
#
# Why: S1 found Q1 (eight decomposed atomic Nouls) was OpenJev's BEST config
# (per-event benign FPR 0.07653, F1 0.97778) while being unusable on hosted Jev
# (0.93367) and DiffusionGemma (0.99490). It was dropped from later stages on a
# 200-case read. S2 already proved one 200-case conclusion wrong (the cascade was
# NOT strictly dominant), so Q1 deserves a real 4,277-family measurement before
# Q2 is locked in as the recommended question.
set -u
O=$WORK/.system-one-data/outputs/s2
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
cd $WORK/defenseclaw-system-one || exit 1

# Wait for BOTH Q3 halves to close out (meta.json is written only on completion).
# Cap the wait at 8h so this never becomes an orphan poller.
for _ in $(seq 1 2880); do
  [ -f "$O/openjev-q3-h0.jsonl.meta.json" ] && [ -f "$O/openjev-q3-h1.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$O/openjev-q3-h0.jsonl.meta.json" ] || [ ! -f "$O/openjev-q3-h1.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: Q3 halves did not complete within 8h; not launching Q1" >> $WORK/q1-chain.log
  exit 1
fi
echo "$(date -u +%FT%TZ) Q3 halves complete; launching Q1" >> $WORK/q1-chain.log

launch () {
  local H=$1 PORT=$2
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$O/cases.$H.jsonl" \
    --context C7 --instruction I3 --question Q1 \
    --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
    --model openjev --model-revision "$REV" \
    --instruction-format structured \
    --run-id "s2-openjev-q1-$H" \
    --output "$O/openjev-q1-$H.jsonl" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/q1-$H.log" 2>&1
  echo "$(date -u +%FT%TZ) q1-$H exit=$?" >> $WORK/q1-chain.log
}

launch h0 8767 &
launch h1 8768 &
wait
echo "$(date -u +%FT%TZ) Q1 S2 chain finished" >> $WORK/q1-chain.log
