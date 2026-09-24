#!/bin/bash
# Replacement for queue_q1_s2.sh, which lacked per-arm idempotency and gated BOTH
# Q1 halves on BOTH Q3 halves finishing. Q3 h1 finished first, leaving GPU 3 idle
# while h0 still had ~4,800 decisions to go. This runs each half as soon as ITS OWN
# predecessor closes out, and skips any arm already complete.
set -u
O=$WORK/.system-one-data/outputs/s2
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
CHAIN=$WORK/q1-chain.log
cd $WORK/defenseclaw-system-one || exit 1

H=$1; PORT=$2
if [ -f "$O/openjev-q1-$H.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) q1-$H already complete; skipping" >> "$CHAIN"; exit 0
fi
# Wait for this half's own Q3 predecessor only. Cap 8h.
for _ in $(seq 1 2880); do
  [ -f "$O/openjev-q3-$H.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$O/openjev-q3-$H.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: q3-$H did not close out in 8h" >> "$CHAIN"; exit 1
fi
echo "$(date -u +%FT%TZ) launching q1-$H on $PORT" >> "$CHAIN"
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
echo "$(date -u +%FT%TZ) q1-$H exit=$?" >> "$CHAIN"
