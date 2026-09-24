#!/bin/bash
# Gemma 4 arms of the intent-real replication, via bedrock-mantle. No GPU.
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
CHAIN=$WORK/intent-real-replicate.log
cd $WORK/defenseclaw-system-one || exit 1
for CTX in C0 C7; do
  OUT="$I/gemma4-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) gemma4 $CTX done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching gemma4 $CTX/I3/Q0 (flex)" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_gemma_judge.py \
    --cases "$I/cases.jsonl" \
    --context "$CTX" --instruction I3 --question Q0 \
    --model google.gemma-4-26b-a4b --service-tier flex \
    --run-id "intent-real-gemma4-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/intent-real-gemma4-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) gemma4 $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) gemma4 arms finished" >> "$CHAIN"
