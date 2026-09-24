#!/bin/bash
# Q4 C7 under instruction I2, queued behind intent-real C7 on 8765.
#
# WHY: the Q4 C7 run showed that on unsafe rows, supplying a harm-describing intent
# moves disposition_ordinal by -0.1023 -- TOWARD allow. The harm-describing intent
# partially EXCUSES the action, and that cost Lane A its zero-false-block property
# (block recall 0.6307 -> 0.5899, first false block appeared).
#
# I2 is the long-policy instruction whose text explicitly states that user intent
# cannot excuse harm. If the -0.1023 softening disappears under I2, this is an
# INSTRUCTION failure that is trivially fixable, not a question-design failure.
# That distinction decides whether Q4 is salvageable.
#
# I2 is also the highest-precision / lowest-recall instruction at S1
# (C0/I2/Q0: FPR 0.01429, the joint-lowest, at recall 0.54545), so expect a
# precision-for-recall trade on top of whatever the intent effect is.
set -u
I=$WORK/.system-one-data/outputs/intent-real
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-i2.log
cd $WORK/defenseclaw-system-one || exit 1

# Wait for intent-real C7 to release 8765. Cap 6h.
for _ in $(seq 1 2160); do
  [ -f "$I/openjev-C7.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$I/openjev-C7.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: intent-real C7 did not close out in 6h" >> "$CHAIN"; exit 1
fi
# Precise live-runner guard on 8765 (a loose pgrep grep matched script text earlier today).
for _ in $(seq 1 60); do
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8765/v1/systemone" && sleep 30 || break
done

for ARM in I2 I1; do
  OUT="$L/openjev-q4-C7-$ARM.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) q4-C7-$ARM done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching Q4 C7/$ARM on 8765" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$L/cases.jsonl" --questions-config "$QCFG" \
    --context C7 --instruction "$ARM" --question Q4 \
    --endpoint "http://127.0.0.1:8765/v1/systemone" \
    --model openjev --model-revision "$REV" --instruction-format structured \
    --run-id "toolcall-labels-openjev-q4-C7-$ARM" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/q4-C7-$ARM.log" 2>&1
  echo "$(date -u +%FT%TZ) q4-C7-$ARM exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) q4 instruction arms finished" >> "$CHAIN"
