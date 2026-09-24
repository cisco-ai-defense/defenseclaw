#!/bin/bash
# Queue the first-ever Q4 run, chained behind the Q1 S2 chain.
#
# Why Q4: it is the only question variant that splits intrinsic_danger from serves_intent -
# i.e. it is the two-lane hypothesis written as a question. It has never been run.
#
# Why this corpus: the 9,999 gpt-oss-120b tool-call labels are its natural evaluation set,
# because every row carries a labeller's INTRINSIC verdict to compare intrinsic_danger against
# plus a synthesized intent to feed serves_intent. Those labels are GRADE C (model-adjudicated,
# not human), so any result is agreement with a labeller, never accuracy against truth.
#
# Why two arms: C0 (current call only) is lane A as designed - stateless. C7 adds the
# synthesized intent. With one event per case the C0-vs-C7 contrast is intent-absent vs
# intent-present on identical calls, which is exactly the contrast the two-lane claim needs.
#
# Chain: waits for BOTH Q1 halves to close out. Q1 itself waits on the Q3 halves, so the
# wait cap here is 16h (Q3 up to 8h, then Q1) rather than the 8h used by queue_q1_s2.sh.
set -u
O=$WORK/.system-one-data/outputs/s2
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-chain.log
cd $WORK/defenseclaw-system-one || exit 1

echo "$(date -u +%FT%TZ) q4chain start; questions-v2 sha256=$(sha256sum $QCFG | cut -d' ' -f1)" >> "$CHAIN"
echo "$(date -u +%FT%TZ) cases sha256=$(sha256sum $L/cases.jsonl | cut -d' ' -f1)" >> "$CHAIN"

# Wait for BOTH Q1 halves to complete (meta.json is written only on completion).
for _ in $(seq 1 5760); do
  [ -f "$O/openjev-q1-h0.jsonl.meta.json" ] && [ -f "$O/openjev-q1-h1.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$O/openjev-q1-h0.jsonl.meta.json" ] || [ ! -f "$O/openjev-q1-h1.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: Q1 halves did not complete within 16h; not launching Q4" >> "$CHAIN"
  exit 1
fi
echo "$(date -u +%FT%TZ) Q1 halves complete; launching Q4 C0 and C7" >> "$CHAIN"

launch () {
  local CTX=$1 PORT=$2
  # Idempotent: if this arm already closed out, do not re-run it.
  if [ -f "$L/openjev-q4-$CTX.jsonl.meta.json" ]; then
    echo "$(date -u +%FT%TZ) q4-$CTX already complete; skipping" >> "$CHAIN"
    return 0
  fi
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$L/cases.jsonl" \
    --questions-config "$QCFG" \
    --context "$CTX" --instruction I3 --question Q4 \
    --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
    --model openjev --model-revision "$REV" \
    --instruction-format structured \
    --run-id "toolcall-labels-openjev-q4-$CTX" \
    --output "$L/openjev-q4-$CTX.jsonl" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/q4-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) q4-$CTX exit=$?" >> "$CHAIN"
}

launch C0 8767 &
launch C7 8768 &
wait
echo "$(date -u +%FT%TZ) Q4 label-corpus chain finished" >> "$CHAIN"
