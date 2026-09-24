#!/bin/bash
# Queue the intent-ablation model run on shim 8765 (GPU 1), behind the early Q4 C0 arm.
#
# Why: the matched-vs-swapped ablation corpus is built (18,322 cases = 9,161 calls x 2 arms)
# but has never been run against a model. A trivial lexical baseline already separates the
# arms at 89.1% within-pair accuracy, because the labeller wrote each INTENT while looking
# at the call. So the ONLY interesting question is whether a System One model beats 0.891 --
# a model scoring below that is worse than string matching, which is itself a finding.
#
# Port choice: 8765 -> vLLM :8000 -> GPU 1. q1chain/q4chain/intentchain all use 8767/8768,
# so this cannot contend with them. Guarded anyway.
set -u
A=$WORK/.system-one-data/outputs/intent-ablation
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
CHAIN=$WORK/ablation-chain.log
cd $WORK/defenseclaw-system-one || exit 1

# Wait for the early Q4 C0 arm to release shim 8765. Cap at 6h.
for _ in $(seq 1 2160); do
  [ -f "$L/openjev-q4-C0.jsonl.meta.json" ] && break
  sleep 10
done
if [ ! -f "$L/openjev-q4-C0.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ABORT: q4-C0 did not close out within 6h; not launching ablation" >> "$CHAIN"
  exit 1
fi

# Read-only guard: never start if something else is already talking to 8765.
if pgrep -af benchmark_run_system_one | grep -q "127.0.0.1:8765"; then
  echo "$(date -u +%FT%TZ) ABORT: shim 8765 already in use; not launching ablation" >> "$CHAIN"
  exit 1
fi

if [ -f "$A/openjev-C1.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) ablation already complete; skipping" >> "$CHAIN"
  exit 0
fi
echo "$(date -u +%FT%TZ) launching intent-ablation C1/I3/Q2 on 8765 (18,322 cases)" >> "$CHAIN"

# C1 = intent + current call. That is the minimal context that can express the ablation:
# the swapped arm differs from the matched arm ONLY in payload.content, so any context
# carrying intent isolates the manipulated variable.
"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$A/cases.jsonl" \
  --context C1 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:8765/v1/systemone" \
  --model openjev --model-revision "$REV" \
  --instruction-format structured \
  --run-id "intent-ablation-openjev-C1" \
  --output "$A/openjev-C1.jsonl" \
  --concurrency 16 --timeout 300 --retries 2 \
  >> $WORK/ablation-C1.log 2>&1
echo "$(date -u +%FT%TZ) ablation C1 exit=$?" >> "$CHAIN"
