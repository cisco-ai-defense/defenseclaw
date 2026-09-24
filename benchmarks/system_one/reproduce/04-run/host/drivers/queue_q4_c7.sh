#!/bin/bash
# Run Q4 C7 on shim 8765 as soon as the intent-ablation run releases it.
#
# Why promote this ahead of the q4chain (which waits on Q3 -> Q1, hours away):
# the Q4 C0 result made C7 the DECISIVE experiment. Under C0 the state carries no
# intent at all, yet serves_intent came back at r = -0.9623 to intrinsic_danger --
# an inverted harm score, not an intent judgement. All four Q4 answers collapsed onto
# one axis. So Lane B is untested, not unsupported. C7 supplies the intent the model
# was missing; if serves_intent decorrelates from intrinsic_danger under C7, Lane B is
# real. If it stays at r ~ -0.96, the two-lane architecture has no second axis.
set -u
A=$WORK/.system-one-data/outputs/intent-ablation
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4c7-chain.log
cd $WORK/defenseclaw-system-one || exit 1

# Wait for the ablation run on 8765 to close out. Cap 6h.
for _ in $(seq 1 2160); do
  [ -f "$A/openjev-C1.jsonl.meta.json" ] && break
  sleep 10
done

# Precise guard: a LIVE runner process (line begins with a python interpreter path)
# actually pointed at 8765. The loose pgrep grep used earlier matched script text.
for _ in $(seq 1 60); do
  if ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8765/v1/systemone"; then
    sleep 30
  else
    break
  fi
done
if ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8765/v1/systemone"; then
  echo "$(date -u +%FT%TZ) ABORT: 8765 still busy after 30m grace" >> "$CHAIN"
  exit 1
fi

if [ -f "$L/openjev-q4-C7.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) q4-C7 already complete; skipping" >> "$CHAIN"
  exit 0
fi
echo "$(date -u +%FT%TZ) launching Q4 C7 on 8765 (9,999 cases) - the decisive Lane B test" >> "$CHAIN"

"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$L/cases.jsonl" \
  --questions-config "$QCFG" \
  --context C7 --instruction I3 --question Q4 \
  --endpoint "http://127.0.0.1:8765/v1/systemone" \
  --model openjev --model-revision "$REV" \
  --instruction-format structured \
  --run-id "toolcall-labels-openjev-q4-C7" \
  --output "$L/openjev-q4-C7.jsonl" \
  --concurrency 16 --timeout 300 --retries 2 \
  >> $WORK/q4-C7.log 2>&1
echo "$(date -u +%FT%TZ) q4-C7 exit=$?" >> "$CHAIN"
