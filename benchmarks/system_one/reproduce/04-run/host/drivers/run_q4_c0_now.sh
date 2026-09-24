#!/bin/bash
# Fill the idle GPU 1 (vLLM :8000 via shim :8765) with the Q4 C0 arm NOW,
# instead of letting it sit idle until the q4chain's Q1 dependency clears.
# The q4chain is idempotent per arm (skips any arm whose meta.json exists),
# and this run will close out hours before that chain fires, so no duplicate.
set -u
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
cd $WORK/defenseclaw-system-one || exit 1

if [ -f "$L/openjev-q4-C0.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) q4-C0 already complete; nothing to do" >> $WORK/q4-chain.log
  exit 0
fi
echo "$(date -u +%FT%TZ) q4-C0 launched EARLY on idle GPU1 via shim 8765" >> $WORK/q4-chain.log

"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$L/cases.jsonl" \
  --questions-config "$QCFG" \
  --context C0 --instruction I3 --question Q4 \
  --endpoint "http://127.0.0.1:8765/v1/systemone" \
  --model openjev --model-revision "$REV" \
  --instruction-format structured \
  --run-id "toolcall-labels-openjev-q4-C0" \
  --output "$L/openjev-q4-C0.jsonl" \
  --concurrency 16 --timeout 300 --retries 2 \
  >> $WORK/q4-C0.log 2>&1
echo "$(date -u +%FT%TZ) q4-C0 (early) exit=$?" >> $WORK/q4-chain.log
