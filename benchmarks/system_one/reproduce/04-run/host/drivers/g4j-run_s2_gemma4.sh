#!/bin/bash
# s2 C7/I3/Q2 run for a Gemma 4 arm, on the dev host, against a tunnelled shim.
#
#   ./run_s2_gemma4.sh jevify-gemma4-26b-a4b 8911 s2-gemma4jev-jevify jevify
#
# Flags are the ones the ranked OpenJev row used (openjev-final.jsonl.plan.json):
# default contexts-v1/questions-v1 configs, --instruction-format structured,
# --context C7 --instruction I3 --question Q2, --timeout 300 --retries 2.
# Concurrency is 1 here because the shim serialises inference behind one lock and
# reuses the state prefix across a request's three questions.
set -eu
NAME="${1:?served model name}"
PORT="${2:?tunnelled port}"
RUN_ID="${3:?run id}"
TAG="${4:?output tag}"
O=$WORK/.system-one-data/outputs/s2
OUT=$WORK/.system-one-data/outputs/gemma4jev
PY=$WORK/.system-one-venv/bin/python
mkdir -p "$OUT"
cd $WORK/defenseclaw-system-one

curl -sf -m 10 "http://127.0.0.1:$PORT/v1/models" >/dev/null || { echo "shim not reachable on $PORT" >&2; exit 1; }

"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$O/cases.jsonl" \
  --context C7 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model "$NAME" --model-revision "$(curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null; echo "${REVISION:?set REVISION to the pinned hub revision}")" \
  --instruction-format structured \
  --run-id "$RUN_ID" \
  --output "$OUT/$TAG.jsonl" \
  --concurrency 1 --timeout 300 --retries 2 \
  >> "$OUT/$TAG.log" 2>&1
echo "runner exit=$?"
