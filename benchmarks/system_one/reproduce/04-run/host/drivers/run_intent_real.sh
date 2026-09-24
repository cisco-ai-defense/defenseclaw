#!/bin/bash
# Run the intent-real stage (grade-A rebuild of the intent lane) on 8765 / GPU 1.
# The intentchain logged a launch at 08:16:58 but no runner survived, so this drives
# both arms directly, sequentially, on the one genuinely idle shim.
#
# Why this stage matters: the 8-of-8 negative separation result rests entirely on
# AgentDojo -- 651 cases, 194 compromised, all grade B, zero grade A, synthetic
# slack/banking/travel tool APIs rather than shell. This stage has 1,049 compromised
# cases of which 405 are grade-A proof-backed, drawn from mcptox (real emitted MCP
# calls with per-model outcomes), injecagent and agenttrace. C0-vs-C7 is the contrast.
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
CHAIN=$WORK/intent-real.log
cd $WORK/defenseclaw-system-one || exit 1

run_arm () {
  local CTX=$1
  if [ -f "$I/openjev-$CTX.jsonl.meta.json" ]; then
    echo "$(date -u +%FT%TZ) intent-real $CTX already complete; skipping" >> "$CHAIN"; return 0
  fi
  echo "$(date -u +%FT%TZ) launching intent-real $CTX/I3/Q2 on 8765" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$I/cases.jsonl" \
    --context "$CTX" --instruction I3 --question Q2 \
    --endpoint "http://127.0.0.1:8765/v1/systemone" \
    --model openjev --model-revision "$REV" \
    --instruction-format structured \
    --run-id "intent-real-openjev-$CTX" \
    --output "$I/openjev-$CTX.jsonl" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/intent-real-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) intent-real $CTX exit=$?" >> "$CHAIN"
}

run_arm C0
run_arm C7
echo "$(date -u +%FT%TZ) intent-real both arms finished" >> "$CHAIN"
