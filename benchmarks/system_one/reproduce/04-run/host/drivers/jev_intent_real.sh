#!/bin/bash
# Hosted Jev arms of the intent-real separation stage.
#
# WHY: Jev is the ONE backend not re-run on the separation reversal, and
# "three of four backends" is the last named limitation on that headline result.
# Jev also produced the ORIGINAL negative (AgentDojo C0 -0.1826, C7 -0.2282),
# so it is the most direct possible test: same model, same scorer, same seed,
# different corpus. If Jev reverses too, the corpus explanation is complete.
#
# No GPU. Prior Jev spend was $0.098 for 2,705 requests, so ~$0.15/arm here.
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
CHAIN=$WORK/jev-intent-real.log
set -a; . $WORK/.config/defenseclaw/system-one.env; set +a
cd $WORK/defenseclaw-system-one || exit 1
for CTX in C7 C0; do
  OUT="$I/jev-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) jev $CTX done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching intent-real jev $CTX/I3/Q2" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$I/cases.jsonl" \
    --context "$CTX" --instruction I3 --question Q2 \
    --endpoint "https://api.typesafe.ai/v1/systemone" \
    --model jev-1.13.0 --model-revision jev-1.13.0 \
    --instruction-format structured \
    --run-id "intent-real-jev-$CTX" --output "$OUT" \
    --concurrency 8 --timeout 120 --retries 2 \
    >> "$WORK/intent-real-jev-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) intent-real jev $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) jev intent-real arms finished" >> "$CHAIN"
