#!/bin/bash
set -u
I=$WORK/.system-one-data/outputs/intent-real
A=$WORK/.system-one-data/outputs/intent-ablation
PY=$WORK/.system-one-venv/bin/python
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-more.log
cd $WORK/defenseclaw-system-one || exit 1
ARM=$1

# (a) Gemma 4 Q4 on intent-real via bedrock-mantle (no GPU). Completes the
#     three-backend Lane B test the same way the separation reversal was made
#     defensible. Q4 has a disposition head (unlike Q3) so the judge path works.
if [ "$ARM" = "g4" ]; then
  for CTX in C7 C0; do
    OUT="$I/gemma4-q4-$CTX.jsonl"
    [ -f "$OUT.meta.json" ] && continue
    echo "$(date -u +%FT%TZ) launching intent-real gemma4 Q4 $CTX (flex)" >> "$CHAIN"
    "$PY" benchmarks/scripts/benchmark_run_gemma_judge.py \
      --cases "$I/cases.jsonl" --questions-config "$QCFG" \
      --context "$CTX" --instruction I3 --question Q4 \
      --model google.gemma-4-26b-a4b --service-tier flex \
      --run-id "intent-real-gemma4-q4-$CTX" --output "$OUT" \
      --concurrency 16 --timeout 300 --retries 2 >> "$WORK/ir-g4-q4-$CTX.log" 2>&1
    echo "$(date -u +%FT%TZ) intent-real gemma4 q4 $CTX exit=$?" >> "$CHAIN"
  done
fi

# (b) DiffusionGemma Q4 on the ablation corpus (8011 / GPU 0), mirroring the
#     OpenJev arm already running on 8768. Half the rows are deliberate
#     intent/action mismatches, so this is the sharpest serves_intent test, and
#     having it on two backends is what made every other claim here defensible.
if [ "$ARM" = "abldg" ]; then
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8011/v1/systemone" && { echo "$(date -u +%FT%TZ) ABORT abldg: 8011 busy" >> "$CHAIN"; exit 1; }
  OUT="$A/diffgemma-q4-C1.jsonl"
  if [ ! -f "$OUT.meta.json" ]; then
    echo "$(date -u +%FT%TZ) launching ablation diffgemma Q4 C1 on 8011" >> "$CHAIN"
    "$PY" benchmarks/scripts/benchmark_run_system_one.py \
      --cases "$A/cases.jsonl" --questions-config "$QCFG" \
      --context C1 --instruction I3 --question Q4 \
      --endpoint "http://127.0.0.1:8011/v1/systemone" \
      --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
      --instruction-format string \
      --run-id "intent-ablation-diffgemma-q4-C1" --output "$OUT" \
      --concurrency 16 --timeout 300 --retries 2 >> $WORK/abl-dg-q4-C1.log 2>&1
    echo "$(date -u +%FT%TZ) ablation diffgemma q4 exit=$?" >> "$CHAIN"
  fi
fi
