#!/bin/bash
# Q4 on DiffusionGemma (8011 / GPU 0), C0 and C7.
#
# WHY: Q4's four answers collapsed onto ONE axis on OpenJev -- r(serves_intent,
# intrinsic_danger) = -0.9623 at C0 and -0.9221 at C7, with serves_intent read
# inverted being the single best harm gate. That was called a question-design
# problem. But the separation reversal just showed that a conclusion replicated
# eight times across four backends was a property of the CORPUS, not the models.
# So before concluding Q4's design is at fault, check whether the collapse is
# even backend-general. If DiffusionGemma's Q4 answers decorrelate, the collapse
# is OpenJev-specific and Q4 is salvageable by backend choice alone.
set -u
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-diffgemma.log
cd $WORK/defenseclaw-system-one || exit 1

if ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8011/v1/systemone"; then
  echo "$(date -u +%FT%TZ) ABORT: 8011 in use" >> "$CHAIN"; exit 1
fi
for CTX in C0 C7; do
  OUT="$L/diffgemma-q4-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) diffgemma q4 $CTX done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching diffgemma Q4 $CTX/I3 on 8011" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$L/cases.jsonl" --questions-config "$QCFG" \
    --context "$CTX" --instruction I3 --question Q4 \
    --endpoint "http://127.0.0.1:8011/v1/systemone" \
    --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
    --instruction-format string \
    --run-id "toolcall-labels-diffgemma-q4-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/q4-diffgemma-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) diffgemma q4 $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) diffgemma Q4 arms finished" >> "$CHAIN"
