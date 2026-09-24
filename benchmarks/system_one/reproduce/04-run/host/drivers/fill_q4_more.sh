#!/bin/bash
# Fill both freed cards with the two runs that extend the Lane B test.
#
# (a) GPU 0 / 8011: DiffusionGemma Q4 on intent-real. The separation reversal only
#     became defensible once it replicated across three backends; the Lane B test on
#     intent-real deserves the same treatment before any conclusion is drawn.
# (b) GPU 3 / 8768: OpenJev Q4 on the intent-ABLATION corpus (18,322 cases). This is
#     the sharpest available test of serves_intent, because the swapped arm is an
#     intent that demonstrably does NOT describe the action. On the label corpus
#     serves_intent collapsed onto harm (r = -0.96) but that corpus cannot falsify
#     Lane B in principle -- every intent asks for the action taken. Here half the
#     rows are deliberate mismatches, so if the two heads are separate axes anywhere,
#     it is here.
set -u
I=$WORK/.system-one-data/outputs/intent-real
A=$WORK/.system-one-data/outputs/intent-ablation
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-more.log
cd $WORK/defenseclaw-system-one || exit 1

ARM=$1
if [ "$ARM" = "dg" ]; then
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8011/v1/systemone" && { echo "$(date -u +%FT%TZ) ABORT dg: 8011 busy" >> "$CHAIN"; exit 1; }
  for CTX in C7 C0; do
    OUT="$I/diffgemma-q4-$CTX.jsonl"
    [ -f "$OUT.meta.json" ] && continue
    echo "$(date -u +%FT%TZ) launching intent-real diffgemma Q4 $CTX on 8011" >> "$CHAIN"
    "$PY" benchmarks/scripts/benchmark_run_system_one.py \
      --cases "$I/cases.jsonl" --questions-config "$QCFG" \
      --context "$CTX" --instruction I3 --question Q4 \
      --endpoint "http://127.0.0.1:8011/v1/systemone" \
      --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
      --instruction-format string \
      --run-id "intent-real-diffgemma-q4-$CTX" --output "$OUT" \
      --concurrency 16 --timeout 300 --retries 2 >> "$WORK/ir-dg-q4-$CTX.log" 2>&1
    echo "$(date -u +%FT%TZ) intent-real diffgemma q4 $CTX exit=$?" >> "$CHAIN"
  done
fi
if [ "$ARM" = "abl" ]; then
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8768/v1/systemone" && { echo "$(date -u +%FT%TZ) ABORT abl: 8768 busy" >> "$CHAIN"; exit 1; }
  OUT="$A/openjev-q4-C1.jsonl"
  if [ ! -f "$OUT.meta.json" ]; then
    echo "$(date -u +%FT%TZ) launching ablation Q4 C1 on 8768 (18,322 cases)" >> "$CHAIN"
    "$PY" benchmarks/scripts/benchmark_run_system_one.py \
      --cases "$A/cases.jsonl" --questions-config "$QCFG" \
      --context C1 --instruction I3 --question Q4 \
      --endpoint "http://127.0.0.1:8768/v1/systemone" \
      --model openjev --model-revision "$REV" --instruction-format structured \
      --run-id "intent-ablation-openjev-q4-C1" --output "$OUT" \
      --concurrency 16 --timeout 300 --retries 2 >> $WORK/abl-q4-C1.log 2>&1
    echo "$(date -u +%FT%TZ) ablation q4 C1 exit=$?" >> "$CHAIN"
  fi
fi
