#!/bin/bash
# Replicate the matched-vs-swapped intent ablation on DiffusionGemma (8011 / GPU 0).
#
# WHY: the ablation positive (OpenJev within-pair accuracy 0.9103 vs a 0.891 lexical
# baseline, r = -0.1194 to overlap, and 0.8733 on the 1,748 pairs where the lexical
# baseline is WRONG) is currently ONE backend -- the same weakness the separation
# reversal had before it was replicated. If DiffusionGemma also beats 0.891 and also
# shows weak correlation to overlap, the intent signal is a property of the task
# rather than of OpenJev. If it fails, the positive is backend-specific and must be
# stated that way.
#
# Note DiffusionGemma needs --instruction-format string (confirmed from the S2/S3 metas)
# and is ~5x faster than OpenJev at p50, so 18,322 cases is tractable here.
set -u
A=$WORK/.system-one-data/outputs/intent-ablation
PY=$WORK/.system-one-venv/bin/python
CHAIN=$WORK/ablation-diffgemma.log
cd $WORK/defenseclaw-system-one || exit 1

if [ -f "$A/diffgemma-C1.jsonl.meta.json" ]; then
  echo "$(date -u +%FT%TZ) diffgemma ablation already complete" >> "$CHAIN"; exit 0
fi
# Precise live-runner guard on 8011.
if ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8011/v1/systemone"; then
  echo "$(date -u +%FT%TZ) ABORT: 8011 in use" >> "$CHAIN"; exit 1
fi
echo "$(date -u +%FT%TZ) launching diffgemma ablation C1/I3/Q2 on 8011 (18,322 cases)" >> "$CHAIN"
"$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$A/cases.jsonl" \
  --context C1 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:8011/v1/systemone" \
  --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
  --instruction-format string \
  --run-id "intent-ablation-diffgemma-C1" --output "$A/diffgemma-C1.jsonl" \
  --concurrency 16 --timeout 300 --retries 2 \
  >> $WORK/ablation-diffgemma-C1.log 2>&1
echo "$(date -u +%FT%TZ) diffgemma ablation exit=$?" >> "$CHAIN"
