#!/bin/bash
# Replicate the intent-real separation reversal on the other backends.
#
# WHY THIS IS THE TOP PRIORITY: on 405 grade-A proof-backed cases, OpenJev's
# separation REVERSED from the 8-of-8 negative (-0.1555..-0.3404) to
# block-only sep|res +0.2667 (C0) and +0.5750 (C7), every bootstrap interval
# excluding zero, and the within-family paired design (325 mcptox families
# holding BOTH a compromised and a resisted case) confirms +0.2462 / +0.5877,
# which kills the corpus-identity confound.
#
# BUT: the negative spanned FOUR backends and this reversal spans ONE. The
# scoring agent named replicating on diffgemma and gemma4 as the highest-value
# follow-up, and it is right -- a single-backend reversal is not enough to
# overturn a four-backend negative.
#
# DiffusionGemma needs --instruction-format string (confirmed from the S3 metas).
# Gemma 4 goes through bedrock-mantle via benchmark_run_gemma_judge.py and uses
# flex, which measured inside Gemma 4's own noise floor (38 same-tier vs 21
# cross-tier disagreements) and ran 2.9x faster.
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
CHAIN=$WORK/intent-real-replicate.log
cd $WORK/defenseclaw-system-one || exit 1

# --- DiffusionGemma on the restored 8011 shim (GPU 0, idle) ---
for CTX in C0 C7; do
  OUT="$I/diffgemma-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) diffgemma $CTX done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching diffgemma $CTX/I3/Q2 on 8011" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$I/cases.jsonl" \
    --context "$CTX" --instruction I3 --question Q2 \
    --endpoint "http://127.0.0.1:8011/v1/systemone" \
    --model diffusiongemma \
    --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
    --instruction-format string \
    --run-id "intent-real-diffgemma-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/intent-real-diffgemma-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) diffgemma $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) diffgemma arms finished" >> "$CHAIN"
