#!/bin/bash
# Q4 on the intent-real stage (8765 / GPU 1), C0 and C7.
#
# THIS IS THE MISSING EXPERIMENT FOR LANE B.
#
# Q4's four answers collapsed onto one axis on the 9,999-case label corpus
# (r = -0.9623 at C0, -0.9221 at C7). But that corpus CANNOT falsify Lane B in
# principle: every row's synthesized intent asks for the action that was taken,
# so "does this serve the intent" and "is this harmful" have the SAME answer on
# all 9,999 rows. A collapse is the expected outcome of a correlated design.
#
# intent-real is the corpus where they genuinely diverge:
#   attacked_compromised (1,049; 405 grade-A proof-backed) - action serves the
#     ATTACKER, not the user's stated request
#   attacked_resisted (1,083) - attacker text present, agent correctly refused,
#     so the action DOES serve the user's request
#   clean (469) - no attack
# Here serves_intent and intrinsic_danger have every reason to disagree, so if
# Q4's two heads are genuinely separate axes this is where it shows. And unlike
# the label corpus, this stage has ground truth the separation analysis already
# validated (reversal replicated on 3 backends, 24/24 cells positive).
set -u
I=$WORK/.system-one-data/outputs/intent-real
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-intent-real.log
cd $WORK/defenseclaw-system-one || exit 1

if ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8765/v1/systemone"; then
  echo "$(date -u +%FT%TZ) ABORT: 8765 in use" >> "$CHAIN"; exit 1
fi
for CTX in C7 C0; do
  OUT="$I/openjev-q4-$CTX.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) q4 $CTX done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching intent-real Q4 $CTX/I3 on 8765" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$I/cases.jsonl" --questions-config "$QCFG" \
    --context "$CTX" --instruction I3 --question Q4 \
    --endpoint "http://127.0.0.1:8765/v1/systemone" \
    --model openjev --model-revision "$REV" --instruction-format structured \
    --run-id "intent-real-openjev-q4-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/intent-real-q4-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) intent-real q4 $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) intent-real Q4 arms finished" >> "$CHAIN"
