#!/bin/bash
# Q4 on TerminalBench (8011 / GPU 0) - measures Lane B's false-positive rate on
# REAL benign coding-agent traffic.
#
# WHY THIS SPECIFIC RUN: the Lane B validation flagged one weak flank -
# serves_intent <= 0.5 fires on 40.3% of `clean` cases (OpenJev C7), so sep|clean
# (+0.5303) is far weaker than sep|res (+0.8696), and a deployed intent gate needs
# a clean-class calibration the resisted contrast hides. TerminalBench is 40 real
# coding-agent trajectories / 1,543 events, 100% benign, grade D, 38.6 events per
# trajectory - i.e. exactly the clean traffic a shipped intent gate would face, and
# the corpus that already showed curated benign lanes understate FPR by 5x.
#
# So this measures, on realistic traffic: what fraction of benign events would a
# serves_intent gate flag? That number bounds whether Lane B is deployable at all,
# independently of how well it separates attacks.
set -u
T=$WORK/.system-one-data/outputs/s1-n1000
PY=$WORK/.system-one-venv/bin/python
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-tb.log
cd $WORK/defenseclaw-system-one || exit 1
CASES="$T/terminalbench-context-cases.jsonl"
[ -f "$CASES" ] || { echo "$(date -u +%FT%TZ) ABORT: TB corpus not found at $CASES" >> "$CHAIN"; exit 1; }
ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8011/v1/systemone" && { echo "$(date -u +%FT%TZ) ABORT: 8011 busy" >> "$CHAIN"; exit 1; }

for CTX in C7 C1; do
  OUT="$WORK/.system-one-data/outputs/terminalbench/diffgemma-q4-$CTX.jsonl"
  mkdir -p "$(dirname "$OUT")"
  [ -f "$OUT.meta.json" ] && continue
  echo "$(date -u +%FT%TZ) launching TB diffgemma Q4 $CTX on 8011" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$CASES" --questions-config "$QCFG" \
    --context "$CTX" --instruction I3 --question Q4 \
    --endpoint "http://127.0.0.1:8011/v1/systemone" \
    --model diffusiongemma --model-revision diffusiongemma-26B-A4B-it-FP8-dynamic \
    --instruction-format string \
    --run-id "terminalbench-diffgemma-q4-$CTX" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 >> "$WORK/tb-dg-q4-$CTX.log" 2>&1
  echo "$(date -u +%FT%TZ) TB diffgemma q4 $CTX exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) TB Q4 arms finished" >> "$CHAIN"
