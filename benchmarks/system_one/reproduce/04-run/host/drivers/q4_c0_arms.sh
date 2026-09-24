#!/bin/bash
# Q4 C0/I2 and C0/I1 on the label corpus, queued behind the intent-real Q4 arms (8765).
#
# WHY: the instruction-arms analysis showed the intent-softening is instruction-
# invariant (-0.094 to -0.107 across I3/I2/I1, 92% retained under the instruction
# that explicitly forbids it). But the ABSOLUTE I2/I1 attribution assumed the
# instruction main effect is additive across the intent-present and intent-absent
# subgroups. The scoring agent named exactly the run that drops that assumption:
# C0/I2/Q4 and C0/I1/Q4 give each instruction arm its OWN matched baseline instead
# of borrowing C0/I3's. Cheap, no new corpus, and it converts the load-bearing
# number from assumption-dependent to measured.
set -u
I=$WORK/.system-one-data/outputs/intent-real
L=$WORK/.system-one-data/outputs/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
REV=5ec9e5fd2f80a6fff386779b1e5ac7e389971889
QCFG=benchmarks/system_one/questions-v2.json
CHAIN=$WORK/q4-c0-arms.log
cd $WORK/defenseclaw-system-one || exit 1

# Wait for BOTH intent-real Q4 arms to release 8765. Cap 6h.
for _ in $(seq 1 2160); do
  [ -f "$I/openjev-q4-C7.jsonl.meta.json" ] && [ -f "$I/openjev-q4-C0.jsonl.meta.json" ] && break
  sleep 10
done
for _ in $(seq 1 60); do
  ps -eo args= | grep -E "^[^ ]*python[0-9.]* .*benchmark_run_system_one" | grep -q "127.0.0.1:8765/v1/systemone" && sleep 30 || break
done

for ARM in I2 I1; do
  OUT="$L/openjev-q4-C0-$ARM.jsonl"
  [ -f "$OUT.meta.json" ] && { echo "$(date -u +%FT%TZ) q4-C0-$ARM done; skip" >> "$CHAIN"; continue; }
  echo "$(date -u +%FT%TZ) launching Q4 C0/$ARM on 8765" >> "$CHAIN"
  "$PY" benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$L/cases.jsonl" --questions-config "$QCFG" \
    --context C0 --instruction "$ARM" --question Q4 \
    --endpoint "http://127.0.0.1:8765/v1/systemone" \
    --model openjev --model-revision "$REV" --instruction-format structured \
    --run-id "toolcall-labels-openjev-q4-C0-$ARM" --output "$OUT" \
    --concurrency 16 --timeout 300 --retries 2 \
    >> "$WORK/q4-C0-$ARM.log" 2>&1
  echo "$(date -u +%FT%TZ) q4-C0-$ARM exit=$?" >> "$CHAIN"
done
echo "$(date -u +%FT%TZ) q4 C0 instruction baselines finished" >> "$CHAIN"
