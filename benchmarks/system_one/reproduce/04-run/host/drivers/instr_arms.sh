#!/usr/bin/env bash
# Label-corpus instruction-arm analysis with the hosted-Jev arms added alongside OpenJev.
# baseline/reference stay the OpenJev arms so the script's hard-coded published-number
# validation gate still has to reproduce; the Jev arms come in as extra treatments.
set -uo pipefail
REPO=$WORK/defenseclaw-system-one
D=$WORK/.system-one-data/outputs
T=$D/toolcall-labels
PY=$WORK/.system-one-venv/bin/python
export PYTHONPATH="$REPO/benchmarks/scripts"

"$PY" "$REPO/benchmarks/scripts/score_q4_instruction_arms.py" \
  --cases "$T/cases.jsonl" \
  --arm "C0/I3:C0:$T/openjev-q4-C0.jsonl" \
  --arm "C7/I3:C7:$T/openjev-q4-C7.jsonl" \
  --arm "C7/I2:C7:$T/openjev-q4-C7-I2.jsonl" \
  --arm "jev-C0/I3:C0:$T/jev-q4-C0.jsonl" \
  --arm "jev-C7/I3:C7:$T/jev-q4-C7.jsonl" \
  --arm "jev-C7/I2:C7:$T/jev-q4-C7-I2.jsonl" \
  --arm "jev-C7/I1:C7:$T/jev-q4-C7-I1.jsonl" \
  --optional-arm "C7/I1:C7:$T/openjev-q4-C7-I1.jsonl" \
  --baseline "C0/I3" \
  --reference "C7/I3" \
  --headline-arm "C7/I2" \
  --out-json "$T/q4-instruction-arms-with-jev.json" \
  --out-txt "$T/q4-instruction-arms-with-jev.txt"
echo "exit=$?"
