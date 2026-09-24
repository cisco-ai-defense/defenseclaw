#!/usr/bin/env bash
# Intent-ablation Q4 analysis with the hosted-Jev backend added alongside OpenJev and
# DiffusionGemma. The two Q2 --validate references must still reproduce their published
# tie-at-chance values, which is what proves adding the Jev backend did not perturb the
# shared pair set.
set -uo pipefail
REPO=$WORK/defenseclaw-system-one
D=$WORK/.system-one-data/outputs
A=$D/intent-ablation
PY=$WORK/.system-one-venv/bin/python
export PYTHONPATH="$REPO/benchmarks/scripts"

"$PY" "$REPO/benchmarks/scripts/score_q4_intent_ablation.py" \
  --cases "$A/cases.jsonl" \
  --backend "openjev C1/I3/Q4=$A/openjev-q4-C1.jsonl" \
  --backend "diffusiongemma C1/I3/Q4=$A/diffgemma-q4-C1.jsonl" \
  --backend "jev C1/I3/Q4=$A/jev-q4-C1.jsonl" \
  --validate "openjev-Q2=$A/openjev-C1.jsonl=0.910326" \
  --validate "diffgemma-Q2=$A/diffgemma-C1.jsonl=0.810501" \
  --out-json "$A/q4-ablation-analysis-with-jev.json" \
  --out-txt "$A/q4-ablation-analysis-with-jev.txt"
echo "exit=$?"
