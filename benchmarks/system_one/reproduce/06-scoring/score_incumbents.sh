#!/bin/bash
# Score the incumbent models with the SAME shared scorer, same cases, same REAL deterministic
# tier and same LLM tier, into outputs/secjudge/scores/ so the SecJudge comparison is 1:1 and
# does not depend on any other agent's in-flight scorecards.
set -u
D=$WORK/.system-one-data/outputs
SJ=$D/secjudge
REPO=$WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py

score() {  # name cases pred schema det llm
  local name=$1 cases=$2 pred=$3 schema=$4 det=$5 llm=$6
  local extra=()
  [ -n "$det" ] && extra+=(--deterministic-predictions "$det")
  [ -n "$llm" ] && extra+=(--llm-predictions "$llm")
  echo "### $name"
  ( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PY "$SCORER" \
      --cases "$cases" --system-one-predictions "$pred" \
      --prediction-schema "$schema" "${extra[@]}" \
      --output "$SJ/scores/incumbent-$name.json" \
      --input-usd-per-million 0.042 ) 2>&1 | tail -2
  echo "### $name rc=$?"
}

SCH=$REPO/benchmarks/schema/system-one-prediction-v1.schema.json

# s2 -- real deterministic tier + Gemma 4 LLM tier
score s2-jev            $D/s2/cases.jsonl $D/s2/jev-C7.jsonl       $SCH $D/s2/deterministic.jsonl $D/s2/gemma4-c7.jsonl
score s2-openjev        $D/s2/cases.jsonl $D/s2/openjev-final.jsonl $SCH $D/s2/deterministic.jsonl $D/s2/gemma4-c7.jsonl
score s2-diffusiongemma $D/s2/cases.jsonl $D/s2/diffgemma-q2.jsonl  $SCH $D/s2/deterministic.jsonl $D/s2/gemma4-c7.jsonl

# s3
score s3-jev            $D/s3/cases.jsonl $D/s3/jev-C7.jsonl       $SCH $D/s3/deterministic.jsonl $D/s3/gemma4-c7.jsonl
score s3-openjev        $D/s3/cases.jsonl $D/s3/openjev-full.jsonl  $SCH $D/s3/deterministic.jsonl $D/s3/gemma4-c7.jsonl
score s3-diffusiongemma $D/s3/cases.jsonl $D/s3/diffgemma-q2.jsonl  $SCH $D/s3/deterministic.jsonl $D/s3/gemma4-c7.jsonl

# intent-real (no deterministic tier for this stage in the parity harness)
score intent-real-jev-C7       $D/intent-real/cases.jsonl $D/intent-real/jev-C7.jsonl       $SCH "" $D/intent-real/gemma4-C7.jsonl
score intent-real-openjev-C7   $D/intent-real/cases.jsonl $D/intent-real/openjev-C7.jsonl   $SCH "" $D/intent-real/gemma4-C7.jsonl
score intent-real-diffgemma-C7 $D/intent-real/cases.jsonl $D/intent-real/diffgemma-C7.jsonl $SCH "" $D/intent-real/gemma4-C7.jsonl
score intent-real-jev-C0       $D/intent-real/cases.jsonl $D/intent-real/jev-C0.jsonl       $SCH "" $D/intent-real/gemma4-C0.jsonl
score intent-real-openjev-C0   $D/intent-real/cases.jsonl $D/intent-real/openjev-C0.jsonl   $SCH "" $D/intent-real/gemma4-C0.jsonl
score intent-real-diffgemma-C0 $D/intent-real/cases.jsonl $D/intent-real/diffgemma-C0.jsonl $SCH "" $D/intent-real/gemma4-C0.jsonl

echo INCUMBENTSDONE
