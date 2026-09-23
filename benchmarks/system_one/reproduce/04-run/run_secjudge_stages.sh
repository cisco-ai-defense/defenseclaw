#!/bin/bash
# SecJudge stage runner: inference -> merge -> emit prediction arms -> score with the SHARED scorer.
# Priority order is cheapest-and-most-informative first, so a time-out still leaves settled stages.
set -u

D=$WORK/.system-one-data/outputs
SJ=$D/secjudge
REPO=$WORK/defenseclaw-system-one
PYI=$WORK/.von-venv/bin/python           # torch + transformers
PYS=$WORK/.system-one-venv/bin/python    # jsonschema, runs the shared scorer
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py
SHARDS=${SHARDS:-4}
THREADS=${THREADS:-2}
TAG=$(date -u +%Y%m%dT%H%M%SZ)

export PYTHONPATH=$WORK/.secjudge-deps

infer_stage() {   # stage cases variants
  local stage=$1 cases=$2 variants=$3
  local key="${stage}-${variants//,/}"
  echo "### INFER $stage variants=$variants shards=$SHARDS threads=$THREADS start $(date -Is)"
  local pids=()
  for i in $(seq 0 $((SHARDS-1))); do
    $PYI $SJ/code/secjudge_infer.py --cases "$cases" --stage "$stage" --variants "$variants" \
        --out "$SJ/raw/$key.shard$i.jsonl" --shard $i --shards $SHARDS --threads $THREADS \
        > "$SJ/logs/infer-$key-$i.log" 2>&1 &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  echo "### INFER $stage rc=$rc $(date -Is)"
  return $rc
}

emit_and_score() {  # stage cases context detpath llmpath
  local stage=$1 cases=$2 ctx=$3 det=$4 llm=$5
  local key="${stage}-C0C7"
  [ -f "$SJ/raw/$key.shard0.jsonl" ] || key="${stage}-${ctx}"
  local raws=()
  for f in $SJ/raw/$key.shard*.jsonl; do raws+=(--raw "$f"); done
  echo "### EMIT $stage $ctx from ${#raws[@]} raw args"
  $PYI $SJ/code/secjudge_emit.py "${raws[@]}" --stage "$stage" --context "$ctx" \
       --outdir "$SJ/predictions" --run-tag "$TAG" > "$SJ/logs/emit-$stage-$ctx.log" 2>&1 || return 1

  local preds=()
  for f in $SJ/predictions/secjudge-$stage-$ctx-*.jsonl; do
    case "$f" in *.meta.json) continue;; esac
    preds+=(--system-one-predictions "$f")
  done
  local extra=()
  [ -n "$det" ] && extra+=(--deterministic-predictions "$det")
  [ -n "$llm" ] && extra+=(--llm-predictions "$llm")
  echo "### SCORE $stage $ctx  arms=$(( ${#preds[@]} / 2 ))"
  ( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PYS "$SCORER" \
      --cases "$cases" "${preds[@]}" \
      --prediction-schema "$REPO/benchmarks/schema/system-one-prediction-v1.schema.json" \
      "${extra[@]}" \
      --output "$SJ/scores/$stage-$ctx.json" \
      --culling-output "$SJ/scores/$stage-$ctx.culling.json" \
      --closure-output "$SJ/scores/$stage-$ctx.closure.json" \
      --max-candidates 8 --input-usd-per-million 0.042 ) \
      > "$SJ/logs/score-$stage-$ctx.log" 2>&1
  echo "### SCORE $stage $ctx rc=$? $(date -Is)"
}

# ---------------- 1. intent-real (both variants; the reversal test) ----------------
infer_stage intent-real "$D/intent-real/cases.jsonl" "C0,C7"
emit_and_score intent-real "$D/intent-real/cases.jsonl" C0 "" "$D/intent-real/gemma4-C0.jsonl"
emit_and_score intent-real "$D/intent-real/cases.jsonl" C7 "" "$D/intent-real/gemma4-C7.jsonl"
echo "MILESTONE intent-real done $(date -Is)"

# ---------------- 2. s2 C0 (low truncation control) ----------------
infer_stage s2 "$D/s2/cases.jsonl" "C0"
emit_and_score s2 "$D/s2/cases.jsonl" C0 "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
echo "MILESTONE s2-C0 done $(date -Is)"

# ---------------- 3. s2 C7 (parity context) ----------------
infer_stage s2 "$D/s2/cases.jsonl" "C7"
emit_and_score s2 "$D/s2/cases.jsonl" C7 "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
echo "MILESTONE s2-C7 done $(date -Is)"

# ---------------- 4. s3 C0 ----------------
infer_stage s3 "$D/s3/cases.jsonl" "C0"
emit_and_score s3 "$D/s3/cases.jsonl" C0 "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
echo "MILESTONE s3-C0 done $(date -Is)"

# ---------------- 5. toolcall-labels ----------------
infer_stage toolcall-labels "$D/toolcall-labels/cases.jsonl" "C0,C7"
emit_and_score toolcall-labels "$D/toolcall-labels/cases.jsonl" C7 "" ""
emit_and_score toolcall-labels "$D/toolcall-labels/cases.jsonl" C0 "" ""
echo "MILESTONE toolcall-labels done $(date -Is)"

# ---------------- 6. s3 C7 (longest; may not finish) ----------------
infer_stage s3 "$D/s3/cases.jsonl" "C7"
emit_and_score s3 "$D/s3/cases.jsonl" C7 "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
echo "MILESTONE s3-C7 done $(date -Is)"

echo "ALLSTAGESDONE $(date -Is)"
