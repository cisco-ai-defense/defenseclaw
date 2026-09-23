#!/bin/bash
# SecJudge stage runner, revision 2.
# Change vs r1: 8 shards x 1 thread (much better than 3x2 for the short sequences that dominate
# these corpora), and the order is re-prioritised by value-per-token now that throughput is known:
#   s2 C0 -> s3 C0 -> s2 CMD diagnostic -> s2 C7 -> s3 C7
# s3 C7 is the most expensive stage by far (28.5M padded tokens) and is last on purpose, so a
# time-out leaves every cheaper stage settled rather than leaving everything half-done.
set -u

D=$WORK/.system-one-data/outputs
SJ=$D/secjudge
REPO=$WORK/defenseclaw-system-one
PYI=$WORK/.von-venv/bin/python
PYS=$WORK/.system-one-venv/bin/python
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py
SHARDS=${SHARDS:-8}
THREADS=${THREADS:-1}
TAG=$(date -u +%Y%m%dT%H%M%SZ)
export PYTHONPATH=$WORK/.secjudge-deps

infer() {   # key cases variants serialisation
  local key=$1 cases=$2 variants=$3 ser=${4:-production_text}
  echo "### INFER $key variants=$variants ser=$ser shards=$SHARDS threads=$THREADS start $(date -Is)"
  local pids=()
  for i in $(seq 0 $((SHARDS-1))); do
    $PYI $SJ/code/secjudge_infer.py --cases "$cases" --stage "$key" --variants "$variants" \
        --serialisation "$ser" \
        --out "$SJ/raw/$key.shard$i.jsonl" --shard $i --shards $SHARDS --threads $THREADS \
        > "$SJ/logs/infer-$key-$i.log" 2>&1 &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  echo "### INFER $key rc=$rc $(date -Is)"
  return $rc
}

emit_score() {  # key stage cases context armsuffix detpath llmpath
  local key=$1 stage=$2 cases=$3 ctx=$4 suffix=$5 det=$6 llm=$7
  local raws=()
  for f in $SJ/raw/$key.shard*.jsonl; do raws+=(--raw "$f"); done
  echo "### EMIT $key $ctx suffix=$suffix"
  $PYI $SJ/code/secjudge_emit.py "${raws[@]}" --stage "$stage$suffix" --context "$ctx" \
       --outdir "$SJ/predictions" --run-tag "$TAG" --arm-suffix "$suffix" \
       > "$SJ/logs/emit-$stage$suffix-$ctx.log" 2>&1 || return 1
  local preds=()
  for f in $SJ/predictions/secjudge-$stage$suffix-$ctx-*.jsonl; do
    case "$f" in *.meta.json) continue;; esac
    preds+=(--system-one-predictions "$f")
  done
  local extra=()
  [ -n "$det" ] && extra+=(--deterministic-predictions "$det")
  [ -n "$llm" ] && extra+=(--llm-predictions "$llm")
  echo "### SCORE $stage$suffix $ctx arms=$(( ${#preds[@]} / 2 ))"
  ( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PYS "$SCORER" \
      --cases "$cases" "${preds[@]}" \
      --prediction-schema "$REPO/benchmarks/schema/system-one-prediction-v1.schema.json" \
      "${extra[@]}" \
      --output "$SJ/scores/$stage$suffix-$ctx.json" \
      --culling-output "$SJ/scores/$stage$suffix-$ctx.culling.json" \
      --closure-output "$SJ/scores/$stage$suffix-$ctx.closure.json" \
      --max-candidates 8 --input-usd-per-million 0.042 ) \
      > "$SJ/logs/score-$stage$suffix-$ctx.log" 2>&1
  echo "### SCORE $stage$suffix $ctx rc=$? $(date -Is)"
}

# 1. s2 C0 -- low-truncation parity-content arm
infer s2-C0 "$D/s2/cases.jsonl" C0
emit_score s2-C0 s2 "$D/s2/cases.jsonl" C0 "" "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
echo "MILESTONE s2-C0 $(date -Is)"

# 2. s3 C0 -- production-weighted, 0.39% truncation
infer s3-C0 "$D/s3/cases.jsonl" C0
emit_score s3-C0 s3 "$D/s3/cases.jsonl" C0 "" "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
echo "MILESTONE s3-C0 $(date -Is)"

# 3. s2 bare-command serialisation -- SecJudge's best case (in-distribution input shape)
infer s2-CMD "$D/s2/cases.jsonl" C0 cmd
emit_score s2-CMD s2 "$D/s2/cases.jsonl" C0 "-cmd" "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
echo "MILESTONE s2-CMD $(date -Is)"

# 4. s3 bare-command serialisation
infer s3-CMD "$D/s3/cases.jsonl" C0 cmd
emit_score s3-CMD s3 "$D/s3/cases.jsonl" C0 "-cmd" "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
echo "MILESTONE s3-CMD $(date -Is)"

# 5. s2 C7 -- the exact parity context (41% truncation); expensive
infer s2-C7 "$D/s2/cases.jsonl" C7
emit_score s2-C7 s2 "$D/s2/cases.jsonl" C7 "" "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
echo "MILESTONE s2-C7 $(date -Is)"

# 6. toolcall-labels
infer toolcall-labels-C0C7 "$D/toolcall-labels/cases.jsonl" "C0,C7"
emit_score toolcall-labels-C0C7 toolcall-labels "$D/toolcall-labels/cases.jsonl" C7 "" "" ""
emit_score toolcall-labels-C0C7 toolcall-labels "$D/toolcall-labels/cases.jsonl" C0 "" "" ""
echo "MILESTONE toolcall-labels $(date -Is)"

# 7. s3 C7 -- 28.5M padded tokens, last on purpose
infer s3-C7 "$D/s3/cases.jsonl" C7
emit_score s3-C7 s3 "$D/s3/cases.jsonl" C7 "" "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
echo "MILESTONE s3-C7 $(date -Is)"

echo "ALLSTAGESDONE $(date -Is)"
