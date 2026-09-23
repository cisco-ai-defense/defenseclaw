#!/bin/bash
# SecJudge stage runner, revision 4.
#
# Priority order set by the methodological constraint that matters most: every incumbent arm ran at
# C7, so `s2 C7` is the only apples-to-apples cell for the head-to-head and it goes first.
#   wait for in-flight s2-CMD -> s2 C7 -> toolcall-labels (contaminated lane) -> s3 C0 -> s3 C7
#
# Parallelism: SHARDS=12 THREADS=1. Memory, not cores, is the binding constraint: each shard holds
# its own fp32 model copy at ~4.0 GB RSS, so 12 shards is ~48 GB peak against ~38 GB MemAvailable
# plus page cache -- 12 is the approved ceiling while the Jev arms are still running.
#
# dtype is fp32 and stays fp32. bf16 (1.97x) flipped is_attack on 6.25% of a sample; int8 dynamic
# (1.83x) moved the calibrated score by a median of 0.151 and changed 2/400 dispositions. Neither is
# admissible when the comparison models are full precision. See int8-equivalence.json.
set -u

D=$WORK/.system-one-data/outputs
SJ=$D/secjudge
REPO=$WORK/defenseclaw-system-one
PYI=$WORK/.von-venv/bin/python
PYS=$WORK/.system-one-venv/bin/python
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py
SHARDS=${SHARDS:-12}
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
  echo "### EMIT $key $ctx suffix=$suffix from $(( ${#raws[@]} / 2 )) shards"
  $PYI $SJ/code/secjudge_emit.py "${raws[@]}" --stage "$stage$suffix" --context "$ctx" \
       --outdir "$SJ/predictions" --run-tag "$TAG" --arm-suffix "$suffix" \
       > "$SJ/logs/emit-$stage$suffix-$ctx.log" 2>&1 || { echo "### EMIT FAILED $stage$suffix $ctx"; return 1; }
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

recall() {  # stage cases ctx rawglob out
  local stage=$1 cases=$2 ctx=$3 key=$4 out=$5
  local raw
  raw=$(ls $SJ/raw/$key.shard*.jsonl | tr '\n' ',' | sed 's/,$//')
  echo "### RECALL@FPR $stage $ctx"
  ( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PYS $SJ/code/recall_at_fpr.py \
      --cases "$cases" --stage "$stage" --raw-context "$ctx" \
      --arm secjudge-sev=$SJ/predictions/secjudge-$stage-$ctx-sev.jsonl \
      --raw-arm secjudge="$raw" --out "$out" ) > "$SJ/logs/recall-$stage-$ctx.log" 2>&1
  echo "### RECALL@FPR $stage $ctx rc=$? $(date -Is)"
}

# ---- 0. wait for the in-flight 8-shard s2-CMD run, then settle it ----
echo "### WAIT for in-flight s2-CMD shards $(date -Is)"
while pgrep -f "secjudge_infer.py .*--stage s2-CMD" > /dev/null; do sleep 20; done
echo "### s2-CMD shards finished $(date -Is)"
emit_score s2-CMD s2 "$D/s2/cases.jsonl" C0 "-cmd" "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
recall s2-cmd "$D/s2/cases.jsonl" C0 s2-CMD "$SJ/scores/recall-at-fpr-s2-secjudge-cmd-C0.json"
echo "MILESTONE s2-CMD $(date -Is)"

# ---- 1. s2 C7 -- THE apples-to-apples cell against every incumbent ----
infer s2-C7 "$D/s2/cases.jsonl" C7
emit_score s2-C7 s2 "$D/s2/cases.jsonl" C7 "" "$D/s2/deterministic.jsonl" "$D/s2/gemma4-c7.jsonl"
recall s2 "$D/s2/cases.jsonl" C7 s2-C7 "$SJ/scores/recall-at-fpr-s2-secjudge-C7.json"
echo "MILESTONE s2-C7 $(date -Is)"

# ---- 2. toolcall-labels -- CONTAMINATED LANE, labelled as such everywhere ----
infer toolcall-labels-C0C7 "$D/toolcall-labels/cases.jsonl" "C0,C7"
emit_score toolcall-labels-C0C7 toolcall-labels "$D/toolcall-labels/cases.jsonl" C7 "" "" ""
emit_score toolcall-labels-C0C7 toolcall-labels "$D/toolcall-labels/cases.jsonl" C0 "" "" ""
echo "MILESTONE toolcall-labels-CONTAMINATED $(date -Is)"

# ---- 3. s3 C0 ----
infer s3-C0 "$D/s3/cases.jsonl" C0
emit_score s3-C0 s3 "$D/s3/cases.jsonl" C0 "" "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
recall s3 "$D/s3/cases.jsonl" C0 s3-C0 "$SJ/scores/recall-at-fpr-s3-secjudge-C0.json"
echo "MILESTONE s3-C0 $(date -Is)"

# ---- 4. s3 C7 -- 28.5M padded tokens, the single most expensive stage ----
infer s3-C7 "$D/s3/cases.jsonl" C7
emit_score s3-C7 s3 "$D/s3/cases.jsonl" C7 "" "$D/s3/deterministic.jsonl" "$D/s3/gemma4-c7.jsonl"
recall s3 "$D/s3/cases.jsonl" C7 s3-C7 "$SJ/scores/recall-at-fpr-s3-secjudge-C7.json"
echo "MILESTONE s3-C7 $(date -Is)"

echo "ALLSTAGESDONE4 $(date -Is)"
