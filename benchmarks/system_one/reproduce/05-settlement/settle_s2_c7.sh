#!/bin/bash
# Settle ONLY s2-C7: wait for in-flight shards -> verify shard completeness -> emit -> score -> recall@FPR.
# Deliberately contains NO s3 and NO toolcall-labels stage. Those are explicitly out of scope.
# emit/score/recall invocations are copied verbatim from run_secjudge_stages4.sh so the numbers are
# computed identically to the settled C0 arms and to the incumbents.
set -u

D=$WORK/.system-one-data/outputs
SJ=$D/secjudge
REPO=$WORK/defenseclaw-system-one
PYI=$WORK/.von-venv/bin/python
PYS=$WORK/.system-one-venv/bin/python
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py
TAG=$(date -u +%Y%m%dT%H%M%SZ)
export PYTHONPATH=$WORK/.secjudge-deps

echo "### SETTLE s2-C7 start $(date -Is)"

# ---- 1. wait for the orphaned but still-running 12 inference shards ----
while pgrep -f "secjudge_infer.py .*--stage s2-C7" > /dev/null; do sleep 30; done
echo "### s2-C7 shards finished $(date -Is)"

# ---- 2. verify every shard settled before any merge ----
$PYI - <<'PY'
import json, pathlib, sys
raw = pathlib.Path("$WORK/.system-one-data/outputs/secjudge/raw")
tot = 0
bad = []
for i in range(12):
    p = raw / f"s2-C7.shard{i}.jsonl"
    m = pathlib.Path(str(p) + ".meta.json")
    if not m.exists():
        bad.append(f"shard{i}: no meta"); continue
    meta = json.loads(m.read_text())
    lines = sum(1 for _ in p.open())
    ok = (meta.get("complete") is True and meta.get("shards") == 12
          and meta.get("stage") == "s2-C7" and meta.get("variants") == ["C7"]
          and meta.get("serialisation") == "production_text"
          and meta.get("decisions") == lines)
    if not ok:
        bad.append(f"shard{i}: complete={meta.get('complete')} decisions={meta.get('decisions')} lines={lines}")
    tot += lines
print(json.dumps({"total_decisions": tot, "expected": 30310, "bad": bad}))
if bad or tot != 30310:
    sys.exit(3)
PY
if [ $? -ne 0 ]; then echo "### SHARD VERIFY FAILED -- stopping, nothing quotable"; exit 3; fi
echo "### shard verify OK $(date -Is)"

# ---- 3. emit the 5 prediction arms ----
raws=()
for f in $SJ/raw/s2-C7.shard*.jsonl; do raws+=(--raw "$f"); done
echo "### EMIT s2 C7 from $(( ${#raws[@]} / 2 )) shards"
$PYI $SJ/code/secjudge_emit.py "${raws[@]}" --stage "s2" --context "C7" \
     --outdir "$SJ/predictions" --run-tag "$TAG" --arm-suffix "" \
     > "$SJ/logs/emit-s2-C7.log" 2>&1 || { echo "### EMIT FAILED s2 C7"; cat "$SJ/logs/emit-s2-C7.log"; exit 4; }
cat "$SJ/logs/emit-s2-C7.log"

# ---- 4. score with the EXISTING shared scorer, real deterministic tier ----
preds=()
for f in $SJ/predictions/secjudge-s2-C7-*.jsonl; do
  case "$f" in *.meta.json) continue;; esac
  preds+=(--system-one-predictions "$f")
done
echo "### SCORE s2 C7 arms=$(( ${#preds[@]} / 2 ))"
( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PYS "$SCORER" \
    --cases "$D/s2/cases.jsonl" "${preds[@]}" \
    --prediction-schema "$REPO/benchmarks/schema/system-one-prediction-v1.schema.json" \
    --deterministic-predictions "$D/s2/deterministic.jsonl" \
    --llm-predictions "$D/s2/gemma4-c7.jsonl" \
    --output "$SJ/scores/s2-C7.json" \
    --culling-output "$SJ/scores/s2-C7.culling.json" \
    --closure-output "$SJ/scores/s2-C7.closure.json" \
    --max-candidates 8 --input-usd-per-million 0.042 ) \
    > "$SJ/logs/score-s2-C7.log" 2>&1
echo "### SCORE s2 C7 rc=$? $(date -Is)"
tail -5 "$SJ/logs/score-s2-C7.log"

# ---- 5. recall at fixed FPR ----
raw=$(ls $SJ/raw/s2-C7.shard*.jsonl | tr '\n' ',' | sed 's/,$//')
echo "### RECALL@FPR s2 C7"
( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PYS $SJ/code/recall_at_fpr.py \
    --cases "$D/s2/cases.jsonl" --stage "s2" --raw-context "C7" \
    --arm secjudge-sev=$SJ/predictions/secjudge-s2-C7-sev.jsonl \
    --raw-arm secjudge="$raw" --out "$SJ/scores/recall-at-fpr-s2-secjudge-C7.json" ) \
    > "$SJ/logs/recall-s2-C7.log" 2>&1
echo "### RECALL@FPR s2 C7 rc=$? $(date -Is)"

echo "SETTLE_S2_C7_DONE $(date -Is)"
