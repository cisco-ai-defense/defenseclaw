#!/bin/bash
# Settle and score one model's s2 run with the existing shared scorer.
#
#  1. verify every shard meta is complete:true and its on-disk sha256 matches prediction_sha256
#  2. merge the 4 shards with coverage verification (hard-fails on any error row)
#  3. verify the merged file's on-disk sha256 against the merge attestation
#  4. score with benchmark_score_system_one.py against the REAL deterministic tier
#     (outputs/deterministic-real/s2-run/predictions.jsonl) and the Gemma 4 judge tier
#  5. compute recall at fixed FPR with the same recall_at_fpr.py the incumbents used
set -uo pipefail
REPO=$WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
O=$WORK/.system-one-data/outputs
SCORER=$REPO/benchmarks/scripts/benchmark_score_system_one.py
SCHEMA=$REPO/benchmarks/schema/system-one-prediction-v1.schema.json
RECALL=$O/secjudge/code/recall_at_fpr.py
CASES=$O/s2/cases.jsonl
DET=$O/deterministic-real/s2-run/predictions.jsonl
LLM=$O/s2/gemma4-c7.jsonl

NAME=${1:?model display name}
OUTDIR=${2:?output dir}
SHARDS=$OUTDIR/shards
MERGED=$OUTDIR/$NAME.jsonl
mkdir -p "$OUTDIR/scores"

echo "=== 1. shard settledness ==="
$PY - "$SHARDS" "$NAME" <<'PY' || exit 1
import hashlib, json, sys, pathlib
shards, name = pathlib.Path(sys.argv[1]), sys.argv[2]
bad = []
for i in range(4):
    pred = shards / f"{name}-shard{i}.jsonl"
    meta = pathlib.Path(str(pred) + ".meta.json")
    if not meta.exists():
        bad.append(f"shard{i}: no meta"); continue
    m = json.loads(meta.read_text())
    digest = hashlib.sha256(pred.read_bytes()).hexdigest()
    ok = m.get("complete") is True and digest == m.get("prediction_sha256")
    print(f"  shard{i}: complete={m.get('complete')} rows={m.get('requests')} "
          f"sha_match={digest == m.get('prediction_sha256')}")
    if not ok:
        bad.append(f"shard{i}: complete={m.get('complete')} sha_match={digest == m.get('prediction_sha256')}")
if bad:
    print("NOT SETTLED: " + "; ".join(bad)); sys.exit(1)
print("  all 4 shards settled")
PY

echo "=== 2. merge with coverage verification ==="
$PY "$REPO/benchmarks/scripts/merge_s2_halves.py" \
  --half "$SHARDS/$NAME-shard0.jsonl" --half "$SHARDS/$NAME-shard1.jsonl" \
  --half "$SHARDS/$NAME-shard2.jsonl" --half "$SHARDS/$NAME-shard3.jsonl" \
  --cases "$CASES" --out "$MERGED" \
  --merge-json "$OUTDIR/$NAME.merge.json" --merged-run-id "s2-$NAME" || exit 1

echo "=== 3. merged digest check ==="
$PY - "$MERGED" "$OUTDIR/$NAME.merge.json" <<'PY' || exit 1
import hashlib, json, sys
disk = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
rec = json.load(open(sys.argv[2]))
print(f"  on-disk={disk[:16]} attested={rec['merged_sha256'][:16]} match={disk == rec['merged_sha256']}")
print(f"  rows={rec['verification']['rows']} coverage_complete={rec['verification']['coverage_complete']} "
      f"errors={rec['verification']['errors_by_code']}")
sys.exit(0 if disk == rec["merged_sha256"] else 1)
PY

echo "=== 3b. settled meta for the merged file ==="
$PY $WORK/sysone-capture_provenance.py --name "$NAME" \
  --out "$OUTDIR/$NAME.serving.json" ${GPU_SECONDS:+--gpu-seconds $GPU_SECONDS} || exit 1
$PY $WORK/sysone-write_meta.py \
  --merged "$MERGED" --merge-json "$OUTDIR/$NAME.merge.json" \
  --serving-json "$OUTDIR/$NAME.serving.json" \
  --shard-meta "$SHARDS/$NAME-shard0.jsonl.meta.json" \
  --shard-meta "$SHARDS/$NAME-shard1.jsonl.meta.json" \
  --shard-meta "$SHARDS/$NAME-shard2.jsonl.meta.json" \
  --shard-meta "$SHARDS/$NAME-shard3.jsonl.meta.json" || exit 1

echo "=== 4. score (real deterministic tier) ==="
( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PY "$SCORER" \
    --cases "$CASES" \
    --system-one-predictions "$MERGED" \
    --prediction-schema "$SCHEMA" \
    --deterministic-predictions "$DET" \
    --llm-predictions "$LLM" \
    --output "$OUTDIR/scores/s2-$NAME.json" \
    --culling-output "$OUTDIR/scores/s2-$NAME.culling.json" \
    --closure-output "$OUTDIR/scores/s2-$NAME.closure.json" \
    --max-candidates 8 --input-usd-per-million 0.042 ) || exit 1

echo "=== 5. recall at fixed FPR ==="
( cd "$REPO" && PYTHONPATH=$REPO/benchmarks/scripts $PY "$RECALL" \
    --cases "$CASES" --stage s2 \
    --arm "$NAME=$MERGED" \
    --out "$OUTDIR/scores/recall-at-fpr-s2-$NAME.json" ) || exit 1

echo "=== 6. headline ==="
$PY - "$OUTDIR/scores/s2-$NAME.json" "$OUTDIR/scores/recall-at-fpr-s2-$NAME.json" "$NAME" <<'PY'
import json, sys
score = json.load(open(sys.argv[1]))
recall = json.load(open(sys.argv[2]))
name = sys.argv[3]
c = score["candidates"][0]
d = c.get("deterministic_then_system_one", c["system_one"])
print(f"model            : {name}")
print(f"candidate        : {c['candidate']}")
print(f"scorable_cases   : {c['scorable_cases']}")
print(f"errors           : {c['system_one']['errors']}")
for lens, key in (("block-only", "binary_block_only"), ("any-intervention", "binary")):
    m = d[key]
    print(f"{lens:17s}: f1={m['f1']} precision={m['precision']} recall={m['recall']} fpr={m['false_positive_rate']}")
print(f"three-way acc    : {d['three_way']['accuracy']}  macro_f1={d['three_way']['macro_f1']}")
print(f"review rate      : {d['review_rate']}")
arm = next(iter(recall["arms"].values()))
print(f"roc_auc          : {arm.get('roc_auc')}")
for t in ("0.001", "0.005", "0.01", "0.05"):
    k = f"recall_at_fpr_{t}"
    if k in arm:
        print(f"recall@FPR<={t:6s}: {arm[k]['recall']}  (achieved_fpr={arm[k].get('achieved_fpr')})")
PY
