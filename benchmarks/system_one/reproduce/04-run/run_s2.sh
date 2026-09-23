#!/bin/bash
# Run the s2 stage (C7/I3/Q2, 4,277 cases / 30,310 decisions) for one model, sharded
# 4 ways across the four L40S replicas. Mirrors the incumbent s3 fan-out: stride
# sharding of the corpus, one runner per replica port, then a coverage-verified merge
# into a single prediction file because the scorer rejects mixed run_ids per candidate.
set -uo pipefail
cd $WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
O=$WORK/.system-one-data/outputs
CASES=$O/s2/cases.jsonl
# PORTS may be overridden so a second model can run concurrently on spare capacity.
PORTS=(${RUN_PORTS:-8801 8802 8803 8804})

NAME=${1:?model display name}
REV=${2:?model revision}
OUTDIR=${3:?output dir}
mkdir -p "$OUTDIR" "$OUTDIR/shards"

# --- stride shards, created once and reused by every model for identical partitioning
SHARDDIR=$O/openjev-qwen/s2-shards
mkdir -p "$SHARDDIR"
if [ ! -f "$SHARDDIR/cases.shard3.jsonl" ]; then
  $PY - "$CASES" "$SHARDDIR" <<'PY'
import sys, pathlib
rows = [l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
out = pathlib.Path(sys.argv[2])
for i in range(4):
    part = rows[i::4]
    (out / f"cases.shard{i}.jsonl").write_text("".join(part), encoding="utf-8")
    print(f"shard{i}: {len(part)} cases")
print("total:", sum(len(rows[i::4]) for i in range(4)))
PY
fi

for i in 0 1 2 3; do
  OUT="$OUTDIR/shards/${NAME}-shard${i}.jsonl"
  RESUME=""
  [ -f "$OUT" ] && RESUME="--resume"
  setsid nohup $PY benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$SHARDDIR/cases.shard${i}.jsonl" \
    --context C7 --instruction I3 --question Q2 \
    --endpoint "http://127.0.0.1:${PORTS[$i]}/v1/systemone" \
    --model "$NAME" --model-revision "$REV" \
    --instruction-format structured \
    --api-key-env SYSONE_NO_KEY \
    --run-id "s2-${NAME}-shard${i}" \
    --output "$OUT" \
    --concurrency 4 --timeout 300 --retries 2 \
    --max-input-tokens 4000000000 --max-calls 2000000 $RESUME \
    > "$OUTDIR/shards/${NAME}-shard${i}.log" 2>&1 < /dev/null &
  echo "launched $NAME shard$i -> :${PORTS[$i]}"
done
echo "all shards launched for $NAME"
