#!/bin/bash
# Drive one Gemma 4 s2 arm end to end: serve, tunnel, placement gate, smoke, full 30,310, settle.
# Usage: ./drive_arm.sh <alias> <port> <cuda_devices> <temperature> <out_name> [per_card_cap]
set -eu
ALIAS=$1; PORT=$2; DEVICES=$3; TEMP=$4; OUT=$5; CAP=${6:-}

case "$ALIAS" in
  jevify)   REPO_ID=kushalpatil/jevify-gemma4-26b-a4b; MODELNAME=jevify-gemma4-26b-a4b ;;
  26b-base) REPO_ID=google/gemma-4-26B-A4B-it;         MODELNAME=gemma-4-26b-a4b-it ;;
  *) echo "unknown alias $ALIAS" >&2; exit 2 ;;
esac

G=$WORK/.system-one-data/outputs/gemma4jev
S2=$WORK/.system-one-data/outputs/s2
SRC=$WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python
KEY=<SSH_KEY>
GPUH=ubuntu@<GPU_HOST>
mkdir -p "$G/s2"
LOG=$G/s2/$OUT.drive.log
exec >>"$LOG" 2>&1

echo "===== $(date -u +%FT%TZ) drive_arm alias=$ALIAS repo=$REPO_ID port=$PORT dev=$DEVICES T=$TEMP cap=${CAP:-none}"
REV=$(python3 -c "import json;print(json.load(open('$G/artifacts/pins.json'))['$REPO_ID'])")
echo "revision=$REV"

# 1. serve on the GPU host, detached so it outlives this ssh session
ssh -i "$KEY" -o StrictHostKeyChecking=yes "$GPUH" \
  "cd $WORK/g4j && setsid nohup ./serve_g4_multi.sh $ALIAS $PORT $DEVICES $TEMP $CAP > logs/serve-$OUT.log 2>&1 < /dev/null & sleep 3; echo launched"

# 2. tunnel dev -> GPU for this port only (never binds 8801-8804 / 8811-8814)
pkill -f "127.0.0.1:$PORT:127.0.0.1:$PORT" || true
ssh -f -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
    -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes \
    -i "$KEY" -L "127.0.0.1:$PORT:127.0.0.1:$PORT" "$GPUH"
echo "tunnel up"

# 3. wait for 51.6 GB of weights to load
for i in $(seq 1 240); do
  if curl -sf --max-time 10 "http://127.0.0.1:$PORT/v1/models" > "$G/s2/$OUT.serving.json" 2>/dev/null; then
    echo "ready after $((i*10))s"; break
  fi
  sleep 10
done
curl -sf --max-time 10 "http://127.0.0.1:$PORT/v1/models" > "$G/s2/$OUT.serving.json" \
  || { echo "SERVER NEVER CAME UP -- tail of serve log:"; \
       ssh -i "$KEY" -o StrictHostKeyChecking=yes "$GPUH" "tail -30 $WORK/g4j/logs/serve-$OUT.log"; exit 4; }

# 3b. PLACEMENT GATE: any layer on cpu/disk means the 4.65 s/item offload path, which is not viable.
$PY "$G/check_placement.py" "$G/s2/$OUT.serving.json" || { echo "PLACEMENT GATE FAILED"; exit 6; }

# 4. smoke: proves the G1 template assertion fired, probabilities+confidence parse, and times a prefill
rm -f "$G/s2/$OUT.smoke.jsonl" "$G/s2/$OUT.smoke.jsonl.plan.json" "$G/s2/$OUT.smoke.jsonl.meta.json"
cd "$SRC"
SMOKE_START=$(date +%s)
$PY benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$G/cases-smoke5.jsonl" --context C7 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model "$MODELNAME" --model-revision "$REV" \
  --instruction-format structured --api-key-env SYSONE_NO_KEY \
  --run-id "smoke-$OUT" --output "$G/s2/$OUT.smoke.jsonl" \
  --concurrency 1 --timeout 600 --retries 1 \
  --max-input-tokens 4000000000 --max-calls 2000000 || { echo "SMOKE FAILED"; exit 5; }
echo "smoke wall=$(( $(date +%s) - SMOKE_START ))s"
$PY "$G/check_rows.py" "$G/s2/$OUT.smoke.jsonl"

# 5. full run, resumable
cd "$SRC"
FULL_START=$(date +%s)
echo "FULL START $(date -u +%FT%TZ)"
$PY benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$S2/cases.jsonl" --context C7 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model "$MODELNAME" --model-revision "$REV" \
  --instruction-format structured --api-key-env SYSONE_NO_KEY \
  --run-id "s2-$OUT" --output "$G/s2/$OUT.jsonl" \
  --concurrency 2 --timeout 900 --retries 2 --resume \
  --max-input-tokens 4000000000 --max-calls 2000000
echo "FULL DONE wall=$(( $(date +%s) - FULL_START ))s $(date -u +%FT%TZ)"

# 6. settle
python3 "$G/settle_meta.py" --predictions "$G/s2/$OUT.jsonl" \
  --repo-id "$REPO_ID" --temperature "$TEMP" --cuda-devices "$DEVICES" \
  --serving-json "$G/s2/$OUT.serving.json"
echo "===== ARM COMPLETE $OUT $(date -u +%FT%TZ)"
