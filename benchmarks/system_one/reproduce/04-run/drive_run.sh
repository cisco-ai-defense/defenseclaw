#!/bin/bash
# Attach to an already-serving Gemma 4 shim and run one s2 arm to settlement.
# Usage: ./drive_run.sh <alias> <port> <cuda_devices> <temperature> <out_name>
set -eu
ALIAS=$1; PORT=$2; DEVICES=$3; TEMP=$4; OUT=$5

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
exec >>"$G/s2/$OUT.drive.log" 2>&1

echo "===== $(date -u +%FT%TZ) drive_run alias=$ALIAS port=$PORT dev=$DEVICES T=$TEMP"
REV=$(python3 -c "import json;print(json.load(open('$G/artifacts/pins.json'))['$REPO_ID'])")
echo "revision=$REV"

# tunnel dev -> GPU for this port only (never binds 8801-8804 / 8811-8814)
if ! ss -lnt 2>/dev/null | grep -q "127.0.0.1:$PORT "; then
  ssh -f -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
      -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes \
      -i "$KEY" -L "127.0.0.1:$PORT:127.0.0.1:$PORT" "$GPUH"
  echo "tunnel opened"
else
  echo "tunnel already present"
fi

for i in $(seq 1 240); do
  curl -sf --max-time 10 "http://127.0.0.1:$PORT/v1/models" > "$G/s2/$OUT.models.json" 2>/dev/null && break
  sleep 10
done
[ -s "$G/s2/$OUT.models.json" ] || { echo "SERVER NOT REACHABLE"; exit 4; }

# /v1/models is only the Open-Jev model listing; the serving provenance is the shim's
# startup banner, so pull that off the GPU host and gate on it.
ssh -i "$KEY" -o StrictHostKeyChecking=yes "$GPUH" \
  "grep -h '\"chat_template_sha256\"' $WORK/g4j/logs/serve-$OUT.log | tail -1" \
  > "$G/s2/$OUT.serving.json"
[ -s "$G/s2/$OUT.serving.json" ] || { echo "NO SERVING BANNER FOUND"; exit 4; }

# gate: eager, cache-free, pinned template, fully GPU-resident
$PY "$G/check_placement.py" "$G/s2/$OUT.serving.json" || { echo "GATE FAILED"; exit 6; }

# smoke: proves the G1 tail assertion fired and probabilities/confidence parse; times a prefill
rm -f "$G/s2/$OUT.smoke.jsonl" "$G/s2/$OUT.smoke.jsonl.plan.json" "$G/s2/$OUT.smoke.jsonl.meta.json"
cd "$SRC"
T0=$(date +%s)
$PY benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$G/cases-smoke5.jsonl" --context C7 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model "$MODELNAME" --model-revision "$REV" \
  --instruction-format structured --api-key-env SYSONE_NO_KEY \
  --run-id "smoke-$OUT" --output "$G/s2/$OUT.smoke.jsonl" \
  --concurrency 1 --timeout 600 --retries 1 \
  --max-input-tokens 4000000000 --max-calls 2000000 || { echo "SMOKE FAILED"; exit 5; }
echo "smoke wall=$(( $(date +%s) - T0 ))s"
$PY "$G/check_rows.py" "$G/s2/$OUT.smoke.jsonl"

# full run. --resume only once a matching plan exists; the runner rejects --resume otherwise.
cd "$SRC"
RESUME=""
[ -f "$G/s2/$OUT.jsonl.plan.json" ] && RESUME="--resume"
T1=$(date +%s)
echo "FULL START $(date -u +%FT%TZ) resume=${RESUME:-no}"
$PY benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$S2/cases.jsonl" --context C7 --instruction I3 --question Q2 \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model "$MODELNAME" --model-revision "$REV" \
  --instruction-format structured --api-key-env SYSONE_NO_KEY \
  --run-id "s2-$OUT" --output "$G/s2/$OUT.jsonl" \
  --concurrency 2 --timeout 900 --retries 2 $RESUME \
  --max-input-tokens 4000000000 --max-calls 2000000
echo "FULL DONE wall=$(( $(date +%s) - T1 ))s $(date -u +%FT%TZ)"

python3 "$G/settle_meta.py" --predictions "$G/s2/$OUT.jsonl" \
  --repo-id "$REPO_ID" --temperature "$TEMP" --cuda-devices "$DEVICES" \
  --serving-json "$G/s2/$OUT.serving.json"
echo "===== ARM COMPLETE $OUT $(date -u +%FT%TZ)"
