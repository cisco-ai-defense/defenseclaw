#!/bin/bash
# 27B smoke on one H200 card: serve with eager attention (this arm's own control, which
# overrides the sdpa hardcoded in jev/model.py), then replay the same 507 requests the 2B
# ran so the rows/min comparison is exact. Arg 1 = batch size, arg 2 = card, arg 3 = port.
set -uo pipefail
R="$HOME/sysone"
BS="${1:-4}"; CARD="${2:-0}"; PORT="${3:-8821}"
CK="$R/checkpoints"
export HF_HOME="$R/hf"
LOG="$R/logs/serve27-bs${BS}-card${CARD}.log"
mkdir -p "$R/agree/out27"

OLD=$(ss -ltnp 2>/dev/null | grep "127.0.0.1:$PORT " | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -1)
[ -n "${OLD:-}" ] && { echo "stopping previous on :$PORT (pid $OLD)"; kill "$OLD"; sleep 5; }

echo "=== launching 27B: eager, bs=$BS, card=$CARD, port=$PORT ==="
CUDA_VISIBLE_DEVICES="$CARD" PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-ojev/bin/python" "$R/j27/serve27.py" \
  --checkpoint "$CK/open-jev-27b/package/checkpoint" \
  --name open-jev-qwen-27b \
  --repo-id ZefanCai/Open-Jev-27B-v1.1 \
  --repo-revision 28cf73067d5b337860bbef3c85b8b82ba8730956 \
  --device cuda:0 --device-map balanced --max-memory-per-card 120GiB \
  --attn eager --batch-size "$BS" --no-prefix-cache --max-length 4096 \
  --host 127.0.0.1 --port "$PORT" \
  --provenance-out "$R/agree/out27/startup-27b-bs${BS}.json" \
  > "$LOG" 2>&1 < /dev/null &

for _ in $(seq 240); do
  curl -s -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -q ready && { echo "READY :$PORT"; break; }
  sleep 5
done
curl -s -m 5 "http://127.0.0.1:$PORT/health"; echo
echo "--- resident memory on card $CARD ---"
nvidia-smi --query-gpu=index,memory.used --format=csv,noheader | sed -n "$((CARD+1))p"

echo "=== timed replay: 507 requests (same subset the 2B ran) ==="
cd "$R/agree"
OUT="out27/h200-27b-bs${BS}.jsonl"
rm -f "$OUT" "$OUT".plan.json "$OUT".meta.json
S=$(date +%s)
"$R/venv-ojev/bin/python" "$R/benchmark_run_system_one.py" \
  --cases s2-cases-agree.jsonl \
  --contexts-config cfg/contexts-v1.json \
  --questions-config cfg/questions-v1.json \
  --prediction-schema cfg/system-one-prediction-v1.schema.json \
  --context C7 --instruction I3 --question Q2 --instruction-format structured \
  --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
  --model open-jev-qwen-27b \
  --model-revision c49994563c3c4f04a99d9130203c4e526f4ae5086c84deec57698d18cb652e71 \
  --run-id "h200-smoke-27b-bs${BS}" --output "$OUT" \
  --concurrency 4 --timeout 600 > "$R/logs/run27-bs${BS}.log" 2>&1
echo "EXIT=$?"
E=$(date +%s)
N=$(wc -l < "$OUT" 2>/dev/null || echo 0)
python3 -c "
n=$N; s=$((E-S))
print(f'batch_size=$BS rows={n} seconds={s}')
if n and s:
    r=n/s*60
    print(f'rows_per_min_1card={r:.1f}')
    print(f'rows_per_min_4card_aggregate={r*4:.1f}')
    print(f's2_30310_on_4cards_hours={30310/(r*4)/60:.2f}')
"
tail -3 "$R/logs/run27-bs${BS}.log"
