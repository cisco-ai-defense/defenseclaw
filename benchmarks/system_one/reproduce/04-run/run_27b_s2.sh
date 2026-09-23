#!/bin/bash
# open-jev-qwen-27b on the s2 ranked cell (C7/I3/Q2, 4,277 cases -> 30,310 requests),
# four independent single-card replicas on the 4x H200 studio.
#
# Sharding follows the published convention exactly: corpus stride shards rows[i::4],
# one single-GPU replica per shard, no tensor parallelism. The published shard request
# counts are [7808, 7370, 7597, 7535]; this script asserts that before serving anything,
# so a sharding drift cannot silently produce a non-comparable arm.
#
# Serving controls are this arm's own, not the Open-Jev family default: eager attention
# (serve27.py overrides the sdpa hardcoded in jev/model.py), bf16, prefix cache off,
# batch_size 4, max_length 4096.
set -uo pipefail
R="$HOME/sysone"
CK="$R/checkpoints"
export HF_HOME="$R/hf"
OUTD="$R/runs/27b-s2"
BS="${BS:-4}"
mkdir -p "$OUTD" "$R/logs"
cd "$R/agree"

REV=c49994563c3c4f04a99d9130203c4e526f4ae5086c84deec57698d18cb652e71
EXPECTED=(7808 7370 7597 7535)

echo "=== [1/4] build stride shards rows[i::4] ==="
python3 - <<'PY'
rows = open('s2-cases.jsonl').readlines()
assert len(rows) == 4277, f"expected 4277 cases, got {len(rows)}"
import os
os.makedirs(os.path.expanduser('~/sysone/runs/27b-s2'), exist_ok=True)
for i in range(4):
    with open(os.path.expanduser(f'~/sysone/runs/27b-s2/cases-shard{i}.jsonl'), 'w') as fh:
        fh.writelines(rows[i::4])
    print(f"shard{i}: {len(rows[i::4])} cases")
PY

echo "=== [2/4] verify shard request counts match published ==="
for i in 0 1 2 3; do
  N=$("$R/venv-ojev/bin/python" "$R/benchmark_run_system_one.py" \
    --cases "$OUTD/cases-shard$i.jsonl" \
    --contexts-config cfg/contexts-v1.json --questions-config cfg/questions-v1.json \
    --context C7 --instruction I3 --question Q2 --instruction-format structured \
    --endpoint http://127.0.0.1:1/v1/systemone --model x --model-revision x \
    --run-id x --output /tmp/x.jsonl --dry-run | python3 -c 'import sys,json;print(json.load(sys.stdin)["requests"])')
  if [ "$N" != "${EXPECTED[$i]}" ]; then
    echo "SHARD $i REQUEST MISMATCH: got $N expected ${EXPECTED[$i]}"; exit 1
  fi
  echo "shard$i requests=$N matches published ${EXPECTED[$i]}"
done

echo "=== [3/4] launch 4 single-card 27B replicas ==="
for i in 0 1 2 3; do
  PORT=$((8821 + i))
  OLD=$(ss -ltnp 2>/dev/null | grep "127.0.0.1:$PORT " | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -1)
  [ -n "${OLD:-}" ] && { kill "$OLD" 2>/dev/null; sleep 3; }
  CUDA_VISIBLE_DEVICES="$i" PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    setsid nohup "$R/venv-ojev/bin/python" "$R/j27/serve27.py" \
    --checkpoint "$CK/open-jev-27b/package/checkpoint" \
    --name open-jev-qwen-27b \
    --repo-id ZefanCai/Open-Jev-27B-v1.1 \
    --repo-revision 28cf73067d5b337860bbef3c85b8b82ba8730956 \
    --device cuda:0 --device-map balanced --max-memory-per-card 120GiB \
    --attn eager --batch-size "$BS" --no-prefix-cache --max-length 4096 \
    --host 127.0.0.1 --port "$PORT" \
    --provenance-out "$OUTD/startup-shard$i.json" \
    > "$R/logs/serve27-s2-card$i.log" 2>&1 &
  echo "launched card=$i port=$PORT"
done

echo "--- waiting for all four ready ---"
for i in 0 1 2 3; do
  PORT=$((8821 + i))
  for _ in $(seq 240); do
    curl -s -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -q ready && { echo "  :$PORT ready"; break; }
    sleep 5
  done
done
nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv,noheader

echo "=== [4/4] launch 4 runners ==="
date +%s > "$OUTD/t_start"
for i in 0 1 2 3; do
  PORT=$((8821 + i))
  setsid nohup "$R/venv-ojev/bin/python" "$R/benchmark_run_system_one.py" \
    --cases "$OUTD/cases-shard$i.jsonl" \
    --contexts-config cfg/contexts-v1.json \
    --questions-config cfg/questions-v1.json \
    --prediction-schema cfg/system-one-prediction-v1.schema.json \
    --context C7 --instruction I3 --question Q2 --instruction-format structured \
    --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
    --model open-jev-qwen-27b --model-revision "$REV" \
    --run-id "s2-open-jev-qwen-27b-h200-shard$i" \
    --output "$OUTD/open-jev-qwen-27b-shard$i.jsonl" \
    --concurrency 4 --timeout 600 --resume \
    > "$R/logs/run27-s2-shard$i.log" 2>&1 &
  echo "runner shard$i -> :$PORT"
done
sleep 45
echo "=== early progress ==="
for i in 0 1 2 3; do
  echo "  shard$i rows=$(wc -l < "$OUTD/open-jev-qwen-27b-shard$i.jsonl" 2>/dev/null || echo 0)"
done
