#!/bin/bash
# Launch open-jev-qwen-2b replicas alongside the running bespoke-nimble-9b replicas.
# Nimble's readout is 3 sequential batch-1 forward passes behind a per-server lock, so it
# leaves each card at roughly 57% utilisation. The 2B checkpoint is ~5 GB, so it fits in
# that headroom on GPUs 0-2 and soaks up the idle capacity instead of waiting for a
# sequential phase. GPU 3 is deliberately skipped: another agent's Gemma 4 holdout job is
# resident there (~18.6 GB) and must not be evicted or OOMed.
set -uo pipefail
export HF_HOME=/opt/dlami/nvme/hf
ROOT=$WORK/sysone
CK=/opt/dlami/nvme/checkpoints
LOGS=$ROOT/logs
cd "$ROOT"

# shard index -> (gpu, port); two replicas share GPU 0, which has the most free memory.
GPUS=(0 1 2 0)
PORTS=(8811 8812 8813 8814)

for i in 0 1 2 3; do
  port=${PORTS[$i]}
  if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$port "; then
    echo "port $port already listening, skip"; continue
  fi
  CUDA_VISIBLE_DEVICES=${GPUS[$i]} PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    setsid nohup "$ROOT/venv-ojev/bin/python" "$ROOT/openjev_serve.py" \
    --checkpoint "$CK/open-jev-2b/package/checkpoint" \
    --name open-jev-qwen-2b --repo-id ZefanCai/Open-Jev-2B \
    --batch-size 32 --no-prefix-cache \
    --device cuda:0 --host 127.0.0.1 --port "$port" \
    > "$LOGS/serve-open-jev-qwen-2b-gpu${GPUS[$i]}-$port.log" 2>&1 < /dev/null &
  echo "launched open-jev-qwen-2b gpu=${GPUS[$i]} port=$port"
done

echo "=== waiting for readiness ==="
for port in "${PORTS[@]}"; do
  for _ in $(seq 120); do
    if curl -s -m 3 "http://127.0.0.1:$port/health" | grep -q '"status": "ready"'; then
      echo "  :$port ready"; break
    fi
    sleep 2
  done
done
nvidia-smi --query-gpu=index,utilization.gpu,memory.used --format=csv,noheader
