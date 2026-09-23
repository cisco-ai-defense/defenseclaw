#!/bin/bash
# Phase launcher on the GPU host: bring up 4 single-GPU replicas of one model so the
# s2 corpus can be sharded 4 ways, exactly as the incumbent s3 runs were sharded
# (independent replicas + CUDA_VISIBLE_DEVICES, never tensor parallel).
#
# Open-Jev runs under venv-ojev (transformers 5.10.2 / peft 0.19.1, the pins its model
# card mandates). Nimble runs under venv (transformers 5.17.0 / peft 0.21.0, the pins in
# its schema_config.json). Prefix caching stays OFF: it failed numeric A/B and was slower.
set -uo pipefail
export HF_HOME=/opt/dlami/nvme/hf
ROOT=$WORK/sysone
CK=/opt/dlami/nvme/checkpoints
LOGS=$ROOT/logs
PORTS=(8801 8802 8803 8804)
mkdir -p "$LOGS"
cd "$ROOT"

stop_all() {
  pkill -f openjev_serve.py 2>/dev/null
  pkill -f nimble_shim.py 2>/dev/null
  for _ in $(seq 30); do
    pgrep -f 'openjev_serve.py|nimble_shim.py' > /dev/null || break
    sleep 1
  done
  sleep 3
  echo "stopped all serving processes"
}

wait_ready() {
  local port=$1 tries=${2:-180}
  for _ in $(seq "$tries"); do
    if curl -s -m 3 "http://127.0.0.1:$port/health" | grep -q '"status": "ready"'; then
      echo "  :$port ready"; return 0
    fi
    sleep 2
  done
  echo "  :$port FAILED to become ready"; return 1
}

launch_openjev() { # name repo checkpoint_subdir
  local name=$1 repo=$2 sub=$3
  for i in 0 1 2 3; do
    CUDA_VISIBLE_DEVICES=$i setsid nohup "$ROOT/venv-ojev/bin/python" "$ROOT/openjev_serve.py" \
      --checkpoint "$CK/$sub/package/checkpoint" --name "$name" --repo-id "$repo" \
      --batch-size 32 --no-prefix-cache \
      --device cuda:0 --host 127.0.0.1 --port "${PORTS[$i]}" \
      > "$LOGS/serve-$name-gpu$i.log" 2>&1 < /dev/null &
    echo "launched $name gpu=$i port=${PORTS[$i]}"
  done
}

launch_nimble() {
  for i in 0 1 2 3; do
    CUDA_VISIBLE_DEVICES=$i setsid nohup "$ROOT/venv/bin/python" "$ROOT/nimble_shim.py" \
      --checkpoint "$CK/nimble-9b" --name bespoke-nimble-9b --max-length 8192 \
      --device cuda:0 --host 127.0.0.1 --port "${PORTS[$i]}" \
      > "$LOGS/serve-bespoke-nimble-9b-gpu$i.log" 2>&1 < /dev/null &
    echo "launched bespoke-nimble-9b gpu=$i port=${PORTS[$i]}"
  done
}

case "${1:-}" in
  open-jev-qwen-9b) stop_all; launch_openjev open-jev-qwen-9b ZefanCai/Open-Jev-9B open-jev-9b ;;
  open-jev-qwen-2b) stop_all; launch_openjev open-jev-qwen-2b ZefanCai/Open-Jev-2B open-jev-2b ;;
  bespoke-nimble-9b) stop_all; launch_nimble ;;
  stop) stop_all; exit 0 ;;
  audit-nimble)
    CUDA_VISIBLE_DEVICES=3 setsid nohup "$ROOT/venv/bin/python" audit_lengths.py \
      --requests /opt/dlami/nvme/s2-requests-all.jsonl --family nimble \
      --tokenizer "$CK/nimble-9b" --out /opt/dlami/nvme/audit-nimble-lengths.json \
      > "$LOGS/audit-nimble.log" 2>&1 < /dev/null &
    echo "audit-nimble started"; exit 0 ;;
  *) echo "usage: phase.sh {open-jev-qwen-9b|open-jev-qwen-2b|bespoke-nimble-9b|stop|audit-nimble}"; exit 2 ;;
esac

echo "=== waiting for readiness ==="
for p in "${PORTS[@]}"; do wait_ready "$p"; done
nvidia-smi --query-gpu=index,utilization.gpu,memory.used --format=csv,noheader
