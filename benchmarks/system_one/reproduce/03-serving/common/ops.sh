#!/bin/bash
# Operations helper executed ON the GPU host. Keeps backgrounding out of nested ssh quoting.
set -uo pipefail
export HF_HOME=/opt/dlami/nvme/hf
ROOT=$WORK/sysone
PY=$ROOT/venv/bin/python
CK=/opt/dlami/nvme/checkpoints
LOGS=$ROOT/logs
NVME=/opt/dlami/nvme
mkdir -p "$LOGS"
cd "$ROOT"

bg() { local log=$1; shift; CUDA_VISIBLE_DEVICES=${GPU:-0} setsid nohup "$@" > "$LOGS/$log" 2>&1 < /dev/null & echo "started $log pid=$!"; }

case "${1:-}" in
  restart-nimble)
    pkill -f nimble_shim.py; sleep 4
    GPU=2 bg serve-bespoke-nimble-9b.log "$PY" nimble_shim.py \
      --checkpoint "$CK/nimble-9b" --name bespoke-nimble-9b --max-length 8192 \
      --device cuda:0 --host 127.0.0.1 --port 8803
    ;;
  audit-openjev)
    GPU=3 bg audit-openjev.log "$PY" audit_lengths.py --requests "$NVME/s2-requests-all.jsonl" \
      --family openjev --tokenizer Qwen/Qwen3.5-9B --revision c202236235762e1c871ad0ccb60c8ee5ba337b9a \
      --out "$NVME/audit-openjev-lengths.json"
    ;;
  audit-nimble)
    GPU=3 bg audit-nimble.log "$PY" audit_lengths.py --requests "$NVME/s2-requests-all.jsonl" \
      --family nimble --tokenizer "$CK/nimble-9b" --out "$NVME/audit-nimble-lengths.json"
    ;;
  ab-prefix)
    GPU=3 bg ab-prefix.log "$PY" ab_prefix.py \
      --checkpoint "$CK/open-jev-9b/package/checkpoint" \
      --requests "$NVME/s2-requests-sample.jsonl" --limit "${2:-60}" \
      --out "$NVME/ab-prefix-open-jev-qwen-9b.json"
    ;;
  status)
    nvidia-smi --query-gpu=index,utilization.gpu,memory.used --format=csv,noheader
    echo "--- listeners ---"; ss -ltn 2>/dev/null | grep -E ':88[0-9][0-9]' || echo none
    echo "--- procs ---"; pgrep -af 'openjev_serve|nimble_shim|audit_lengths|ab_prefix' | sed 's/ --/ \n    --/' | head -40
    ;;
  *) echo "usage: ops.sh {restart-nimble|audit-openjev|audit-nimble|ab-prefix [n]|status}"; exit 2;;
esac
