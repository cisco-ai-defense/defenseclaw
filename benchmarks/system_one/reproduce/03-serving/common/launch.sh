#!/bin/bash
set -euo pipefail
export HF_HOME=/opt/dlami/nvme/hf
ROOT=$WORK/sysone
PY=$ROOT/venv/bin/python
CK=/opt/dlami/nvme/checkpoints
LOGS=$ROOT/logs
mkdir -p "$LOGS"

cd "$ROOT/Open-Jev"
"$PY" -m pip -q install -e . --no-deps 2>&1 | tail -2
"$PY" -c "import jev, jev.server, jev.serving; print('jev importable')"

launch() {
  local gpu=$1 port=$2 log=$3; shift 3
  if ss -ltn 2>/dev/null | grep -q ":$port "; then echo "port $port already listening, skip"; return; fi
  CUDA_VISIBLE_DEVICES=$gpu HF_HOME=/opt/dlami/nvme/hf \
    setsid nohup "$@" --device cuda:0 --host 127.0.0.1 --port "$port" \
    > "$LOGS/$log" 2>&1 < /dev/null &
  echo "launched gpu=$gpu port=$port log=$log"
}

# GPU0: open-jev-qwen-9b  (ZefanCai/Open-Jev-9B adapter + scalar head on Qwen3.5-9B)
launch 0 8801 serve-open-jev-qwen-9b.log \
  "$PY" "$ROOT/openjev_serve.py" --checkpoint "$CK/open-jev-9b/package/checkpoint" \
  --name open-jev-qwen-9b --repo-id ZefanCai/Open-Jev-9B --batch-size 32

# GPU1: open-jev-qwen-2b
launch 1 8802 serve-open-jev-qwen-2b.log \
  "$PY" "$ROOT/openjev_serve.py" --checkpoint "$CK/open-jev-2b/package/checkpoint" \
  --name open-jev-qwen-2b --repo-id ZefanCai/Open-Jev-2B --batch-size 32

# GPU2: bespoke-nimble-9b (same Qwen3.5-9B base, different adapter, letter-code readout)
launch 2 8803 serve-bespoke-nimble-9b.log \
  "$PY" "$ROOT/nimble_shim.py" --checkpoint "$CK/nimble-9b" --max-length 8192

sleep 5
echo "=== launched; tailing ==="
for f in serve-open-jev-qwen-9b.log serve-open-jev-qwen-2b.log serve-bespoke-nimble-9b.log; do
  echo "--- $f ---"; tail -3 "$LOGS/$f" 2>/dev/null || true
done
