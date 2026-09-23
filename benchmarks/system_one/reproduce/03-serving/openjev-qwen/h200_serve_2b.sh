#!/bin/bash
# Launch open-jev-qwen-2b on the H200, loopback only, matching the published L40S controls:
# Open-Jev commit ed45657b, bf16, sdpa (hardcoded in jev/model.py), prefix cache disabled.
set -uo pipefail
R="$HOME/sysone"
PORT="${1:-8791}"
LOG="$R/logs/serve-2b-$PORT.log"
export HF_HOME="$R/hf"

# Stop only a server already bound to this exact port (never a pattern that self-matches).
OLD=$(ss -ltnp 2>/dev/null | grep "127.0.0.1:$PORT " | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -1)
if [ -n "${OLD:-}" ]; then
  echo "stopping previous server on :$PORT (pid $OLD)"
  kill "$OLD" 2>/dev/null
  sleep 4
fi

CUDA_VISIBLE_DEVICES=0 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  setsid nohup "$R/venv-ojev/bin/python" "$R/openjev_serve.py" \
  --checkpoint "$R/checkpoints/open-jev-2b/package/checkpoint" \
  --name open-jev-qwen-2b --repo-id ZefanCai/Open-Jev-2B \
  --batch-size 32 --no-prefix-cache \
  --device cuda:0 --host 127.0.0.1 --port "$PORT" \
  > "$LOG" 2>&1 < /dev/null &

for _ in $(seq 120); do
  if curl -s -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -q ready; then
    echo "READY on :$PORT"
    break
  fi
  sleep 2
done

echo "fast_path_warnings=$(grep -c 'fast path is not available' "$LOG")"
echo "python_h_errors=$(grep -c 'Python.h' "$LOG")"
echo "cpu_rollback=$(grep -c 'roll back to CPU' "$LOG")"
grep -o '{"url".*' "$LOG" | tail -1
