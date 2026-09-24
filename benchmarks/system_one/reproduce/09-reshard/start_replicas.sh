#!/usr/bin/env bash
# Bring up N extra bespoke-nimble-9b replicas on card 3 ONLY.
# Identical to the original card-2 server apart from --port: same checkpoint,
# same --max-length 8192, --device cuda:0 against CUDA_VISIBLE_DEVICES=3.
# nimble_shim.py hardcodes attn_implementation="sdpa"; left exactly as is.
#
# OMP_NUM_THREADS / TOKENIZERS_PARALLELISM are set as command-prefix env vars so
# they are in the environment BEFORE python starts, hence before the torch import.
# Splice-safe: every float reduction here is either on the GPU (where OMP is
# irrelevant) or in jev.metrics.softmax, which is pure-Python math.exp/sum.
set -uo pipefail
N="${1:?usage: start_replicas.sh <n> <first_port>}"
FIRST="${2:?usage: start_replicas.sh <n> <first_port>}"
R=/teamspace/studios/this_studio/sysone
CK=$R/checkpoints
RS=$R/reshard
export HF_HOME="$R/hf"
mkdir -p "$RS/logs"
cd "$R/agree" || exit 91

# Fail fast on the studio-setup hydration hazard: assert serving imports first.
OMP_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
"$R/venv-nimble/bin/python" - <<'PRE' || { echo "PREFLIGHT FAILED"; exit 90; }
import torch, transformers, peft
from transformers import AutoTokenizer, Qwen3_5ForConditionalGeneration
from peft import PeftModel
import jev, jev.api, jev.server, jev.metrics
from jev.api import compile_request, format_response
from jev.server import make_server
from jev.metrics import softmax
assert torch.cuda.is_available(), "cuda not available"
print("preflight ok torch=%s transformers=%s peft=%s cuda=%s cards=%d" %
      (torch.__version__, transformers.__version__, peft.__version__,
       torch.cuda.is_available(), torch.cuda.device_count()))
PRE

for i in $(seq 0 $((N - 1))); do
  port=$((FIRST + i))
  echo "=== card 3 replica on :$port ==="
  CUDA_VISIBLE_DEVICES=3 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  OMP_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
    setsid nohup "$R/venv-nimble/bin/python" "$R/nimble_shim.py" \
    --checkpoint "$CK/nimble-9b" --name bespoke-nimble-9b --max-length 8192 \
    --device cuda:0 --host 127.0.0.1 --port "$port" \
    > "$RS/logs/serve-nimble-$port.log" 2>&1 &
  sleep 20
done

# Weight loading is slow while the studio drive rehydrates from object storage.
# Wait patiently (up to 40 min each); do NOT kill and retry, that multiplies I/O contention.
for i in $(seq 0 $((N - 1))); do
  port=$((FIRST + i))
  ok=no
  for _ in $(seq 480); do
    if curl -s -m 3 "http://127.0.0.1:$port/health" 2>/dev/null | grep -q '"status": "ready"'; then
      ok=yes; break
    fi
    sleep 5
  done
  echo "  :$port ready=$ok"
  [ "$ok" = yes ] && head -1 "$RS/logs/serve-nimble-$port.log" \
    > "$R/runs/nimble-s3/startup-replica-$port.json"
done
nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv,noheader
