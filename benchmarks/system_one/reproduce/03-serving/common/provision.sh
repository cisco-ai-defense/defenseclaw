#!/bin/bash
# Provision the GPU host for System One benchmarking of three LoRA adapters.
# Read-only with respect to every pre-existing artifact: /opt/openjev-venv is
# reused via a .pth path entry and never written to.
set -euo pipefail

ROOT=$WORK/sysone
SHARED=/opt/openjev-venv/lib/python3.12/site-packages
VENV=$ROOT/venv
SP=$VENV/lib/python3.12/site-packages

mkdir -p "$ROOT" "$ROOT/logs"

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi

# Share the already-installed torch/transformers/hf-hub stack read-only instead of
# re-downloading ~5 GB of CUDA wheels. Our own site-packages takes precedence, so
# locally installed peft/accelerate win over anything in the shared tree.
echo "$SHARED" > "$SP/zz_shared_openjev.pth"

"$VENV/bin/python" -m pip -q install --upgrade pip setuptools wheel 2>&1 | tail -2

# peft + accelerate are absent from every existing venv on this host.
"$VENV/bin/python" -m pip -q install "peft==0.21.0" "accelerate==1.15.0" 2>&1 | tail -5

echo "=== import check ==="
"$VENV/bin/python" - <<'PY'
import torch, transformers, peft, accelerate, huggingface_hub
print("torch", torch.__version__, "cuda", torch.version.cuda, "avail", torch.cuda.is_available(), "n", torch.cuda.device_count())
print("transformers", transformers.__version__, "peft", peft.__version__, "accelerate", accelerate.__version__, "hub", huggingface_hub.__version__)
print("bf16", torch.cuda.is_bf16_supported())
from transformers import Qwen3_5ForConditionalGeneration, AutoModelForImageTextToText
print("Qwen3_5 classes OK")
PY

echo "=== clone loaders ==="
cd "$ROOT"
[ -d Open-Jev ]  || git clone --depth 1 -q https://github.com/Zefan-Cai/Open-Jev.git
[ -d nimble ]    || git clone --depth 1 -q https://github.com/bespokelabsai/nimble.git

echo "=== disk before download ==="
df -h / | tail -1
exit 0
