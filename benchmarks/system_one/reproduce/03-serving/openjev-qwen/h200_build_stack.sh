#!/bin/bash
# Build the pinned System One serving stack on the free H200 studio.
# Pins come from each project's own dependency metadata, not from hand-picked versions:
#   Open-Jev family : the repo's own `[train]` extra -> transformers 5.10.2, peft 0.19.1
#   Nimble          : transformers 5.17.0, peft 0.21.0 (from bespoke-nimble-9b.serving.json)
set -euo pipefail
ROOT="$HOME/sysone"   # /teamspace/studios/this_studio is the writable 922G volume
export HF_HOME="$ROOT/hf"
mkdir -p "$ROOT" "$HF_HOME" "$ROOT/logs" "$ROOT/checkpoints"
cd "$ROOT"

echo "=== [1/5] Open-Jev loader source ==="
if [ ! -d "$ROOT/Open-Jev/.git" ]; then
  git clone --depth 1 https://github.com/Zefan-Cai/Open-Jev.git "$ROOT/Open-Jev"
fi
echo "Open-Jev HEAD: $(git -C "$ROOT/Open-Jev" rev-parse HEAD)"

echo "=== [2/5] venv-ojev (Open-Jev family) ==="
uv venv --python 3.12 "$ROOT/venv-ojev"
uv pip install --python "$ROOT/venv-ojev/bin/python" -e "$ROOT/Open-Jev[train]"
"$ROOT/venv-ojev/bin/python" -c "import jev, jev.server, jev.serving; print('jev importable OK')"

echo "=== [3/5] venv-nimble (Nimble pins) ==="
uv venv --python 3.12 "$ROOT/venv-nimble"
uv pip install --python "$ROOT/venv-nimble/bin/python" \
  "transformers==5.17.0" "peft==0.21.0" torch accelerate safetensors "huggingface_hub[hf_transfer]"

echo "=== [4/5] CUDA / device sanity (both venvs) ==="
for v in venv-ojev venv-nimble; do
  echo "--- $v ---"
  "$ROOT/$v/bin/python" - <<'PY'
import torch
print("torch", torch.__version__, "cuda", torch.version.cuda, "avail", torch.cuda.is_available())
print("device", torch.cuda.get_device_name(0), torch.cuda.get_device_capability(0))
print("arch_list", torch.cuda.get_arch_list())
PY
done

echo "=== [5/5] resolved version record ==="
"$ROOT/venv-ojev/bin/python" - <<'PY'
import json, subprocess, sys, importlib.metadata as md
import torch
pkgs = ["torch","transformers","peft","tokenizers","safetensors","accelerate","numpy","huggingface-hub"]
def ver(p):
    try: return md.version(p)
    except Exception: return None
rec = {
  "venv": "venv-ojev",
  "python": sys.version.split()[0],
  "packages": {p: ver(p) for p in pkgs},
  "torch_cuda": torch.version.cuda,
  "torch_cudnn": torch.backends.cudnn.version(),
  "gpu": torch.cuda.get_device_name(0),
  "compute_capability": ".".join(map(str, torch.cuda.get_device_capability(0))),
  "arch_list": torch.cuda.get_arch_list(),
  "driver": subprocess.run(["nvidia-smi","--query-gpu=driver_version","--format=csv,noheader"],
                           capture_output=True, text=True).stdout.strip(),
}
print(json.dumps(rec, indent=2))
PY

echo "=== BUILD DONE ==="
