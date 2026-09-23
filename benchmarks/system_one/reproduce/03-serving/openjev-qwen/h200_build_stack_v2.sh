#!/bin/bash
# Reproduce the validated single-card H200 stack on the 4x H200 studio.
# Stack identity is the point: drifted versions make arms non-comparable.
#
# Pins, all recovered from published run metadata rather than chosen:
#   Open-Jev family : transformers 5.10.2, peft 0.19.1 (the repo's own [train] extra)
#   Nimble          : transformers 5.17.0, peft 0.21.0
#   loader commit   : ed45657b (what the published 2B was served at; NOT fresh-clone main)
#   fla 0.5.0, accelerate 1.13.0 (Open-Jev's documented L40S environment)
set -euo pipefail
ROOT="$HOME/sysone"
export HF_HOME="$ROOT/hf"
mkdir -p "$ROOT"/{logs,checkpoints,agree/cfg,agree/out}
cd "$ROOT"

# [0/6] FRONT-LOADED: python dev headers. Without these Triton cannot compile its
# driver shim (Python.h not found) and flash-linear-attention silently rolls back to
# CPU -- 99 rows/min at 0% GPU with no error raised. This is the single worst trap.
echo "=== [0/6] python3.12-dev (front-loaded) ==="
if [ ! -f /usr/include/python3.12/Python.h ]; then
  sudo -n apt-get update -qq 2>&1 | tail -1 || true
  sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3.12-dev 2>&1 | tail -2
fi
test -f /usr/include/python3.12/Python.h && echo "Python.h present OK"

echo "=== [1/6] Open-Jev loader pinned at ed45657b ==="
if [ ! -d "$ROOT/Open-Jev/.git" ]; then
  git clone -q https://github.com/Zefan-Cai/Open-Jev.git "$ROOT/Open-Jev"
fi
git -C "$ROOT/Open-Jev" fetch -q --depth 1 origin ed45657bf726c3b77408942830e5578f99df904e
git -C "$ROOT/Open-Jev" checkout -q ed45657bf726c3b77408942830e5578f99df904e
COMMIT=$(git -C "$ROOT/Open-Jev" rev-parse HEAD)
echo "Open-Jev HEAD: $COMMIT"
[ "$COMMIT" = "ed45657bf726c3b77408942830e5578f99df904e" ] || { echo "COMMIT MISMATCH"; exit 1; }

echo "=== [2/6] venv-ojev ==="
uv venv -q --python 3.12 "$ROOT/venv-ojev"
uv pip install -q --python "$ROOT/venv-ojev/bin/python" -e "$ROOT/Open-Jev[train]"
uv pip install -q --python "$ROOT/venv-ojev/bin/python" \
  "flash-linear-attention==0.5.0" requests jsonschema
"$ROOT/venv-ojev/bin/python" -c "import jev, jev.server, jev.serving; print('jev importable OK')"

echo "=== [3/6] venv-nimble ==="
uv venv -q --python 3.12 "$ROOT/venv-nimble"
uv pip install -q --python "$ROOT/venv-nimble/bin/python" \
  "transformers==5.17.0" "peft==0.21.0" torch accelerate safetensors \
  huggingface_hub "flash-linear-attention==0.5.0" requests jsonschema

echo "=== [4/6] verify Triton compiles and fla does NOT fall back to CPU ==="
cat > /tmp/tri_check.py <<'PY'
import warnings, torch, triton, triton.language as tl
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    import fla.utils
    bad = [str(x.message) for x in w if "roll back to CPU" in str(x.message)]
print("fla_cpu_rollback:", bad if bad else "NONE")
@triton.jit
def add1(X, Y):
    i = tl.program_id(0)
    tl.store(Y + i, tl.load(X + i) + 1.0)
x = torch.zeros(8, device="cuda"); y = torch.empty_like(x)
add1[(8,)](x, y); torch.cuda.synchronize()
print("triton_ok:", y.tolist()[:4] == [1.0, 1.0, 1.0, 1.0])
print("cards:", torch.cuda.device_count(), torch.cuda.get_device_name(0),
      torch.cuda.get_device_capability(0))
PY
for v in venv-ojev venv-nimble; do
  echo "--- $v ---"; "$ROOT/$v/bin/python" /tmp/tri_check.py
done

echo "=== [5/6] resolved version record, both venvs ==="
for v in venv-ojev venv-nimble; do
  "$ROOT/$v/bin/python" - "$v" <<'PY'
import importlib.metadata as md, json, subprocess, sys, torch
name = sys.argv[1]
pk = ["torch","transformers","peft","tokenizers","safetensors","accelerate","numpy",
      "huggingface-hub","flash-linear-attention","fla-core","triton","einops"]
def v(p):
    try: return md.version(p)
    except Exception: return None
print(json.dumps({
  "venv": name, "python": sys.version.split()[0],
  "packages": {p: v(p) for p in pk},
  "torch_cuda": torch.version.cuda, "torch_cudnn": torch.backends.cudnn.version(),
  "gpu_count": torch.cuda.device_count(),
  "driver": subprocess.run(["nvidia-smi","--query-gpu=driver_version","--format=csv,noheader"],
                           capture_output=True, text=True).stdout.strip().splitlines()[0],
}, indent=2))
PY
done

echo "=== [6/6] BUILD DONE ==="
