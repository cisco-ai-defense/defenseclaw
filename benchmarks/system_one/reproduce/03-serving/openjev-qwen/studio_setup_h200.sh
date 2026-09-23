#!/bin/bash
# Bring up OpenJev on the 4xH200 studio.
#
# The model is 54.7 GB and each H200 carries 143 GB, so it fits on one GPU. Four
# independent single-GPU replicas therefore give far more throughput than one
# tensor-parallel copy, and this workload is many small independent requests rather
# than a few long ones.
#
# Everything lives under this studio's own directory: /teamspace is read-only and
# shared with other studios in the teamspace.
set -uo pipefail
ROOT=/teamspace/studios/this_studio/openjev
mkdir -p "$ROOT"
LOG="$ROOT/setup.log"
exec >>"$LOG" 2>&1
echo "=== setup start $(date -u +%FT%TZ) ==="

export HF_HOME="$ROOT/hf"
mkdir -p "$HF_HOME"
df -h "$ROOT" | tail -1

python3 -m venv "$ROOT/venv" 2>/dev/null || true
"$ROOT/venv/bin/pip" install -q --upgrade pip
echo "--- installing vllm ---"
"$ROOT/venv/bin/pip" install -q vllm huggingface_hub
echo "pip rc=$?"
"$ROOT/venv/bin/python" -c "import vllm, torch; print('vllm', vllm.__version__, 'torch', torch.__version__, 'gpus', torch.cuda.device_count())"

echo "--- downloading openjev/openjev ---"
HF_HOME="$HF_HOME" "$ROOT/venv/bin/python" - <<PY
import os
from huggingface_hub import snapshot_download
p = snapshot_download("openjev/openjev", local_dir="$ROOT/model", max_workers=16)
total = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(p) for f in fs)
print("downloaded to", p)
print("bytes on disk: %.1f GB" % (total / 1e9))
PY
echo "download rc=$?"
echo "--- serve docs shipped with the model ---"
sed -n '1,60p' "$ROOT/model/serve/SERVE.md" 2>/dev/null || echo "no SERVE.md"
echo "=== setup done $(date -u +%FT%TZ) ==="
