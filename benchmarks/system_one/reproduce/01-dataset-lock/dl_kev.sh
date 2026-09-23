#!/bin/bash
export HF_HOME=/opt/dlami/nvme/kevbench/hf
cd /opt/dlami/nvme/kevbench
./venv/bin/python - <<'PY'
from huggingface_hub import snapshot_download
a = snapshot_download("jaredpalmer/kev-9b", revision="2629c06a5aeb0feb3b9783bafed17ed8f39ecf5c")
print("ADAPTER", a, flush=True)
b = snapshot_download("Qwen/Qwen3.5-9B-Base", revision="68c46c4b3498877f3ef123c856ecfde50c39f404")
print("BASE", b, flush=True)
PY
git clone -q https://github.com/jaredpalmer/kev.git /opt/dlami/nvme/kevbench/kev-src 2>&1 || echo "CLONE_FAILED"
echo "DL_DONE"
