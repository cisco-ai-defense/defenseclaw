#!/bin/bash
# Second venv pinned to Open-Jev's documented inference stack (transformers 5.10.2,
# peft 0.19.1). This is what the model card mandates, and it is also the only version
# its request-local prefix cache supports: transformers 5.17.0 changed
# LinearAttentionLayer's constructor, so the cache path raises there.
# torch and the CUDA wheels are shared read-only from /opt/openjev-venv rather than
# re-downloaded; locally installed transformers/peft shadow the shared copies because
# the venv's own site-packages precedes any .pth-appended path.
set -euo pipefail
VENV=$WORK/sysone/venv-ojev
SHARED=/opt/openjev-venv/lib/python3.12/site-packages
SP=$VENV/lib/python3.12/site-packages

[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
echo "$SHARED" > "$SP/zz_shared_openjev.pth"

"$VENV/bin/python" -m pip -q install --upgrade "pip<26" 2>&1 | tail -1
"$VENV/bin/python" -m pip -q install --no-deps \
  "transformers==5.10.2" "peft==0.19.1" "accelerate==1.13.0" 2>&1 | tail -3
# tokenizers/safetensors ABI must match transformers 5.10.2; let pip resolve just those.
"$VENV/bin/python" -m pip -q install "tokenizers>=0.22,<0.24" 2>&1 | tail -2 || true

"$VENV/bin/python" - <<'PY'
import torch, transformers, peft
print("torch", torch.__version__, "cuda avail", torch.cuda.is_available())
print("transformers", transformers.__version__, "peft", peft.__version__)
from transformers import AutoModelForImageTextToText
from transformers.cache_utils import DynamicCache, LinearAttentionLayer
import inspect
print("LinearAttentionLayer signature:", inspect.signature(LinearAttentionLayer.__init__))
PY

cd $WORK/sysone/Open-Jev
"$VENV/bin/python" -m pip -q install -e . --no-deps 2>&1 | tail -1
"$VENV/bin/python" -c "import jev.prefix_cache; print('jev.prefix_cache importable')"
echo PROVISIONED
