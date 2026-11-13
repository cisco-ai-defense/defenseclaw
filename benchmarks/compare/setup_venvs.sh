#!/bin/bash
# One venv per competitor under $CMP (default ~/cmp/venv), CPU wheels of torch, exact versions (requirements/*.txt pin the
# top-level packages; the resolved set is frozen to requirements/<tool>.lock.txt after install).
#   bash setup_venvs.sh [tool ...]      tools: lf llmguard nemo invariant gr lg4
set -euo pipefail
CMP=${CMP:-$HOME/cmp}
HERE=$(cd "$(dirname "$0")" && pwd)
UV=${UV:-$(command -v uv || echo $HOME/.local/bin/uv)}
TORCH_INDEX=https://download.pytorch.org/whl/cpu
mkdir -p "$CMP/venv" "$CMP/locks"
tools=${*:-lf llmguard nemo invariant gr lg4}
for t in $tools; do
  v=$CMP/venv/$t
  [ -x "$v/bin/python" ] || "$UV" venv -q -p python3.12 "$v"
  # torch from the CPU index first, so no CUDA wheels are pulled on the CPU box (lg4 on a GPU box: TORCH_INDEX=... cu124)
  VIRTUAL_ENV=$v "$UV" pip install -q --index-url "$TORCH_INDEX" torch
  VIRTUAL_ENV=$v "$UV" pip install -q -r "$HERE/requirements/$t.txt"
  VIRTUAL_ENV=$v "$UV" pip freeze > "$CMP/locks/$t.lock.txt"
  echo "venv $t ready ($(wc -l < "$CMP/locks/$t.lock.txt") packages)"
done
# Guardrails AI: no usage metrics leave the box
printf 'id=s7-compare\nenable_metrics=false\nuse_remote_inferencing=false\n' > "$HOME/.guardrailsrc"
