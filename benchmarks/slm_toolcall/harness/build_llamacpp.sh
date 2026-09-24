#!/usr/bin/env bash
# CPU-only llama.cpp, for honest GGUF quantized sizes and laptop-shaped CPU throughput.
set -euo pipefail
W=/teamspace/studios/this_studio/laptopguard
cd "$W"
export PATH="$HOME/.local/bin:$PATH"

if [ ! -d llama.cpp/.git ]; then
  git clone -q --depth 1 https://github.com/ggml-org/llama.cpp.git llama.cpp
fi
cd llama.cpp
echo "llama.cpp commit: $(git rev-parse --short HEAD)"

# CPU-only on purpose: these numbers must represent a laptop, not an H200.
cmake -S . -B build -DGGML_CUDA=OFF -DGGML_NATIVE=ON -DLLAMA_CURL=OFF \
      -DCMAKE_BUILD_TYPE=Release > "$W/logs/cmake-config.log" 2>&1
cmake --build build -j 32 --target llama-bench llama-quantize llama-cli \
      > "$W/logs/cmake-build.log" 2>&1
echo "binaries:"
ls -la build/bin/llama-bench build/bin/llama-quantize build/bin/llama-cli

# gguf conversion deps into MY venv only
VIRTUAL_ENV="$W/venv-laptop" uv pip install -q gguf
"$W/venv-laptop/bin/python" -c "import gguf; print('gguf', gguf.__version__)"
echo "LLAMACPP BUILD OK"
