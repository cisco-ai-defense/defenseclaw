#!/bin/bash
# On the GPU box: every guard model on every set (both sides), then its latency on the shared 800-event sample.
#   bash gpu_all.sh [model ...]
set -uo pipefail
cd "$(dirname "$0")"
export CUDA_HOME=/opt/pytorch/cuda PATH=/opt/pytorch/cuda/bin:$HOME/cmp/venv/vllm/bin:$PATH HF_HOME=$HOME/cmp/hf HF_HUB_OFFLINE=1
SETS=agentdojo,mcptox,injecagent,mcphunt,dtap,agentic-redteam,nemotron-terminal,extra-public,llm-labelled-augur,prompt-agentdojo,tool-result-agentdojo,windows-shell-public
mkdir -p ~/s7c/compare/logs
for m in ${*:-llama-guard-4 granite-guardian-3.3 qwen3guard-8b}; do
  python gpu_run.py --model $m --sets $SETS --sides holdout,tune > ~/s7c/compare/logs/gpu-$m.log 2>&1; echo "$m run rc=$?"
  python gpu_run.py --model $m --latency ~/s7c/compare/latency-sample.jsonl > ~/s7c/compare/logs/gpu-$m-lat.log 2>&1; echo "$m latency rc=$?"
  grep -E "^\[|^\{" ~/s7c/compare/logs/gpu-$m.log ~/s7c/compare/logs/gpu-$m-lat.log | tail -30
done
