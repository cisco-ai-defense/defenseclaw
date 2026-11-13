#!/bin/bash
# Latency + throughput of every CPU competitor on the shared 800-event sample, one tool at a time on a quiet box (bench2).
#   bash lat_all.sh [tool ...]       tools: pg86 pg22 codeshield llmguard nemo invariant gr lg4cpu
set -uo pipefail
cd "$(dirname "$0")"
CMP=${CMP:-$HOME/cmp}; export HF_HOME=$CMP/hf HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false EMBEDDING_CLASSIFIER_PATH=$CMP/hf/nemoguard-jailbreakdetect
S=$HOME/s7c/compare/latency-sample.jsonl; O=$HOME/s7c/compare/latency; mkdir -p $O
L() { v=$1; shift; PATH="$CMP/venv/$v/bin:$PATH" "$CMP/venv/$v/bin/python" latency.py --sample $S --out $O "$@" 2>&1 | grep -E '^\{' ; }
for t in ${*:-pg86 pg22 codeshield llmguard nemo invariant gr}; do
  echo "== $t $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  case $t in
    pg86) L lf --adapter adapters.lf_promptguard --opt variant=86m --kinds prompt,result ;;
    pg22) L lf --adapter adapters.lf_promptguard --opt variant=22m --kinds prompt,result ;;
    codeshield) L lf --adapter adapters.lf_codeshield --kinds call --par-threads 1 ;;
    llmguard) L llmguard --adapter adapters.llmguard --kinds prompt,result ;;
    nemo) L nemo --adapter adapters.nemo ;;
    invariant) L invariant --adapter adapters.invariant --par-threads 1 ;;
    gr) L gr --adapter adapters.guardrailsai ;;
    lg4cpu) L lg4 --adapter adapters.llamaguard4 --opt device=cpu --kinds prompt,call --every 8 --threads 32 --par 0 ;;
  esac
done
