#!/bin/bash
# Run every competitor adapter on the comparison sets, then materialize, score and aggregate. On the bench box, from ~/cmp/compare.
#   bash run_all.sh [step ...]       steps: pg86 pg22 codeshield llmguard nemo invariant gr lg4 align materialize aggregate
# Score-based CPU tools run both sides (the tune side is where thresholds are fitted); LLM-backed tools (AlignmentCheck,
# Llama Guard 4) run the holdout side only and use their native decisions, so they need no tune side.
set -euo pipefail
cd "$(dirname "$0")"
CMP=${CMP:-$HOME/cmp}; export HF_HOME=$CMP/hf TOKENIZERS_PARALLELISM=false   # public repos may be fetched once into HF_HOME; the gated Meta weights are already there
export EMBEDDING_CLASSIFIER_PATH=$CMP/hf/nemoguard-jailbreakdetect
SETS=agentdojo,mcptox,injecagent,mcphunt,dtap,agentic-redteam,nemotron-terminal,extra-public,llm-labelled-augur,prompt-agentdojo,tool-result-agentdojo,windows-shell-public
LOGS=$HOME/s7c/compare/logs; mkdir -p $LOGS
py() {   # exit 3 = a worker died and the run stopped for a resume: rerun (rows and the answer cache are kept), at most 8 times
  set -- "$@" ${RUN_EXTRA:-}
  for try in 1 2 3 4 5 6 7 8; do
    PATH="$CMP/venv/$1/bin:$PATH" "$CMP/venv/$1/bin/python" "${@:2}" && return 0
    rc=$?; [ $rc = 3 ] || return $rc
  done
  return 3
}   # semgrep (CodeShield, Invariant) is a venv console script
steps=${*:-pg86 pg22 codeshield llmguard nemo invariant gr}
for s in $steps; do
  case $s in
    pg86) py lf run.py --adapter adapters.lf_promptguard --opt variant=86m --sets $SETS --workers ${W:-12} --threads ${T:-2} >> $LOGS/pg86.log 2>&1 ;;
    pg22) py lf run.py --adapter adapters.lf_promptguard --opt variant=22m --sets $SETS --workers ${W:-12} --threads ${T:-2} >> $LOGS/pg22.log 2>&1 ;;
    codeshield) py lf run.py --adapter adapters.lf_codeshield --sets $SETS --workers ${W:-12} --threads 1 >> $LOGS/codeshield.log 2>&1 ;;
    llmguard) py llmguard run.py --adapter adapters.llmguard --sets $SETS --workers ${W:-12} --threads ${T:-2} >> $LOGS/llmguard.log 2>&1 ;;
    nemo) py nemo run.py --adapter adapters.nemo --sets $SETS --workers ${W:-12} --threads ${T:-2} >> $LOGS/nemo.log 2>&1 ;;
    invariant) py invariant run.py --adapter adapters.invariant --sets $SETS --workers ${W:-12} --threads 1 >> $LOGS/invariant.log 2>&1 ;;
    gr) py gr run.py --adapter adapters.guardrailsai --sets $SETS --workers ${W:-12} --threads ${T:-2} >> $LOGS/gr.log 2>&1 ;;
    lg4) py lg4 run.py --adapter adapters.llamaguard4 --sets $SETS --sides holdout --workers ${LG4_WORKERS:-4} --threads ${LG4_THREADS:-15} >> $LOGS/lg4.log 2>&1 ;;
    align) py lf run.py --adapter adapters.lf_alignment --sets $SETS --sides holdout --workers ${AC_WORKERS:-24} --threads 1 >> $LOGS/align.log 2>&1 ;;
    *) echo "unknown step $s" >&2; exit 2 ;;
  esac
  echo "step $s done $(date -u +%FT%TZ)"
done
