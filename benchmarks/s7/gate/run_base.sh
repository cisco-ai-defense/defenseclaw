#!/bin/bash
# run on dc-build-1:  bash ~/s7c/run_base.sh <label> <bin> <policy-dir> [only-corpora]   -- one command for a gate run (detached; log ~/s7c/gate/<label>.log)
L=${1:?label}; BIN=${2:?bin}; POL=${3:?policies}; ONLY=${4:-}; shift 4; EXTRA="$*"
cd ~/s7c && mkdir -p gate
nohup setsid bash -c "python3 -I s7gate.py all --bin $BIN --policy-dir $POL --corpora ${CORP:-corpora_all.json} --out ~/s7c/gate/$L --gomaxprocs 3 --workers 6 --parallel ${PAR:-6} ${ONLY:+--only $ONLY} $EXTRA > ~/s7c/gate/$L.log 2>&1; echo __DONE__ rc=\$? >> ~/s7c/gate/$L.log" > /dev/null 2>&1 < /dev/null &
echo started $L
