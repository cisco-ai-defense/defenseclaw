#!/bin/bash
# On the host with the worktree: pull the scored results, latency files and run metadata off the bench box into the evidence
# folder, then build the docs data file and the COMPARE.md tables.
#   bash finalize.sh <bench box ssh alias> <evidence dir> <worktree>
set -euo pipefail
BOX=$1 EV=$2 WT=$3
E="ssh -F $HOME/dc-eh/ssh/config -o BatchMode=yes -o ControlPath=none"
mkdir -p $EV/runs $EV/latency $EV/raw-versions
rsync -a -e "$E" $BOX:s7c/compare/results.json $BOX:s7c/compare/sets/SETS.json $EV/
rsync -a -e "$E" --include='*/' --include='RUN.json' --include='COVERAGE.json' --include='THRESHOLDS.json' --include='SUMMARY.md' --include='scores/***' --exclude='*' $BOX:s7c/compare/runs/ $EV/runs/
rsync -a -e "$E" $BOX:s7c/compare/latency/ $EV/latency/
rsync -a -e "$E" --include='*/' --include='VERSION.json' --exclude='*' $BOX:s7c/compare/raw/ $EV/raw-versions/
rsync -a -e "$E" $BOX:cmp/locks/ $EV/locks/ 2>/dev/null || true
python3 $WT/benchmarks/compare/export.py --results $EV/results.json --sets $EV/SETS.json --latency-dir $EV/latency --meta $WT/benchmarks/compare/meta.json \
  --out-json $WT/docs-site/data/guardrail-compare.json --out-md $EV/tables.md
cp $WT/docs-site/data/guardrail-compare.json $EV/
echo "evidence: $EV; docs data: $WT/docs-site/data/guardrail-compare.json"
