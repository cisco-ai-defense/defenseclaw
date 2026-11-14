#!/bin/bash
# Materialize + score every competitor config whose raw outputs exist (default thresholds, and tuned where a rule is tunable and
# the tune side was run), build the DefenseClaw views, then aggregate. On the bench box, from ~/cmp/compare.
#   bash score_all.sh <dc-gate-label>[:name] ...        e.g. bash score_all.sh cmp-dc-herm3:dc-rules-herm
set -euo pipefail
cd "$(dirname "$0")"
S7C=$HOME/s7c; RAW=$S7C/compare/raw; RUNS=$S7C/compare/runs
runs=()
for spec in "$@"; do
  g=${spec%%:*}; n=${spec#*:}; [ "$n" = "$spec" ] && n=dc-$g
  python3 -I dcview.py --gate-label "$g" --name "$n" --score > /dev/null
  runs+=("$n")
done
for cfg in $(python3 -I -c 'import sys; sys.path.insert(0, "."); from configs import CONFIGS; print(" ".join(sorted(CONFIGS, key=lambda c: bool(CONFIGS[c].get("thresholds_from")))))'); do
  raws=$(python3 -I -c "import sys; sys.path.insert(0, '.'); from configs import CONFIGS; print(' '.join(sorted({r['raw'] for r in CONFIGS['$cfg']['rules']})))")
  ok=1; for r in $raws; do [ -d "$RAW/$r" ] || ok=0; done
  [ $ok = 1 ] || { echo "skip $cfg (no raw output yet)"; continue; }
  hold_only=0; for r in $raws; do ls $RAW/$r/*.tune.jsonl >/dev/null 2>&1 || hold_only=1; done
  sides=holdout,tune; [ $hold_only = 1 ] && sides=holdout
  python3 -I materialize.py --config "$cfg" --sides $sides --score > $S7C/compare/logs/mat-$cfg.log 2>&1 && runs+=("$cfg") || echo "materialize $cfg failed (see logs/mat-$cfg.log)"
  tunable=$(python3 -I -c "import sys; sys.path.insert(0, '.'); from configs import CONFIGS; c=CONFIGS['$cfg']; print(int(any(r.get('tune') for r in c['rules'])) + int(bool(c.get('thresholds_from'))))")
  if { [ "$tunable" = 1 ] && [ $hold_only = 0 ]; } || [ "$tunable" = 2 ]; then
    python3 -I materialize.py --config "$cfg" --tuned --sides $sides --score > $S7C/compare/logs/mat-$cfg-tuned.log 2>&1 && runs+=("$cfg-tuned") || echo "materialize $cfg --tuned failed"
  fi
done
IFS=,; python3 -I aggregate.py --runs "${runs[*]}" --out $S7C/compare/results.json
