#!/bin/bash
# run_layers.sh <judge-model> <dm-model|-> <ids-file> <out-name> [extra s7bench flags]
[ "$(uname -s)" = Linux ] || { echo refusing; exit 99; }
JM=$1 DM=$2 IDS=$3 NAME=$4; shift 4
B=~/dc-eh/wt/s7-bench
OUT=~/dc-eh/evidence/rel-1-0-10/s7/bench/models/runs
mkdir -p $OUT
DMF=(); LAY=judge
if [ "$DM" != "-" ]; then DMF=(-dm-url http://127.0.0.1:18991/v1/systemone -dm-model $DM -dm-timeout 60); LAY=dm,judge; fi
[ -n "$LAYERS" ] && LAY=$LAYERS
for corpus in s3 s2; do
  GOMAXPROCS=2 nice -n 15 $B/.s7out/s7bench -corpus ~/.system-one-data/outputs/$corpus/cases.jsonl -ids $IDS \
    -out $OUT/$NAME-$corpus.jsonl -policy-dir $B/policies -pack default -workers ${WORKERS:-24} -layers $LAY \
    -judge-model $JM -judge-url http://127.0.0.1:18991/v1 -judge-timeout 120 "${DMF[@]}" "$@" \
    2> >(grep -v "applying migration\|notification suppressed" > $OUT/$NAME-$corpus.err)
  echo "$NAME $corpus rc=$? $(date -u +%T)" >> $OUT/RUN.txt
done
