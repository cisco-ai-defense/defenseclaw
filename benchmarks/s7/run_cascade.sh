#!/bin/bash
# run_cascade.sh <strategy> <judge-model|-> <ids-file> <out-name> [extra s7bench flags]
# Full hook-path cascade on the real claudecode hook: rules, then (strategy) the LLM
# judge through the local spend-capped proxy (port 18992). No decision model: no real
# System One endpoint is available (BENCH-cascade.md). The hook's answer wait is sent
# (ANSWER_MS, default 3700 -> the gateway's 3.4 s judge window), so a late judge answer
# keeps the rule verdict exactly as on a live Claude Code hook.
[ "$(uname -s)" = Linux ] || { echo refusing; exit 99; }
ST=$1 JM=$2 IDS=$3 NAME=$4; shift 4
B=~/dc-eh/wt/s7-cascade
OUT=~/dc-eh/evidence/rel-1-0-10/s7/cascade/runs
mkdir -p $OUT
JF=()
[ "$JM" != "-" ] && JF=(-judge-model $JM -judge-url http://127.0.0.1:18992/v1)
for corpus in ${CORPORA:-s3 s2}; do
  GOMAXPROCS=3 nice -n 15 $B/.s7out/s7bench -corpus ~/.system-one-data/outputs/$corpus/cases.jsonl -ids $IDS \
    -out $OUT/$NAME-$corpus.jsonl -policy-dir $B/policies -pack ${PACK:-default} -workers ${WORKERS:-12} \
    -strategy $ST -answer-within-ms ${ANSWER_MS:-3700} "${JF[@]}" "$@" \
    2> >(grep -v "applying migration\|notification suppressed" > $OUT/$NAME-$corpus.err)
  echo "$NAME $corpus rc=$? $(date -u +%T)" >> $OUT/RUN.txt
done
