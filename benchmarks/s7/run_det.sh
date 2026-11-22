#!/bin/bash
[ "$(uname -s)" = Linux ] || { echo refusing; exit 99; }
B=~/dc-eh/wt/s7-bench
OUT=~/dc-eh/evidence/rel-1-0-10/s7/bench/det
mkdir -p $OUT
cp $B/.s7out/s7bench $OUT/../s7bench.bin.det 2>/dev/null
HEAD=$(git -C $B log -1 --format=%H)
echo "head=$HEAD" > $OUT/RUN.txt
for corpus in s3 s2; do
  for pack in default permissive strict; do
    ( GOMAXPROCS=3 nice -n 15 $B/.s7out/s7bench -corpus ~/.system-one-data/outputs/$corpus/cases.jsonl \
        -out $OUT/$corpus-$pack.jsonl -policy-dir $B/policies -pack $pack -workers 24 \
        2> >(grep -v "applying migration\|notification suppressed" > $OUT/$corpus-$pack.err); \
      echo "$corpus $pack rc=$? $(date -u +%T)" >> $OUT/RUN.txt ) &
  done
  wait
done
echo "all done $(date -u +%T)" >> $OUT/RUN.txt
