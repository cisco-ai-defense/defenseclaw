#!/bin/bash
# Phase 1 oracle run: dedupe corpora, dump with pwsh 7 in parallel chunks, build views, compare with psparse.
# Run through dcb on the build box: DCB_BOX=dc-s7-gates dcb r111-det-pwsh-a "bash scripts/pwshoracle/run_all.sh <outdir> <go.b64>"
set -eu -o pipefail
W=${1:-/var/tmp/pwsho/run1}; REC=${2:-/var/tmp/pwsho/go.b64}; N=${N:-16}
mkdir -p $W; cd "$(git rev-parse --show-toplevel)"
python3 scripts/pwshoracle/dedupe.py $W --rec $REC
go build -o $W/psview ./scripts/pwshoracle/psview
for set in pub priv; do
  rm -rf $W/$set.chunks; mkdir -p $W/$set.chunks
  n=$(wc -l < $W/$set.b64); per=$(( (n + N - 1) / N ))
  split -l $per -d -a 2 $W/$set.b64 $W/$set.chunks/c
  base=0; pids=""
  for c in $(ls $W/$set.chunks/c?? ); do
    pwsh -NoLogo -NoProfile -File scripts/pwshoracle/pwsh_oracle_dump.ps1 -InFile $c -OutFile $c.oracle.jsonl &
    pids="$pids $!"
  done
  for p in $pids; do wait $p; done
  : > $W/$set.oracle.jsonl; : > $W/$set.oview.jsonl; base=0
  for c in $(ls $W/$set.chunks/c?? ); do
    cat $c.oracle.jsonl >> $W/$set.oracle.jsonl
    python3 scripts/pwshoracle/oracle_view.py $c.oracle.jsonl $base >> $W/$set.oview.jsonl
    base=$(( base + $(wc -l < $c) ))
  done
  cp $W/$set.chunks/c00.oracle.jsonl.version $W/$set.oracle.version
  $W/psview $W/$set.b64 $W/$set.uview.jsonl
  if [ $set = pub ]; then pubflag=--public; else pubflag=""; fi
  python3 scripts/pwshoracle/compare.py $W/$set.oview.jsonl $W/$set.uview.jsonl $W/$set.ids $W/$set $pubflag > /dev/null
  echo "== $set report:"; cat $W/$set.report.md | cut -c1-700
done
