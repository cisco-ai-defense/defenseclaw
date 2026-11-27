#!/bin/bash
# det111-run-v5.sh <outdir> [shards]   run the DET111 probe on a build box, from the worktree root.
# Env passed through: DET111_CASES (comma list of case-v1 files, repo-relative or absolute), DET111_GEN, DET111_SEEDS,
# DET111_BENIGN, DET111_BENIGN_CASES, DET111_ROUTES, DET111_NATIVE, DET111_ONLY.
# Output: <outdir>/rows.txt (key|tier|route|verdict), meta.tsv, skipped.txt, stamp.txt, and one line
#   DET111RUN rows=N lines=N errors=N shards=N bad=N sha=<sha> dirty=<0|1>
# bad > 0 (a shard failed, a log has no DET111_ROWS line, or no rows) makes the exit code 1: fail closed.
set -uo pipefail
out=${1:?outdir}; n=${2:-16}
root=$(pwd); mkdir -p "$out"; out=$(cd "$out" && pwd); rm -f "$out"/rows-* "$out"/log-* "$out"/rc-*
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.26.4} GOFLAGS=${GOFLAGS:--p=8}
abs() { local o=""; for f in ${1//,/ }; do case $f in /*) ;; *) f="$root/$f";; esac; o="$o${o:+,}$f"; done; echo "$o"; }
[ -n "${DET111_CASES:-}" ] && export DET111_CASES=$(abs "$DET111_CASES")
[ -n "${DET111_SEEDS:-}" ] && export DET111_SEEDS=$(abs "$DET111_SEEDS")
[ -n "${DET111_BENIGN_CASES:-}" ] && export DET111_BENIGN_CASES=$(abs "$DET111_BENIGN_CASES")
T=/var/tmp/det111run-$$; mkdir -p "$T"
sha=$(git rev-parse --short=10 HEAD 2>/dev/null); dirty=$(git status --porcelain --untracked-files=no 2>/dev/null | wc -l)  # tracked changes only; the corpus inputs are untracked by design
go test -c -o "$T/gw.test" ./internal/gateway || { echo "DET111RUN FAIL compile"; exit 3; }
cd internal/gateway
runshard() {
  local k=$1
  rm -f "$out/rows-$k.txt" "$out/rows-$k.txt.meta" "$out/rows-$k.txt.skipped"
  ( DET111_OUT="$out/rows-$k.txt" DET111_SHARD="$k/$n" nice -n 10 "$T/gw.test" -test.run '^TestDET111Probe$' -test.count=1 -test.timeout 180m 2>&1 | grep -aE '^(DET111_ROWS=|--- FAIL|FAIL|PASS|ok |panic:|fatal error)|_test\.go:[0-9]+:' | tail -n 60 > "$out/log-$k.txt"; echo ${PIPESTATUS[0]} > "$out/rc-$k" )
}
for k in $(seq 0 $((n-1))); do runshard $k & done
wait
# One retry of a shard that failed (a full box disk is the usual cause), at lower concurrency.
retry=0
for k in $(seq 0 $((n-1))); do
  if [ "$(cat "$out/rc-$k" 2>/dev/null)" != 0 ] || ! grep -q '^DET111_ROWS=' "$out/log-$k.txt" 2>/dev/null; then
    cp "$out/log-$k.txt" "$out/log-$k.first-attempt.txt" 2>/dev/null; retry=$((retry+1)); runshard $k
  fi
done
echo "retried shards: $retry" > "$out/retry.txt"
cd "$root"
bad=0
for k in $(seq 0 $((n-1))); do
  [ "$(cat "$out/rc-$k" 2>/dev/null)" = 0 ] || { bad=$((bad+1)); continue; }
  grep -q '^DET111_ROWS=' "$out/log-$k.txt" || bad=$((bad+1))
done
cat "$out"/rows-*.txt 2>/dev/null | LC_ALL=C sort > "$out/rows.txt.tmp" && mv "$out/rows.txt.tmp" "$out/rows.txt"
cat "$out"/rows-*.txt.meta 2>/dev/null | LC_ALL=C sort > "$out/meta.tsv"
cat "$out"/rows-*.txt.skipped 2>/dev/null | LC_ALL=C sort -u > "$out/skipped.txt"
lines=$(wc -l < "$out/rows.txt"); rows=$(wc -l < "$out/meta.tsv")
errors=$(grep -c '|error' "$out/rows.txt")
[ "$rows" -gt 0 ] || bad=$((bad+1))
pd=$(git diff --stat a64bfdb931 HEAD -- . ':!internal/gateway/det111_*' ':!benchmarks/s7/det111' 2>/dev/null | wc -l); [ "$pd" = 0 ] && bi=1 || bi=0
printf 'sha=%s dirty=%s base_identical=%s rows=%s lines=%s errors=%s shards=%s bad=%s date=%s\n' "$sha" "$dirty" "$bi" "$rows" "$lines" "$errors" "$n" "$bad" "$(date -u +%FT%TZ)" > "$out/stamp.txt"
rm -rf "$T" "$out"/rows-*
echo "DET111RUN rows=$rows lines=$lines errors=$errors shards=$n bad=$bad sha=$sha dirty=$dirty"
[ "$bad" = 0 ]
