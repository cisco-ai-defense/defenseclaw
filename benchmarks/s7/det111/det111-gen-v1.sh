#!/bin/bash
# det111-gen-v1.sh <indir> <outdir> [workers]   DET111 gen run + R-NOLOSS (rel-1-0-10:GAP-1969). Run from the worktree
# root on a build box (DCB_BOX=<box> dcb <worktree> 'bash benchmarks/s7/det111/det111-gen-v1.sh ...'). Fails closed.
#
# <indir> holds the gen inputs listed in gen-inputs-v1.sha256 (checked before the run; any other bytes = NOT-READY):
#   gap-regression, windows-shell, win-credential-paths (evidence/rel-1-0-10/s7/corpus), gaps-A/B/C
#   (plans/r111/detection/corpus), owner-benign (the owner transcript sample: never committed).
# The seeds are the tracked seeds-a64bfdb931.txt. Generators r1,r2w,r2o,r3; routes hook-cc,hook-codex,inspect-oc,llm;
# DET111_BENIGN=700; no native connector shapes: the same inputs every train gen since T20 used.
# DET111_REFS="t20=<dir>,t21f=<dir>,..." names reference gen runs (trains that passed); each one is checked with
# det111-noloss-v2.py (attack_lower, benign_raise, benign_newblock, missing, errors all 0).
# Writes <outdir>/{rows.txt,meta.tsv,stamp.txt,kit.txt,props.txt,noloss-<name>.{txt,tsv}}.
# Last line: DET111GEN PASS|FAIL|NOT-READY run=<rc> <name>=<PASS|FAIL|NOT-READY> ... kit=<sha> sha=<head>
# props (det111cmp.py props) is written for the evidence; it has never passed at any train, so it is not part of the verdict.
set -uo pipefail
in=${1:?indir}; out=${2:?outdir}; n=${3:-40}; here=benchmarks/s7/det111; root=$(pwd)
[ -s $here/det111-run-v5.sh ] && [ -s $here/gen-inputs-v1.sha256 ] || { echo "DET111GEN NOT-READY run it from the worktree root"; exit 2; }
in=$(cd "$in" 2>/dev/null && pwd) || { echo "DET111GEN NOT-READY no input dir $1"; exit 2; }
( cd "$in" && sha256sum --quiet -c "$root/$here/gen-inputs-v1.sha256" ) >&2 || { echo "DET111GEN NOT-READY inputs in $in differ from $here/gen-inputs-v1.sha256"; exit 2; }
u=$(df -P "$(dirname "$out")" 2>/dev/null | awk 'NR==2{print $5+0}'); [ "${u:-100}" -le 85 ] || { echo "DET111GEN NOT-READY disk ${u:-?}% used"; exit 2; }
refs=(); for r in ${DET111_REFS//,/ }; do d=${r#*=}; [ -s "$d/rows.txt" ] && [ -s "$d/meta.tsv" ] || { echo "DET111GEN NOT-READY reference $r has no rows.txt/meta.tsv"; exit 2; }; refs+=("$r"); done
mkdir -p "$out"; out=$(cd "$out" && pwd)
# The probe's fixture trees and the gateway's own temp folders live in a TMPDIR of this run, not the shared one: a box
# guard that sweeps empty folders of the shared TMPDIR (dc-s7-gates) changed verdicts mid-run (rel-1-0-10:GAP-2113).
export TMPDIR=$(mktemp -d "$(dirname "$out")/det111gen-tmp.XXXXXX") || { echo "DET111GEN NOT-READY no private TMPDIR"; exit 2; }
trap 'rm -rf "$TMPDIR"' EXIT
kit=$(cat $here/det111-run-v5.sh $here/det111-gen-v1.sh $here/det111-noloss-v2.py $here/seeds-a64bfdb931.txt $here/gen-inputs-v1.sha256 internal/gateway/det111_gen_test.go internal/gateway/det111_probe_test.go internal/gateway/det111_rows_test.go | sha256sum | cut -c1-16)
printf 'kit=%s sha=%s dirty=%s\n' "$kit" "$(git rev-parse --short=10 HEAD)" "$(git status --porcelain --untracked-files=no | wc -l)" > "$out/kit.txt"
C=$in/gap-regression.cases.jsonl,$in/windows-shell.cases.jsonl,$in/win-credential-paths.cases.jsonl,$in/gaps-A.cases.jsonl,$in/gaps-B.cases.jsonl,$in/gaps-C.cases.jsonl
DET111_CASES=$C DET111_SEEDS=$here/seeds-a64bfdb931.txt DET111_BENIGN_CASES=$in/owner-benign.cases.jsonl DET111_BENIGN=700 \
  DET111_GEN=r1,r2w,r2o,r3 DET111_ROUTES=hook-cc,hook-codex,inspect-oc,llm DET111_NATIVE=0 DET111_ONLY= \
  bash $here/det111-run-v5.sh "$out" "$n" > "$out/run.log" 2>&1
run=$?; tail -n 1 "$out/run.log"
python3 $here/det111cmp.py props "$out" --out "$out/props.tsv" > "$out/props.txt" 2>&1; echo "props rc=$? (evidence only)"
verdict=PASS; [ "$run" = 0 ] || verdict=FAIL; line="run=$run"
for r in "${refs[@]}"; do name=${r%%=*}; d=${r#*=}
  python3 $here/det111-noloss-v2.py "$d" "$out" --out "$out/noloss-$name.tsv" > "$out/noloss-$name.txt" 2>&1; rc=$?
  tail -n 1 "$out/noloss-$name.txt"
  case $rc in 0) line="$line $name=PASS";; 1) line="$line $name=FAIL"; verdict=FAIL;; *) line="$line $name=NOT-READY"; [ $verdict = FAIL ] || verdict=NOT-READY;; esac
done
[ ${#refs[@]} -gt 0 ] || { line="$line refs=none"; [ $verdict = FAIL ] || verdict=NOT-READY; }
echo "DET111GEN $verdict $line kit=$kit sha=$(git rev-parse --short=10 HEAD)"
case $verdict in PASS) exit 0;; FAIL) exit 1;; *) exit 2;; esac
