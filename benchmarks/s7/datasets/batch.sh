#!/bin/bash
# DATA-A batch runner on the box: build each id (fetch+normalize+convert), one log per id, summary rows to ~/s7c/dsets/report.tsv
# usage: batch.sh <step> id...   (step: build|convert|normalize|fetch). HFTOK=<file> passes --hf-token-file.
cd "$(dirname "$0")" || exit 1
step=$1; shift
mkdir -p ~/s7c/dsets/logs
for id in "$@"; do
  l=~/s7c/dsets/logs/$(echo "$id" | tr '/' '_').log
  ~/dvenv/bin/python -I s7_datasets.py $step "$id" ${HFTOK:+--hf-token-file $HFTOK} --corpus-dir ~/s7c/corpora/dsets --report ~/s7c/dsets/report.tsv > "$l" 2>&1
  echo "$id rc=$? $(grep -E '^[^ ]+: (kept|0 rows|fetched|FAILED|already)' "$l" | tail -2 | cut -c1-250 | tr '\n' '|')"
done
