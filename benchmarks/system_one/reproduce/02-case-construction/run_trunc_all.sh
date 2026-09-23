#!/bin/bash
set -u
D=$WORK/.system-one-data/outputs
O=$D/secjudge/truncation
export PYTHONPATH=$WORK/.secjudge-deps
PY=$WORK/.von-venv/bin/python
cd $WORK/.system-one-data/outputs/secjudge/code
for spec in "s2:$D/s2/cases.jsonl" "intent-real:$D/intent-real/cases.jsonl" "toolcall-labels:$D/toolcall-labels/cases.jsonl" "s3:$D/s3/cases.jsonl"; do
  stage=${spec%%:*}; cases=${spec#*:}
  echo "=== $stage start $(date -Is) ==="
  $PY secjudge_trunc.py --cases "$cases" --stage "$stage" --variants C0,C7 \
      --out "$O/$stage.json" --per-decision-out "$O/$stage-per-decision.jsonl" > "$O/$stage.summary.txt" 2>&1
  echo "=== $stage rc=$? $(date -Is) ==="
done
echo ALLDONE
