#!/bin/bash
# Usage: arm_passes.sh <ARM_LABEL> <VLLM_PORT> <SHIM_PORT>
# Identical pass sequence for every arm so metric deltas are comparable pass-by-pass.
ARM="$1"; VP="$2"; SP="$3"
D=$WORK/prefix-unit-test
SCREEN=$WORK/.system-one-data/outputs/s1-n1000/screen-cases.jsonl
C20=$WORK/.system-one-data/outputs/cache/cases20.jsonl
for pass in "P2-screen200-cold screen $SCREEN" "P3-screen200-warm screen $SCREEN" "P4-cases20-warm c20 $C20"; do
  set -- $pass
  NAME="$1"; CASES="$3"
  echo "########## $ARM $NAME ##########"
  date -u
  "$D/run_load.sh" "$SP" "$ARM-$NAME" "$CASES"
  "$D/gsnap.sh" "$VP" "$ARM-$NAME"
  echo
done
echo "########## $ARM summaries ##########"
$WORK/.system-one-venv/bin/python "$D/summarize.py" "$D/$ARM"-*.jsonl
