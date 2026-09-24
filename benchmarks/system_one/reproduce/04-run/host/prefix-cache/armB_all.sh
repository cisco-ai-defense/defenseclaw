#!/bin/bash
D=$WORK/prefix-unit-test
ARM=armB-default784
echo "########## $ARM P1-cases20-cold ##########"
date -u
"$D/run_load.sh" 8769 "$ARM-P1-cases20-cold" $WORK/.system-one-data/outputs/cache/cases20.jsonl
"$D/gsnap.sh" 8004 "$ARM-P1-cases20-cold"
echo
"$D/arm_passes.sh" "$ARM" 8004 8769
