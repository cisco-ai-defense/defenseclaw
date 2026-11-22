#!/bin/bash
# rerun_cmp.sh <rundir>: recompare existing views
W=${1:-/var/tmp/pwsho/run1}; cd "$(git rev-parse --show-toplevel)"
python3 scripts/pwshoracle/compare.py $W/pub.oview.jsonl $W/pub.uview.jsonl $W/pub.ids $W/pub --public > /dev/null
python3 scripts/pwshoracle/compare.py $W/priv.oview.jsonl $W/priv.uview.jsonl $W/priv.ids $W/priv > /dev/null
