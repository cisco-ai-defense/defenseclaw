#!/bin/bash
# DefenseClaw configs (c) rules + System One and (d) rules + System One + Gemma 4 31B judge on the compare HOLDOUT sets (public data
# only), with the s7-sysone bench harness (answer cache keyed by sha256 of the exact request body, reused where bodies match).
# Run on defenseclaw-dev (the Gemini key and the AWS credentials live there).
#   bash dc_cascade.sh <label> <c|d> <box path of a harness binary built with -tags s7bench> <box path of its policies dir>
# Rate: <= 250 RPM and <= 150k input tokens/min to gemini-decision-1 in all (2 harness processes x 125 RPM x 75k TPM), own
# request budget file, cap 30,000 requests. Judge (d): Gemma 4 31B on Bedrock through s7proxy.py, cap USD 10, own ledger.
# Both: the user's task is sent as UserPromptSubmit (-prompt-from-content) so intent-aware layers see what AlignmentCheck sees.
set -euo pipefail
L=$1 MODE=$2 BIN=$3 POL=$4
CFG=$HOME/dc-eh/ssh/config; BOX=${BOX:-dc-s7-bench2}
B() { ssh -n -F $CFG -o BatchMode=yes -o ControlPath=none $BOX "$@"; }
ALLOW=$(B "python3 -c 'import json; print(\"+\".join(json.load(open(\"/home/ubuntu/s7c/corpora_compare_h.json\"))))'")
B "umask 077; mkdir -p -m 700 ~/s7c/secrets ~/s7c/sysone/cache/go"
rsync -a --chmod=F600 -e "ssh -F $CFG -o BatchMode=yes -o ControlPath=none" $HOME/dc-eh/secrets/s7/gemini.key $BOX:s7c/secrets/$L.dmkey >/dev/null
DM="-dm-url,https://generativelanguage.googleapis.com/v1beta/decisions,-dm-model,gemini-decision-1,-dm-protocol,gemini-decisions,-dm-allow-corpus,$ALLOW,-dm-cache-dir,/home/ubuntu/s7c/sysone/cache/go,-dm-cache-inflight,4,-dm-cache-rpm,125,-dm-cache-tpm,75000,-dm-cache-budget-file,/home/ubuntu/s7c/sysone/budget-cmp-$L,-dm-cache-budget,30000,-prompt-from-content"
tpid=""; ppid=""
if [ "$MODE" = c ]; then
  HA="-dm-hook,-dm-hook-connectors,all,$DM"
else
  JD=$HOME/dc-eh/evidence/rel-1-0-10/s7/compare/judge; mkdir -p $JD
  port=$((19000 + RANDOM % 900))
  python3 $HOME/dc-eh/jobs/s7-corpus/s7proxy.py --port $port --log $JD/calls-$L.jsonl --ledger $JD/spend-$L.json --cache $JD/cache.tsv --cap-usd 10 --conc 16 > $JD/proxy-$L.err 2>&1 < /dev/null &
  ppid=$!
  ssh -F "$CFG" -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ControlMaster=no -o ControlPath=none -R 127.0.0.1:$port:127.0.0.1:$port $BOX < /dev/null > $JD/tunnel-$L.err 2>&1 &
  tpid=$!
  HA="-strategy,regex_judge,-judge-model,gemma-4-31b,-judge-url,http://127.0.0.1:$port/v1,-answer-within-ms,3700,$DM"
fi
trap '[ -n "$tpid" ] && kill $tpid $ppid 2>/dev/null; B "rm -f ~/s7c/secrets/$L.dmkey"' EXIT
B "cd ~/s7c && mkdir -p gate && nice -n 15 python3 -I s7gate.py all --bin $BIN --policy-dir $POL --corpora corpora_compare_h.json --out ~/s7c/gate/$L --gomaxprocs 4 --workers 2 --parallel 2 --connector auto --packs default --dm-key-file /home/ubuntu/s7c/secrets/$L.dmkey --harness-args=$HA > gate/$L.log 2>&1; echo __DONE__ rc=\$? >> gate/$L.log; tail -2 gate/$L.log"
