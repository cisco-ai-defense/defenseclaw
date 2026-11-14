#!/bin/bash
# DefenseClaw configs (c) rules + System One and (d) rules + System One + Gemma 4 31B judge on the compare HOLDOUT sets (public data
# only), with the s7-sysone bench harness (answer cache keyed by sha256 of the exact request body, reused where bodies match).
# Run on the host that holds the Gemini key and the AWS credentials; the harness runs on the bench box BOX (an ssh alias).
#   bash dc_cascade.sh <label> <fill|c|d> <box path of a harness binary built with -tags s7bench> <box path of its policies dir>
# fill: every System One request is sent with a 30 s timeout and its answer cached (the product's own 1-3.4 s budget plus the
#       relay's rate pacing would trip the 30 s breaker and skip whole stretches of calls; s7-sysone's method). Repeat until a
#       replay reports offline_misses=0. What converged on the compare sets (2026-11-14): one harness process, one case at a
#       time, a short pace interval: FW=1 PAR=1 INFL=1 RPM=200 TPM=140000 CHUNK=100; more processes trip the breaker more often.
# Env knobs: FW (fill workers), PAR (harness processes), INFL/RPM/TPM (relay pacing per process), BUDGET (request cap),
#       CHUNK (cases per shard), ONLY (comma list of corpora).
# c, d: the scored runs, cache-only replays through the real hook path at the product's default timeout (every System One answer
#       real and instant). d adds the Gemma 4 judge (live through s7proxy, cap USD 10, answer window 3.7 s).
# Rate: <= 250 RPM and <= 150k input tokens/min to gemini-decision-1 in all (2 harness processes x 125 RPM x 62k TPM (the pacer estimates tokens about 10% low)), own
# request budget file, cap 30,000 requests. Judge (d): Gemma 4 31B on Bedrock through s7proxy.py, cap USD 10, own ledger.
# Both: the user's task is sent as UserPromptSubmit (-prompt-from-content) so intent-aware layers see what AlignmentCheck sees.
set -euo pipefail
L=$1 MODE=$2 BIN=$3 POL=$4
CFG=$HOME/dc-eh/ssh/config; BOX=${BOX:?set BOX to the bench box ssh alias}
B() { ssh -n -F $CFG -o BatchMode=yes -o ControlPath=none $BOX "$@"; }
ALLOW=$(B "python3 -c 'import json; print(\"+\".join(json.load(open(\"/home/ubuntu/s7c/corpora_compare_h.json\"))))'")
B "umask 077; mkdir -p -m 700 ~/s7c/secrets ~/s7c/sysone/cache/go"
rsync -a --chmod=F600 -e "ssh -F $CFG -o BatchMode=yes -o ControlPath=none" $HOME/dc-eh/secrets/s7/gemini.key $BOX:s7c/secrets/$L.dmkey >/dev/null
DM="-dm-url,https://generativelanguage.googleapis.com/v1beta/decisions,-dm-model,gemini-decision-1,-dm-protocol,gemini-decisions,-dm-allow-corpus,$ALLOW,-dm-cache-dir,/home/ubuntu/s7c/sysone/cache/go,-dm-cache-inflight,${INFL:-4},-dm-cache-rpm,${RPM:-83},-dm-cache-tpm,${TPM:-42000},-dm-cache-budget-file,/home/ubuntu/s7c/sysone/budget-cmp-$L,-dm-cache-budget,${BUDGET:-30000},-prompt-from-content"
tpid=""; ppid=""
if [ "$MODE" = fill ]; then
  HA="-dm-hook,-dm-hook-connectors,all,-dm-timeout,30,-answer-within-ms,30000,$DM"; WORKERS=${FW:-2}
elif [ "$MODE" = c ]; then
  HA="-dm-hook,-dm-hook-connectors,all,-dm-cache-only,$DM"
else
  JD=$HOME/dc-eh/evidence/rel-1-0-10/s7/compare/judge; mkdir -p $JD
  port=$((19000 + RANDOM % 900))
  python3 $HOME/dc-eh/jobs/s7-corpus/s7proxy.py --port $port --log $JD/calls-$L.jsonl --ledger $JD/spend-$L.json --cache $JD/cache.tsv --cap-usd 10 --conc 16 > $JD/proxy-$L.err 2>&1 < /dev/null &
  ppid=$!
  ssh -F "$CFG" -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ControlMaster=no -o ControlPath=none -R 127.0.0.1:$port:127.0.0.1:$port $BOX < /dev/null > $JD/tunnel-$L.err 2>&1 &
  tpid=$!
  HA="-strategy,regex_judge,-judge-model,gemma-4-31b,-judge-url,http://127.0.0.1:$port/v1,-answer-within-ms,3700,-dm-cache-only,$DM"
fi
trap '[ -n "$tpid" ] && kill $tpid $ppid 2>/dev/null; B "rm -f ~/s7c/secrets/$L.dmkey"' EXIT
B "cd ~/s7c && mkdir -p gate && nice -n 15 python3 -I s7gate.py all --bin $BIN --policy-dir $POL --corpora corpora_compare_h.json --out ~/s7c/gate/$L --gomaxprocs 4 --workers ${WORKERS:-2} --parallel ${PAR:-3} --chunk ${CHUNK:-2500} ${ONLY:+--only $ONLY} --connector auto --packs default --dm-key-file /home/ubuntu/s7c/secrets/$L.dmkey --harness-args=$HA > gate/$L.log 2>&1; echo __DONE__ rc=\$? >> gate/$L.log; tail -2 gate/$L.log"
