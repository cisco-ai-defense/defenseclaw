#!/usr/bin/env bash
# One dispatcher per nimble replica. Claims chunks from the end of the case file
# backwards and runs one driver per chunk against its own replica port.
#
# Splice discipline: concurrency 4, timeout 600, same checkpoint, same
# --model-revision, same C7/I3/Q2 + structured cell, same cfg files, server
# --max-length 8192, attn sdpa as hardcoded in nimble_shim.py. Nothing here
# changes a per-row serving condition; throughput comes from more replicas on
# disjoint slices.
#
# Token cap: left at the 200,000,000 default deliberately. A chunk is ~1.5k
# requests (~4.2M input tokens), so the cap cannot bind and the accounting is
# left exactly as the other arms had it.
set -uo pipefail
PORT="${1:?usage: worker.sh <port>}"
R=/teamspace/studios/this_studio/sysone
RS=$R/reshard
PY=$R/venv-nimble/bin/python
export OMP_NUM_THREADS=4
export TOKENIZERS_PARALLELISM=false
REV=93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c
mkdir -p "$RS/claims" "$RS/done" "$RS/logs"

$PY - <<'PRE' || { echo "PREFLIGHT FAILED"; exit 90; }
import requests, jsonschema, json, hashlib
from jsonschema import Draft202012Validator
print("preflight ok requests=%s jsonschema=%s" % (requests.__version__, jsonschema.__version__))
PRE

cd "$R/agree" || exit 91
errors=0

drive () {  # slice out shard extra...
  local slice=$1 out=$2 shard=$3; shift 3
  $PY "$R/benchmark_run_system_one.py" \
    --cases "$slice" \
    --contexts-config cfg/contexts-v1.json \
    --questions-config cfg/questions-v1.json \
    --prediction-schema cfg/system-one-prediction-v1.schema.json \
    --context C7 --instruction I3 --question Q2 --instruction-format structured \
    --endpoint "http://127.0.0.1:$PORT/v1/systemone" \
    --model bespoke-nimble-9b --model-revision "$REV" \
    --run-id "s3-bespoke-nimble-9b-h200-shard$shard" \
    --output "$out" \
    --concurrency 4 --timeout 600 "$@"
}

while true; do
  if [ -e "$RS/STOP" ]; then echo "[:$PORT] STOP present, exiting"; exit 0; fi
  sel=$($PY "$RS/next_chunk.py" 2>>"$RS/logs/claim-$PORT.log")
  crc=$?
  if [ "$crc" -ne 0 ]; then
    errors=$((errors + 1))
    echo "[:$PORT] next_chunk rc=$crc (transient #$errors), retry in 30s"
    if [ "$errors" -ge 20 ]; then echo "[:$PORT] too many claim errors, exiting"; exit 92; fi
    sleep 30; continue
  fi
  if [ -z "$sel" ]; then echo "[:$PORT] no more chunks (met shard0 or exhausted)"; exit 0; fi
  errors=0
  set -- $sel
  chunk=$1; shard=$2; cstart=$3; rstart=$4; nreq=$5; slice=$6
  out=$R/runs/nimble-s3/bespoke-nimble-9b-shard$shard.jsonl
  log=$RS/logs/shard$shard.log
  echo "[:$PORT] $(date -u +%H:%M:%S) START chunk=$chunk shard=$shard cases[$cstart..) req[$rstart..) n=$nreq"
  rc=1
  for attempt in 1 2 3; do
    if [ "$attempt" -gt 1 ] && [ -s "$out" ]; then
      drive "$slice" "$out" "$shard" --resume >>"$log" 2>&1
    else
      drive "$slice" "$out" "$shard" >>"$log" 2>&1
    fi
    rc=$?
    if [ "$rc" -eq 0 ]; then break; fi
    echo "[:$PORT] shard$shard attempt $attempt rc=$rc, retrying" >>"$log"
    sleep 15
  done
  if [ "$rc" -ne 0 ]; then
    echo "[:$PORT] $(date -u +%H:%M:%S) FAILED chunk=$chunk shard=$shard rc=$rc"
    printf '{"chunk":%s,"shard":%s,"status":"failed","rc":%s}\n' "$chunk" "$shard" "$rc" \
      > "$RS/done/$chunk.json"; continue
  fi
  gate=$($PY "$RS/check_chunk.py" "$out.meta.json" "$out" "$nreq" 2>&1); grc=$?
  if [ "$grc" -ne 0 ]; then
    echo "[:$PORT] shard$shard gate failed: $gate ; retrying error rows" >>"$log"
    drive "$slice" "$out" "$shard" --resume --resume-retry-errors >>"$log" 2>&1
    gate=$($PY "$RS/check_chunk.py" "$out.meta.json" "$out" "$nreq" 2>&1); grc=$?
    if [ "$grc" -ne 0 ]; then
      echo "[:$PORT] $(date -u +%H:%M:%S) GATE FAILED chunk=$chunk shard=$shard: $gate"
      printf '{"chunk":%s,"shard":%s,"status":"gate_failed"}\n' "$chunk" "$shard" \
        > "$RS/done/$chunk.json"; continue
    fi
  fi
  printf '{"chunk":%s,"shard":%s,"status":"ok","requests":%s,"port":%s}\n' \
    "$chunk" "$shard" "$nreq" "$PORT" > "$RS/done/$chunk.json"
  echo "[:$PORT] $(date -u +%H:%M:%S) DONE chunk=$chunk shard=$shard n=$nreq gate=$gate"
done
