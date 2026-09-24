#!/usr/bin/env bash
# Launch one hosted-Jev arm.
# Args:
#   $1 absolute cases path
#   $2 absolute output path (.jsonl)
#   $3 context      (e.g. C7)
#   $4 instruction  (e.g. I3)
#   $5 question     (e.g. Q2)
#   $6 questions config basename (questions-v1.json | questions-v2.json)
#   $7 max_usd
#   $8 max_calls
#   $9 run_id
set -euo pipefail

CASES="$1"; OUT="$2"; CTX="$3"; INS="$4"; QST="$5"; QCFG="$6"; MAXUSD="$7"; MAXCALLS="$8"; RUNID="$9"

REPO=$WORK/defenseclaw-system-one
PY=$WORK/.system-one-venv/bin/python

set +u
# shellcheck disable=SC1091
. $WORK/.config/defenseclaw/system-one.env
set -u

cd "$REPO"
export PYTHONPATH="$REPO/benchmarks/scripts"

exec "$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$CASES" \
  --contexts-config benchmarks/system_one/contexts-v1.json \
  --questions-config "benchmarks/system_one/$QCFG" \
  --context "$CTX" \
  --instruction "$INS" \
  --question "$QST" \
  --instruction-format structured \
  --endpoint https://api.typesafe.ai/v1/systemone \
  --model jev-1.13.0 \
  --model-revision jev-1.13.0 \
  --api-key-env TYPESAFE_API_KEY \
  --run-id "$RUNID" \
  --output "$OUT" \
  --concurrency 8 \
  --timeout 120 \
  --retries 2 \
  --max-calls "$MAXCALLS" \
  --max-input-tokens 500000000 \
  --max-usd "$MAXUSD" \
  --input-usd-per-million 0.042
