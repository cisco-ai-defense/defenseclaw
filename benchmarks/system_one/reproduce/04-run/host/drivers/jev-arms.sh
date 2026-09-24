#!/usr/bin/env bash
# Launch one hosted-Jev arm. Args:
#   $1 stage dir name   (e.g. s2)
#   $2 cases file name  (e.g. cases.jsonl)
#   $3 context          (e.g. C7)
#   $4 instruction      (e.g. I3)
#   $5 question         (e.g. Q2)
#   $6 questions config (questions-v1.json | questions-v2.json)
#   $7 output basename  (e.g. jev-C7.jsonl)
#   $8 max_usd
#   $9 max_calls
#   ${10} run_id
set -euo pipefail

STAGE="$1"; CASES="$2"; CTX="$3"; INS="$4"; QST="$5"; QCFG="$6"; OUT="$7"; MAXUSD="$8"; MAXCALLS="$9"; RUNID="${10}"

REPO=$WORK/defenseclaw-system-one
DATA=$WORK/.system-one-data/outputs
PY=$WORK/.system-one-venv/bin/python

# shellcheck disable=SC1090
set +u
. $WORK/.config/defenseclaw/system-one.env
set -u

cd "$REPO"
export PYTHONPATH="$REPO/benchmarks/scripts"

exec "$PY" benchmarks/scripts/benchmark_run_system_one.py \
  --cases "$DATA/$STAGE/$CASES" \
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
  --output "$DATA/$STAGE/$OUT" \
  --concurrency 8 \
  --timeout 120 \
  --retries 2 \
  --max-calls "$MAXCALLS" \
  --max-input-tokens 500000000 \
  --max-usd "$MAXUSD" \
  --input-usd-per-million 0.042
