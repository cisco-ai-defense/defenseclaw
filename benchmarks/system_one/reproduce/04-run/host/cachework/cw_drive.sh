#!/bin/bash
# Controlled shim-config comparison. Runs on the controller; drives ONE extra shim on GPU-host port 8769.
set -u
GPU=$WORK/cachework-gpu.sh
PY=$WORK/.system-one-venv/bin/python
REPO=$WORK/defenseclaw-system-one
OUT=$WORK/.system-one-data/outputs/cache
CASES=$OUT/cases20.jsonl
UP=8002
CONC=${CONC:-4}
ROUNDS=${ROUNDS:-4}
MARKS=$OUT/marks.jsonl

mkdir -p "$OUT"
: > "$MARKS"

cfg_env() {
  case "$1" in
    base)    echo "" ;;
    compact) echo "SHIM_COMPACT=1" ;;
    layout)  echo "SHIM_LAYOUT=page_first" ;;
    pad)     echo "SHIM_PAD=784" ;;
    stagger) echo "SHIM_STAGGER=1 SHIM_STAGGER_MIN_CHARS=1" ;;
    padstag) echo "SHIM_PAD=784 SHIM_STAGGER=1 SHIM_STAGGER_MIN_CHARS=1" ;;
    allopt)  echo "SHIM_COMPACT=1 SHIM_LAYOUT=page_first SHIM_PAD=784 SHIM_STAGGER=1 SHIM_STAGGER_MIN_CHARS=1" ;;
  esac
}

CFGS="base compact layout pad stagger padstag allopt"

mark() { echo "{\"event\":\"$1\",\"cfg\":\"$2\",\"round\":$3,\"t\":$(date +%s.%N)}" >> "$MARKS"; }

echo "== drive start $(date -u +%FT%TZ) conc=$CONC rounds=$ROUNDS upstream=$UP =="
$GPU $WORK/cw/cw_shimctl.sh stop || true

for r in $(seq 1 "$ROUNDS"); do
  for cfg in $CFGS; do
    tag="$cfg-r$r"
    echo "---- $tag ----"
    mark gap_end "$cfg" "$r"
    $GPU $WORK/cw/cw_shimctl.sh start "$tag" "$UP" $(cfg_env "$cfg") || { echo "START FAILED $tag"; continue; }
    sleep 2
    mark run_start "$cfg" "$r"
    cd "$REPO" || exit 1
    $PY benchmarks/scripts/benchmark_run_system_one.py \
      --cases "$CASES" \
      --context C7 --instruction I3 --question Q2 --instruction-format structured \
      --endpoint http://127.0.0.1:8769/v1/systemone \
      --model openjev --model-revision 5ec9e5fd2f80a6fff386779b1e5ac7e389971889 \
      --run-id "cache-$tag" --output "$OUT/$tag.jsonl" \
      --concurrency "$CONC" --timeout 300 --retries 2 > "$OUT/$tag.log" 2>&1
    rc=$?
    mark run_end "$cfg" "$r"
    echo "rc=$rc  $(tail -1 "$OUT/$tag.log" | cut -c1-200)"
    $GPU $WORK/cw/cw_shimctl.sh stop || true
    mark gap_start "$cfg" "$r"
    sleep 25
  done
done
echo "== drive done $(date -u +%FT%TZ) =="
