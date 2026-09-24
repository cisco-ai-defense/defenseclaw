#!/bin/bash
# Follow-up: does SHIM_COMPACT / SHIM_LAYOUT do anything on a *dict* (structured) state?
# C7 renders the state as a string, which both knobs skip. CS is the 7-prior-event structured shape.
set -u
GPU=$WORK/cachework-gpu.sh
PY=$WORK/.system-one-venv/bin/python
REPO=$WORK/defenseclaw-system-one
OUT=$WORK/.system-one-data/outputs/cache
CASES=$OUT/cases20.jsonl
UP=8002
MARKS=$OUT/marks-cs.jsonl
: > "$MARKS"

mark() { echo "{\"event\":\"$1\",\"cfg\":\"$2\",\"round\":$3,\"t\":$(date +%s.%N)}" >> "$MARKS"; }

cfg_env() {
  case "$1" in
    base)    echo "" ;;
    compact) echo "SHIM_COMPACT=1" ;;
    layout)  echo "SHIM_LAYOUT=page_first" ;;
  esac
}

$GPU $WORK/cw/cw_shimctl.sh stop || true
for cfg in base compact layout; do
  tag="cs-$cfg-r1"
  echo "---- $tag ----"
  mark gap_end "cs-$cfg" 1
  $GPU $WORK/cw/cw_shimctl.sh start "$tag" "$UP" $(cfg_env "$cfg") || continue
  sleep 2
  mark run_start "cs-$cfg" 1
  cd "$REPO" || exit 1
  $PY benchmarks/scripts/benchmark_run_system_one.py \
    --cases "$CASES" \
    --context CS --instruction I3 --question Q2 --instruction-format structured \
    --endpoint http://127.0.0.1:8769/v1/systemone \
    --model openjev --model-revision 5ec9e5fd2f80a6fff386779b1e5ac7e389971889 \
    --run-id "cache-$tag" --output "$OUT/$tag.jsonl" \
    --concurrency 4 --timeout 300 --retries 2 > "$OUT/$tag.log" 2>&1
  echo "rc=$? $(tail -1 "$OUT/$tag.log" | cut -c1-140)"
  mark run_end "cs-$cfg" 1
  $GPU $WORK/cw/cw_shimctl.sh stop || true
  mark gap_start "cs-$cfg" 1
  sleep 20
done
echo "== cs done =="
