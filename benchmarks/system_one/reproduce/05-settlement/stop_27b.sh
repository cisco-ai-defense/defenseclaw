#!/bin/bash
# Clean stop of the open-jev-qwen-27b AWS run, superseded by the H200 re-launch.
#
# Order matters: the waiter is armed to settle and score the moment the runners exit, so it
# goes first. If the runners died first, the waiter would wake on a 17k-row file. It does
# check the row count and refuses to score a short run, but the ordering removes the
# question entirely rather than relying on that guard.
#
# Every signal is PID-verified: the PID was recorded earlier, and /proc/<pid>/cmdline is
# re-read immediately before signalling and must still match this run's own signature.
# Anything that does not match prints REFUSING and is left alone. No pkill, no killall --
# a pattern match would also match this script's own command line, which is the trap.
set -u

stop() { # pid  required-substring  [second-required-substring]
  local pid=$1 want=$2 want2=${3:-}
  if [ ! -d "/proc/$pid" ]; then
    echo "  pid $pid: already gone"
    return 0
  fi
  local cmd
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  if [ -z "$cmd" ]; then
    echo "  pid $pid: no cmdline (exited during check)"
    return 0
  fi
  case "$cmd" in
    *"$want"*)
      if [ -n "$want2" ] && [ "${cmd#*$want2}" = "$cmd" ]; then
        echo "  REFUSING pid $pid: lacks '$want2' -> ${cmd:0:110}"
        return 1
      fi
      echo "  signalling pid $pid (TERM): ${cmd:0:100}"
      kill -TERM "$pid"
      ;;
    *)
      echo "  REFUSING pid $pid: lacks '$want' -> ${cmd:0:110}"
      return 1
      ;;
  esac
}

wait_gone() {
  local label=$1; shift
  for _ in $(seq 40); do
    local alive=0
    for pid in "$@"; do [ -d "/proc/$pid" ] && alive=1; done
    [ $alive -eq 0 ] && { echo "  $label: all gone"; return 0; }
    sleep 1
  done
  echo "  $label: STILL ALIVE after 40s:"
  for pid in "$@"; do
    [ -d "/proc/$pid" ] && echo "    $pid $(tr '\0' ' ' < /proc/$pid/cmdline | cut -c1-90)"
  done
  return 1
}

echo "=== 1. waiter (armed to settle/score -- must go first) ==="
stop 656510 "j27/wait_then_finish.sh"
stop 656507 "j27/wait_then_finish.sh"
wait_gone "waiter" 656510 656507

echo "=== 2. the four shard runners ==="
for pid in 654062 654063 654064 654065; do
  stop "$pid" "benchmark_run_system_one.py" "open-jev-qwen-27b-shard"
done
wait_gone "runners" 654062 654063 654064 654065

echo "=== 3. tunnel watchdog ==="
stop 658330 "j27/tunnel_watchdog.sh"
stop 658327 "j27/tunnel_watchdog.sh"
wait_gone "watchdog" 658330 658327

echo "=== 4. my ssh forward (8831/8832 only) ==="
# Verified against the protected ports before signalling: this forward must mention 8831
# and 8832 and must not mention any of 8011/8765/8767/8768/8921/8922/3100.
fwd_cmd=$(tr '\0' ' ' < /proc/653415/cmdline 2>/dev/null)
protected=0
for p in 8011 8765 8767 8768 8921 8922 3100; do
  case "$fwd_cmd" in *"$p"*) echo "  REFUSING pid 653415: mentions protected port $p"; protected=1 ;; esac
done
if [ $protected -eq 0 ]; then
  stop 653415 "127.0.0.1:8831:127.0.0.1:8831" "127.0.0.1:8832:127.0.0.1:8832"
  wait_gone "forward" 653415
fi

echo "=== 5. decider-2b must be untouched and healthy ==="
if [ -d /proc/793502 ]; then
  cmd=$(tr '\0' ' ' < /proc/793502/cmdline)
  case "$cmd" in
    *decider-2b*) echo "  decider-2b pid 793502 ALIVE (untouched)" ;;
    *) echo "  WARNING: pid 793502 is no longer decider-2b: ${cmd:0:110}" ;;
  esac
  echo "  rows: $(wc -l < $WORK/.system-one-data/outputs/decider/s2/decider-2b.jsonl 2>/dev/null) / 30310"
else
  echo "  WARNING: decider-2b pid 793502 is GONE -- it was not mine to stop"
  echo "  rows: $(wc -l < $WORK/.system-one-data/outputs/decider/s2/decider-2b.jsonl 2>/dev/null) / 30310"
fi

echo "=== 6. other agents' work, for the record (not touched) ==="
pgrep -af "benchmark_run_system_one.py" | grep -v "open-jev-qwen-27b" | grep -v "stop_27b" \
  | cut -c1-120 || echo "  none running"
echo "=== protected forwards still listening ==="
for p in 8011 8765 8767 8768 8921 8922 3100; do
  ss -ltn 2>/dev/null | grep -q "127.0.0.1:$p " && echo "  :$p up" || echo "  :$p not listening"
done
