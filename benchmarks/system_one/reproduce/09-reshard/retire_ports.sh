#!/usr/bin/env bash
# Retire the shims on the given ports, worker -> driver -> shim, each by EXACT pid
# after matching its cmdline. Never a pattern kill.
#
# Why: nimble_shim leaks host RAM (~0.21 GB/min/process; 18 GB model, 51 GB RSS at
# 2h35m). Retiring the two oldest reclaims ~102 GB and removes the duplicated workers.
# Interrupted chunks are released afterwards and re-run whole by a fresh driver.
set -uo pipefail
R=/teamspace/studios/this_studio/sysone
PORTS="$*"
[ -z "$PORTS" ] && { echo "usage: retire_ports.sh <port> [port...]"; exit 2; }

cmdline () { tr "\0" " " < "/proc/$1/cmdline" 2>/dev/null; }

for stage in worker driver shim; do
  for port in $PORTS; do
    for d in /proc/[0-9]*; do
      p=${d#/proc/}
      c=$(cmdline "$p") || continue
      [ -z "$c" ] && continue
      keep=no
      case "$stage:$c" in
        worker:*worker.sh*)            case "$c" in *"worker.sh $port"*) keep=yes;; esac;;
        driver:*benchmark_run_system_one*) case "$c" in *"127.0.0.1:$port/"*) keep=yes;; esac;;
        shim:*nimble_shim.py*)         case "$c" in *"--port $port"*) keep=yes;; esac;;
      esac
      if [ "$keep" = yes ]; then
        rss=$(awk "/VmRSS/{print \$2}" "$d/status" 2>/dev/null)
        echo "SIGTERM $stage pid=$p port=$port rss_kb=${rss:-?}"
        kill -TERM "$p" 2>/dev/null || echo "  (already gone)"
      fi
    done
  done
  sleep 6
done

sleep 8
echo "--- survivors on retired ports ---"
for port in $PORTS; do
  n=0
  for d in /proc/[0-9]*; do
    c=$(cmdline "${d#/proc/}") || continue
    case "$c" in *"--port $port"*|*"worker.sh $port"*|*"127.0.0.1:$port/"*) n=$((n+1));; esac
  done
  echo "  port $port: $n process(es) remaining"
done
free -g | head -2
