#!/bin/bash
# Keep the loopback forwards for the two 27B replicas alive for the length of the run.
#
# A dropped forward would turn every in-flight request into an `error` row, and the merge
# hard-fails on any error row, so a blip nine hours in would cost the whole run. This probes
# /health once a minute and re-establishes only if a probe fails.
#
# Scope is deliberately narrow: it touches ONLY ports 8831 and 8832, which this run created.
# It never signals an existing tunnel and never goes near 8011, 8765, 8767, 8768, 8921,
# 8922 or 3100.
set -uo pipefail
PORTS=(8831 8832)
NAME=open-jev-qwen-27b

while pgrep -f "benchmark_run_system_one.py.*${NAME}-shard" > /dev/null; do
  down=()
  for port in "${PORTS[@]}"; do
    curl -s -m 8 "http://127.0.0.1:$port/health" | grep -q '"status": "ready"' || down+=("$port")
  done
  if [ ${#down[@]} -gt 0 ]; then
    echo "$(date -u +%H:%M:%S) forwards down: ${down[*]} -- re-establishing"
    WANT_PORTS="${PORTS[*]}" bash $WORK/sysone-tunnel.sh 2>&1 | sed 's/^/    /'
  fi
  sleep 60
done
echo "$(date -u +%H:%M:%S) runners finished; watchdog exiting"
