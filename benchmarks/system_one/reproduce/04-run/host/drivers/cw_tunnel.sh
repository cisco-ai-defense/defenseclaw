#!/bin/bash
# Dedicated, separate SSH tunnel for MY shim port 8769 only.
# Does NOT touch the existing tunnel process that forwards 8011/8765/8767/8768.
set -u
PIDF=$WORK/cw/tunnel-8769.pid
mkdir -p $WORK/cw

case "${1:-up}" in
up)
  if ss -ltn | grep -q '127.0.0.1:8769 '; then echo "8769 already forwarded locally"; exit 0; fi
  ssh -f -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
      -o ControlMaster=no -o ControlPath=none \
      -i "<SSH_KEY>" -o StrictHostKeyChecking=yes \
      -L 127.0.0.1:8769:127.0.0.1:8769 "ubuntu@<GPU_HOST>"
  sleep 1
  PID=$(pgrep -f 'ssh -f -N .*8769:127.0.0.1:8769' | head -1)
  echo "$PID" > "$PIDF"
  ss -ltn | grep '8769 ' || echo "WARN: not listening"
  echo "tunnel pid=$PID"
  ;;
down)
  if [ -f "$PIDF" ]; then
    PID=$(cat "$PIDF")
    CMD=$(tr '\0' ' ' < /proc/$PID/cmdline 2>/dev/null)
    case "$CMD" in
      *8769:127.0.0.1:8769*) kill "$PID" && echo "killed tunnel $PID" ;;
      *) echo "REFUSING: pid $PID is not my 8769 tunnel: $CMD"; exit 1 ;;
    esac
    rm -f "$PIDF"
  fi
  ;;
esac
