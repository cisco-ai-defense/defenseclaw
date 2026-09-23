#!/bin/bash
# Idempotent loopback-only forward from the dev host to the GPU host serving ports.
# Ports are bound on 127.0.0.1 at both ends; nothing is exposed publicly.
set -uo pipefail
GPU_HOST=${GPU_HOST:-<GPU_HOST>}
KEY=<SSH_KEY>
WANT=(${WANT_PORTS:-8801 8802 8803 8804})

missing=()
for p in "${WANT[@]}"; do
  ss -ltn 2>/dev/null | grep -q "127.0.0.1:$p " || missing+=("$p")
done

if [ ${#missing[@]} -eq 0 ]; then
  echo "all forwards already up: ${WANT[*]}"
else
  args=()
  for p in "${WANT[@]}"; do args+=(-L "127.0.0.1:$p:127.0.0.1:$p"); done
  ssh -f -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
      -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=no \
      -i "$KEY" "${args[@]}" "ubuntu@$GPU_HOST"
  echo "tunnel started rc=$? for ${WANT[*]}"
  sleep 3
fi

for p in "${WANT[@]}"; do
  printf '%s: ' "$p"
  curl -s -m 8 "http://127.0.0.1:$p/health" || echo DOWN
  echo
done
