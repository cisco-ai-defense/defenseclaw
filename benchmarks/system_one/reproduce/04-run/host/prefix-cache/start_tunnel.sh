#!/bin/bash
# Additional tunnel forwarding ONLY 8769. The existing 4-port tunnel (pid 66175) is left untouched.
ssh -f -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
  -i "<SSH_KEY>" -o StrictHostKeyChecking=yes \
  -L 127.0.0.1:8769:127.0.0.1:8769 "ubuntu@<GPU_HOST>"
echo "rc=$?"
sleep 2
echo "=== tunnels now (expect the original 4-port one + a new 8769-only one) ==="
ps -eo pid=,args= | grep -E "ssh .*-L 127.0.0.1" | grep -v grep
echo
echo "=== dev-host loopback listeners ==="
ss -lntp | grep -E "127.0.0.1:(8011|8765|8767|8768|8769)"
echo
echo "=== end-to-end: /v1/version through dev:8769 ==="
curl -s --max-time 20 http://127.0.0.1:8769/v1/version; echo
