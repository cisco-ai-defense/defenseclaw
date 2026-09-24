#!/bin/bash
# Snapshot vLLM metrics on the GPU host. Usage: gsnap.sh <PORT> <LABEL>
ssh -o ConnectTimeout=20 -i "<SSH_KEY>" "ubuntu@<GPU_HOST>" \
  "$WORK/prefix-unit-test/snap.sh $1 $2" | tail -3
