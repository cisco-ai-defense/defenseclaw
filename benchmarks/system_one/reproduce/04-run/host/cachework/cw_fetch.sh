#!/bin/bash
# Copy the GPU-host experiment artefacts to the controller for analysis.
set -u
mkdir -p $WORK/cw/gpu
rsync -a -e "ssh -i <SSH_KEY> -o StrictHostKeyChecking=yes" \
  --include='*/' --include='calls.jsonl' --include='env.txt' --exclude='*' \
  "ubuntu@<GPU_HOST>":$WORK/cw/runs/ $WORK/cw/gpu/runs/
rsync -a -e "ssh -i <SSH_KEY> -o StrictHostKeyChecking=yes" \
  "ubuntu@<GPU_HOST>":$WORK/cw/poll-8002.jsonl $WORK/cw/gpu/poll-8002.jsonl
echo "fetched: $(ls $WORK/cw/gpu/runs | wc -l) run dirs, $(wc -l < $WORK/cw/gpu/poll-8002.jsonl) poll samples"
