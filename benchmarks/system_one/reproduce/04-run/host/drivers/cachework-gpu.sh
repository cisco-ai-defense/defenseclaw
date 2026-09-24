#!/bin/bash
# run a command on the GPU host from the controller
exec ssh -i "<SSH_KEY>" -o StrictHostKeyChecking=yes -o ConnectTimeout=20 "ubuntu@<GPU_HOST>" "$@"
