#!/bin/bash
# Start llmshim.py on the host with the AWS credentials (the bench boxes have none) and forward its port to a bench box,
# so an adapter on the box reaches Bedrock at http://127.0.0.1:$PORT/v1. Stops both when the given run command ends.
#   bash shim_tunnel.sh <box> <port> <cap-usd> <log> -- <command to run on the box>
set -euo pipefail
BOX=$1 PORT=$2 CAP=$3 LOG=$4; shift 4; [ "${1:-}" = "--" ] && shift
CFG=$HOME/dc-eh/ssh/config
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$LOG")"
python3 "$HERE/llmshim.py" --port "$PORT" --log "$LOG" --cap-usd "$CAP" > "$LOG.err" 2>&1 < /dev/null &
spid=$!
ssh -F "$CFG" -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ControlMaster=no -o ControlPath=none \
    -R 127.0.0.1:$PORT:127.0.0.1:$PORT "$BOX" < /dev/null > "$LOG.tunnel.err" 2>&1 &
tpid=$!
trap 'kill $tpid $spid 2>/dev/null' EXIT
ok=0
for i in $(seq 1 20); do sleep 2; ssh -n -F "$CFG" -o BatchMode=yes "$BOX" "curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -d '{}' http://127.0.0.1:$PORT/v1/chat/completions" 2>/dev/null | grep -q 400 && { ok=1; break; }; done
[ $ok = 1 ] || { echo "shim or tunnel did not come up on port $PORT" >&2; exit 1; }
ssh -n -F "$CFG" -o BatchMode=yes "$BOX" "$*"
echo "shim spend USD: $(python3 -c "import json,sys; print(round(sum(json.loads(l).get('usd',0) for l in open(sys.argv[1])),4))" "$LOG")"
