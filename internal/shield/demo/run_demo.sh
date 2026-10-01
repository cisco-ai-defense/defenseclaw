#!/bin/bash
# DefenseClaw Shield — End-to-End Demo

set -e

SHIELD_DIR="$HOME/.defenseclaw-shield"
SHIELD_BIN="$SHIELD_DIR/defenseclaw-shield"
SOCKET="$SHIELD_DIR/shield.sock"
AUDIT_LOG="$SHIELD_DIR/audit.jsonl"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check prerequisites
if [ ! -f "$SHIELD_BIN" ]; then
    echo "ERROR: Shield daemon not built."
    echo "Run: go build -o ~/.defenseclaw-shield/defenseclaw-shield ./cmd/defenseclaw-shield"
    exit 1
fi

# Clean up old state
rm -f "$SOCKET" "$AUDIT_LOG"

# Start daemon in background
echo ""
echo "▸ Starting shield daemon..."
"$SHIELD_BIN" start &
DAEMON_PID=$!
sleep 1

if [ ! -S "$SOCKET" ]; then
    echo "ERROR: Daemon failed to start"
    kill $DAEMON_PID 2>/dev/null
    exit 1
fi

cleanup() {
    kill $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
}
trap cleanup EXIT

# Run all scenarios
SHIELD_SOCKET="$SOCKET" python3 "$DEMO_DIR/test_agent.py" all

# Show audit log
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  Audit trail ($AUDIT_LOG):"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
if [ -f "$AUDIT_LOG" ]; then
    python3 -c "
import json
for line in open('$AUDIT_LOG'):
    e = json.loads(line)
    v = e['verdict']['action']
    action = ['ALLOW','BLOCK','LOG'][v]
    prov = e.get('provider','?')
    direction = e.get('direction','?')
    size = e.get('content_size',0)
    findings = len(e.get('verdict',{}).get('findings') or [])
    reason = (e.get('verdict',{}).get('reason') or '')[:50]
    print(f'  {action:5s} │ {prov:10s} │ {direction:8s} │ {size:5d}B │ findings={findings} │ {reason}')
"
else
    echo "  (no audit log)"
fi
echo ""

echo "▸ Stopping daemon..."
