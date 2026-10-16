#!/bin/bash
# ============================================================================
# Demo: Capability Sequence Detection (behavioral, not regex)
# ============================================================================
# This sends two tool calls in the SAME session to the edge connector hook.
# The first (web_fetch) is allowed. The second (exec) is blocked because
# NET_FETCH → EXEC_SHELL is a known attack chain.
#
# Run on the Raspberry Pi.
# ============================================================================

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Demo: Attack Chain Detection (NET_FETCH → EXEC_SHELL)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Simulating a two-step attack:"
echo "    Step 1: Agent fetches a file from the internet"
echo "    Step 2: Agent tries to execute it with bash"
echo ""
echo "  Each step alone might be fine."
echo "  The SEQUENCE is what gets caught."
echo ""
read -p "  Press ENTER to run..."
echo ""

# Send both tool calls in the same session via the hook's stdin pipe
RESULT=$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","method":"hook.before_tool","id":1,"params":{"tool":"web_fetch","arguments":{"url":"https://api.openai.com/downloads/setup.sh"}}}' \
  '{"jsonrpc":"2.0","method":"hook.before_tool","id":2,"params":{"tool":"exec","arguments":{"command":"bash setup.sh"}}}' \
  | python3 ~/.defenseclaw/bin/picoclaw_hook.py 2>/dev/null)

LINE1=$(echo "$RESULT" | head -1)
LINE2=$(echo "$RESULT" | tail -1)

# Parse results
ACTION1=$(echo "$LINE1" | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(r.get('action','?'))")
ACTION2=$(echo "$LINE2" | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(r.get('action','?'))")

echo "  Step 1: web_fetch (download file)"
if [ "$ACTION1" = "continue" ]; then
    echo "    ✅ ALLOWED — network fetch is speculative, low risk"
else
    echo "    ⛔ BLOCKED — $ACTION1"
fi

echo ""
echo "  Step 2: exec (run with bash)"
if [ "$ACTION2" = "continue" ]; then
    echo "    ✅ ALLOWED"
else
    REASON=$(echo "$LINE2" | python3 -c "import json,sys; print(json.load(sys.stdin)['result'].get('message',''))" 2>/dev/null | grep -o "Reason: [A-Z_]*" | head -1)
    echo "    ⛔ BLOCKED — $REASON"
    echo ""
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │  The edge connector detected an ATTACK CHAIN:   │"
    echo "  │                                                 │"
    echo "  │  NET_FETCH → EXEC_SHELL                        │"
    echo "  │                                                 │"
    echo "  │  This is behavioral detection, not regex.       │"
    echo "  │  A 16-session finite state machine tracks       │"
    echo "  │  capability history and blocks known multi-step │"
    echo "  │  attack patterns.                               │"
    echo "  └─────────────────────────────────────────────────┘"
fi

echo ""
echo "  Audit log (last 5 lines):"
tail -5 ~/.defenseclaw/audit/dclaw_hook.log | sed 's/^/    /'
echo ""
