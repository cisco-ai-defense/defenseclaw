#!/bin/bash
# DefenseClaw PostToolUse hook — inspects tool execution output before it goes back to the LLM.
# Reads tool output from stdin. TOOL_NAME is set by the agent framework.
set -euo pipefail

TOOL_NAME="${CLAUDE_TOOL_NAME:-${TOOL_NAME:-unknown}}"
TOOL_OUTPUT=$(cat)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

RESULT=$(curl -s -X POST "http://${API_ADDR}/api/v1/inspect/tool-response" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "$TOOL_NAME" --arg output "$TOOL_OUTPUT" \
    '{tool: $tool, output: $output}')" 2>/dev/null) || {
  exit 0
}

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null)
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
