#!/bin/bash
# DefenseClaw PreToolUse hook — calls DefenseClaw inspect API before tool execution.
# Used by Claude Code (PreToolUse) and OpenCode (hook command).
# The agent sets CLAUDE_TOOL_NAME (Claude Code) or TOOL_NAME and pipes input to stdin.
set -euo pipefail

TOOL_NAME="${CLAUDE_TOOL_NAME:-${TOOL_NAME:-unknown}}"
TOOL_INPUT=$(cat)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

RESULT=$(curl -s -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "$TOOL_NAME" --arg args "$TOOL_INPUT" \
    '{tool: $tool, args: $args}')" 2>/dev/null) || {
  # If DefenseClaw API is unreachable, fail open to avoid blocking the agent.
  exit 0
}

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null)
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
