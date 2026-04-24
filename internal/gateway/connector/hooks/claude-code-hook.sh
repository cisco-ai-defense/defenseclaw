#!/bin/bash
# DefenseClaw Claude Code hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/claude-code/hook endpoint. Claude Code pipes
# the structured JSON event to stdin and reads the response from stdout.
set -euo pipefail

PAYLOAD=$(cat)
API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-{{.APIToken}}}"

# Build curl auth header only when a token is actually available.
# Empty header would trip the API auth middleware's "invalid_token"
# branch instead of falling through to loopback-allow when no token
# was ever configured.
AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESULT=$(curl -s -X POST "http://${API_ADDR}/api/v1/claude-code/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: claude-code-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
  # Fail open if DefenseClaw is unreachable.
  exit 0
}

# Emit the claude_code_output field if present — Claude Code reads stdout
# for hookSpecificOutput, watchPaths, systemMessage, etc.
OUTPUT=$(echo "$RESULT" | jq -c '.claude_code_output // empty' 2>/dev/null)
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null)
if [ "$ACTION" = "block" ]; then
  exit 2
fi
exit 0
