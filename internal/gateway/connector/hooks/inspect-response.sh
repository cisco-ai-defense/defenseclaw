#!/bin/bash
# DefenseClaw PostResponse hook — inspects LLM response content after it is returned.
# Reads the LLM response from stdin (JSON with "content" field).
set -euo pipefail

CONTENT=$(cat)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

RESULT=$(curl -s -X POST "http://${API_ADDR}/api/v1/inspect/response" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$CONTENT" 2>/dev/null) || {
  exit 0
}

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null)
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
