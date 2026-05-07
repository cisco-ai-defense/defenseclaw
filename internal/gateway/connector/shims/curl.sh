#!/bin/bash
# DefenseClaw shim for curl — inspects URL and flags before executing.
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

RESULT=$("$REAL_BINARY" -s -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "curl" --arg cmd "$*" \
    '{tool: $tool, args: {command: $cmd}}')" 2>/dev/null) || {
  exec "$REAL_BINARY" "$@"
}

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null)
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
