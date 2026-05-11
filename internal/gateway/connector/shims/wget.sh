#!/bin/bash
# DefenseClaw shim for wget — inspects URL and flags before executing.
# fail-closed contract; this shim mirrors the same hardening.
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which wget 2>/dev/null || echo /usr/bin/wget)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
CURL_BIN=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${SHIM_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$("$CURL_BIN" -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: shim/wget/2.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "wget" --arg cmd "$*" \
    '{tool: $tool, args: {command: $cmd}}')" 2>/dev/null) || {
  exec "$REAL_BINARY" "$@"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  echo "DefenseClaw: wget shim refusing to exec real binary (gateway returned HTTP ${HTTP_CODE:-unknown})" >&2
  exit 1
fi

ACTION=$(echo "$RESULT" | jq -r '.action // empty' 2>/dev/null) || ACTION=""
if [ -z "${ACTION}" ]; then
  echo "DefenseClaw: wget shim refusing to exec real binary (unparseable response, HTTP ${HTTP_CODE})" >&2
  exit 1
fi
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
