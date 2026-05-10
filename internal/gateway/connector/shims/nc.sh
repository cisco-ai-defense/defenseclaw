#!/bin/bash
# DefenseClaw shim for nc/ncat — inspects args for C2 patterns before executing.
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which nc 2>/dev/null || echo /usr/bin/nc)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
CURL_BIN=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

# DeepSec hardening (S2.5): source the gateway bearer token. See
# curl.sh shim for the full rationale.
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
  -H "X-DefenseClaw-Client: shim/nc/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "nc" --arg cmd "$*" \
    '{tool: $tool, args: {command: $cmd}}')" 2>/dev/null) || {
  exec "$REAL_BINARY" "$@"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  echo "DefenseClaw: nc shim refusing to exec real binary (gateway returned HTTP ${HTTP_CODE:-unknown})" >&2
  exit 1
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  echo "DefenseClaw: nc shim refusing to exec real binary (malformed inspect response)" >&2
  exit 1
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
