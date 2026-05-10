#!/bin/bash
# DefenseClaw shim for curl — inspects URL and flags before executing.
#
# Pre-fix this shim called the gateway's /api/v1/inspect/tool endpoint
# UNAUTHENTICATED. With a configured gateway token the sidecar returns
# 401 + {"error":"unauthorized"}; the shim's `jq -r '.action // "allow"'`
# then fell back to "allow" and exec'd the real curl. Combined with the
# inspect-request hook also being unauthenticated, a malicious agent had
# a complete unauthenticated path past every inspection layer.
#
# Fix: load the gateway bearer token from .token (written next to the
# shim) or DEFENSECLAW_GATEWAY_TOKEN, send Authorization on every
# inspection call, treat any non-2xx HTTP status as a HARD BLOCK, and
# treat a missing/unrecognized action field as a HARD BLOCK so a
# misconfigured auth path can never be silently downgraded to "allow".
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${SHIM_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$("$REAL_BINARY" -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: shim/curl/2.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "curl" --arg cmd "$*" \
    '{tool: $tool, args: {command: $cmd}}')" 2>/dev/null) || {
  # Transport failures fall back to the real binary (gateway down must
  # not brick the agent) — same posture as the connector hooks. Auth
  # rejections and parse failures take the fail-closed branch below so
  # a 401 cannot silently bypass.
  exec "$REAL_BINARY" "$@"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  echo "DefenseClaw: curl shim refusing to exec real binary (gateway returned HTTP ${HTTP_CODE:-unknown})" >&2
  exit 1
fi

ACTION=$(echo "$RESULT" | jq -r '.action // empty' 2>/dev/null) || ACTION=""
if [ -z "${ACTION}" ]; then
  # No recognized action means either the response is malformed or the
  # gateway returned an error envelope. Either way, do NOT default to
  # allow — that was the original silent-bypass.
  echo "DefenseClaw: curl shim refusing to exec real binary (unparseable response, HTTP ${HTTP_CODE})" >&2
  exit 1
fi

if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
