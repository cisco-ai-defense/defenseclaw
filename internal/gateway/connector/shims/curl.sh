#!/bin/bash
# DefenseClaw shim for curl — inspects URL and flags before executing.
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

# DeepSec hardening (S2.5): source the gateway bearer token. Without
# this header the API server returns 401 to the inspect endpoint, the
# shim's existing fail-open then exec's the real binary, and any
# attacker-controlled curl invocation runs without an inspection
# verdict. See finding "Generated shims and generic inspect hooks
# cannot authenticate to the inspect API".
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${SHIM_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

CURL_BIN="$REAL_BINARY"

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$("$CURL_BIN" -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: shim/curl/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  -d "$(jq -n --arg tool "curl" --arg cmd "$*" \
    '{tool: $tool, args: {command: $cmd}}')" 2>/dev/null) || {
  # Transport failure (gateway unreachable / DNS / connect timeout) --
  # keep the legacy fail-open behaviour so a DefenseClaw outage does
  # not brick `curl` for the operator. Auth/parse failures take the
  # fail-closed branch below so a 401 cannot silently bypass.
  exec "$REAL_BINARY" "$@"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  echo "DefenseClaw: curl shim refusing to exec real binary (gateway returned HTTP ${HTTP_CODE:-unknown})" >&2
  exit 1
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  echo "DefenseClaw: curl shim refusing to exec real binary (malformed inspect response)" >&2
  exit 1
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
