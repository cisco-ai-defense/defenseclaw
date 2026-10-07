#!/bin/bash
# DefenseClaw shim for wget — inspects URL and flags before executing.
# F-2029 / F-3397: see curl.sh for full rationale of the auth + 401
# fail-closed contract; this shim mirrors the same hardening.
set -euo pipefail
SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BINARY=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which wget 2>/dev/null || echo /usr/bin/wget)

API_ADDR="{{.APIAddr}}"
CURL_BIN=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${SHIM_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

# The bearer and the request body reach curl on descriptors 8 and 9, never on
# its command line, which every local account can read; printf is a shell
# builtin. The descriptor-backed --config form works on curl releases older
# than 7.55.0, which lack -H @file. The tool arguments are this shim's own.
AUTH_CONFIG=""
AUTH_CONFIG_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*)
      echo "DefenseClaw: shim gateway token is malformed — refusing to exec wget" >&2
      exit 1
      ;;
  esac
  # The two characters a quoted curl config value escapes.
  AUTH_CONFIG="${API_TOKEN//\\/\\\\}"
  AUTH_CONFIG="${AUTH_CONFIG//\"/\\\"}"
  AUTH_CONFIG="header = \"Authorization: Bearer ${AUTH_CONFIG}\""
  AUTH_CONFIG_ARGS=(--config /dev/fd/8)
fi
INSPECT_BODY="$(jq -cn --arg tool "wget" --args \
  '{tool: $tool, args: {argv: ([$tool] + $ARGS.positional)}}' \
  -- "$@")" || INSPECT_BODY=""

RESPONSE=$("$CURL_BIN" -s --noproxy '*' -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: shim/wget/2.0" \
  "${AUTH_CONFIG_ARGS[@]+"${AUTH_CONFIG_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  --data-binary @/dev/fd/9 2>/dev/null \
  8< <(printf '%s\n' "$AUTH_CONFIG") \
  9< <(printf '%s' "$INSPECT_BODY")) || {
  exec "$REAL_BINARY" "$@"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
  echo "DefenseClaw: shim auth rejected (HTTP ${HTTP_CODE}) — refusing to exec wget" >&2
  exit 1
fi

ACTION=$(echo "$RESULT" | jq -r '.action // empty' 2>/dev/null) || ACTION=""
if [ -z "${ACTION}" ]; then
  echo "DefenseClaw: shim received unparseable response (HTTP ${HTTP_CODE}) — refusing to exec wget" >&2
  exit 1
fi
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $REASON" >&2
  exit 1
fi
exec "$REAL_BINARY" "$@"
