#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw OpenHands hook — forwards OpenHands lifecycle hook payloads
# to the DefenseClaw gateway. Intentional policy blocks exit 2, matching
# the OpenHands hook contract.
set -euo pipefail

DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"
DEFENSECLAW_HOOK_CONNECTOR="openhands"
DEFENSECLAW_HOOK_NAME="openhands-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token openhands openhands-hook "openhands hook"
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: openhands hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    printf '{"decision":"deny","reason":"DefenseClaw hook payload too large"}\n'
    exit 2
  fi
  exit 0
}
API_ADDR="{{.APIAddr}}"
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

fail_unreachable() {
  defenseclaw_log_hook_failure openhands openhands-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "openhands hook" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    printf '{"decision":"deny","reason":"DefenseClaw hook failed closed"}\n'
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure openhands openhands-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: openhands hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  printf '{"decision":"deny","reason":"DefenseClaw hook failed closed"}\n'
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

TRACE_HEADER_ARGS=()
if command -v mapfile >/dev/null 2>&1; then
  mapfile -t TRACE_HEADER_ARGS < <(defenseclaw_extract_trace_context)
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/openhands/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: openhands-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
  DECISION=$(echo "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null || true)
  if [ "$DECISION" = "deny" ] || [ "$DECISION" = "block" ]; then
    exit 2
  fi
fi
exit 0
