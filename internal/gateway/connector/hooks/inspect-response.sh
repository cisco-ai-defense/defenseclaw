#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw PostResponse hook — inspects LLM response content after it is returned.
# Reads the LLM response from stdin (JSON with "content" field).
set -euo pipefail

# Fail-open guard. See inspect-request.sh for rationale.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Plan B4 / S0.4: shell-side hook hardening.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

DEFENSECLAW_HOOK_CONNECTOR="inspect"
DEFENSECLAW_HOOK_NAME="inspect-response"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Avarice F-2025 / chain F-3397: authenticate inspection calls. See
# inspect-request.sh for the full rationale.
if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token inspect inspect-response "response"
fi
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

CONTENT="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: inspect response refusing oversized payload" >&2
  exit 2
}

API_ADDR="{{.APIAddr}}"
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Transport failures (gateway down / 5xx) always allow unless
# DEFENSECLAW_STRICT_AVAILABILITY=1. Response failures respect
# FAIL_MODE.
fail_unreachable() {
  defenseclaw_log_hook_failure inspect inspect-response "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "response" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure inspect inspect-response "$1" response "$FAIL_MODE"
  echo "defenseclaw: inspect-response hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

# Avarice F-2025 / chain F-3397: 401/403 always fail closed.
fail_unauthorized() {
  defenseclaw_log_hook_failure inspect inspect-response "$1" response "closed"
  echo "defenseclaw: inspect-response hook auth rejected: $1 (fail-closed override)" >&2
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$(printf '%s' "$CONTENT" | curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/response" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  --data-binary @- 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
  fail_unauthorized "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"' 2>/dev/null)
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
