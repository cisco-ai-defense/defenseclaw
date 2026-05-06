#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw Windsurf hook — forwards Cascade hook payloads to the
# DefenseClaw gateway. Windsurf blocks pre-hooks when this script exits 2.
set -euo pipefail

DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook).
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token windsurf windsurf-hook "windsurf tool"
fi

PAYLOAD=$(cat)
API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

fail_unreachable() {
  defenseclaw_log_hook_failure windsurf windsurf-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "windsurf tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure windsurf windsurf-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: windsurf hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/windsurf/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: windsurf-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
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

# H-3: a malformed/empty JSON response previously fell through to the
# `// "allow"` default below, which silently allowed Cascade actions
# even with FAIL_MODE=closed. We now route through fail_response so
# the parse error is logged AND respects FAIL_MODE.
if ! echo "$RESULT" | jq -e . >/dev/null 2>&1; then
  fail_response "invalid JSON response"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "DefenseClaw blocked this Cascade action."' 2>/dev/null || printf "DefenseClaw blocked this Cascade action.")
  echo "$REASON" >&2
  exit 2
fi
exit 0
