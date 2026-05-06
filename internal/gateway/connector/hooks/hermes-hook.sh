#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw Hermes hook — forwards Hermes shell-hook payloads to the
# DefenseClaw gateway.
set -euo pipefail

# Fail-open guard. See inspect-request.sh for rationale.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook). Hardening only mutates env that downstream code
# controls (HOME, PATH, locale, GIT_*); none of the subsequent
# token-resolution logic depends on the operator's original PATH or
# HOME.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

# FAIL_MODE set BEFORE the missing-token check so the helper has a
# stable FAIL_MODE to log against. Response-layer failures (4xx, bad
# JSON, missing action) respect FAIL_MODE; transport-layer failures
# (gateway unreachable / 5xx) always allow unless
# DEFENSECLAW_STRICT_AVAILABILITY=1.
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Bail early on missing token via the shared helper so the bypass is
# logged to hook-failures.jsonl AND honors strict availability — the
# previous v1 behaviour silently `exit 0`'d, which hid the bypass and
# defeated DEFENSECLAW_STRICT_AVAILABILITY.
if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token hermes hermes-hook "hermes tool"
fi

PAYLOAD=$(cat)
API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"

# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). The env var takes precedence if already set.
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "${HOOK_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

fail_unreachable() {
  defenseclaw_log_hook_failure hermes hermes-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "hermes tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    printf '{"action":"block","message":"DefenseClaw hook failed closed"}\n'
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure hermes hermes-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: hermes hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  printf '{"action":"block","message":"DefenseClaw hook failed closed"}\n'
  exit 0
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/hermes/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: hermes-hook/1.0" \
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

OUTPUT=$(echo "$RESULT" | jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
exit 0
