#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw Codex hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/codex/hook endpoint. Codex pipes the
# structured JSON event to stdin and reads the response from stdout.
set -euo pipefail

# Fail-open guard. See inspect-request.sh for rationale.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Plan B4 / S0.4: shell-side hook hardening, sourced BEFORE the
# missing-token branch so the helper is available to log + branch on
# DEFENSECLAW_STRICT_AVAILABILITY. Hardening only mutates env that
# downstream code controls (HOME, PATH, locale, GIT_*); none of the
# subsequent token-resolution logic depends on the operator's
# original PATH or HOME.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

# Fail mode governs response-layer failures (4xx, bad JSON, missing
# action). Transport failures (gateway unreachable / 5xx) are handled
# separately by fail_unreachable below — they ALWAYS allow unless the
# operator has set DEFENSECLAW_STRICT_AVAILABILITY=1, because a
# DefenseClaw outage must not brick the user's agent. Set BEFORE the
# missing-token check so defenseclaw_handle_missing_token below has a
# stable FAIL_MODE to log against.
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Bail early when neither the companion .token file nor the env var
# carries a token: without one the gateway will reject every request
# with 401, so the historical default is exit-0 (don't brick the
# agent). The helper preserves that default and additionally lets an
# operator who set DEFENSECLAW_STRICT_AVAILABILITY=1 fail-closed on a
# missing-token misconfiguration; either way, the bypass is recorded
# in hook-failures.jsonl.
if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token codex codex-hook "codex tool"
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

# Transport-layer failure: gateway is unreachable, the connection was
# refused, the request timed out, or the gateway answered with 5xx.
# Always allow unless the operator opted into strict availability.
fail_unreachable() {
  defenseclaw_log_hook_failure codex codex-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "codex tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

# Response-layer failure: gateway answered but the answer was bad
# (auth failure, malformed JSON, missing action). These usually
# indicate misconfiguration — respect FAIL_MODE so an operator who
# explicitly set FAIL_MODE=closed is told about a real problem.
fail_response() {
  defenseclaw_log_hook_failure codex codex-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: codex hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/codex/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: codex-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

# 5xx (server error) is treated as transport — the gateway hit an
# infrastructure problem, not a policy verdict. 4xx falls through to
# response-layer handling so auth/payload bugs surface loudly.
if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

OUTPUT=$(echo "$RESULT" | jq -c '.codex_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  exit 2
fi
exit 0
