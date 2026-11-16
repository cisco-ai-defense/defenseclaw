#!/bin/bash
# defenseclaw-managed-hook v8
# defenseclaw-derived: sha256=70d6d1b81ce5e0077b1afcd1d0771572d04dfb03820fc502cfb82a109b070e18 fail_mode=open
# DefenseClaw Antigravity (`agy`) hook. Setup passes the documented lifecycle
# event as argv[1] because Antigravity's official stdin schemas omit it.
# PreToolUse blocks only through synchronous stdout {"decision":"deny"}; this
# bridge does not rely on undocumented non-zero-exit enforcement.
set -euo pipefail

HOOK_EVENT="${1:-}"
HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || exit 2
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  else
    exit 2
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET

DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi


# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook).
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-open}"

antigravity_emit_fallback() {
  local closed="${1:-0}"
  case "$HOOK_EVENT" in
    PreToolUse)
      if [ "$closed" = "1" ]; then
        printf '%s\n' '{"decision":"deny","reason":"DefenseClaw policy service is unavailable."}'
      else
        printf '%s\n' '{"decision":"allow"}'
      fi
      ;;
    Stop)
      printf '%s\n' '{"decision":"allow"}'
      ;;
    *)
      printf '%s\n' '{}'
      ;;
  esac
}

DEFENSECLAW_HOOK_CONNECTOR="antigravity"
DEFENSECLAW_HOOK_NAME="antigravity-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_failure antigravity antigravity-hook "missing gateway token" transport "$FAIL_MODE"
  if defenseclaw_should_fail_closed_on_unreachable; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: antigravity hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}
API_ADDR="127.0.0.1:9"
if [ "0" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/.token" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/.token" || true
  fi
  export DEFENSECLAW_GATEWAY_TOKEN
elif [ -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/.token"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

fail_unreachable() {
  defenseclaw_log_hook_failure antigravity antigravity-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "antigravity tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure antigravity antigravity-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: antigravity hook error: $1" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

# W3C trace propagation: forward validated traceparent / tracestate.
TRACE_HEADER_ARGS=()
if command -v mapfile >/dev/null 2>&1; then
  mapfile -t TRACE_HEADER_ARGS < <(defenseclaw_extract_trace_context)
fi

# Per-user attribution: the gateway cannot read the real user's identity from
# its own service-account process, so the hook reports it.
# Read with a read loop rather than mapfile: macOS ships bash 3.2, which has
# no mapfile, and there the array would stay empty and the endpoint would send
# no identity at all.
IDENTITY_HEADER_ARGS=()
if declare -F defenseclaw_user_identity_args >/dev/null 2>&1; then
  while IFS= read -r identity_header_arg; do
    IDENTITY_HEADER_ARGS+=("$identity_header_arg")
  done < <(defenseclaw_user_identity_args)
fi

if defenseclaw_api_listener_foreign "$API_ADDR"; then
  fail_unreachable "${API_ADDR} is held by another account while this account's gateway is not running; no token was sent. Run \`defenseclaw-gateway start\` for the fix"
fi
# A refused connection means this account's gateway is not running (after
# a reboot, for example): start it once and retry. See
# defenseclaw_gateway_cold_start in _hardening.sh.
defenseclaw_hook_post() {
  curl -s --noproxy '*' -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/antigravity/hook" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: antigravity-hook/1.0" \
    -H "X-DefenseClaw-Antigravity-Event: ${HOOK_EVENT}" \
    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}" \
    --connect-timeout 2 \
    --max-time 29 \
    -d "$PAYLOAD" 2>/dev/null
}
RESPONSE=$(defenseclaw_hook_post) || {
  defenseclaw_gateway_cold_start "$?" || fail_unreachable "gateway unreachable"
  RESPONSE=$(defenseclaw_hook_post) || fail_unreachable "gateway unreachable"
}
defenseclaw_retry_busy _dc_hook_post_response || fail_unreachable "gateway unreachable"

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
else
  antigravity_emit_fallback 0
fi
exit 0
