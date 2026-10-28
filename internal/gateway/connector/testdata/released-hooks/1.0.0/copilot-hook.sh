#!/bin/bash
# defenseclaw-managed-hook v7
# defenseclaw-derived: sha256=12ed22ac795d7ac7176bad3ecd947b09689e11ccd58762dfaa208cbd4d44b85b fail_mode=open
# DefenseClaw Copilot CLI hook — forwards Copilot CLI hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-}}"
if [ -z "$HOME" ]; then
  HOME="$(cd ~ 2>/dev/null && pwd)" || exit 0
fi
export HOME

HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || exit 0
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 0
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || exit 0
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || exit 0
  else
    exit 0
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 0
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET

DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi


# Plan B4 / S0.4: shell-side hook hardening.
if [ ! -r "${HOOK_DIR}/_hardening.sh" ]; then
  echo "defenseclaw: hook hardening helper unavailable, allowing copilot tool" >&2
  exit 0
fi
if ! . "${HOOK_DIR}/_hardening.sh"; then
  echo "defenseclaw: hook hardening helper failed, allowing copilot tool" >&2
  exit 0
fi
if ! defenseclaw_harden_resources; then
  echo "defenseclaw: resource hardening failed, allowing copilot tool" >&2
  exit 0
fi
if ! defenseclaw_harden_env; then
  echo "defenseclaw: environment hardening failed, allowing copilot tool" >&2
  exit 0
fi

# Copilot documents timeout failures as fail-open and has no connector-wide
# transport fail-closed switch. Ignore inherited strict/closed settings here;
# only a valid event-native gateway response may request enforcement.
FAIL_MODE="open"

DEFENSECLAW_HOOK_CONNECTOR="copilot"
DEFENSECLAW_HOOK_NAME="copilot-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Native camelCase Copilot payloads intentionally omit an event discriminator.
# Setup binds every reviewed registration to this exact argv pair and the bridge
# carries it in an authenticated, DefenseClaw-only HTTP header without rewriting
# the official stdin body.
if [ "$#" -ne 2 ] || [ "$1" != "--event" ]; then
  echo "defenseclaw: copilot hook requires --event <event>" >&2
  exit 0
fi
COPILOT_HOOK_EVENT="$2"
case "$COPILOT_HOOK_EVENT" in
  sessionStart|sessionEnd|userPromptSubmitted|userPromptTransformed|preToolUse|postToolUse|permissionRequest|agentStop|subagentStart|subagentStop|postToolUseFailure|errorOccurred|preCompact|notification) ;;
  *)
    echo "defenseclaw: copilot hook received unsupported event" >&2
    exit 0
    ;;
esac

if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_failure copilot copilot-hook "missing gateway token" transport "$FAIL_MODE"
  echo "defenseclaw: missing gateway token, allowing copilot tool" >&2
  exit 0
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: copilot hook refusing oversized payload" >&2
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
  defenseclaw_log_hook_failure copilot copilot-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "copilot tool" "$1"
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure copilot copilot-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: copilot hook error: $1" >&2
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
  curl -s --noproxy '*' -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/copilot/hook" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: copilot-hook/1.0" \
    -H "X-DefenseClaw-Copilot-Event: ${COPILOT_HOOK_EVENT}" \
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
fi
exit 0
