#!/bin/bash
# defenseclaw-managed-hook v8
# defenseclaw-derived: sha256=2d9ef83d141a29d357aa9815b865938ccd81c7ee0e9ac6b305ac32997c4fdc94 fail_mode=open
# DefenseClaw Cursor hook — forwards Cursor command-hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-$(cd ~ 2>/dev/null && pwd)}}"
export HOME

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

# Cursor requires one JSON object on stdout. Its accepted fields differ by
# event, so local fallbacks must never combine prompt `continue` with tool
# `permission` fields. CURSOR_EVENT is populated after the capped stdin read;
# pre-read and malformed/oversized paths use the exact no-fields object.
CURSOR_EVENT=""
emit_cursor_allow() {
  case "$CURSOR_EVENT" in
    beforeSubmitPrompt) printf '{"continue":true}\n' ;;
    preToolUse|subagentStart|beforeShellExecution|beforeMCPExecution|beforeReadFile|beforeTabFileRead)
      printf '{"permission":"allow"}\n'
      ;;
    *) printf '{}\n' ;;
  esac
}
emit_cursor_deny() {
  MESSAGE="$1"
  case "$CURSOR_EVENT" in
    beforeSubmitPrompt)
      printf '{"continue":false,"user_message":"%s"}\n' "$MESSAGE"
      ;;
    preToolUse|beforeShellExecution|beforeMCPExecution)
      printf '{"permission":"deny","user_message":"%s","agent_message":"%s"}\n' "$MESSAGE" "$MESSAGE"
      ;;
    subagentStart|beforeReadFile)
      printf '{"permission":"deny","user_message":"%s"}\n' "$MESSAGE"
      ;;
    beforeTabFileRead) printf '{"permission":"deny"}\n' ;;
    *) printf '{}\n' ;;
  esac
}


DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  # Disabling DefenseClaw (or an absent install) must fail OPEN for the
  # agent. Cursor treats a failClosed:true hook entry that produces empty
  # stdout as a hook failure and blocks the tool, so emit an explicit
  # allow instead of exiting silently — otherwise dropping the .disabled
  # marker would brick a fail-closed Cursor install with no way to
  # self-recover.
  emit_cursor_allow
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
DEFENSECLAW_HOOK_CONNECTOR="cursor"
DEFENSECLAW_HOOK_NAME="cursor-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Read stdin under a 1MB cap so a hostile / runaway agent can't OOM
# the hook process before the gateway sees the payload.
PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: cursor hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    emit_cursor_deny "DefenseClaw hook payload too large"
    exit 2
  fi
  emit_cursor_allow
  exit 0
}
CURSOR_EVENT="$(defenseclaw_json_string_field "$PAYLOAD" "hook_event_name" 2>/dev/null || true)"

if [ ! -f "${HOOK_DIR}/.token" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  MISSING_TOKEN_REASON="missing gateway token: ${HOOK_DIR}/.token not found"
  defenseclaw_log_hook_failure cursor cursor-hook "$MISSING_TOKEN_REASON" transport "$FAIL_MODE"
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: ${MISSING_TOKEN_REASON}, blocking cursor tool (DEFENSECLAW_STRICT_AVAILABILITY=1)" >&2
    emit_cursor_deny "DefenseClaw hook failed closed"
    exit 2
  fi
  echo "defenseclaw: ${MISSING_TOKEN_REASON}, allowing cursor tool" >&2
  emit_cursor_allow
  exit 0
fi
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
  defenseclaw_log_hook_failure cursor cursor-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "cursor tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    emit_cursor_deny "DefenseClaw gateway unreachable; run defenseclaw-gateway start"
    exit 2
  fi
  emit_cursor_allow
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure cursor cursor-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: cursor hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    emit_cursor_allow
    exit 0
  fi
  emit_cursor_deny "DefenseClaw hook failed closed"
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
  curl -s --noproxy '*' -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/cursor/hook" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: cursor-hook/1.0" \
    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}" \
    --connect-timeout 2 \
    --max-time 10 \
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
  # Gateway answered but carried no hook_output (e.g. an observe-mode
  # response with nothing to enforce). Emit an explicit allow so a
  # failClosed:true entry never misreads the empty stdout as a failure.
  emit_cursor_allow
fi
exit 0
