#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw PreRequest hook — inspects user query before it is sent to the LLM.
# Reads the user message content from stdin (JSON with "content" field).
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
{{if .Managed}}
DEFENSECLAW_MANAGED_HOOK=1
export DEFENSECLAW_MANAGED_HOOK
DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)"
export DEFENSECLAW_HOME
{{else}}
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
{{end}}

# Plan B4 / S0.4: shell-side hook hardening (sourced before reading
# stdin so the bounded fd limit is in place when curl spawns).
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

DEFENSECLAW_HOOK_CONNECTOR="inspect"
DEFENSECLAW_HOOK_NAME="inspect-request"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME
RUNTIME_CONNECTOR="$(defenseclaw_shared_runtime_connector "$HOOK_DIR")"
FAIL_MODE="$(defenseclaw_shared_runtime_fail_mode "$HOOK_DIR" "$RUNTIME_CONNECTOR")"

# Avarice F-2025 / chain F-3397: include the gateway bearer token on
# every inspection call. Pre-fix the hook never sent Authorization,
# so a sidecar that required token auth would 401 every request and
# (with FAIL_MODE=open) silently allow them. The token lives in
# a runtime-selected token file (mode 0600, written by the hook installer)
# and may be overridden by the env var for ephemeral CI shells.
TOKEN_FILE="$(defenseclaw_shared_hook_token_file "$HOOK_DIR" "$RUNTIME_CONNECTOR")"
if [ ! -f "$TOKEN_FILE" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token inspect inspect-request "request"
fi
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "$TOKEN_FILE" ]; then
  if [ -n "$RUNTIME_CONNECTOR" ]; then
    DEFENSECLAW_GATEWAY_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
  else
    # shellcheck source=/dev/null
    . "$TOKEN_FILE"
  fi
  export DEFENSECLAW_GATEWAY_TOKEN
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

CONTENT="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: inspect request refusing oversized payload" >&2
  exit 2
}

API_ADDR="{{.APIAddr}}"

# Transport and response failures respect FAIL_MODE;
# DEFENSECLAW_STRICT_AVAILABILITY=1 remains a force-closed override.
fail_unreachable() {
  defenseclaw_log_hook_failure inspect inspect-request "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "request" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure inspect inspect-request "$1" response "$FAIL_MODE"
  echo "defenseclaw: inspect-request hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

# Avarice F-2025 / chain F-3397: HTTP 401/403 from the gateway means
# the hook's token is missing or wrong. That is a misconfiguration the
# attacker can rely on (curl shim or rogue runtime can race the auth
# rotation), so we fail CLOSED unconditionally — bypassing FAIL_MODE.
# Operators that genuinely need to disable the inspect surface use
# the explicit ${DEFENSECLAW_HOME}/.disabled sentinel (line 14 above).
fail_unauthorized() {
  defenseclaw_log_hook_failure inspect inspect-request "$1" response "closed"
  echo "defenseclaw: inspect-request hook auth rejected: $1 (fail-closed override)" >&2
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi
CONNECTOR_HEADER_ARGS=()
if [ -n "$RUNTIME_CONNECTOR" ]; then
  CONNECTOR_HEADER_ARGS=(-H "X-DefenseClaw-Connector: ${RUNTIME_CONNECTOR}")
fi

RESPONSE=$(printf '%s' "$CONTENT" | curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/request" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${CONNECTOR_HEADER_ARGS[@]+"${CONNECTOR_HEADER_ARGS[@]}"}" \
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

ACTION=$(echo "$RESULT" | _dc_jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // "blocked by DefenseClaw"' 2>/dev/null)
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
