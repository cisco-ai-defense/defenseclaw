#!/bin/bash
# defenseclaw-managed-hook v8
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

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook).
. "${HOOK_DIR}/_hardening.sh"
{{if .Sandbox}}# OpenShell sandbox: _sandbox.sh drops every inherited variable the hook
# does not read and pins the baked PATH before the first child process
# (mktemp in defenseclaw_harden_env) or helper call. The registered event
# is taken from argv again afterwards: an inherited HOOK_EVENT export would
# otherwise have been dropped with the rest of the environment.
. "${HOOK_DIR}/_sandbox.sh"
HOOK_EVENT="${1:-}"
{{end}}defenseclaw_harden_resources
defenseclaw_harden_env

{{if .Sandbox}}# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
# Antigravity enforces only a synchronous PreToolUse {"decision":"deny"} on
# stdout, which every failure below prints for that event.
FAIL_MODE="closed"
readonly FAIL_MODE{{else}}FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"{{end}}

{{if .Sandbox}}# A closed PreToolUse fallback's deny reason says why (the second argument):
# an unreachable DefenseClaw, a request it refused, a reply that is no
# verdict. The tool call is blocked either way.
{{end}}antigravity_emit_fallback() {
  local closed="${1:-0}"{{if .Sandbox}}
  local reason="${2:-DefenseClaw policy service is unavailable.}"{{end}}
  case "$HOOK_EVENT" in
    PreToolUse)
      if [ "$closed" = "1" ]; then
{{if .Sandbox}}        printf '{"decision":"deny","reason":"%s"}\n' "$(defenseclaw_json_escape "$reason")"
{{else}}        printf '%s\n' '{"decision":"deny","reason":"DefenseClaw policy service is unavailable."}'
{{end}}      else
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

{{if .Sandbox}}# The image registers exactly one documented lifecycle event per handler.
if [ "$#" -ne 1 ]; then
  defenseclaw_log_hook_failure antigravity antigravity-hook "unexpected registered command arguments" response closed
  antigravity_emit_fallback 1 "DefenseClaw hook was called with unexpected arguments, so the tool call is blocked."
  exit 0
fi
case "$HOOK_EVENT" in
  PreInvocation|PreToolUse|PostToolUse|PostInvocation|Stop) ;;
  *)
    defenseclaw_log_hook_failure antigravity antigravity-hook "unregistered event" response closed
    antigravity_emit_fallback 1
    exit 0
    ;;
esac

# The binding token is the only credential a sandbox hook may present.
case "${DEFENSECLAW_SANDBOX_TOKEN:-}" in
  ''|*$'\n'*|*$'\r'*)
    defenseclaw_log_hook_failure antigravity antigravity-hook "missing or malformed sandbox binding token" transport closed
    echo "defenseclaw: missing or malformed sandbox binding token (DEFENSECLAW_SANDBOX_TOKEN), blocking antigravity tool (sandbox hooks fail closed)" >&2
    antigravity_emit_fallback 1 "DefenseClaw hook has no valid sandbox binding token, so the tool call is blocked."
    exit 0
    ;;
esac
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_failure antigravity antigravity-hook "missing gateway token" transport "$FAIL_MODE"
  if defenseclaw_should_fail_closed_on_unreachable; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
fi
{{end}}
PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: antigravity hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    antigravity_emit_fallback 1{{if .Sandbox}} "DefenseClaw hook payload is too large, so the tool call is blocked."{{end}}
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}
API_ADDR="{{.APIAddr}}"
{{if .Sandbox}}# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"{{else}}if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
  export DEFENSECLAW_GATEWAY_TOKEN
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"{{end}}

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
    antigravity_emit_fallback 1{{if .Sandbox}} "${2:-DefenseClaw answered the hook request without a verdict, so the tool call is blocked.}"{{end}}
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}

{{.HookSocketTransportSH}}AUTH_HEADER_ARGS=()
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

{{if .Sandbox}}# One short attempt plus one retry carrying the same idempotency key: the
# OpenShell relay occasionally drops a request, and the ingress dedupes by key.
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/antigravity/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: antigravity-hook/1.0" \
  -H "X-DefenseClaw-Antigravity-Event: ${HOOK_EVENT}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "sandbox ingress unreachable"
}{{else}}# A refused connection means this account's gateway is not running (after
# a reboot, for example): start it once and retry. See
# defenseclaw_gateway_cold_start in _hardening.sh.
defenseclaw_hook_post() {
  curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/antigravity/hook" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: antigravity-hook/1.0" \
    -H "X-DefenseClaw-Antigravity-Event: ${HOOK_EVENT}" \
    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}" \
    --connect-timeout 2{{if .HookSocketTransportSH}} --unix-socket "${DEFENSECLAW_HOOK_SOCKET}"{{end}} \
    --max-time 29 \
    -d "$PAYLOAD" 2>/dev/null
}
RESPONSE=$(defenseclaw_hook_post) || {
  defenseclaw_gateway_cold_start "$?" || fail_unreachable "gateway unreachable"
  RESPONSE=$(defenseclaw_hook_post) || fail_unreachable "gateway unreachable"
}{{end}}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
{{if .Sandbox}}elif [ "$HTTP_CODE" -ge 400 ] 2>/dev/null && [ "$HTTP_CODE" -lt 500 ] 2>/dev/null; then
  # The request was refused (a malformed hook input, a token or route the
  # ingress does not accept, a rate limit), which is no unreachable service.
  fail_response "gateway returned HTTP ${HTTP_CODE}" "DefenseClaw hook request was refused (HTTP ${HTTP_CODE}), so the tool call is blocked."
{{end}}elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
{{if .Sandbox}}# Every DefenseClaw verdict names its action: an empty or unknown one is a
# reply the workload may have shaped, never an allow. A block without a
# rendered directive still denies PreToolUse.
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|alert|confirm) ;;
  block)
    if { [ -z "$OUTPUT" ] || [ "$OUTPUT" = "null" ]; } && [ "$HOOK_EVENT" = "PreToolUse" ]; then
      REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null) || REASON=""
      if [ -z "$REASON" ]; then
        REASON="Blocked by DefenseClaw Antigravity policy."
      fi
      OUTPUT="$(printf '{"decision":"deny","reason":"%s"}' "$(defenseclaw_json_escape "$REASON")")"
    fi
    ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
{{end}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
else
  antigravity_emit_fallback 0
fi
exit 0
