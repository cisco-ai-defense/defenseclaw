#!/bin/bash
{{$fail := "0"}}{{if .Sandbox}}{{$fail = "2"}}{{end}}# defenseclaw-managed-hook v7
# DefenseClaw Copilot CLI hook — forwards Copilot CLI hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-}}"
if [ -z "$HOME" ]; then
  HOME="$(cd ~ 2>/dev/null && pwd)" || exit {{$fail}}
fi
export HOME

HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || exit {{$fail}}
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit {{$fail}}
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || exit {{$fail}}
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || exit {{$fail}}
  else
    exit {{$fail}}
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit {{$fail}}
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET
{{if .Managed}}
DEFENSECLAW_MANAGED_HOOK=1
export DEFENSECLAW_MANAGED_HOOK
DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)" || exit {{$fail}}
export DEFENSECLAW_HOME
{{else}}
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
{{end}}
{{if .Sandbox}}
# OpenShell sandbox: Copilot denies a tool only on exit 2 (or a deny verdict
# on stdout); any other failure would let the tool run. Every exit path below
# is explicit, and the EXIT trap installed after defenseclaw_harden_env turns
# an unexpected status (set -e, set -u) into 2 as well.
if [ ! -r "${HOOK_DIR}/_hardening.sh" ]; then
  echo "defenseclaw: hook hardening helper unavailable, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
fi
if ! . "${HOOK_DIR}/_hardening.sh"; then
  echo "defenseclaw: hook hardening helper failed, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
fi
# _sandbox.sh drops every inherited variable the hook does not read and pins
# the baked PATH before the first child process (mktemp in
# defenseclaw_harden_env) or helper call.
if [ ! -r "${HOOK_DIR}/_sandbox.sh" ] || ! . "${HOOK_DIR}/_sandbox.sh"; then
  echo "defenseclaw: sandbox transport helper unavailable, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
fi
if ! defenseclaw_harden_resources; then
  echo "defenseclaw: resource hardening failed, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
fi
if ! defenseclaw_harden_env; then
  echo "defenseclaw: environment hardening failed, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
fi
trap '_dc_copilot_rc=$?; _defenseclaw_hook_cleanup; case "$_dc_copilot_rc" in 0|2) ;; *) exit 2 ;; esac' EXIT

# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
FAIL_MODE="closed"
readonly FAIL_MODE
{{else}}
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
{{end}}
DEFENSECLAW_HOOK_CONNECTOR="copilot"
DEFENSECLAW_HOOK_NAME="copilot-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Native camelCase Copilot payloads intentionally omit an event discriminator.
# Setup binds every reviewed registration to this exact argv pair and the bridge
# carries it in an authenticated, DefenseClaw-only HTTP header without rewriting
# the official stdin body.
if [ "$#" -ne 2 ] || [ "$1" != "--event" ]; then
  echo "defenseclaw: copilot hook requires --event <event>" >&2
  exit {{$fail}}
fi
COPILOT_HOOK_EVENT="$2"
case "$COPILOT_HOOK_EVENT" in
  sessionStart|sessionEnd|userPromptSubmitted|userPromptTransformed|preToolUse|postToolUse|permissionRequest|agentStop|subagentStart|subagentStop|postToolUseFailure|errorOccurred|preCompact|notification) ;;
  *)
    echo "defenseclaw: copilot hook received unsupported event" >&2
    exit {{$fail}}
    ;;
esac

{{if .Sandbox}}defenseclaw_sandbox_require_token copilot copilot-hook "copilot tool"

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: copilot hook refusing oversized payload, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
}
# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"

fail_unreachable() {
  defenseclaw_log_hook_failure copilot copilot-hook "$1" transport "$FAIL_MODE"
  echo "defenseclaw: sandbox ingress unreachable, blocking copilot tool (sandbox hooks fail closed): $1" >&2
  exit 2
}

fail_response() {
  defenseclaw_log_hook_failure copilot copilot-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: copilot hook error, blocking copilot tool (sandbox hooks fail closed): $1" >&2
  exit 2
}
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_failure copilot copilot-hook "missing gateway token" transport "$FAIL_MODE"
  echo "defenseclaw: missing gateway token, allowing copilot tool" >&2
  exit 0
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: copilot hook refusing oversized payload" >&2
  exit 0
}
API_ADDR="{{.APIAddr}}"
if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
  export DEFENSECLAW_GATEWAY_TOKEN
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
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
{{end}}
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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/copilot/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: copilot-hook/1.0" \
  -H "X-DefenseClaw-Copilot-Event: ${COPILOT_HOOK_EVENT}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "sandbox ingress unreachable"
}{{else}}RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/copilot/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: copilot-hook/1.0" \
  -H "X-DefenseClaw-Copilot-Event: ${COPILOT_HOOK_EVENT}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}" \
  --connect-timeout 2{{if .HookSocketTransportSH}} --unix-socket "${DEFENSECLAW_HOOK_SOCKET}"{{end}} \
  --max-time 29 \
  -d "$PAYLOAD" 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}{{end}}

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
{{if .Sandbox}}ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|block|confirm|alert) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
  exit 0
fi
# A block without an event-native verdict still denies: exit 2 is Copilot's
# hook deny for preToolUse and permissionRequest.
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null) || REASON=""
  printf '%s\n' "${REASON:-Blocked by DefenseClaw Copilot policy.}" >&2
  exit 2
fi
exit 0
{{else}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
exit 0
{{end}}