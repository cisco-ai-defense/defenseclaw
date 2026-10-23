#!/bin/bash
{{$fail := "0"}}{{if .Sandbox}}{{$fail = "2"}}{{end}}{{$failure := printf "exit %s" $fail}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{$failure = "copilot_managed_failure"}}{{end}}{{if and (not .Managed) (not .Sandbox)}}{{$failure = "copilot_hook_failure"}}{{end}}# defenseclaw-managed-hook v7
# DefenseClaw Copilot CLI hook — forwards Copilot CLI hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
{{if and (not .Sandbox) (or (not .Managed) (not .SecureClient))}}# Copilot honours a native deny only on preToolUse and permissionRequest,
# and its stdin does not name the event: setup binds a reviewed one with
# --event. copilot_deny prints the deny with the text ($1) before helpers,
# credentials and the gateway are consulted. A hook bound to no reviewed
# event prints both denies, so whichever of the two Copilot ran it for is
# denied; Copilot's other events ignore them.
_DC_COPILOT_EVENT=""
if [ "$#" -eq 2 ] && [ "$1" = "--event" ]; then
  case "$2" in
    sessionStart|sessionEnd|userPromptSubmitted|userPromptTransformed|preToolUse|postToolUse|permissionRequest|agentStop|subagentStart|subagentStop|postToolUseFailure|errorOccurred|preCompact|notification) _DC_COPILOT_EVENT="$2" ;;
  esac
fi
copilot_deny() {
  case "$_DC_COPILOT_EVENT" in
    preToolUse) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$1" ;;
    permissionRequest) printf '{"behavior":"deny","message":"%s"}\n' "$1" ;;
    "") printf '{"permissionDecision":"deny","permissionDecisionReason":"%s","behavior":"deny","message":"%s"}\n' "$1" "$1" ;;
  esac
}
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}copilot_managed_failure() {
  copilot_deny "DefenseClaw hook failed closed"
  exit 0
}
trap '_dc_copilot_rc=$?; if [ "$_dc_copilot_rc" -ne 0 ]; then copilot_managed_failure; fi' EXIT
{{end}}{{if and (not .Managed) (not .Sandbox)}}FAIL_MODE="{{.FailMode}}"
# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's
# environment is not read, so status and doctor report what runs (GAP-0315).
# Strict availability closes it.
case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) FAIL_MODE="closed" ;; esac
# Copilot CLI lets a call run when its hook fails. In fail mode closed every
# failure DefenseClaw sees prints Copilot's native deny with the reason ($1)
# instead; Copilot's other events cannot block. Fail mode open lets the call
# run.
copilot_hook_failure() {
  ! declare -F defenseclaw_close_during_install >/dev/null 2>&1 || defenseclaw_close_during_install
  [ "$FAIL_MODE" != "open" ] || exit 0
  local text="DefenseClaw blocked this tool call (fail mode closed). Run \`defenseclaw doctor\` to see why."
  if [ -n "${1:-}" ] && declare -F defenseclaw_json_escape >/dev/null 2>&1; then
    text="$(defenseclaw_json_escape "DefenseClaw blocked this tool call: $1")"
  fi
  copilot_deny "$text"
  exit 0
}
{{end}}# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-}}"
if [ -z "$HOME" ]; then
  HOME="$(cd ~ 2>/dev/null && pwd)" || {{$failure}}
fi
export HOME

HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || {{$failure}}
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || {{$failure}}
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || {{$failure}}
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || {{$failure}}
  else
    {{$failure}}
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || {{$failure}}
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET
{{if .Managed}}
DEFENSECLAW_MANAGED_HOOK=1
export DEFENSECLAW_MANAGED_HOOK
{{if not .Sandbox}}_DC_SECURE_CLIENT_HOOK={{if .SecureClient}}1{{else}}0{{end}}
_DC_SECURE_CLIENT_DELIVERY={{if .SecureClientDelivery}}1{{else}}0{{end}}
{{end}}DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)" || {{$failure}}
export DEFENSECLAW_HOME
{{else}}
# A per-user render is never a managed or Secure Client hook: those markers
# come only from a managed render (the branch above), never from the
# agent's environment, where they would change how the per-user hook answers
# a missing token.
unset DEFENSECLAW_MANAGED_HOOK _DC_SECURE_CLIENT_HOOK _DC_SECURE_CLIENT_DELIVERY
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  # A registered closed hook cannot treat missing local state as retirement.
  [ ! -e "${DEFENSECLAW_HOME}/.install.lock" ] && [ ! -L "${DEFENSECLAW_HOME}/.install.lock" ] || FAIL_MODE="closed"
  if [ "$FAIL_MODE" != "open" ]; then
    echo "defenseclaw: hook home unavailable; blocking (fail mode closed)" >&2
    copilot_hook_failure
  fi
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
  echo "defenseclaw: hook hardening helper unavailable{{if .SecureClient}}, allowing copilot tool{{end}}" >&2
  {{$failure}}
fi
if ! . "${HOOK_DIR}/_hardening.sh"; then
  echo "defenseclaw: hook hardening helper failed{{if .SecureClient}}, allowing copilot tool{{end}}" >&2
  {{$failure}}
fi
if ! defenseclaw_harden_resources; then
  echo "defenseclaw: resource hardening failed{{if .SecureClient}}, allowing copilot tool{{end}}" >&2
  {{$failure}}
fi
if ! defenseclaw_harden_env; then
  echo "defenseclaw: environment hardening failed{{if .SecureClient}}, allowing copilot tool{{end}}" >&2
  {{$failure}}
fi
{{if not .Managed}}defenseclaw_close_during_install
{{end}}

{{if .Managed}}# A standalone hook denies every call it cannot check. A Secure Client hook
# keeps Copilot's upstream fail-open and ignores inherited strict or closed
# settings: only a valid event-native gateway response may enforce.
FAIL_MODE="{{if .ManagedOutageClosed}}closed{{else}}open{{end}}"
{{else}}# Every failure below goes through copilot_hook_failure, which follows
# FAIL_MODE. An unexpected error status (set -e, set -u) does too.
trap '_dc_copilot_rc=$?; _defenseclaw_hook_cleanup; if [ "$_dc_copilot_rc" -ne 0 ]; then copilot_hook_failure; fi' EXIT
{{end}}{{end}}
DEFENSECLAW_HOOK_CONNECTOR="copilot"
DEFENSECLAW_HOOK_NAME="copilot-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Native camelCase Copilot payloads intentionally omit an event discriminator.
# Setup binds every reviewed registration to this exact argv pair and the bridge
# carries it in an authenticated, DefenseClaw-only HTTP header without rewriting
# the official stdin body.
if [ "$#" -ne 2 ] || [ "$1" != "--event" ]; then
  echo "defenseclaw: copilot hook requires --event <event>" >&2
  {{$failure}}{{if and (not .Managed) (not .Sandbox)}} "its DefenseClaw hook is registered without a Copilot event DefenseClaw reviewed. Run \`defenseclaw setup copilot\` to register it again."{{end}}
fi
COPILOT_HOOK_EVENT="$2"
case "$COPILOT_HOOK_EVENT" in
  sessionStart|sessionEnd|userPromptSubmitted|userPromptTransformed|preToolUse|postToolUse|permissionRequest|agentStop|subagentStart|subagentStop|postToolUseFailure|errorOccurred|preCompact|notification) ;;
  *)
    echo "defenseclaw: copilot hook received unsupported event" >&2
    {{$failure}}{{if and (not .Managed) (not .Sandbox)}} "its DefenseClaw hook is registered without a Copilot event DefenseClaw reviewed. Run \`defenseclaw setup copilot\` to register it again."{{end}}
    ;;
esac

{{if .Sandbox}}defenseclaw_sandbox_require_token copilot copilot-hook "copilot tool"

PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "$FAIL_MODE")")" || {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  echo "defenseclaw: copilot hook refusing oversized payload, blocking copilot tool (sandbox hooks fail closed)" >&2
  exit 2
}
# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"

fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_allow_failed_stop_event copilot copilot-hook "$COPILOT_HOOK_EVENT" "" "$1" transport
  defenseclaw_log_hook_failure copilot copilot-hook "$1" transport "$FAIL_MODE" fail_closed
  echo "defenseclaw: sandbox ingress unreachable, blocking copilot tool (sandbox hooks fail closed): $1" >&2
  exit 2
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_allow_failed_stop_event copilot copilot-hook "$COPILOT_HOOK_EVENT" "" "$1" response
  defenseclaw_log_hook_failure copilot copilot-hook "$1" response "$FAIL_MODE" fail_closed
  echo "defenseclaw: copilot hook error, blocking copilot tool (sandbox hooks fail closed): $1" >&2
  exit 2
}
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_failure copilot copilot-hook "missing gateway token" transport "$FAIL_MODE" "$(defenseclaw_hook_delivery_outcome response "$FAIL_MODE")"
  echo "defenseclaw: missing gateway token{{if .SecureClient}}, allowing copilot tool{{end}}" >&2
  {{$failure}}
fi

PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "$FAIL_MODE")")" || {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  echo "defenseclaw: copilot hook refusing oversized payload" >&2
  {{if .Managed}}{{$failure}}{{else}}copilot_hook_failure "it is too large for DefenseClaw to inspect. Make it smaller and try again."{{end}}
}
API_ADDR="{{.APIAddr}}"
if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
# Only the private copy is used from here on: no child process (curl, jq, the
# cold-started gateway) inherits the bearer in its environment.
unset DEFENSECLAW_GATEWAY_TOKEN

fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_log_hook_failure copilot copilot-hook "$1" transport "$FAIL_MODE" "$(defenseclaw_hook_delivery_outcome response "$FAIL_MODE")"
  defenseclaw_emit_unreachable_stderr "copilot tool" "$1"
{{if .Managed}}  {{$failure}}
{{else}}  local next=""
  [ "$1" != "gateway unreachable" ] || next="$(defenseclaw_unreachable_next_step)"
  copilot_hook_failure "${next:-the DefenseClaw gateway is unavailable ($1). Run \`defenseclaw-gateway status\`.}"
{{end}}}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_log_hook_failure copilot copilot-hook "$1" response "$FAIL_MODE" "$(defenseclaw_hook_delivery_outcome response "$FAIL_MODE")"
  echo "defenseclaw: copilot hook error: $1" >&2
  {{if .Managed}}{{$failure}}{{else}}copilot_hook_failure "the DefenseClaw gateway returned an answer DefenseClaw could not use. Run \`defenseclaw doctor\` to see why."{{end}}
}
{{end}}
{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{.ManagedHTTPFailureSH}}{{end}}{{.HookSocketTransportSH}}AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
{{if not .Sandbox}}  # A bearer is an HTTP field value: CR or LF is never valid in it, and either
  # would end the curl config line defenseclaw_gateway_post writes it to.
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*) fail_response "invalid gateway token" ;;
  esac
{{end}}  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
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
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}if defenseclaw_api_listener_foreign "$API_ADDR"; then
  fail_unreachable "${API_ADDR} is held by another account while this account's gateway is not running; no token was sent. Run \`defenseclaw-gateway start\` for the fix"
fi
# A refused or dropped connection means this account's gateway is
# restarting or not running (after a reboot, for example): send the call
# again for up to 3 seconds, starting the gateway after a refusal. See
# defenseclaw_await_gateway in _hardening.sh.
# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# payload on descriptors, never on its command line.
defenseclaw_hook_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/copilot/hook" 29 "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: copilot-hook/1.0" \
    -H "X-DefenseClaw-Copilot-Event: ${COPILOT_HOOK_EVENT}" \
    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}"{{if .HookSocketTransportSH}} \
    --unix-socket "${DEFENSECLAW_HOOK_SOCKET}"{{end}}
}
RESPONSE=$(defenseclaw_hook_post) || {
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  DC_POST_STATUS=$?
  defenseclaw_split_response
  defenseclaw_managed_http_result "$HTTP_CODE" incomplete
  defenseclaw_await_gateway "$DC_POST_STATUS" _dc_hook_post_response || {
    defenseclaw_split_response
    defenseclaw_managed_http_result "$HTTP_CODE" incomplete
    fail_unreachable "gateway unreachable"
  }
{{else}}  defenseclaw_await_gateway "$?" _dc_hook_post_response || fail_unreachable "gateway unreachable"{{end}}
}
defenseclaw_retry_busy _dc_hook_post_response || {{if and .Managed (not .SecureClient) (not .Sandbox)}}fail_response "gateway returned HTTP 429"{{else}}fail_unreachable "gateway unreachable"{{end}}{{end}}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

{{if and .Managed (not .SecureClient) (not .Sandbox)}}defenseclaw_managed_http_result "$HTTP_CODE"
{{else}}if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi{{end}}

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
{{else}}{{if and .Managed (not .SecureClient)}}ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || fail_response "invalid action in gateway response"
case "$ACTION" in
  allow|block|confirm|alert) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
if { [ -z "$OUTPUT" ] || [ "$OUTPUT" = "null" ]; } && { [ "$ACTION" = "block" ] || [ "$ACTION" = "confirm" ]; }; then
  fail_response "missing native output in gateway response"
fi
if [ "$ACTION" = "block" ]; then
  case "$COPILOT_HOOK_EVENT" in
    preToolUse) NATIVE_DENY=$(echo "$OUTPUT" | _dc_jq -r '.permissionDecision == "deny"' 2>/dev/null) || fail_response "invalid native output in gateway response" ;;
    permissionRequest) NATIVE_DENY=$(echo "$OUTPUT" | _dc_jq -r '.behavior == "deny"' 2>/dev/null) || fail_response "invalid native output in gateway response" ;;
    *) fail_response "unsupported native block in gateway response" ;;
  esac
  [ "$NATIVE_DENY" = "true" ] || fail_response "missing native deny in gateway response"
fi
if [ "$ACTION" = "confirm" ]; then
  NATIVE_ASK=true
  case "$COPILOT_HOOK_EVENT" in
    preToolUse) NATIVE_ASK=$(echo "$OUTPUT" | _dc_jq -r '.permissionDecision == "ask"' 2>/dev/null) || fail_response "invalid native output in gateway response" ;;
    permissionRequest) NATIVE_ASK=$(echo "$OUTPUT" | _dc_jq -r '.behavior == "ask"' 2>/dev/null) || fail_response "invalid native output in gateway response" ;;
  esac
  [ "$NATIVE_ASK" = "true" ] || fail_response "missing native confirmation in gateway response"
fi
{{else if not .Managed}}# Fail mode open skips these checks, except while an install that started
# during the call holds the data directory.
defenseclaw_close_during_install
if [ "$FAIL_MODE" != "open" ]; then
  # Every verdict names its action, and on a tool boundary a block carries
  # Copilot's native deny and a confirmation its native ask, as the Windows
  # hook checks: anything else is no verdict, and would let the call run.
  ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || fail_response "invalid action in gateway response"
  case "$ACTION" in
    allow|block|confirm|alert) ;;
    *) fail_response "invalid or missing action in gateway response" ;;
  esac
  NATIVE_ANSWER=true
  case "$COPILOT_HOOK_EVENT:$ACTION" in
    preToolUse:block) NATIVE_ANSWER=$(echo "$OUTPUT" | _dc_jq -r '.permissionDecision == "deny"' 2>/dev/null) || NATIVE_ANSWER=false ;;
    preToolUse:confirm) NATIVE_ANSWER=$(echo "$OUTPUT" | _dc_jq -r '.permissionDecision == "ask"' 2>/dev/null) || NATIVE_ANSWER=false ;;
    permissionRequest:block) NATIVE_ANSWER=$(echo "$OUTPUT" | _dc_jq -r '.behavior == "deny"' 2>/dev/null) || NATIVE_ANSWER=false ;;
    permissionRequest:confirm) NATIVE_ANSWER=$(echo "$OUTPUT" | _dc_jq -r '.behavior == "ask"' 2>/dev/null) || NATIVE_ANSWER=false ;;
  esac
  if [ "$NATIVE_ANSWER" != "true" ]; then
    case "$ACTION" in
      block) fail_response "missing native deny in gateway response" ;;
      *) fail_response "missing native confirmation in gateway response" ;;
    esac
  fi
fi
{{end}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
exit 0
{{end}}
