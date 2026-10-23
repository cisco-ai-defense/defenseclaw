#!/bin/bash
# defenseclaw-managed-hook v8
# DefenseClaw Antigravity (`agy`) hook. Setup passes the documented lifecycle
# event as argv[1] because Antigravity's official stdin schemas omit it.
# PreToolUse blocks only through synchronous stdout {"decision":"deny"}; this
# bridge does not rely on undocumented non-zero-exit enforcement.
set -euo pipefail

HOOK_EVENT="${1:-}"
# A failure before the helpers load (a hook path that does not resolve, a
# missing or broken _hardening.sh, a set -e error) still answers: in fail
# mode closed PreToolUse gets Antigravity's deny, which needs no helper. Other
# events and fail mode open keep the exit status. The installed mode decides
# (the environment's DEFENSECLAW_FAIL_MODE is not read, GAP-0315); strict
# availability closes it, as it closes every later failure.
{{if or .Sandbox (and .Managed (not .SecureClient) (not .SecureClientDelivery))}}_DC_BOOT_FAIL_MODE="closed"
{{else}}_DC_BOOT_FAIL_MODE="{{.FailMode}}"
case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) _DC_BOOT_FAIL_MODE="closed" ;; esac
{{end}}antigravity_bootstrap_failure() {
  if [ "$_DC_BOOT_FAIL_MODE" != "open" ] && [ "$HOOK_EVENT" = "PreToolUse" ]; then
    echo "defenseclaw: antigravity hook could not start; blocking (fail mode closed)" >&2
    printf '%s\n' '{"decision":"deny","reason":"DefenseClaw hook failed closed"}'
    exit 0
  fi
  exit "$1"
}
trap '_dc_boot_rc=$?; if [ "$_dc_boot_rc" -ne 0 ]; then antigravity_bootstrap_failure "$_dc_boot_rc"; fi' EXIT
# A registration that lost its event gets no verdict: the gateway requires
# the event. In fail mode closed any input that may be a tool call gets
# PreToolUse's deny before anything else can answer it. Only an input that
# is clearly another event keeps the no-op answer (Stop reads the same
# decision field): a JSON object with a field of PreInvocation,
# PostInvocation or Stop and no tool field (toolCall, tool_call, stepIdx).
case "$HOOK_EVENT" in
  PreInvocation|PreToolUse|PostToolUse|PostInvocation|Stop) ;;
  *)
    if [ "$_DC_BOOT_FAIL_MODE" != "open" ]; then
      _dc_unbound_input=""
      IFS= read -r -d '' -n 1048576 _dc_unbound_input || true
      _dc_object_re='^[[:space:]]*\{'
      _dc_tool_field_re='"(toolCall|tool_call|stepIdx)"[[:space:]]*:'
      _dc_other_event_re='"(invocationNum|initialNumSteps|executionNum|terminationReason|fullyIdle)"[[:space:]]*:'
      if [ "${#_dc_unbound_input}" -lt 1048576 ] && [[ "$_dc_unbound_input" =~ $_dc_object_re ]] &&
        [[ "$_dc_unbound_input" =~ $_dc_other_event_re ]] && ! [[ "$_dc_unbound_input" =~ $_dc_tool_field_re ]]; then
        printf '%s\n' '{}'
        exit 0
      fi
      echo "defenseclaw: antigravity hook is registered without a reviewed event; blocking an input that may be a tool call (fail mode closed)" >&2
{{if .Sandbox}}      printf '%s\n' '{"decision":"deny","reason":"DefenseClaw hook was called without its registered event, so the tool call is blocked."}'
{{else if .Managed}}      printf '%s\n' '{"decision":"deny","reason":"DefenseClaw blocked this tool call: its DefenseClaw hook is registered without an Antigravity event DefenseClaw reviewed. Ask your administrator to run ensure, which rewrites the DefenseClaw hooks."}'
{{else}}      printf '%s\n' '{"decision":"deny","reason":"DefenseClaw blocked this tool call: its DefenseClaw hook is registered without an Antigravity event DefenseClaw reviewed. Run `defenseclaw setup antigravity` to register it again."}'
{{end}}      exit 0
    fi
    ;;
esac
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
{{if not .Sandbox}}_DC_SECURE_CLIENT_HOOK={{if .SecureClient}}1{{else}}0{{end}}
_DC_SECURE_CLIENT_DELIVERY={{if .SecureClientDelivery}}1{{else}}0{{end}}
{{end}}DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)"
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
  # The installed mode decides; strict availability tightens this exit as it
  # tightens every later outage (_DC_BOOT_FAIL_MODE).
  if [ "$_DC_BOOT_FAIL_MODE" != "open" ]; then
    echo "defenseclaw: hook home unavailable; blocking (fail mode closed)" >&2
    if [ "$HOOK_EVENT" = "PreToolUse" ]; then
      printf '%s\n' '{"decision":"deny","reason":"DefenseClaw hook failed closed"}'
      exit 0
    fi
    exit 2
  fi
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
# defenseclaw_harden_env replaced the EXIT trap with its cleanup: keep both.
trap '_dc_boot_rc=$?; _defenseclaw_hook_cleanup; if [ "$_dc_boot_rc" -ne 0 ]; then antigravity_bootstrap_failure "$_dc_boot_rc"; fi' EXIT

{{if .Sandbox}}# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
# Antigravity enforces only a synchronous PreToolUse {"decision":"deny"} on
# stdout, which every failure below prints for that event.
FAIL_MODE="closed"
readonly FAIL_MODE{{else}}FAIL_MODE="{{.FailMode}}"
# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's
# environment is not read, so status and doctor report what runs (GAP-0461).{{end}}
{{if and (not .Managed) (not .Sandbox)}}defenseclaw_close_during_install
{{end}}
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
  defenseclaw_log_hook_failure antigravity antigravity-hook "unexpected registered command arguments" response closed fail_closed
  antigravity_emit_fallback 1 "DefenseClaw hook was called with unexpected arguments, so the tool call is blocked."
  exit 0
fi
case "$HOOK_EVENT" in
  PreInvocation|PreToolUse|PostToolUse|PostInvocation|Stop) ;;
  *)
    defenseclaw_log_hook_failure antigravity antigravity-hook "unregistered event" response closed fail_closed
    antigravity_emit_fallback 1
    exit 0
    ;;
esac

# The binding token is the only credential a sandbox hook may present.
case "${DEFENSECLAW_SANDBOX_TOKEN:-}" in
  ''|*$'\n'*|*$'\r'*)
    defenseclaw_log_hook_failure antigravity antigravity-hook "missing or malformed sandbox binding token" transport closed fail_closed
    echo "defenseclaw: missing or malformed sandbox binding token (DEFENSECLAW_SANDBOX_TOKEN), blocking antigravity tool (sandbox hooks fail closed)" >&2
    antigravity_emit_fallback 1 "DefenseClaw hook has no valid sandbox binding token, so the tool call is blocked."
    exit 0
    ;;
esac
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_log_hook_delivery_failure antigravity antigravity-hook "missing gateway token" transport "$FAIL_MODE"
  if defenseclaw_should_fail_closed_on_unreachable; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
fi
{{end}}
{{if and .Managed (not .SecureClient) (not .Sandbox)}}# A standalone managed hook blocks input too large to inspect in every
# fail mode: the administrator's open covers a gateway outage only.
{{end}}PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}")")" || {
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  FAIL_MODE=closed
{{end}}  echo "defenseclaw: antigravity hook refusing oversized payload" >&2
  if [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" != "open" ]; then
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
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
# Only the private copy is used from here on: no child process (curl, jq, the
# cold-started gateway) inherits the bearer in its environment.
unset DEFENSECLAW_GATEWAY_TOKEN{{end}}

fail_unreachable() {
  defenseclaw_log_hook_delivery_failure antigravity antigravity-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "antigravity tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    antigravity_emit_fallback 1
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}

fail_response() {
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  # A standalone managed hook: the administrator's open covers a gateway
  # outage only (the service not running, restarting or giving no answer
  # in time). A refusal, an error status or an unusable answer blocks.
  FAIL_MODE="closed"
{{end}}  defenseclaw_log_hook_delivery_failure antigravity antigravity-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: antigravity hook error: $1" >&2
  if [ "$FAIL_MODE" != "open" ]; then
    antigravity_emit_fallback 1{{if .Sandbox}} "${2:-DefenseClaw answered the hook request without a verdict, so the tool call is blocked.}"{{end}}
  else
    antigravity_emit_fallback 0
  fi
  exit 0
}

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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/antigravity/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: antigravity-hook/1.0" \
  -H "X-DefenseClaw-Antigravity-Event: ${HOOK_EVENT}" \
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
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/antigravity/hook" 29 "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: antigravity-hook/1.0" \
    -H "X-DefenseClaw-Antigravity-Event: ${HOOK_EVENT}" \
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
{{if and .Managed (not .SecureClient) (not .Sandbox)}}# The gateway answered 429, so it is up: a resend that fails after it is no
# outage in a standalone managed hook.
{{end}}defenseclaw_retry_busy _dc_hook_post_response || {{if and .Managed (not .SecureClient) (not .Sandbox)}}fail_response "gateway returned HTTP 429"{{else}}fail_unreachable "gateway unreachable"{{end}}{{end}}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

{{if and .Managed (not .SecureClient) (not .Sandbox)}}defenseclaw_managed_http_result "$HTTP_CODE"
{{else}}if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  fail_response "gateway returned HTTP ${HTTP_CODE}"
{{else}}  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
{{end}}
{{if .Sandbox}}elif [ "$HTTP_CODE" -ge 400 ] 2>/dev/null && [ "$HTTP_CODE" -lt 500 ] 2>/dev/null; then
  # The request was refused (a malformed hook input, a token or route the
  # ingress does not accept, a rate limit), which is no unreachable service.
  fail_response "gateway returned HTTP ${HTTP_CODE}" "DefenseClaw hook request was refused (HTTP ${HTTP_CODE}), so the tool call is blocked."
{{end}}elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi{{end}}

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
{{if or .Sandbox (not .SecureClient)}}# Every DefenseClaw verdict names its action: an empty or unknown one is no
# verdict, never an allow (a sandbox workload may have shaped it; a hook in
# fail mode closed blocks on it, open lets the call run: rel-1-0-3 GAP-0037,
# GAP-0153; a Secure Client render keeps its own contract). A
# block whose directive is missing or does not deny still denies PreToolUse.
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|alert) ;;
  confirm)
    # A confirmation is Antigravity's force_ask; without it the call would
    # run (plain ask honors a cached Always Allow grant: GAP-0405).
    if [ "$HOOK_EVENT" = "PreToolUse" ]; then
      OUTPUT_DECISION=""
      if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
        OUTPUT_DECISION=$(echo "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null) || OUTPUT_DECISION=""
      fi
      [ "$OUTPUT_DECISION" = "force_ask" ] || fail_response "missing native confirmation in gateway response"
    fi
    ;;
  block)
    OUTPUT_DECISION=""
    if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
      OUTPUT_DECISION=$(echo "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null) || OUTPUT_DECISION=""
    fi
    if [ "$OUTPUT_DECISION" != "deny" ] && [ "$HOOK_EVENT" = "PreToolUse" ]; then
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
