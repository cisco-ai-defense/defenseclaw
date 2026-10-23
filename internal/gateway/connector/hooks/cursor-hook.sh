#!/bin/bash
# defenseclaw-managed-hook v8
# DefenseClaw Cursor hook — forwards Cursor command-hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
{{if and (not .Managed) (not .Sandbox)}}# defenseclaw_install_lock_held DATA returns 0 (true) while this account's
# installer holds its data directory DATA: DATA/.install.lock exists as any
# file type, or DATA exists but cannot be searched, so the lock cannot be
# shown absent; no DATA to look in counts as held too. It is the one install
# check of every shell hook. The native hook (installLockHeld), the in-agent
# plugins and the Windows adapters apply the same rule (GAP-0914).
defenseclaw_install_lock_held() {
  local data="${1:-}"
  [ -n "$data" ] || return 0
  if [ -e "${data}/.install.lock" ] || [ -L "${data}/.install.lock" ]; then
    return 0
  fi
  if [ -e "$data" ] || [ -L "$data" ]; then
    if [ -d "$data" ] && [ -x "$data" ]; then
      return 1
    fi
    return 0
  fi
  return 1
}
# A failure before the helpers load (a hook path that does not resolve, a
# missing or broken _hardening.sh, a set -e error) blocks with exit 2
# in fail mode closed, under strict availability and while this account's
# installer holds its data directory; fail mode open keeps the exit status.
# The installed mode decides (GAP-0315).
# defenseclaw_harden_env replaces this trap with the hook's own.
_DC_BOOT_FAIL_MODE="{{.FailMode}}"
defenseclaw_boot_fails_closed() {
  [ "$_DC_BOOT_FAIL_MODE" = "open" ] || return 0
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) return 0 ;; esac
  defenseclaw_install_lock_held "${DEFENSECLAW_HOME:-${HOME:+${HOME}/.defenseclaw}}"
}
trap '_dc_boot_rc=$?; if [ "$_dc_boot_rc" -ne 0 ] && defenseclaw_boot_fails_closed; then exit 2; fi' EXIT
{{end}}# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
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
  # tightens every later outage.
  _DC_HOME_FAIL_MODE="{{.FailMode}}"
  ! defenseclaw_install_lock_held "${DEFENSECLAW_HOME}" || _DC_HOME_FAIL_MODE="closed"
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) _DC_HOME_FAIL_MODE="closed" ;; esac
  if [ "$_DC_HOME_FAIL_MODE" != "open" ]; then
    echo "defenseclaw: hook home unavailable; blocking (fail mode closed)" >&2
    exit 2
  fi
  # A configured open hook keeps its explicit Cursor allow shape if its
  # installation has been removed.
  emit_cursor_allow
  exit 0
fi
{{end}}

{{if .Sandbox}}# OpenShell sandbox: the image registers every hook with failClosed, so
# Cursor denies the action when this hook exits non-zero or prints no valid
# object, and exit 2 or a deny object denies it outright. Every failure path
# below prints the event's deny object and exits 2; the EXIT trap installed
# after defenseclaw_harden_env turns an unexpected status (set -e, set -u)
# into 2 as well.
if [ ! -r "${HOOK_DIR}/_hardening.sh" ] || ! . "${HOOK_DIR}/_hardening.sh"; then
  echo "defenseclaw: hook hardening helper unavailable, blocking cursor tool (sandbox hooks fail closed)" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
fi
# _sandbox.sh drops every inherited variable the hook does not read and pins
# the baked PATH before the first child process (mktemp in
# defenseclaw_harden_env) or helper call.
if [ ! -r "${HOOK_DIR}/_sandbox.sh" ] || ! . "${HOOK_DIR}/_sandbox.sh"; then
  echo "defenseclaw: sandbox transport helper unavailable, blocking cursor tool (sandbox hooks fail closed)" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
fi
if ! defenseclaw_harden_resources; then
  echo "defenseclaw: resource hardening failed, blocking cursor tool (sandbox hooks fail closed)" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
fi
if ! defenseclaw_harden_env; then
  echo "defenseclaw: environment hardening failed, blocking cursor tool (sandbox hooks fail closed)" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
fi
trap '_dc_cursor_rc=$?; _defenseclaw_hook_cleanup; case "$_dc_cursor_rc" in 0|2) ;; *) exit 2 ;; esac' EXIT

# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
FAIL_MODE="closed"
readonly FAIL_MODE
{{else}}# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook).
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

{{if .Managed}}# Managed hooks use the installer-owned delivery policy; an inherited
# DEFENSECLAW_FAIL_MODE cannot weaken an explicitly closed managed hook.
FAIL_MODE="{{.FailMode}}"{{else}}FAIL_MODE="{{.FailMode}}"
# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's
# environment is not read, so status and doctor report what runs (GAP-0315).{{end}}
{{if and (not .Managed) (not .Sandbox)}}defenseclaw_close_during_install
{{end}}
{{end}}DEFENSECLAW_HOOK_CONNECTOR="cursor"
DEFENSECLAW_HOOK_NAME="cursor-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

# Read stdin under a 1MB cap so a hostile / runaway agent can't OOM
# the hook process before the gateway sees the payload.
{{if and .Managed (not .SecureClient) (not .Sandbox)}}# A standalone managed hook blocks input too large to inspect in every
# fail mode: the administrator's open covers a gateway outage only.
{{end}}PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}")")" || {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  FAIL_MODE=closed
{{end}}  echo "defenseclaw: cursor hook refusing oversized payload" >&2
  if [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" != "open" ]; then
    emit_cursor_deny "DefenseClaw hook payload too large"
    exit 2
  fi
  emit_cursor_allow
  exit 0
}
{{if .Sandbox}}# jq, not the awk field scanner: the image verifies only the tools the
# sandbox hooks list as runtime binaries.
CURSOR_EVENT="$(printf '%s' "$PAYLOAD" | _dc_jq -r 'if type == "object" then (.hook_event_name // empty) else empty end | strings' 2>/dev/null || true)"
{{else}}CURSOR_EVENT="$(defenseclaw_json_string_field "$PAYLOAD" "hook_event_name" 2>/dev/null || true)"
{{end}}
{{if .Sandbox}}if ! ( defenseclaw_sandbox_require_token cursor cursor-hook "cursor tool" ); then
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
fi
# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"

fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_allow_failed_stop_event cursor cursor-hook "" "${PAYLOAD:-}" "$1" transport
  defenseclaw_log_hook_delivery_failure cursor cursor-hook "$1" transport "$FAIL_MODE"
  echo "defenseclaw: sandbox ingress unreachable, blocking cursor tool (sandbox hooks fail closed): $1" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_allow_failed_stop_event cursor cursor-hook "" "${PAYLOAD:-}" "$1" response
  defenseclaw_log_hook_delivery_failure cursor cursor-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: cursor hook error, blocking cursor tool (sandbox hooks fail closed): $1" >&2
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 2
}
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  MISSING_TOKEN_REASON="missing gateway token: ${HOOK_DIR}/{{.TokenFile}} not found"
  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_allow_failed_stop_event cursor cursor-hook "" "$PAYLOAD" "$MISSING_TOKEN_REASON" transport
  fi
  defenseclaw_log_hook_delivery_failure cursor cursor-hook "$MISSING_TOKEN_REASON" transport "$FAIL_MODE"
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: ${MISSING_TOKEN_REASON}, blocking cursor tool (DEFENSECLAW_STRICT_AVAILABILITY=1)" >&2
    emit_cursor_deny "DefenseClaw hook failed closed"
    exit 2
  fi
  echo "defenseclaw: ${MISSING_TOKEN_REASON}, allowing cursor tool" >&2
  emit_cursor_allow
  exit 0
fi
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
{{end}}  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_allow_failed_stop_event cursor cursor-hook "" "${PAYLOAD:-}" "$1" transport
  fi
  defenseclaw_log_hook_delivery_failure cursor cursor-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "cursor tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    emit_cursor_deny "{{if .Managed}}DefenseClaw hook failed closed{{else}}DefenseClaw gateway unreachable; run defenseclaw-gateway start{{end}}"
    exit 2
  fi
  emit_cursor_allow
  exit 0
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  # A standalone managed hook: the administrator's open covers a gateway
  # outage only (the service not running, restarting or giving no answer
  # in time). A refusal, an error status or an unusable answer blocks.
  FAIL_MODE="closed"
{{end}}  [ "$FAIL_MODE" = "open" ] ||
    defenseclaw_allow_failed_stop_event cursor cursor-hook "" "${PAYLOAD:-}" "$1" response
  defenseclaw_log_hook_delivery_failure cursor cursor-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: cursor hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    emit_cursor_allow
    exit 0
  fi
  emit_cursor_deny "DefenseClaw hook failed closed"
  exit 0
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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/cursor/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: cursor-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}if defenseclaw_api_listener_unproven "$API_ADDR"; then
  fail_unreachable "${API_ADDR} is not proven to be this account's gateway; no token or payload was sent. Another account may hold the port. Run \`defenseclaw setup gateway --api-port <free-port>\` to choose a free port"
fi
# A refused or dropped connection means this account's gateway is
# restarting or not running (after a reboot, for example): send the call
# again for up to 3 seconds, starting the gateway after a refusal. See
# defenseclaw_await_gateway in _hardening.sh.
# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# payload on descriptors, never on its command line.
defenseclaw_hook_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/cursor/hook" 10 "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: cursor-hook/1.0" \
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
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi{{end}}

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
{{if or .Sandbox (not .SecureClient)}}{{/* Every DefenseClaw verdict names its action: an empty or unknown one is no
verdict, never an allow (a sandbox workload may have shaped it; a hook in fail
mode closed blocks on it, open lets the call run: rel-1-0-3 GAP-0037, GAP-0153;
a Secure Client render keeps its own contract). */}}ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|block|confirm|alert) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
if [ "$ACTION" = "block" ]; then
{{if or .Sandbox .Managed}}  # Exit 2 denies whatever the object says; the event-native object carries
  # DefenseClaw's reason when the gateway rendered one.
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
    echo "$OUTPUT"
  else
    emit_cursor_deny "Blocked by DefenseClaw Cursor policy."
  fi
  exit 2
{{else}}  # A per-user hook keeps the exit-0 contract, where the object decides: a
  # block whose object does not deny is answered with DefenseClaw's own deny.
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ] &&
    echo "$OUTPUT" | _dc_jq -e '.permission == "deny" or .continue == false' >/dev/null 2>&1; then
    echo "$OUTPUT"
  else
    emit_cursor_deny "Blocked by DefenseClaw Cursor policy."
  fi
  exit 0
{{end}}fi
{{end}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
else
  # Gateway answered but carried no hook_output (e.g. an observe-mode
  # response with nothing to enforce). Emit an explicit allow so a
  # failClosed:true entry never misreads the empty stdout as a failure.
  emit_cursor_allow
fi
exit 0
