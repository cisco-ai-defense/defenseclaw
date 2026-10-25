#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw PostToolUse hook — inspects tool execution output before it goes back to the LLM.
# Reads tool output from stdin. TOOL_NAME is set by the agent framework.
set -euo pipefail
{{if and (not .Managed) (not .Sandbox)}}# _DC_HOOK_DATA_DIR is the data directory this hook was installed in, the
# folder above its hooks folder (defenseclaw_install_held). Until the hook
# path is resolved below it is the folder above the path the agent ran.
_DC_HOOK_DATA_DIR="${BASH_SOURCE[0]:-$0}"
case "$_DC_HOOK_DATA_DIR" in
  */*) _DC_HOOK_DATA_DIR="${_DC_HOOK_DATA_DIR%/*}/.." ;;
  *) _DC_HOOK_DATA_DIR=".." ;;
esac
# defenseclaw_install_lock_held DATA returns 0 (true) while this account's
# installer holds its data directory DATA. A marker is live only while its
# owner pid lives and it is at most ten minutes old; a newly made marker
# without a pid is held while the installer writes it. Unsearchable state
# stays held. Every shell hook carries this same pre-helper check.
defenseclaw_install_lock_held() {
  local data="${1:-}" lock modified now pid
  [ -n "$data" ] || return 0
  lock="${data}/.install.lock"
  if [ -e "$lock" ] || [ -L "$lock" ]; then
    modified="$(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock" 2>/dev/null)" || return 0
    now="$(date +%s)" || return 0
    case "$modified:$now" in *[!0-9:]*|:*) return 0 ;; esac
    if [ "$((now - modified))" -gt 600 ] || [ "$((modified - now))" -gt 60 ]; then
      return 1
    fi
    if [ -d "$lock" ] && [ -r "$lock/pid" ]; then
      pid="$(head -c 64 "$lock/pid" 2>/dev/null)" || return 0
      case "$pid" in ''|*[!0-9]*) return 0 ;; esac
      kill -0 "$pid" 2>/dev/null || return 1
    fi
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
# defenseclaw_install_held returns 0 (true) while an installer holds either
# data directory of this account's hook: the one DEFENSECLAW_HOME names, else
# ~/.defenseclaw, where install.sh and install.ps1 take the lock, and the one
# the hook was installed in (_DC_HOOK_DATA_DIR, the folder above its hooks
# folder), which the gateway rendered it into from its resolved data
# directory. An agent that runs the hook without DEFENSECLAW_HOME, or a
# data_dir apart from DEFENSECLAW_HOME, still finds the lock (GAP-0948).
defenseclaw_install_held() {
  defenseclaw_install_lock_held "${DEFENSECLAW_HOME:-${HOME:+${HOME}/.defenseclaw}}" && return 0
  [ -n "${_DC_HOOK_DATA_DIR:-}" ] && defenseclaw_install_lock_held "${_DC_HOOK_DATA_DIR}"
}
# A failure before the helpers load (a hook path that does not resolve, a
# missing or broken _hardening.sh, a set -e error) blocks with exit 2
# in fail mode closed, under strict availability and while this account's
# installer holds its data directory; this one script serves every
# connector, and its installed mode is the sidecar the helpers read, so it
# is closed here.
# defenseclaw_harden_env replaces this trap with the hook's own.
_DC_BOOT_FAIL_MODE="closed"
defenseclaw_boot_fails_closed() {
  [ "$_DC_BOOT_FAIL_MODE" = "open" ] || return 0
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) return 0 ;; esac
  defenseclaw_install_held
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
{{if not .Sandbox}}# The hook path is resolved: this is the data directory it was installed in.
_DC_HOOK_DATA_DIR="${HOOK_DIR}/.."
{{end}}{{end}}

# Plan B4 / S0.4: shell-side hook hardening.
. "${HOOK_DIR}/_hardening.sh"
{{if .Sandbox}}# OpenShell sandbox: _sandbox.sh drops every inherited variable the hook
# does not read and pins the baked PATH before the first child process
# (mktemp in defenseclaw_harden_env) or helper call.
. "${HOOK_DIR}/_sandbox.sh"
{{end}}defenseclaw_harden_resources
defenseclaw_harden_env

DEFENSECLAW_HOOK_CONNECTOR="inspect"
DEFENSECLAW_HOOK_NAME="inspect-tool-response"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME
{{if .Sandbox}}# OpenShell sandbox images run exactly one harness: the connector identity
# is baked at image build, never read from the environment. Sandbox hooks
# always fail closed: the workload can make the ingress, or the relay in
# front of it, answer any status (401, 429, a relay 500), so no failed,
# refused or unparseable reply may ever turn into an allow.
RUNTIME_CONNECTOR="{{.ConnectorName}}"
FAIL_MODE="closed"
readonly RUNTIME_CONNECTOR FAIL_MODE{{else}}RUNTIME_CONNECTOR="$(defenseclaw_shared_runtime_connector "$HOOK_DIR")"
FAIL_MODE="$(defenseclaw_shared_runtime_fail_mode "$HOOK_DIR" "$RUNTIME_CONNECTOR")"{{end}}{{if and (not .Managed) (not .Sandbox)}}
defenseclaw_close_during_install{{end}}{{if not .Managed}}
# A missing or disabled DEFENSECLAW_HOME is not retirement for a hook
# installed closed. This one script serves every connector, so its installed
# mode is the sidecar next to it (HOOK_DIR), read above, not a render-time
# value: missing or unreadable state reads closed, and an inherited closed
# mode or strict availability tightens it, as every later failure (GAP-0315).
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  if defenseclaw_should_fail_closed_on_unreachable; then
    echo "defenseclaw: hook home unavailable; blocking (fail mode closed)" >&2
    exit 2
  fi
  exit 0
fi{{end}}

# Avarice F-2025 / chain F-3397: authenticate inspection calls. See
# inspect-request.sh for the full rationale.
{{if .Sandbox}}defenseclaw_sandbox_require_token inspect inspect-tool-response "tool-response"
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"{{else}}TOKEN_FILE="$(defenseclaw_shared_hook_token_file "$HOOK_DIR" "$RUNTIME_CONNECTOR")"
if [ ! -f "$TOKEN_FILE" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token inspect inspect-tool-response "tool-response" "$TOKEN_FILE"
fi
if [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ] && [ -f "$TOKEN_FILE" ]; then
  if [ -n "$RUNTIME_CONNECTOR" ]; then
    DEFENSECLAW_GATEWAY_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
  else
    # shellcheck source=/dev/null
    . "$TOKEN_FILE"
  fi
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
# Only the private copy is used from here on: no child process inherits the
# bearer in its environment.
unset DEFENSECLAW_GATEWAY_TOKEN{{end}}

TOOL_NAME="${CLAUDE_TOOL_NAME:-${TOOL_NAME:-unknown}}"
TOOL_OUTPUT="$(defenseclaw_read_stdin_capped fail_closed)" || {
  echo "defenseclaw: inspect tool response refusing oversized payload" >&2
  exit 2
}

API_ADDR="{{.APIAddr}}"

# Transport and response failures respect FAIL_MODE;
# DEFENSECLAW_STRICT_AVAILABILITY=1 remains a force-closed override.
fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_log_hook_delivery_failure inspect inspect-tool-response "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "tool-response" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  # A standalone managed hook: the administrator's open covers a gateway
  # outage only (no answer through fail_unreachable). Every answered error
  # and unusable verdict blocks, including 5xx.
  FAIL_MODE="closed"
{{end}}  defenseclaw_log_hook_delivery_failure inspect inspect-tool-response "$1" response "$FAIL_MODE"
  echo "defenseclaw: inspect-tool-response hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

# Avarice F-2025 / chain F-3397: 401/403 always fail closed.
fail_unauthorized() {
  defenseclaw_log_hook_failure inspect inspect-tool-response "$1" response closed fail_closed
  echo "defenseclaw: inspect-tool-response hook auth rejected: $1 (fail-closed override)" >&2
  exit 2
}

{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{.ManagedHTTPFailureSH}}{{end}}{{if not .SecureClient}}# Refuse a checked call when no complete JSON parser is available.
if ! command -v jq >/dev/null 2>&1 && ! _dc_python3_usable; then
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  fail_response "DefenseClaw needs jq or python3 to check this call"
{{else}}  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_log_hook_failure inspect inspect-tool-response "DefenseClaw needs jq or python3 to check this call" response closed fail_closed
    echo "defenseclaw: DefenseClaw needs jq or python3 to check this call; blocking tool-response" >&2
    exit 2
  fi
  defenseclaw_log_hook_failure inspect inspect-tool-response "DefenseClaw needs jq or python3 to check this call" response open fail_open
  echo "defenseclaw: DefenseClaw needs jq or python3 to check this call; allowing tool-response (fail mode open)" >&2
  exit 0{{end}}
fi
{{end}}AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
{{if not .Sandbox}}  # A bearer is an HTTP field value: CR or LF is never valid in it, and either
  # would end the curl config line defenseclaw_gateway_post writes it to. Like
  # a 401, a malformed bearer fails closed whatever the fail mode: otherwise a
  # CR in an inherited DEFENSECLAW_GATEWAY_TOKEN would turn it into an allow.
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*) fail_unauthorized "invalid gateway token" ;;
  esac
{{end}}  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi
CONNECTOR_HEADER_ARGS=()
if [ -n "$RUNTIME_CONNECTOR" ]; then
  CONNECTOR_HEADER_ARGS=(-H "X-DefenseClaw-Connector: ${RUNTIME_CONNECTOR}")
fi

# The tool output reaches the JSON encoder on stdin and the gateway on a curl
# descriptor, never on a command line.
INSPECT_BODY="$(printf '%s' "$TOOL_OUTPUT" | defenseclaw_inspect_tool_body "$TOOL_NAME" output)" || {
  {{if and .Managed (not .SecureClient) (not .Sandbox)}}fail_response{{else}}fail_unreachable{{end}} "failed to build inspect body"
}
{{if .Sandbox}}RESPONSE="$(defenseclaw_sandbox_post "/api/v1/inspect/tool-response" "$INSPECT_BODY" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${CONNECTOR_HEADER_ARGS[@]+"${CONNECTOR_HEADER_ARGS[@]}"}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}if defenseclaw_api_listener_unproven "$API_ADDR"; then
  fail_unreachable "${API_ADDR} is not proven to be this account's gateway; no token or payload was sent. Another account may hold the port. Run \`defenseclaw setup gateway --api-port <free-port>\` to choose a free port"
fi
RESPONSE=$(defenseclaw_gateway_post "http://${API_ADDR}/api/v1/inspect/tool-response" 5 "$INSPECT_BODY" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${CONNECTOR_HEADER_ARGS[@]+"${CONNECTOR_HEADER_ARGS[@]}"}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}") || {
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  defenseclaw_split_response
  defenseclaw_managed_http_result "$HTTP_CODE" incomplete
{{end}}  fail_unreachable "gateway unreachable"
}{{end}}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

{{if and .Managed (not .SecureClient) (not .Sandbox)}}defenseclaw_managed_http_result "$HTTP_CODE"
{{else}}if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  {{if not .SecureClient}}fail_response{{else}}fail_unreachable{{end}} "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
  fail_unauthorized "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi{{end}}

{{if not .SecureClient}}defenseclaw_json_string_field "$RESULT" action >/dev/null || fail_response "invalid or ambiguous JSON response"
{{end}}
{{if .Sandbox}}# Every DefenseClaw inspect verdict names its action: an empty or
# action-less reply from the sandbox ingress is not a verdict.
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
[ -n "$ACTION" ] || fail_response "missing action in ingress response"
{{else}}{{if .SecureClient}}ACTION=$(echo "$RESULT" | _dc_jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
{{else}}# Only a recognized string action is a usable gateway verdict.
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|alert|block|confirm) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
{{end}}{{end}}if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // "blocked by DefenseClaw"' 2>/dev/null)
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
