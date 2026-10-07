#!/bin/bash
# defenseclaw-managed-hook v7
# DefenseClaw native Devin CLI hook. Devin blocks only on exit 2; all other
# failures intentionally fail open unless the operator selected strict mode.
set -euo pipefail

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

{{if .Sandbox}}# OpenShell sandbox: Devin blocks only on exit 2 and fails open on every other
# hook error. Every exit path below is explicit, and the EXIT trap installed
# after defenseclaw_harden_env turns an unexpected status (set -e, set -u)
# into 2 as well.
if [ ! -r "${HOOK_DIR}/_hardening.sh" ] || ! . "${HOOK_DIR}/_hardening.sh"; then
  echo "defenseclaw: hook hardening helper unavailable, blocking devin tool (sandbox hooks fail closed)" >&2
  exit 2
fi
# _sandbox.sh drops every inherited variable the hook does not read and pins
# the baked PATH before the first child process (mktemp in
# defenseclaw_harden_env) or helper call.
if [ ! -r "${HOOK_DIR}/_sandbox.sh" ] || ! . "${HOOK_DIR}/_sandbox.sh"; then
  echo "defenseclaw: sandbox transport helper unavailable, blocking devin tool (sandbox hooks fail closed)" >&2
  exit 2
fi
if ! defenseclaw_harden_resources; then
  echo "defenseclaw: resource hardening failed, blocking devin tool (sandbox hooks fail closed)" >&2
  exit 2
fi
if ! defenseclaw_harden_env; then
  echo "defenseclaw: environment hardening failed, blocking devin tool (sandbox hooks fail closed)" >&2
  exit 2
fi
trap '_dc_devin_rc=$?; _defenseclaw_hook_cleanup; case "$_dc_devin_rc" in 0|2) ;; *) exit 2 ;; esac' EXIT

# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
FAIL_MODE="closed"
readonly FAIL_MODE
{{else}}. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"
{{end}}DEFENSECLAW_HOOK_CONNECTOR="devin"
DEFENSECLAW_HOOK_NAME="devin-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

{{if .Sandbox}}defenseclaw_sandbox_require_token devin devin-hook "devin tool"

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: devin hook refusing oversized payload, blocking devin tool (sandbox hooks fail closed)" >&2
  printf 'DefenseClaw hook payload too large\n'
  exit 2
}
# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"

fail_unreachable() {
  defenseclaw_log_hook_failure devin devin-hook "$1" transport "$FAIL_MODE"
  echo "defenseclaw: sandbox ingress unreachable, blocking devin tool (sandbox hooks fail closed): $1" >&2
  printf 'DefenseClaw hook failed closed\n'
  exit 2
}

fail_response() {
  defenseclaw_log_hook_failure devin devin-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: devin hook error, blocking devin tool (sandbox hooks fail closed): $1" >&2
  printf 'DefenseClaw hook failed closed\n'
  exit 2
}
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token devin devin-hook "devin hook" "${HOOK_DIR}/{{.TokenFile}}"
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: devin hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    printf 'DefenseClaw hook payload too large\n'
    exit 2
  fi
  exit 0
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
  defenseclaw_log_hook_failure devin devin-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "devin hook" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    printf 'DefenseClaw hook failed closed\n'
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure devin devin-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: devin hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  printf 'DefenseClaw hook failed closed\n'
  exit 2
}
{{end}}
{{.HookSocketTransportSH}}AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
{{if not .Sandbox}}  # A bearer is an HTTP field value: CR or LF is never valid in it, and either
  # would end the curl config line defenseclaw_gateway_post writes it to.
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*) fail_response "invalid gateway token" ;;
  esac
{{end}}  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi
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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/devin/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: devin-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "sandbox ingress unreachable"
}{{else}}if defenseclaw_api_listener_foreign "$API_ADDR"; then
  fail_unreachable "${API_ADDR} is held by another account while this account's gateway is not running; no token was sent. Run \`defenseclaw-gateway start\` for the fix"
fi
# A refused connection means this account's gateway is not running (after
# a reboot, for example): start it once and retry. See
# defenseclaw_gateway_cold_start in _hardening.sh.
# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# payload on descriptors, never on its command line.
defenseclaw_hook_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/devin/hook" 10 "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: devin-hook/1.0" \
    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}"{{if .HookSocketTransportSH}} \
    --unix-socket "${DEFENSECLAW_HOOK_SOCKET}"{{end}}
}
RESPONSE=$(defenseclaw_hook_post) || {
  defenseclaw_gateway_cold_start "$?" || fail_unreachable "gateway unreachable"
  RESPONSE=$(defenseclaw_hook_post) || fail_unreachable "gateway unreachable"
}{{end}}

# devin_block ends a block. Devin shows an exit-2 hook's stdout verbatim
# ("Tool rejected: <stdout>") rather than parsing it, so the block prints its
# reason as one plain line, not the {"decision":"block"} object.
devin_block() {
  printf '%s\n' "${1:-Blocked by DefenseClaw Devin policy.}" | tr '\n' ' ' | sed 's/[[:space:]]*$//'
  printf '\n'
  exit 2
}

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
DECISION=""
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  DECISION=$(echo "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null) || DECISION=""
  if [ "$DECISION" = "block" ]; then
    devin_block "$(echo "$OUTPUT" | _dc_jq -r '.reason // empty' 2>/dev/null || true)"
  fi
  echo "$OUTPUT"
elif [ "$ACTION" = "block" ]; then
  # A block without an event-native verdict still denies: exit 2 is Devin's
  # veto. The gateway's reason goes on stderr too.
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null) || REASON=""
  printf '%s\n' "${REASON:-Blocked by DefenseClaw Devin policy.}" >&2
  devin_block "$REASON"
fi
if [ "$ACTION" = "block" ]; then
  exit 2
fi
exit 0{{else}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  DECISION=$(echo "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null || true)
  if [ "$DECISION" = "block" ]; then
    devin_block "$(echo "$OUTPUT" | _dc_jq -r '.reason // empty' 2>/dev/null || true)"
  fi
  echo "$OUTPUT"
fi
exit 0{{end}}
