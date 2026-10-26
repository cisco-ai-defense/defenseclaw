#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw PreRequest hook — inspects user query before it is sent to the LLM.
# Reads the user message content from stdin (JSON with "content" field).
set -euo pipefail
{{if and (not .Managed) (not .Sandbox)}}# _DC_HOOK_DATA_DIR is the data directory this hook was installed in, the
# folder above its hooks folder (defenseclaw_install_held). Until the hook
# path is resolved below it is the folder above the path the agent ran.
_DC_HOOK_DATA_DIR="${BASH_SOURCE[0]:-$0}"
case "$_DC_HOOK_DATA_DIR" in
  */*) _DC_HOOK_DATA_DIR="${_DC_HOOK_DATA_DIR%/*}/.." ;;
  *) _DC_HOOK_DATA_DIR=".." ;;
esac
# _DC_HOOK_HOME is the data directory the gateway rendered this hook into,
# written into the file: a hard link, a symlink or a copy of the hook, run
# from any folder, still finds the installer's lock there.
_DC_HOOK_HOME={{.HookHomeSH}}
# defenseclaw_install_lock_held DATA returns 0 (true) while this account's
# installer holds its data directory DATA: DATA/.install.lock exists as any
# file type and is not stale (defenseclaw_install_lock_stale), or DATA
# exists but cannot be searched, so the lock cannot be shown absent; no DATA
# to look in counts as held too. The native hook (installLockHeld), the
# in-agent plugins and the Windows adapters apply the same rule (GAP-0914).
# defenseclaw_install_held below, the one install check of every shell hook,
# reads it.
defenseclaw_install_lock_held() {
  local data="${1:-}"
  [ -n "$data" ] || return 0
  if [ -e "${data}/.install.lock" ] || [ -L "${data}/.install.lock" ]; then
    defenseclaw_install_lock_stale "$data" && return 1
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
# defenseclaw_install_lock_stale DATA returns 0 (true) when DATA/.install.lock
# is a folder whose installer is proven gone and no interrupted-install
# record sits beside it: its pid names no process, or this hook's own (no
# hook writes a lock), or another process than its proc-start record names
# (a reused pid). It reads no clock (hookexec installLockStale, the one
# rule): a live owner keeps the lock for as long as it runs, and so do a
# lock without a valid pid, a lock without a proc-start record whose pid
# names a process (1.0.2, 1.0.3) and an owner whose identity cannot be read.
defenseclaw_install_lock_stale() {
  local data="${1:-}" lock rc pid name recorded current
  lock="${data}/.install.lock"
  [ -d "$lock" ] && [ ! -L "$lock" ] || return 1
  for name in previous.new .repair .rollback-hold .lifecycle-txn.json; do
    if [ -e "${data}/${name}" ] || [ -L "${data}/${name}" ]; then
      return 1
    fi
  done
  rc=0
  pid="$(defenseclaw_install_lock_number "${lock}/pid")" || rc=$?
  [ "$rc" = 0 ] || return 1
  [ "$pid" -le 2147483647 ] || return 1
  # A live installer's pid names no other process: this one is reused.
  [ "$pid" = "$$" ] && return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    # A process of another account refuses the signal; only ps proves it gone.
    command -v ps >/dev/null 2>&1 || return 1
    ps -p "$pid" >/dev/null 2>&1 || return 0
  fi
  # An installer that exited but is not reaped (a zombie) keeps its pid and
  # its start, but runs nothing.
  defenseclaw_process_ended "$pid" && return 0
  [ -e "${lock}/proc-start" ] || [ -L "${lock}/proc-start" ] || return 1
  recorded="$(defenseclaw_install_lock_record "${lock}/proc-start")" || return 1
  current="$(defenseclaw_process_identity "$pid")" || return 1
  [ "$recorded" != "$current" ] && return 0
  return 1
}
# defenseclaw_process_identity PID prints the identity of process PID as the
# system keeps it from its creation, the record install.sh keeps of itself
# in a lock (proc-start; hookexec procidentity): on Linux its boot id and
# kernel start, "<boot_id> <starttime>" (field 22 of /proc/PID/stat); on
# macOS its creation second as `LC_ALL=C TZ=UTC ps -o lstart=` prints it,
# one space apart. No clock step moves either. It returns 1 when the system
# does not say.
defenseclaw_process_identity() {
  local boot stat out IFS=' '
  if [ -e /proc/self/stat ]; then
    boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" || return 1
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    case "$boot" in ''|*[!0-9a-f-]*) return 1 ;; esac
    printf '%s %s' "$boot" "$1"
    return 0
  fi
  [ "$(uname -s 2>/dev/null)" = Darwin ] && [ -x /bin/ps ] || return 1
  out="$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "${1:-}" 2>/dev/null)" || return 1
  set -- $out
  [ "$#" -eq 5 ] || return 1
  printf '%s %s %s %s %s' "$1" "$2" "$3" "$4" "$5"
}
# defenseclaw_process_ended PID returns 0 when process PID has exited but
# keeps its pid: a zombie its parent has not reaped (hookexec
# procidentity.Ended). It returns 1 while it runs or when the system does
# not say.
defenseclaw_process_ended() {
  local stat IFS=' '
  if [ -e /proc/self/stat ]; then
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    case "${1:-}" in Z|X|x) return 0 ;; esac
    return 1
  fi
  [ -x /bin/ps ] || return 1
  stat="$(LC_ALL=C /bin/ps -o stat= -p "${1:-}" 2>/dev/null)" || return 1
  set -- $stat
  case "${1:-}" in Z*) return 0 ;; esac
  return 1
}
# defenseclaw_install_lock_record FILE prints the trimmed text of a small
# owner record (proc-start); it returns 1 when FILE is not a small regular
# file or is empty.
defenseclaw_install_lock_record() {
  local file="${1:-}" size text
  [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 1
  size="$(wc -c < "$file" 2>/dev/null | tr -d ' ')" || return 1
  case "$size" in ''|*[!0-9]*) return 1 ;; esac
  [ "$size" -le 128 ] || return 1
  text="$(cat "$file" 2>/dev/null)" || return 1
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"
  [ -n "$text" ] || return 1
  printf '%s' "$text"
}
# defenseclaw_install_lock_number FILE prints the decimal number of the owner
# record file (pid). It returns 1 when FILE is absent, empty or
# not a positive number, and 2 when it cannot be read (not a small regular
# file).
defenseclaw_install_lock_number() {
  local file="${1:-}" size text
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    return 1
  fi
  [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 2
  size="$(wc -c < "$file" 2>/dev/null | tr -d ' ')" || return 2
  case "$size" in ''|*[!0-9]*) return 2 ;; esac
  [ "$size" -le 64 ] || return 2
  text="$(cat "$file" 2>/dev/null)" || return 2
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"
  case "$text" in ''|0*|*[!0-9]*) return 1 ;; esac
  [ "${#text}" -le 12 ] || return 1
  printf '%s' "$text"
}
# defenseclaw_install_held returns 0 (true) while an installer holds either
# data directory of this account's hook: the one DEFENSECLAW_HOME names, else
# ~/.defenseclaw, where install.sh and install.ps1 take the lock, and the one
# the hook was installed in (_DC_HOOK_DATA_DIR, the folder above its hooks
# folder), which the gateway rendered it into from its resolved data
# directory. An agent that runs the hook without DEFENSECLAW_HOME, or a
# data_dir apart from DEFENSECLAW_HOME, still finds the lock (GAP-0948).
# A per-user render also checks the data directory the gateway rendered it
# into (_DC_HOOK_HOME, written into the file), so a hard link, a symlink or a
# copy of the hook, run from any folder, is held by that install's lock.
defenseclaw_install_held() {
  if [ -n "${_DC_HOOK_HOME:-}" ] && defenseclaw_install_lock_held "${_DC_HOOK_HOME}"; then
    return 0
  fi
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
{{if .Sandbox}}DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
{{else}}# Without DEFENSECLAW_HOME the hook's home is the data directory it was
# installed in, not ~/.defenseclaw: a custom-home install keeps its own
# config, lock and gateway when the agent does not pass the variable
# (GAP-1854).
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-$(cd "${HOOK_DIR}/.." && pwd -P)}"
{{end}}{{if not .Sandbox}}# The hook path is resolved: this is the data directory it was installed in.
_DC_HOOK_DATA_DIR="${HOOK_DIR}/.."
# An inherited DEFENSECLAW_HOME that names no folder does not retire the
# hook installed here, and does not block it: the hook keeps the data
# directory it was installed in and asks its gateway (GAP-1256).
[ -d "${DEFENSECLAW_HOME}" ] || DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)"
{{end}}{{end}}

# Plan B4 / S0.4: shell-side hook hardening (sourced before reading
# stdin so the bounded fd limit is in place when curl spawns).
# command: bash 3.2 (macOS /bin/bash) exits 0 when a sourced helper is missing or unreadable.
command . "${HOOK_DIR}/_hardening.sh" || exit "$?"
{{if .Sandbox}}# OpenShell sandbox: _sandbox.sh drops every inherited variable the hook
# does not read and pins the baked PATH before the first child process
# (mktemp in defenseclaw_harden_env) or helper call.
. "${HOOK_DIR}/_sandbox.sh"
{{end}}defenseclaw_harden_resources
defenseclaw_harden_env

DEFENSECLAW_HOOK_CONNECTOR="inspect"
DEFENSECLAW_HOOK_NAME="inspect-request"
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

# Avarice F-2025 / chain F-3397: include the gateway bearer token on
# every inspection call. Pre-fix the hook never sent Authorization,
# so a sidecar that required token auth would 401 every request and
# (with FAIL_MODE=open) silently allow them. The token lives in
# a runtime-selected token file (mode 0600, written by the hook installer)
# and may be overridden by the env var for ephemeral CI shells.
{{if .Sandbox}}defenseclaw_sandbox_require_token inspect inspect-request "request"
unset DEFENSECLAW_GATEWAY_TOKEN
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"{{else}}TOKEN_FILE="$(defenseclaw_shared_hook_token_file "$HOOK_DIR" "$RUNTIME_CONNECTOR")"
if [ ! -f "$TOKEN_FILE" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token inspect inspect-request "request" "$TOKEN_FILE"
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

CONTENT="$(defenseclaw_read_stdin_capped fail_closed)" || {
  _DC_STDIN_RC=$?
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  PAYLOAD="$CONTENT"
  if defenseclaw_prepare_oversized_stdin "$_DC_STDIN_RC"; then
    CONTENT="$PAYLOAD"
    _DC_OVERSIZED_INSPECT=1
  else
{{end}}
  echo "defenseclaw: inspect request refusing oversized payload" >&2
  exit 2
{{if and (not .Managed) (not .Sandbox)}}  fi
{{end}}
}

API_ADDR="{{.APIAddr}}"

# Transport and response failures respect FAIL_MODE;
# DEFENSECLAW_STRICT_AVAILABILITY=1 remains a force-closed override.
fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  if [ "${_DC_OVERSIZED_INSPECT:-0}" = 1 ]; then
    local DEFENSECLAW_HOOK_CONNECTOR="$RUNTIME_CONNECTOR"
  fi
{{end}}  defenseclaw_log_hook_delivery_failure inspect inspect-request "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "request" "$1"
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
{{end}}  defenseclaw_log_hook_delivery_failure inspect inspect-request "$1" response "$FAIL_MODE"
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
  defenseclaw_log_hook_failure inspect inspect-request "$1" response closed fail_closed
  echo "defenseclaw: inspect-request hook auth rejected: $1 (fail-closed override)" >&2
  exit 2
}

{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{.ManagedHTTPFailureSH}}{{end}}{{if not .SecureClient}}# A checked call needs a complete JSON parser. The string-only helper cannot
# validate a gateway verdict, so refuse before sending or parsing one.
if ! command -v jq >/dev/null 2>&1 && ! _dc_python3_usable; then
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  fail_response "DefenseClaw needs jq or python3 to check this call"
{{else}}  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_log_hook_failure inspect inspect-request "DefenseClaw needs jq or python3 to check this call" response closed fail_closed
    echo "defenseclaw: DefenseClaw needs jq or python3 to check this call; blocking request" >&2
    exit 2
  fi
  defenseclaw_log_hook_failure inspect inspect-request "DefenseClaw needs jq or python3 to check this call" response open fail_open
  echo "defenseclaw: DefenseClaw needs jq or python3 to check this call; allowing request (fail mode open)" >&2
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

{{if .Sandbox}}RESPONSE="$(defenseclaw_sandbox_post "/api/v1/inspect/request" "$CONTENT" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${CONNECTOR_HEADER_ARGS[@]+"${CONNECTOR_HEADER_ARGS[@]}"}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# content on descriptors, never on its command line.
RESPONSE=$(defenseclaw_gateway_post "http://${API_ADDR}/api/v1/inspect/request" 5 "$CONTENT" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  "${CONNECTOR_HEADER_ARGS[@]+"${CONNECTOR_HEADER_ARGS[@]}"}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}") || {
  _DC_TRANSPORT_STATUS=$?
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  defenseclaw_split_response
  defenseclaw_managed_http_result "$HTTP_CODE" incomplete
{{end}}  fail_unreachable "$(defenseclaw_gateway_unreachable_reason 2>/dev/null || printf 'gateway unreachable')"
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
