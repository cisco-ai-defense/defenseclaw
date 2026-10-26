#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw Hermes hook — forwards Hermes shell-hook payloads to the
# DefenseClaw gateway.
set -euo pipefail
{{if not .Sandbox}}# The macOS execution probe has a hard zero-process limit. Reach the proof
# using shell builtins, while still sourcing the installed hardening helper
# and applying its resource limits. The registered hook path is absolute.
if [ "${1:-}" = "--defenseclaw-execution-probe" ] && [ "${2:-}" = "--forkless" ]; then
  case "${BASH_SOURCE[0]}" in /*) ;; *) exit 125 ;; esac
  _DC_PROBE_HOOK_DIR="${BASH_SOURCE[0]%/*}"
  # command: bash 3.2 (macOS /bin/bash) exits 0 when a sourced helper is missing or unreadable.
  command . "${_DC_PROBE_HOOK_DIR}/_hardening.sh" || exit "$?"
  declare -F defenseclaw_harden_resources >/dev/null || exit 125
  declare -F defenseclaw_harden_env >/dev/null || exit 125
  _DC_FORKLESS_PROBE=1
  defenseclaw_harden_resources
  printf '%s\n' 'defenseclaw-execution-probe-ok'
  exit 0
fi
{{end}}{{if and (not .Managed) (not .Sandbox)}}# _DC_HOOK_DATA_DIR is the data directory this hook was installed in, the
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
# is a folder whose installer is proven gone (an interrupted-install record
# beside it does not hold it, GAP-1024): its pid names no process, or this hook's own (no
# hook writes a lock), or another process than its proc-start record names
# (a reused pid). It reads no clock (hookexec installLockStale, the one
# rule): a live owner keeps the lock for as long as it runs, and so do a
# lock without a valid pid, a lock without a proc-start record whose pid
# names a process (1.0.2, 1.0.3) and an owner whose identity cannot be read.
defenseclaw_install_lock_stale() {
  local data="${1:-}" lock rc pid recorded current
  lock="${data}/.install.lock"
  [ -d "$lock" ] && [ ! -L "$lock" ] || return 1
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
# missing or broken _hardening.sh, a set -e error) answers Hermes' block
# in fail mode closed, under strict availability and while this account's
# installer holds its data directory; fail mode open keeps the exit status.
# The installed mode decides (GAP-0315).
# defenseclaw_harden_env replaces this trap with the hook's own.
_DC_BOOT_FAIL_MODE="{{.FailMode}}"
defenseclaw_boot_fails_closed() {
  [ "$_DC_BOOT_FAIL_MODE" = "open" ] || return 0
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) return 0 ;; esac
  defenseclaw_install_held
}
hermes_bootstrap_failure() {
  echo "defenseclaw: hermes hook could not start; blocking (fail mode closed)" >&2
  # Hermes acts on a synchronous JSON block, not on process status.
  printf '%s\n' '{"action":"block","message":"DefenseClaw hook failed closed"}'
  exit 0
}
trap '_dc_boot_rc=$?; if [ "$_dc_boot_rc" -ne 0 ] && defenseclaw_boot_fails_closed; then hermes_bootstrap_failure; fi' EXIT
{{end}}# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-$(cd ~ 2>/dev/null && pwd)}}"
export HOME
{{if .ForeignHookGuardSH}}DEFENSECLAW_GUARD_AGENT_HOME="$HOME"
{{end}}
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
{{end}}if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  # A registered closed hook cannot treat missing local state as retirement.
  # The installed mode decides; strict availability tightens this exit as it
  # tightens every later outage.
  _DC_HOME_FAIL_MODE="{{.FailMode}}"
  ! defenseclaw_install_held || _DC_HOME_FAIL_MODE="closed"
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) _DC_HOME_FAIL_MODE="closed" ;; esac
  if [ "$_DC_HOME_FAIL_MODE" != "open" ]; then
    echo "defenseclaw: hook home unavailable; blocking (fail mode closed)" >&2
    # Hermes acts on a synchronous JSON block, not on process status.
    printf '%s\n' '{"action":"block","message":"DefenseClaw hook failed closed"}'
    exit 0
  fi
  exit 0
fi
{{end}}

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch so the bypass goes through
# defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY (matches claude-code-hook /
# codex-hook). Hardening only mutates env that downstream code
# controls (HOME, PATH, locale, GIT_*); none of the subsequent
# token-resolution logic depends on the operator's original PATH or
# HOME.
# command: bash 3.2 (macOS /bin/bash) exits 0 when a sourced helper is missing or unreadable.
command . "${HOOK_DIR}/_hardening.sh" || exit "$?"
{{if .Sandbox}}# OpenShell sandbox: _sandbox.sh drops every inherited variable the hook
# does not read and pins the baked PATH before the first child process
# (mktemp in defenseclaw_harden_env) or helper call.
command . "${HOOK_DIR}/_sandbox.sh" || exit 2
{{end}}defenseclaw_harden_resources
defenseclaw_harden_env
# Doctor and Verify execute the exact command Hermes has registered. The
# bounded probe checks the shell and local helper without sending a tool event.
if [ "${1:-}" = "--defenseclaw-execution-probe" ]; then
  printf '%s\n' 'defenseclaw-execution-probe-ok'
  exit 0
fi

# FAIL_MODE set BEFORE the missing-token check so the helper has a
# stable FAIL_MODE to log against. Outside Secure Client, response failures
# close and eligible connection outages follow FAIL_MODE.
# DEFENSECLAW_STRICT_AVAILABILITY=1 can only close.
{{if .Sandbox}}# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status, so no failed, refused or unparseable reply may turn into an allow.
# Hermes ignores a hook's exit status and treats a timeout or a spawn error
# as "no opinion", so the only fail-closed signal it honours is a block
# directive on stdout: every failure below prints one before it exits.
FAIL_MODE="closed"
readonly FAIL_MODE

hermes_sandbox_block() {
  defenseclaw_log_hook_failure hermes hermes-hook "$1" "$2" closed fail_closed
  echo "defenseclaw: hermes hook: $1, blocking (sandbox hooks fail closed)" >&2
  printf '{"action":"block","message":"%s"}\n' "$(defenseclaw_json_escape "DefenseClaw blocked this tool call because its policy check failed: $1")"
  exit 2
}{{else}}FAIL_MODE="{{.FailMode}}"
# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's
# environment is not read, so status and doctor report what runs (GAP-0461).{{end}}
{{if and (not .Managed) (not .Sandbox)}}defenseclaw_close_during_install
{{end}}
# Bail early on missing token via the shared helper so the bypass is
# logged to hook-failures.jsonl AND honors strict availability — the
# previous v1 behaviour silently `exit 0`'d, which hid the bypass and
# defeated DEFENSECLAW_STRICT_AVAILABILITY.
DEFENSECLAW_HOOK_CONNECTOR="hermes"
DEFENSECLAW_HOOK_NAME="hermes-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

{{if .Sandbox}}# The binding token is the only credential a sandbox hook may present.
case "${DEFENSECLAW_SANDBOX_TOKEN:-}" in
  '') hermes_sandbox_block "missing sandbox binding token (DEFENSECLAW_SANDBOX_TOKEN unset)" transport ;;
  *$'\n'*|*$'\r'*) hermes_sandbox_block "malformed sandbox binding token" transport ;;
esac

PAYLOAD="$(defenseclaw_read_stdin_capped fail_closed)" || hermes_sandbox_block "hook payload too large" response
API_ADDR="{{.APIAddr}}"

# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"

fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  hermes_sandbox_block "$1" transport
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  hermes_sandbox_block "$(defenseclaw_response_failure_reason "$1")" response
}
{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token hermes hermes-hook "hermes tool" "${HOOK_DIR}/{{.TokenFile}}"
fi

# hermes_block_message is the message of a block this hook makes itself.
# Hermes shows it as the reason the tool call did not run, so it says why
# in plain words: a gateway that is not running and the next step, as the
# native hook does (managedStandaloneFailClosedText). A managed hook keeps
# its internal reasons in the hook-failures log; the Secure Client profile
# keeps its text.
hermes_block_message() {
  local layer="$1" reason="$2" next=""
  if defenseclaw_secure_client_hook; then
    printf '%s' "DefenseClaw hook failed closed"
    return 0
  fi
  case "$layer" in
    oversized) reason="it is too large for DefenseClaw to inspect. Make it smaller and try again." ;;
    response)
      # The reason (an HTTP status, a refused token) goes to stderr and the
      # hook-failures log; the message is the same for every one of them.
      case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
        1) reason="the DefenseClaw gateway returned an answer DefenseClaw could not use. Try again; if this continues, contact your administrator." ;;
        *) reason="the DefenseClaw gateway returned an answer DefenseClaw could not use. Run \`defenseclaw doctor\` to see why." ;;
      esac
      ;;
    *)
      [ "$reason" != "gateway unreachable" ] || next="$(defenseclaw_unreachable_next_step)"
      if [ -n "$next" ]; then
        reason="$next"
      elif [ "${DEFENSECLAW_MANAGED_HOOK:-0}" = "1" ]; then
        case "$reason" in
          "the DefenseClaw "*) ;;
          *) reason="the DefenseClaw gateway is not available. Try again in a moment; if this continues, contact your administrator." ;;
        esac
      else
        case "$reason" in
          "the DefenseClaw "*) ;;
          *) reason="the DefenseClaw gateway is unavailable. Run \`defenseclaw-gateway status\`." ;;
        esac
      fi
      ;;
  esac
  printf 'DefenseClaw blocked this tool call: %s' "$reason"
}

hermes_block() {
  printf '{"action":"block","message":"%s"}\n' "$(defenseclaw_json_escape "$(hermes_block_message "$1" "$2")")"
}

{{if and .Managed (not .SecureClient) (not .Sandbox)}}# A standalone managed hook blocks input too large to inspect in every
# fail mode: the administrator's open covers a gateway outage only.
{{end}}PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}")")" || {
  _DC_STDIN_RC=$?
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  if defenseclaw_prepare_oversized_stdin "$_DC_STDIN_RC"; then
    : # the normal gateway path judges the bounded review payload
  else
    FAIL_MODE=closed
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  FAIL_MODE=closed
{{end}}  echo "defenseclaw: hermes hook refusing oversized payload" >&2
  if [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" != "open" ]; then
    hermes_block oversized "stdin body exceeded cap"
    exit 2
  fi
  exit 0
{{if and (not .Managed) (not .Sandbox)}}  fi
{{end}}
}
API_ADDR="{{.APIAddr}}"

# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). The env var takes precedence if already set.
if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  {{if .SecureClient}}. "${HOOK_DIR}/{{.TokenFile}}"{{else}}command . "${HOOK_DIR}/{{.TokenFile}}" || DEFENSECLAW_GATEWAY_TOKEN={{end}}
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
# Only the private copy is used from here on: no child process (curl, jq, the
# cold-started gateway) inherits the bearer in its environment.
unset DEFENSECLAW_GATEWAY_TOKEN

fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  defenseclaw_log_hook_delivery_failure hermes hermes-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "hermes tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
{{if .SecureClient}}    printf '{"action":"block","message":"DefenseClaw hook failed closed"}\n'
{{else}}    hermes_block transport "$1"
{{end}}    exit 2
  fi
  exit 0
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  # A standalone managed hook: the administrator's open covers a gateway
  # outage only (the service not running, restarting or giving no answer
  # in time). A refusal, an error status or an unusable answer blocks.
  FAIL_MODE="closed"
{{end}}  defenseclaw_log_hook_delivery_failure hermes hermes-hook "$1" response "$FAIL_MODE"
  echo "defenseclaw: hermes hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  hermes_block response "$1"
  exit 0
}
{{end}}
{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{.ManagedHTTPFailureSH}}{{end}}{{.HookSocketTransportSH}}{{if .HermesNativeHookSH}}# The registered Hermes command remains this shell hook. The trusted native
# hook speaks the managed answer/receipt protocol for the same payload.
# Restore the original soft virtual-memory limit before starting Go. Buffer
# its one JSON answer so a missing executable or failed native hook cannot
# leave Hermes with an empty answer (Hermes ignores the process status).
ulimit -S -v "${_DC_HOOK_NATIVE_VMEM_LIMIT:-$(ulimit -H -v)}" 2>/dev/null || :
_DC_NATIVE_STATUS=0
_DC_NATIVE_ANSWER="$(HOME="${DEFENSECLAW_GUARD_AGENT_HOME:-${DEFENSECLAW_AGENT_HOME:-$HOME}}" {{.HermesNativeHookSH}} hook --connector hermes --enterprise-managed <<<"$PAYLOAD")" || _DC_NATIVE_STATUS=$?
if [ "$_DC_NATIVE_STATUS" -eq 0 ] && [ -z "$_DC_NATIVE_ANSWER" ]; then
  # Native Hermes returns an empty successful answer only for its neutral
  # allow result; managed failures print a block directive or exit nonzero.
  exit 0
fi
if [ "$_DC_NATIVE_STATUS" -eq 0 ]; then
  # The native hook has already validated the gateway answer. Preserve each
  # documented Hermes output shape while rejecting an unusable nonempty
  # result. The string-field reader validates the whole JSON, including
  # duplicate keys, even on hosts without jq or Python.
  _DC_NATIVE_EVENT="$(defenseclaw_json_string_field "$PAYLOAD" hook_event_name)" ||
    _DC_NATIVE_EVENT="$(defenseclaw_json_string_field "$PAYLOAD" event)" || _DC_NATIVE_EVENT=""
  _DC_NATIVE_ACTION="$(defenseclaw_json_string_field "$_DC_NATIVE_ANSWER" action)" || _DC_NATIVE_ACTION=""
  _DC_NATIVE_DECISION="$(defenseclaw_json_string_field "$_DC_NATIVE_ANSWER" decision)" || _DC_NATIVE_DECISION=""
  _DC_NATIVE_MESSAGE="$(defenseclaw_json_string_field "$_DC_NATIVE_ANSWER" message)" || _DC_NATIVE_MESSAGE=""
  _DC_NATIVE_REASON="$(defenseclaw_json_string_field "$_DC_NATIVE_ANSWER" reason)" || _DC_NATIVE_REASON=""
  _DC_NATIVE_CONTEXT="$(defenseclaw_json_string_field "$_DC_NATIVE_ANSWER" context)" || _DC_NATIVE_CONTEXT=""
  if { [ "$_DC_NATIVE_ACTION" = "block" ] && [ -n "$_DC_NATIVE_MESSAGE" ]; } ||
     { [ "$_DC_NATIVE_DECISION" = "block" ] && [ -n "$_DC_NATIVE_REASON" ]; } ||
     { [ "$_DC_NATIVE_EVENT" = "pre_llm_call" ] && [ -n "$_DC_NATIVE_CONTEXT" ]; } ||
     { [ "$_DC_NATIVE_EVENT" = "pre_verify" ] && [ "$_DC_NATIVE_ACTION" = "continue" ] && [ -n "$_DC_NATIVE_MESSAGE" ]; }; then
    printf '%s\n' "$_DC_NATIVE_ANSWER"
    exit 0
  fi
fi
hermes_block response "the trusted native hook could not start"
exit 2
{{end}}AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
{{if not .Sandbox}}  # A bearer is an HTTP field value: CR or LF is never valid in it, and either
  # would end the curl config line defenseclaw_gateway_post writes it to.
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*) fail_response "invalid gateway token" ;;
  esac
{{end}}  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

# W3C trace propagation: forward validated traceparent / tracestate via _hardening.sh v6.
TRACE_HEADER_ARGS=()
# A read loop, not mapfile: macOS ships bash 3.2, which has no mapfile.
while IFS= read -r trace_header_arg; do
  TRACE_HEADER_ARGS+=("$trace_header_arg")
done < <(defenseclaw_extract_trace_context)

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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/hermes/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: hermes-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}# A refused or dropped connection means this account's gateway is
# restarting or not running (after a reboot, for example): send the call
# again for up to 3 seconds, starting the gateway after a refusal. See
# defenseclaw_await_gateway in _hardening.sh.
# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# payload on descriptors, never on its command line.
defenseclaw_hook_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/hermes/hook" 10 "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: hermes-hook/1.0" \
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
{{else}}  defenseclaw_await_gateway "$?" _dc_hook_post_response || fail_unreachable "$(defenseclaw_gateway_unreachable_reason 2>/dev/null || printf 'gateway unreachable')"{{end}}
}
{{if and .Managed (not .SecureClient) (not .Sandbox)}}# The gateway answered 429, so it is up: a resend that fails after it is no
# outage in a standalone managed hook.
{{end}}defenseclaw_retry_busy _dc_hook_post_response || {{if and (not .SecureClient) (not .Sandbox)}}fail_response "gateway returned HTTP 429"{{else}}fail_unreachable "gateway unreachable"{{end}}{{end}}

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

{{if and (not .SecureClient) (not .Sandbox)}}defenseclaw_json_string_field "$RESULT" action >/dev/null || fail_response "invalid or ambiguous JSON response"
{{end}}
OUTPUT=$(echo "$RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
{{if or .Sandbox (not .SecureClient)}}# Every DefenseClaw verdict names its action: an empty or unknown one is no
# verdict, never an allow (a sandbox workload may have shaped it; a hook in
# fail mode closed blocks on it, open lets the call run: rel-1-0-3 GAP-0037,
# GAP-0153; a Secure Client render keeps its own contract). A
# block whose directive is missing or does not block still has to reach
# Hermes as a block on stdout.
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|alert|confirm|continue) ;;
  block)
    OUTPUT_DECISION=""
    if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
      OUTPUT_DECISION=$(echo "$OUTPUT" | _dc_jq -r '(.decision // .action) // empty' 2>/dev/null) || OUTPUT_DECISION=""
    fi
    if [ "$OUTPUT_DECISION" != "block" ]; then
      REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null) || REASON=""
      if [ -z "$REASON" ]; then
        REASON="Blocked by DefenseClaw Hermes policy."
      fi
      OUTPUT="$(printf '{"action":"block","message":"%s"}' "$(defenseclaw_json_escape "$REASON")")"
    fi
    ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac
{{end}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
exit 0
