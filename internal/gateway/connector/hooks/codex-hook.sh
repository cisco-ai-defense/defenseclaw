#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw Codex hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/codex/hook endpoint. Codex pipes the
# structured JSON event to stdin and reads the response from stdout.
#
# W3C trace propagation: if the agent has already exported
# DEFENSECLAW_TRACEPARENT / OTEL_TRACEPARENT (etc.), the validated
# values are sent to the gateway as traceparent / tracestate headers
# so the hook span links back to the agent's parent span. Validation
# happens in _hardening.sh — a malformed value is silently dropped
# (the hook still posts to the gateway, it just starts a new root
# span).
set -euo pipefail
{{if not .SecureClient}}# codex_event_can_control CONTRACT EVENT returns 0 for an event whose answer
# Codex acts on (the native hook's codexEventCanControl).
codex_event_can_control() {
  case "${2:-}" in
    UserPromptSubmit|PreToolUse|PermissionRequest|PostToolUse|Stop) return 0 ;;
    SessionStart|SubagentStop|PreCompact|PostCompact)
      case "${1:-}" in codex-hooks-v3|codex-hooks-v4) return 0 ;; esac
      ;;
  esac
  return 1
}
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
  if [ ! -e "${lock}/proc-start" ] && [ ! -L "${lock}/proc-start" ]; then
    defenseclaw_process_started_after_lock "$pid" "$lock"
    return
  fi
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
# defenseclaw_process_started_after_lock PID LOCK returns 0 when process PID
# started more than 2 s after LOCK was last changed: a 1.0.2/1.0.3 lock
# without a proc-start record whose pid a later process got (GAP-1465, the
# hookexec rule). It returns 1 when it started earlier or the system does not
# say.
defenseclaw_process_started_after_lock() {
  local locked="" started="" boot="" stat="" line="" out="" IFS=' '
  locked="$(stat -c %Y "${2:-}" 2>/dev/null || stat -f %m "${2:-}" 2>/dev/null)" || return 1
  case "$locked" in ''|*[!0-9]*) return 1 ;; esac
  if [ -e /proc/self/stat ]; then
    while IFS= read -r line; do
      case "$line" in "btime "*) boot="${line#btime }"; break ;; esac
    done < /proc/stat
    case "$boot" in ''|*[!0-9]*) return 1 ;; esac
    stat="$(cat "/proc/${1:-}/stat" 2>/dev/null)" || return 1
    case "$stat" in *[\)]*) ;; *) return 1 ;; esac
    stat="${stat##*[\)]}"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    started=$((boot + $1 / 100))
  else
    [ "$(uname -s 2>/dev/null)" = Darwin ] && [ -x /bin/ps ] || return 1
    out="$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "${1:-}" 2>/dev/null)" || return 1
    started="$(LC_ALL=C TZ=UTC date -j -u -f "%a %b %e %T %Y" "$out" +%s 2>/dev/null)" || return 1
    case "$started" in ''|*[!0-9]*) return 1 ;; esac
  fi
  [ "$started" -gt $((locked + 2)) ]
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
# missing or broken _hardening.sh, a set -e error) blocks in fail mode
# closed, under strict availability and while this account's installer holds
# its data directory, and so does every exit 2, with Codex's own block of
# the registered event (codex_closed_answer); fail mode open keeps the exit
# status. The installed mode decides (GAP-0315).
# defenseclaw_harden_env replaces this trap with the hook's own.
_DC_BOOT_FAIL_MODE="{{.FailMode}}"
defenseclaw_boot_fails_closed() {
  [ "$_DC_BOOT_FAIL_MODE" = "open" ] || return 0
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-}" in 1|true|TRUE|yes|YES) return 0 ;; esac
  defenseclaw_install_held
}
# The registered event and contract, from the arguments setup binds (--event,
# --hook-contract), before the helpers load; the binding check below
# validates them.
_DC_CODEX_EVENT=""
_DC_CODEX_CONTRACT=""
_DC_CODEX_BLOCK_REASON=""
_dc_codex_arg_prev=""
for _dc_codex_arg in "$@"; do
  case "$_dc_codex_arg_prev" in
    --event) _DC_CODEX_EVENT="$_dc_codex_arg" ;;
    --hook-contract) _DC_CODEX_CONTRACT="$_dc_codex_arg" ;;
  esac
  _dc_codex_arg_prev="$_dc_codex_arg"
done
unset _dc_codex_arg _dc_codex_arg_prev
# codex_closed_answer [REASON] answers a call this hook blocks as Codex reads
# a block of the registered event: the event's block object on stdout and
# exit 0, as the native hook answers (emitCodexBlock). Codex v0.130+ reads a
# non-zero UserPromptSubmit status as a hook failure and submits the prompt,
# so exit 2 is no block there (GAP-0949). An event Codex gives no control
# keeps exit 2, and so do Stop and SubagentStop, where a block only keeps
# Codex running (#1140) as exit 2 does. Codex shows REASON, else why: the
# install, or the failure the hook recorded (_DC_CODEX_BLOCK_REASON).
codex_closed_answer() {
  local reason="${1:-}"
  if [ -z "$reason" ] && defenseclaw_install_held; then
    reason="DefenseClaw blocked this: DefenseClaw is being installed or upgraded for this account (fail mode closed). Try again when it is done."
  fi
  reason="${reason:-${_DC_CODEX_BLOCK_REASON:-DefenseClaw blocked this because its hook failed (fail mode closed). Run defenseclaw doctor to see why.}}"
  reason="${reason//\\/\\\\}"
  reason="${reason//\"/\\\"}"
  reason="${reason//[[:cntrl:]]/ }"
  codex_event_can_control "$_DC_CODEX_CONTRACT" "$_DC_CODEX_EVENT" || exit 2
  case "$_DC_CODEX_EVENT" in
    Stop|SubagentStop) exit 2 ;;
    SessionStart|PreCompact|PostCompact) printf '{"continue":false,"stopReason":"%s"}\n' "$reason" ;;
    PermissionRequest) printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"%s"}}}\n' "$reason" ;;
    PreToolUse) printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason" ;;
    *) printf '{"decision":"block","reason":"%s"}\n' "$reason" ;;
  esac
  exit 0
}
trap '_dc_boot_rc=$?; if [ "$_dc_boot_rc" -eq 2 ] || { [ "$_dc_boot_rc" -ne 0 ] && defenseclaw_boot_fails_closed; }; then codex_closed_answer; fi' EXIT
{{end}}
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
    exit 2
  fi
  exit 0
fi
{{end}}

# Plan B4 / S0.4: shell-side hook hardening, sourced BEFORE the
# missing-token branch so the helper is available to log + branch on
# DEFENSECLAW_STRICT_AVAILABILITY. Hardening only mutates env that
# downstream code controls (HOME, PATH, locale, GIT_*); none of the
# subsequent token-resolution logic depends on the operator's
# original PATH or HOME.
# command: bash 3.2 (macOS /bin/bash) exits 0 when a sourced helper is missing or unreadable.
command . "${HOOK_DIR}/_hardening.sh" || exit "$?"
{{if .Sandbox}}# OpenShell sandbox: _sandbox.sh drops every inherited variable the hook
# does not read and pins the baked PATH before the first child process
# (mktemp in defenseclaw_harden_env) or helper call.
command . "${HOOK_DIR}/_sandbox.sh" || exit 2
{{end}}defenseclaw_harden_resources
defenseclaw_harden_env
{{if and (not .Managed) (not .Sandbox)}}# defenseclaw_harden_env replaced the EXIT trap with its cleanup: keep it, and
# answer every block below (exit 2) as Codex reads one for the registered
# event (codex_closed_answer, GAP-0949).
trap '_dc_codex_rc=$?; _defenseclaw_hook_cleanup; if [ "$_dc_codex_rc" -eq 2 ]; then codex_closed_answer; fi' EXIT
{{end}}
# Fail mode governs response-layer failures (4xx, bad JSON, missing
# action) and transport failures (gateway unreachable / timeout / 5xx).
# DEFENSECLAW_STRICT_AVAILABILITY=1 remains a force-closed override. Set BEFORE the
# missing-token check so defenseclaw_handle_missing_token below has a
# stable FAIL_MODE to log against.
{{if .Sandbox}}# OpenShell sandbox hooks always fail closed, with no environment override:
# the workload can make the ingress, or the relay in front of it, answer any
# status (a garbage DEFENSECLAW_SANDBOX_TOKEN earns a 401, a request flood a
# 429, an unversioned placeholder a relay 500), so no failed, refused or
# unparseable reply may ever turn into an allow.
FAIL_MODE="closed"
readonly FAIL_MODE{{else if .Managed}}# Managed hooks use the installer-owned delivery policy; an inherited
# DEFENSECLAW_FAIL_MODE cannot weaken an explicitly closed managed hook.
FAIL_MODE="{{.FailMode}}"{{else}}FAIL_MODE="{{.FailMode}}"
# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's
# environment is not read, so status and doctor report what runs (GAP-0315).{{end}}
{{if and (not .Managed) (not .Sandbox)}}defenseclaw_close_during_install
{{end}}

# Setup binds each handler to one finite vendor event and hook contract. Keep
# those values out of environment variables so the registered command remains
# the single command-identity source of truth.
BOUND_EVENT=
BOUND_CONTRACT=

fail_binding() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}  local reason="$1"
{{if and (not .Managed) (not .Sandbox)}}  _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because its Codex hook registration does not match this call (${reason}). Run defenseclaw setup codex to register it again."
{{end}}{{if and .Managed (not .SecureClient)}}  # A managed binding error is integrity, not an outage: closed in every
  # fail mode, as in the native runner.
  defenseclaw_log_hook_delivery_failure codex codex-hook "$reason" response closed
  echo "defenseclaw: codex hook binding error: $reason" >&2
  exit 2
{{else}}  defenseclaw_log_hook_delivery_failure codex codex-hook "$reason" response "$FAIL_MODE"
  echo "defenseclaw: codex hook binding error: $reason" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
{{end}}}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --event)
      [ "$#" -ge 2 ] || fail_binding "missing value for --event"
      [ -z "$BOUND_EVENT" ] || fail_binding "duplicate --event binding"
      BOUND_EVENT="$2"
      shift 2
      ;;
    --hook-contract)
      [ "$#" -ge 2 ] || fail_binding "missing value for --hook-contract"
      [ -z "$BOUND_CONTRACT" ] || fail_binding "duplicate --hook-contract binding"
      BOUND_CONTRACT="$2"
      shift 2
      ;;
    *)
      fail_binding "unexpected registered command argument"
      ;;
  esac
done

case "${BOUND_CONTRACT}:${BOUND_EVENT}" in
  codex-hooks-v1:SessionStart|codex-hooks-v1:UserPromptSubmit|codex-hooks-v1:PreToolUse|codex-hooks-v1:PermissionRequest|codex-hooks-v1:PostToolUse|codex-hooks-v1:Stop) ;;
  codex-hooks-v2:SessionStart|codex-hooks-v2:UserPromptSubmit|codex-hooks-v2:PreToolUse|codex-hooks-v2:PermissionRequest|codex-hooks-v2:PostToolUse|codex-hooks-v2:PreCompact|codex-hooks-v2:PostCompact|codex-hooks-v2:Stop) ;;
  codex-hooks-v3:SessionStart|codex-hooks-v3:UserPromptSubmit|codex-hooks-v3:PreToolUse|codex-hooks-v3:PermissionRequest|codex-hooks-v3:PostToolUse|codex-hooks-v3:SubagentStart|codex-hooks-v3:SubagentStop|codex-hooks-v3:PreCompact|codex-hooks-v3:PostCompact|codex-hooks-v3:Stop) ;;
  codex-hooks-v4:SessionStart|codex-hooks-v4:UserPromptSubmit|codex-hooks-v4:PreToolUse|codex-hooks-v4:PermissionRequest|codex-hooks-v4:PostToolUse|codex-hooks-v4:SubagentStart|codex-hooks-v4:SubagentStop|codex-hooks-v4:PreCompact|codex-hooks-v4:PostCompact|codex-hooks-v4:Stop|codex-hooks-v4:SessionEnd) ;;
  *) fail_binding "registered event is not part of the bound Codex hook contract" ;;
esac

DEFENSECLAW_HOOK_CONNECTOR="codex"
DEFENSECLAW_HOOK_NAME="codex-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

{{if and .Managed (not .SecureClient) (not .Sandbox)}}# A standalone managed hook blocks input too large to inspect in every
# fail mode: the agent chooses the size.
{{end}}PAYLOAD="$(defenseclaw_read_stdin_capped "$(defenseclaw_hook_delivery_outcome response "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}")")" || {
  _DC_STDIN_RC=$?
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  if defenseclaw_prepare_oversized_stdin "$_DC_STDIN_RC"; then
    : # the normal gateway path judges the bounded review payload
  else
    FAIL_MODE=closed
{{end}}  [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" = "open" ] ||
    defenseclaw_allow_failed_stop_event codex codex-hook "$BOUND_EVENT" "" "stdin body exceeded cap" transport
  echo "defenseclaw: codex hook refusing oversized payload" >&2
  if [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" != "open" ]; then
{{if and (not .Managed) (not .Sandbox)}}    _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because the hook payload is too large for DefenseClaw to inspect."
{{else}}    printf '{"decision":"block","reason":"DefenseClaw hook payload too large"}\n'
{{end}}    exit 2
  fi
  exit 0
{{if and (not .Managed) (not .Sandbox)}}  fi
{{end}}
}

PAYLOAD_EVENT="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" || {
  fail_binding "Codex hook stdin is not valid JSON"
}
if [ -z "$PAYLOAD_EVENT" ]; then
  fail_binding "Codex hook stdin is missing hook_event_name"
fi
if [ "$PAYLOAD_EVENT" != "$BOUND_EVENT" ]; then
  fail_binding "Codex hook stdin event does not match the registered event"
fi

# Neither the companion .token file nor the env var carries a token: without
# one the gateway rejects every request with 401, so the helper follows the
# fail mode (exit 0 when open) and records the bypass in hook-failures.jsonl.
# It runs after the binding check, as in the native runner, so a stop event
# that gets the fail-closed exception has a payload that matches its
# registered event.
{{if .Sandbox}}defenseclaw_sandbox_require_token codex codex-hook "codex tool"{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token codex codex-hook "codex tool" "${HOOK_DIR}/{{.TokenFile}}" "$BOUND_EVENT" ""
fi{{end}}

API_ADDR="{{.APIAddr}}"

{{if .Sandbox}}# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
API_TOKEN="${DEFENSECLAW_SANDBOX_TOKEN}"{{else}}# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). Connector-scoped sidecars override an inherited generic
# gateway token; legacy .token files retain the explicit env override.
if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  {{if .SecureClient}}. "${HOOK_DIR}/{{.TokenFile}}"{{else}}command . "${HOOK_DIR}/{{.TokenFile}}" || DEFENSECLAW_GATEWAY_TOKEN={{end}}
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"{{end}}
# The hook needs only its private shell-local copy from this point forward.
# Drop the exported source before trace extraction or descriptor writers can
# spawn child processes.
unset DEFENSECLAW_GATEWAY_TOKEN

# Transport-layer failure: gateway is unreachable, the connection was
# refused, the request timed out, or the gateway answered with 5xx.
# Follow FAIL_MODE; strict availability is an additional force-closed override.
fail_unreachable() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  # The same cause and next step as the Claude Code block and the open-mode
  # warning: a stopped gateway names the start step (GAP-2253).
  _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because it could not reach its gateway ($1). Run defenseclaw-gateway status to check it."
  if [ -e "${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/gateway.stopped" ]; then
    _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because its gateway is stopped. Run defenseclaw-gateway start to resume protection (defenseclaw-gateway status shows its state)."
  elif [ "$1" = "gateway unreachable" ] && _dc_next="$(defenseclaw_unreachable_next_step)" && [ -n "$_dc_next" ]; then
    _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this: ${_dc_next//\`/}."
  elif _dc_answer="$(defenseclaw_gateway_error_answer "$1")"; then
    _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because its gateway answered with an error (${_dc_answer}). Run defenseclaw doctor to see what to fix."
  fi
{{end}}  # A blocked Stop only keeps Codex running the turn (#1140).
  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_allow_failed_stop_event codex codex-hook "$BOUND_EVENT" "" "$1" transport
  fi
  defenseclaw_log_hook_delivery_failure codex codex-hook "$1" transport "$FAIL_MODE"
{{if .Sandbox}}  # Codex shows this line under the blocked step: a prompt hook blocks the
  # prompt, every other hook a tool call.
  case "$PAYLOAD_EVENT" in
    UserPromptSubmit) defenseclaw_emit_unreachable_stderr "codex prompt" "$1" ;;
    *) defenseclaw_emit_unreachable_stderr "codex tool" "$1" ;;
  esac{{else}}  defenseclaw_emit_unreachable_stderr "codex tool" "$1"{{end}}
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
{{if not .Sandbox}}  # Codex does not show stderr of a hook that exits 0: say on screen that
  # this account's gateway is down and how to start it again. Codex shows a
  # systemMessage for these two events.
  if [ "$1" = "gateway unreachable" ]; then
    case "$BOUND_EVENT" in
      SessionStart|PreToolUse) defenseclaw_unreachable_notice_json ;;
    esac
  fi
{{end}}  exit 0
}

# A gateway response that cannot be used is a failed check, not an outage.
fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
  _DC_CODEX_BLOCK_REASON="DefenseClaw blocked this because its gateway's answer could not be used (fail mode closed). Run defenseclaw doctor to see why."
{{end}}{{if and (not .SecureClient) (not .Sandbox)}}  # Outside Secure Client the open fail mode covers a gateway outage only
  # (the service not running, restarting or giving no answer in time). A
  # refusal, an error status or an unusable answer blocks.
  FAIL_MODE="closed"
{{end}}  local reason
  reason="$(defenseclaw_response_failure_reason "$1")"
  [ "$FAIL_MODE" = "open" ] ||
    defenseclaw_allow_failed_stop_event codex codex-hook "$BOUND_EVENT" "" "$reason" response
  defenseclaw_log_hook_delivery_failure codex codex-hook "$reason" response "$FAIL_MODE"
  echo "defenseclaw: codex hook error: $reason" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

# W3C trace propagation: TRACE_HEADER_ARGS gets a sequence of
# `-H "traceparent: …"` / `-H "tracestate: …"` arguments; invalid env
# values are dropped by defenseclaw_extract_trace_context.
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

{{if .Sandbox}}HOOK_MAX_TIME="$DC_SANDBOX_MAX_TIME"
HOOK_RETRY_MAX_TIME="$DC_SANDBOX_RETRY_MAX_TIME"
if [ "$BOUND_EVENT" = "SessionEnd" ]; then
  # Codex caps SessionEnd at three seconds: both attempts must fit.
  HOOK_MAX_TIME="$DC_SANDBOX_SESSION_END_MAX_TIME"
  HOOK_RETRY_MAX_TIME="$DC_SANDBOX_SESSION_END_MAX_TIME"
fi

# defenseclaw_sandbox_post keeps the bearer (a revision-scoped OpenShell
# placeholder, or with token_delivery: env the token itself) off curl's
# command line. One short attempt plus one retry carries the same
# idempotency key; the ingress dedupes by key.
AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/codex/hook" "$PAYLOAD" \
  "$HOOK_MAX_TIME" "$HOOK_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: codex-hook/1.0" \
  -H "X-DefenseClaw-Hook-Event: ${BOUND_EVENT}" \
  -H "X-DefenseClaw-Hook-Contract: ${BOUND_CONTRACT}" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}
API_TOKEN=
PAYLOAD=
unset API_TOKEN PAYLOAD{{else}}HOOK_MAX_TIME=10
{{if not .SecureClient}}defenseclaw_tool_gate_max_time "$BOUND_EVENT" 10
{{end}}if [ "$BOUND_EVENT" = "SessionEnd" ]; then
  # Codex's host maximum is three seconds. Leave one second for response
  # parsing and process teardown, matching the native launcher budget.
  HOOK_MAX_TIME=2
fi

{{if and .Managed (not .SecureClient) (not .Sandbox)}}{{.ManagedHTTPFailureSH}}{{end}}{{.HookSocketTransportSH}}AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  # A bearer is an HTTP field value: CR or LF is never valid in it, and either
  # would end the curl config line defenseclaw_gateway_post writes it to.
  case "${API_TOKEN}" in
    *$'\n'*|*$'\r'*) fail_response "invalid gateway token" ;;
  esac
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi
{{if and .Managed (not .SecureClient)}}# Resolve write operands in the user's hook process; the managed gateway
# cannot inspect this home under ProtectHome. Keep the payload off argv.
# The standalone gateway of this OS (managed.StandaloneLayoutFor): a macOS
# hook ran the Linux path, which is not there, and wrote its shell error to
# the agent on every call.
case "${OSTYPE:-}" in
  darwin*) _DC_MANAGED_GATEWAY=/opt/cisco/defenseclaw/bin/defenseclaw-gateway ;;
  *) _DC_MANAGED_GATEWAY=/opt/defenseclaw/bin/defenseclaw-gateway ;;
esac
_DC_RESOLVED_WRITES=
if [ -x "$_DC_MANAGED_GATEWAY" ]; then
  _DC_RESOLVED_WRITES="$("$_DC_MANAGED_GATEWAY" hook resolve-writes < <(printf '%s' "${PAYLOAD}"))" || _DC_RESOLVED_WRITES=
fi
RESOLVED_HEADER_ARGS=()
if [ -n "${_DC_RESOLVED_WRITES}" ]; then
  RESOLVED_HEADER_ARGS=(-H "X-DefenseClaw-Resolved-Writes: ${_DC_RESOLVED_WRITES}")
fi
{{end}}

# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the hook
# event on descriptors, never on its command line.
codex_gateway_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" "$HOOK_MAX_TIME" "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: codex-hook/1.0" \
    -H "X-DefenseClaw-Hook-Event: ${BOUND_EVENT}" \
    -H "X-DefenseClaw-Hook-Contract: ${BOUND_CONTRACT}" \
{{if and .Managed (not .SecureClient)}}    "${RESOLVED_HEADER_ARGS[@]+"${RESOLVED_HEADER_ARGS[@]}"}" \
{{end}}    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
    "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
    "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}"{{if .HookSocketTransportSH}} \
    --unix-socket "${DEFENSECLAW_HOOK_SOCKET}"{{end}}
}

# defenseclaw_await_gateway and defenseclaw_retry_busy send the call again
# through this (POST sets RESPONSE).
codex_gateway_post_response() {
  RESPONSE=$(codex_gateway_post)
}
CURL_STATUS=0
RESPONSE=$(codex_gateway_post) || CURL_STATUS=$?
{{if and .Managed (not .SecureClient) (not .Sandbox)}}if [ "$CURL_STATUS" -ne 0 ]; then
  defenseclaw_split_response
  defenseclaw_managed_http_result "$HTTP_CODE" incomplete
fi
{{end}}# A refused or dropped connection means this account's gateway is restarting
# or not running (after a reboot, for example): send the call again for up to
# 3 seconds, starting the gateway after a refusal. SessionEnd has no time for
# it. See defenseclaw_await_gateway in _hardening.sh.
if [ "$CURL_STATUS" -ne 0 ] && [ "$BOUND_EVENT" != "SessionEnd" ]; then
  if defenseclaw_await_gateway "$CURL_STATUS" codex_gateway_post_response; then
    CURL_STATUS=0
  else
    CURL_STATUS=$?
  fi
fi
if [ "$CURL_STATUS" -eq 0 ]; then
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  # The gateway answered 429, so it is up: a resend that fails after it is
  # no outage in a standalone managed hook.
  defenseclaw_retry_busy codex_gateway_post_response || fail_response "gateway returned HTTP 429"
{{else}}  defenseclaw_retry_busy codex_gateway_post_response || CURL_STATUS=$?
{{end}}fi
API_TOKEN=
{{if .SecureClient}}PAYLOAD=
{{end}}AUTH_HEADER_ARGS=()
unset API_TOKEN{{if .SecureClient}} PAYLOAD{{end}}
# fail_unreachable reads the session id from PAYLOAD for the one outage
# warning per session and the per-call audit row, as in the Claude Code hook:
# drop the event only after it (GAP-1350, GAP-1352).
if [ "$CURL_STATUS" -ne 0 ]; then
{{if and .Managed (not .SecureClient) (not .Sandbox)}}  defenseclaw_split_response
  defenseclaw_managed_http_result "$HTTP_CODE" incomplete
{{end}}  fail_unreachable "$(defenseclaw_gateway_unreachable_reason 2>/dev/null || printf 'gateway unreachable')"
fi
{{if not .SecureClient}}PAYLOAD=
unset PAYLOAD{{end}}{{end}}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

{{if and .Managed (not .SecureClient) (not .Sandbox)}}defenseclaw_managed_http_result "$HTTP_CODE"
{{else}}# 5xx (server error) is treated as transport — the gateway hit an
# infrastructure problem, not a policy verdict. 4xx falls through to
# response-layer handling so auth/payload bugs surface loudly.
if [ -z "$HTTP_CODE" ]; then
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
OUTPUT=$(echo "$RESULT" | _dc_jq -c '.codex_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
{{if not .SecureClient}}# A block or confirmation reaches Codex as the native object, which Codex acts
# on: one that does not deny (or ask) for the registered event would let the
# call run beside the gateway's block. The hook refuses such an answer
# closed, in every fail mode, as the native hook does (GAP-0950). A
# confirmation with no object at all would let the call run too: Codex asks
# only through it (GAP-0983).
_DC_GATEWAY_ACTION="$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null)" || _DC_GATEWAY_ACTION=""
if { [ -z "$OUTPUT" ] || [ "$OUTPUT" = "null" ]; } && [ "$_DC_GATEWAY_ACTION" = "confirm" ] &&
  codex_event_can_control "$BOUND_CONTRACT" "$BOUND_EVENT"; then
  [ "$FAIL_MODE" = "closed" ] || FAIL_MODE=closed
  fail_response "confirm without native output in gateway response"
fi
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  case "$_DC_GATEWAY_ACTION" in
    block|confirm)
      if codex_event_can_control "$BOUND_CONTRACT" "$BOUND_EVENT" &&
        ! defenseclaw_native_output_agrees codex "$BOUND_EVENT" "$_DC_GATEWAY_ACTION" "$OUTPUT"; then
        [ "$FAIL_MODE" = "closed" ] || FAIL_MODE=closed
        fail_response "native output contradicts gateway action"
      fi
      ;;
  esac
fi
{{end}}{{if not .Sandbox}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
{{end}}

ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
# alert is advisory (would_block=false): the notice printed above is all
# Codex gets, and the tool runs, as with allow.
case "$ACTION" in
  allow|alert|block|confirm) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac

{{if .Sandbox}}if ! defenseclaw_sandbox_confirm_receipt "/api/v1/codex/hook" "$RESULT"; then
  fail_unreachable "sandbox hook receipt was not acknowledged"
fi
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi
{{end}}

# Codex's hook protocol is strictly EITHER structured JSON on stdout
# with exit 0 (Codex parses the decision from the JSON) OR exit 2
# with the reason on stderr (Codex blocks with stderr as the
# message). Doing BOTH is a protocol violation: Codex sees exit 2,
# ignores stdout, finds an empty stderr, then logs
# "exited with code 2 but did not write a blocking reason to stderr"
# and FAILS OPEN — which is exactly the bug we hit when our gateway
# returned permissionDecision=deny on stdout AND we exited 2.
#
# Resolution: trust the structured JSON when the gateway gave us one
# (every block path in codex_hook.go does), and only fall back to
# the exit-2-plus-stderr path when no structured output exists.
if [ "$ACTION" = "block" ]; then
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
    # JSON on stdout already carries permissionDecision=deny /
    # decision=block. Exit 0 so Codex honors it.
    exit 0
  fi
  # codex_output was not extractable (no jq/python3 for object fields).
  # Construct minimal structured block JSON so Codex sees exit 0 + JSON
  # rather than exit 2 — newer Codex versions (v0.130+) treat exit 2 on
  # UserPromptSubmit as "hook failed" rather than "hook blocked".
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null)
  if [ -z "$REASON" ]; then
    REASON="Blocked by DefenseClaw Codex policy."
  fi
{{if and (not .Managed) (not .Sandbox)}}  codex_closed_answer "$REASON"
{{else}}  printf '{"decision":"block","reason":"%s"}\n' "$(defenseclaw_json_escape "$REASON")"
  exit 0
{{end}}fi
exit 0
