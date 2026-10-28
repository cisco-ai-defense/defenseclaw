#!/bin/bash
# defenseclaw-managed-hook v7
# DefenseClaw Claude Code hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/claude-code/hook endpoint. Claude Code pipes
# the structured JSON event to stdin and reads the response from stdout.
#
# Forwards W3C trace context (traceparent / tracestate) when the agent
# has exported it via DEFENSECLAW_TRACEPARENT or OTEL_TRACEPARENT, so
# the hook span links back to the agent's parent span. See
# codex-hook.sh for the validation contract.
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
# missing or broken _hardening.sh, a set -e error) blocks with exit 2
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
trap '_dc_boot_rc=$?; if [ "$_dc_boot_rc" -ne 0 ] && defenseclaw_boot_fails_closed; then exit 2; fi' EXIT
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
{{end}}{{if not .Sandbox}}
# A personal hook left on a managed computer must not fall back to its
# personal gateway port. The managed hook is published separately by machine
# policy; this path is never allowed to approve a tool on that host.
if [ -e /etc/defenseclaw/managed-runtime.json ] || [ -L /etc/defenseclaw/managed-runtime.json ] ||
   [ -e /opt/cisco/defenseclaw/etc/managed-runtime.json ] || [ -L /opt/cisco/defenseclaw/etc/managed-runtime.json ]; then
  echo "defenseclaw: this computer is managed; the personal Claude Code hook cannot approve this call" >&2
  exit 2
fi
{{end}}
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
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

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch (mirrors codex-hook.sh) so the bypass goes
# through defenseclaw_handle_missing_token and honors
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

# Fail mode set BEFORE the missing-token check so the helper has a
# stable FAIL_MODE to log against. See codex-hook.sh for the full
# response-layer and transport-layer rationale.
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

# Bail early on missing token: see codex-hook.sh +
# defenseclaw_handle_missing_token in _hardening.sh for rationale.
DEFENSECLAW_HOOK_CONNECTOR="claudecode"
DEFENSECLAW_HOOK_NAME="claude-code-hook"
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
{{end}}{{if and .Managed (not .SecureClient) (not .Sandbox)}}  FAIL_MODE=closed
{{end}}  echo "defenseclaw: claudecode hook refusing oversized payload" >&2
  if [ "{{if and .Managed (not .SecureClient) (not .Sandbox)}}closed{{else}}$FAIL_MODE{{end}}" != "open" ]; then
    printf '{"decision":"block","reason":"DefenseClaw hook payload too large"}\n'
    exit 2
  fi
  exit 0
{{if and (not .Managed) (not .Sandbox)}}  fi
{{end}}
}

# Cursor 2.4+ can import Claude Code hooks from ~/.claude/settings.json while
# also running its native ~/.cursor/hooks.json hooks. Imported invocations are
# still Cursor sessions: Cursor stamps their payload with cursor_version. If
# DefenseClaw's Cursor hook is installed, let that native hook be the sole
# telemetry and policy owner. Otherwise one Cursor action is emitted once as
# cursor and again as claudecode. The selected model is independent of that
# connector identity: choosing Opus inside Cursor must still attribute the
# session to Cursor.
#
# Do not key this decision from CURSOR_* / editor environment variables: a
# genuine Claude Code CLI launched from Cursor's terminal inherits those too.
# The payload marker is injected by Cursor's hook runtime and is absent from a
# genuine Claude Code hook request. Requiring both the connector-scoped Cursor
# token and a live managed Cursor script proves that DefenseClaw configured the
# native bridge that will handle the matching invocation. The script-marker
# check matters because teardown intentionally leaves a v0 no-op tombstone (and
# may leave the scoped token) for already-running host processes.
# Only a payload that names the field can carry it, so a Claude Code call
# runs no jq for this check (issue #1130).
CURSOR_ORIGIN_VERSION=""
case "$PAYLOAD" in
  *cursor_version*)
    CURSOR_ORIGIN_VERSION="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.cursor_version // empty' 2>/dev/null || true)" ;;
esac
if [ -n "$CURSOR_ORIGIN_VERSION" ] && [ -f "${HOOK_DIR}/.hook-cursor.token" ]; then
  CURSOR_HOOK_MARKER=""
  if [ -r "${HOOK_DIR}/cursor-hook.sh" ]; then
    {
      IFS= read -r _CURSOR_HOOK_LINE || true
      IFS= read -r CURSOR_HOOK_MARKER || true
    } < "${HOOK_DIR}/cursor-hook.sh"
  fi
  case "$CURSOR_HOOK_MARKER" in
    "# defenseclaw-managed-hook v"[1-9]*) exit 0 ;;
  esac
fi
unset CURSOR_ORIGIN_VERSION CURSOR_HOOK_MARKER _CURSOR_HOOK_LINE

{{if .Sandbox}}defenseclaw_sandbox_require_token claudecode claude-code-hook "claude-code tool"{{else}}if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token claudecode claude-code-hook "claude-code tool" "${HOOK_DIR}/{{.TokenFile}}" "" "$PAYLOAD"
fi{{end}}

API_ADDR="{{.APIAddr}}"

{{if .Sandbox}}# The per-sandbox binding token is an OpenShell provider placeholder; the
# supervisor substitutes the real credential only on the ingress endpoint.
unset DEFENSECLAW_GATEWAY_TOKEN
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
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
# Only the private copy is used from here on: no child process (curl, jq, the
# cold-started gateway) inherits the bearer in its environment.
unset DEFENSECLAW_GATEWAY_TOKEN{{end}}

# FAIL_MODE was already set above (before the missing-token branch).
# Outside Secure Client, response failures close and eligible connection
# outages follow FAIL_MODE. DEFENSECLAW_STRICT_AVAILABILITY=1 can only close.

{{if and (not .Sandbox) (not .Managed)}}# claude_fail_closed_decision prints the JSON block decision for a prompt,
# tool call or permission request that is blocked because the gateway did not
# answer, with a plain sentence that names no internal file or shell syntax.
# Per-user hooks only.
claude_fail_closed_decision() {
  local reason="" next="" event=""
  # Managed hooks keep their own exit-2 contract and service wording.
  case "${DEFENSECLAW_MANAGED_HOOK:-0}" in
    1|true|TRUE|yes|YES) return 1 ;;
  esac
  if defenseclaw_install_held && next="$(defenseclaw_unreachable_next_step)" && [ -n "$next" ]; then
    reason="DefenseClaw blocked this: ${next//\`/}."
  elif [ -e "${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/gateway.stopped" ]; then
    reason="DefenseClaw blocked this because its gateway is stopped. Run defenseclaw-gateway start to resume protection (defenseclaw-gateway status shows its state)."
  elif [ "$1" = "gateway unreachable" ] && next="$(defenseclaw_unreachable_next_step)" && [ -n "$next" ]; then
    reason="DefenseClaw blocked this: ${next//\`/}."
  elif next="$(defenseclaw_gateway_error_block_text "$1")"; then
    # The gateway is up and answered with an error (GAP-1744).
    reason="$next"
  else
    reason="DefenseClaw blocked this because it could not reach its gateway (${1}). Run defenseclaw-gateway status to check it."
  fi
  event="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" || return 1
  local out=""
  case "$event" in
    PreToolUse)
      out="$(_dc_jq -cn --arg r "$reason" \
        '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}')" || return 1 ;;
    PermissionRequest)
      out="$(_dc_jq -cn --arg r "$reason" \
        '{hookSpecificOutput:{hookEventName:"PermissionRequest",decision:{behavior:"deny",message:$r}}}')" || return 1 ;;
    UserPromptSubmit|UserPromptExpansion)
      out="$(_dc_jq -cn --arg r "$reason" '{decision:"block",reason:$r}')" || return 1 ;;
    *) return 1 ;;
  esac
  # Without jq or python3 the fallback reader cannot build this object and
  # prints "null": that is no decision, so the caller's exit 2 blocks instead.
  case "$out" in
    "{"*deny*|"{"*block*) printf '%s\n' "$out" ;;
    *) return 1 ;;
  esac
}

{{end}}fail_unreachable() {
  # A blocked stop event only keeps Claude Code running (#1140).
  if defenseclaw_should_fail_closed_on_unreachable; then
    defenseclaw_allow_failed_stop_event claudecode claude-code-hook "" "${PAYLOAD:-}" "$1" transport
  fi
  defenseclaw_log_hook_delivery_failure claudecode claude-code-hook "$1" transport "$FAIL_MODE"
{{if .Sandbox}}  # Claude shows this line under the blocked step: a prompt hook blocks the
  # prompt, every other hook a tool call.
  case "$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" in
    UserPromptSubmit|UserPromptExpansion) defenseclaw_emit_unreachable_stderr "claude-code prompt" "$1" ;;
    *) defenseclaw_emit_unreachable_stderr "claude-code tool" "$1" ;;
  esac{{else}}  defenseclaw_emit_unreachable_stderr "claude-code tool" "$1"{{end}}
  if defenseclaw_should_fail_closed_on_unreachable; then
{{if and (not .Sandbox) (not .Managed)}}    # For an exit-2 block Claude Code prints the whole hook command line in
    # front of the reason. A blocked prompt or tool call goes out as Claude's
    # own JSON decision instead, which shows one plain sentence (GAP-1074);
    # exit 2 stays the fallback when the JSON cannot be built.
    local blocked=""
    blocked="$(claude_fail_closed_decision "$1")" && [ -n "$blocked" ] && {
      printf '%s\n' "$blocked"
      exit 0
    }
{{end}}    exit 2
  fi
{{if not .Sandbox}}  # Claude Code does not show stderr of a hook that exits 0: say on screen
  # that this account's gateway is down and how to start it again.
  if [ "$1" = "gateway unreachable" ]; then
    case "$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" in
      SessionStart|UserPromptSubmit|PreToolUse) defenseclaw_unreachable_notice_json ;;
    esac
  fi
{{end}}  exit 0
}

fail_response() {
{{if and (not .Managed) (not .Sandbox)}}  defenseclaw_close_during_install
{{end}}{{if and (not .SecureClient) (not .Sandbox)}}  # Outside Secure Client the open fail mode covers a gateway outage only
  # (the service not running, restarting or giving no answer in time). A
  # refusal, an error status or an unusable answer blocks.
  FAIL_MODE="closed"
{{end}}  local reason
  reason="$(defenseclaw_response_failure_reason "$1")"
  [ "$FAIL_MODE" = "open" ] ||
    defenseclaw_allow_failed_stop_event claudecode claude-code-hook "" "${PAYLOAD:-}" "$reason" response
  defenseclaw_log_hook_delivery_failure claudecode claude-code-hook "$reason" response "$FAIL_MODE"
  echo "defenseclaw: claude-code hook error: $reason" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
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
RESPONSE="$(defenseclaw_sandbox_post "/api/v1/claude-code/hook" "$PAYLOAD" \
  "$DC_SANDBOX_MAX_TIME" "$DC_SANDBOX_RETRY_MAX_TIME" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: claude-code-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}")" || {
  fail_unreachable "$(defenseclaw_sandbox_unreachable_reason "$RESPONSE")"
}{{else}}{{if and .Managed (not .SecureClient)}}# Resolve write operands as the hook user; the managed gateway cannot
# inspect this home under ProtectHome. Keep the payload off argv.
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
{{end}}# A refused or dropped connection means this account's gateway is
# restarting or not running (after a reboot, for example): send the call
# again for up to 3 seconds, starting the gateway after a refusal. See
# defenseclaw_await_gateway in _hardening.sh.
# A tool call's request is bounded like the native hook's answer budget, by
# the payload's top-level event (defenseclaw_payload_tool_gate_max_time).
HOOK_MAX_TIME=10
{{if not .SecureClient}}defenseclaw_payload_tool_gate_max_time "$PAYLOAD" 10
{{end}}# defenseclaw_gateway_post (_hardening.sh) hands curl the bearer and the
# payload on descriptors, never on its command line.
defenseclaw_hook_post() {
  defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" "$HOOK_MAX_TIME" "$PAYLOAD" \
    -H "Content-Type: application/json" \
    -H "X-DefenseClaw-Client: claude-code-hook/1.0" \
{{if and .Managed (not .SecureClient)}}    "${RESOLVED_HEADER_ARGS[@]+"${RESOLVED_HEADER_ARGS[@]}"}" \
{{end}}    "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
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
{{end}}defenseclaw_retry_busy _dc_hook_post_response || {{if and .Managed (not .SecureClient) (not .Sandbox)}}fail_response "gateway returned HTTP 429"{{else}}fail_unreachable "gateway unreachable"{{end}}{{end}}

defenseclaw_split_response

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
{{if and (not .Managed) (not .Sandbox)}}# Decode the action and its structured output together. Successful personal
# hooks need one parser process rather than two (#1130). The fallback keeps
# working on supported hosts without jq; managed/Secure Client renders retain
# their delivery contract.
if command -v jq >/dev/null 2>&1; then
  unset RESPONSE_FIELDS
  RESPONSE_FIELDS=$(printf '%s' "$RESULT" | jq -ers '
    if length != 1 or (.[0] | type) != "object" then error("invalid response") else .[0] end
    | if (.action == "allow" or .action == "alert" or .action == "block" or .action == "confirm")
         and (.claude_code_output == null or (.claude_code_output | type) == "object")
      then .action, (.claude_code_output // empty | tojson)
      else error("invalid response fields") end' 2>/dev/null) || fail_response "invalid JSON response"
  ACTION="${RESPONSE_FIELDS%%$'\n'*}"
  OUTPUT=""
  if [ "$ACTION" != "$RESPONSE_FIELDS" ]; then
    OUTPUT="${RESPONSE_FIELDS#*$'\n'}"
  fi
  unset RESPONSE_FIELDS
else
{{end}}OUTPUT=$(echo "$RESULT" | _dc_jq -c '.claude_code_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
{{if and (not .Managed) (not .Sandbox)}}fi
{{end}}# alert is advisory (would_block=false): the notice printed above is all
# Claude Code gets, and the tool runs, as with allow.
case "$ACTION" in
  allow|alert|block|confirm) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac

# A Stop directive that contradicts a gateway block ends the turn rather than
# allowing it, as in hookexec nativeOutputAgrees: continue must be false with a
# stopReason, or absent with decision block. A block
# without a directive is a policy denial and gets the exit-2 feedback below.
if [ "$ACTION" = "block" ] && [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  CLAUDE_EVENT=$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null) || CLAUDE_EVENT=""
  case "$CLAUDE_EVENT" in
    Stop|SubagentStop|TeammateIdle)
      NATIVE_CONTINUE=$(printf '%s' "$OUTPUT" | _dc_jq -c '.continue' 2>/dev/null) || NATIVE_CONTINUE=""
      NATIVE_STOP_REASON=$(printf '%s' "$OUTPUT" | _dc_jq -r '.stopReason // empty' 2>/dev/null) || NATIVE_STOP_REASON=""
      NATIVE_DECISION=$(printf '%s' "$OUTPUT" | _dc_jq -r '.decision // empty' 2>/dev/null) || NATIVE_DECISION=""
      NATIVE_REASON=$(printf '%s' "$OUTPUT" | _dc_jq -r '.reason // empty' 2>/dev/null) || NATIVE_REASON=""
      NATIVE_AGREES=no
      if [ "$NATIVE_CONTINUE" = "false" ] && [ -n "$NATIVE_STOP_REASON" ]; then
        NATIVE_AGREES=yes
      elif { [ -z "$NATIVE_CONTINUE" ] || [ "$NATIVE_CONTINUE" = "null" ]; } &&
           [ "$NATIVE_DECISION" = "block" ] && [ -n "$NATIVE_REASON" ]; then
        NATIVE_AGREES=yes
      fi
      if [ "$NATIVE_AGREES" != "yes" ]; then
        REASON=$(printf '%s' "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null) || REASON=""
        [ -n "$REASON" ] || REASON="DefenseClaw hook failed closed."
        OUTPUT=$(printf '{"continue":false,"stopReason":"%s"}' "$(defenseclaw_json_escape "$REASON")")
      fi
      ;;
  esac
fi
{{if not .SecureClient}}# A block or confirmation reaches Claude Code as the native object, which
# Claude Code acts on: one that does not deny (or ask) for this event would
# let the call run beside the gateway's block. The hook refuses such an
# answer closed, in every fail mode, as the native hook does (GAP-0950). The
# Stop directives above already agree (or were replaced).
# A confirmation with no object at all would let the call run too: Claude
# Code asks only through it (GAP-0983).
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  case "$ACTION" in
    block|confirm)
      _DC_PAYLOAD_EVENT="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" || _DC_PAYLOAD_EVENT=""
      case "$_DC_PAYLOAD_EVENT" in
        Stop|SubagentStop|TeammateIdle) ;;
        *)
          if ! defenseclaw_native_output_agrees claudecode "$_DC_PAYLOAD_EVENT" "$ACTION" "$OUTPUT"; then
            [ "$FAIL_MODE" = "closed" ] || FAIL_MODE=closed
            fail_response "native output contradicts gateway action"
          fi
          ;;
      esac
      ;;
  esac
elif [ "$ACTION" = "confirm" ]; then
  [ "$FAIL_MODE" = "closed" ] || FAIL_MODE=closed
  fail_response "confirm without native output in gateway response"
fi
{{end}}{{if not .Sandbox}}if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  printf '%s\n' "$OUTPUT"
fi
{{end}}{{if .Sandbox}}if ! defenseclaw_sandbox_confirm_receipt "/api/v1/claude-code/hook" "$RESULT"; then
  fail_unreachable "sandbox hook receipt was not acknowledged"
fi
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  printf '%s\n' "$OUTPUT"
fi
{{end}}
# Anthropic's Claude Code hook protocol — like Codex's — is strictly
# EITHER structured JSON on stdout with exit 0 (Claude parses the
# permissionDecision/decision from the JSON) OR exit 2 with the reason
# on stderr. Doing BOTH is a protocol violation: depending on Claude
# version, either the exit code wins (and the rich JSON reason is
# silently replaced with a generic "Hook exited with code 2" surface),
# or stdout wins inconsistently. This is the same shape bug we hit on
# codex-hook.sh where Codex explicitly logged
# "exited with code 2 but did not write a blocking reason to stderr"
# and then FAILED OPEN. Even where Claude Code currently still blocks
# on the exit code, mixing the protocols means the operator-facing
# reason ("matched: SEC-PRIVKEY:Private key") is at risk of being
# dropped between Claude versions.
#
# Resolution: when the gateway gave us structured claude_code_output
# (every block path in claude_code_hook.go does), trust it and exit 0.
# Fall back to exit-2-plus-stderr only when no structured output is
# present.
if [ "$ACTION" = "block" ]; then
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
    # JSON on stdout already carries permissionDecision=deny /
    # decision=block. Exit 0 so Claude Code honors it.
    exit 0
  fi
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null)
  if [ -z "$REASON" ]; then
    REASON="Blocked by DefenseClaw Claude Code policy."
  fi
  printf '%s\n' "$REASON" >&2
  exit 2
fi
exit 0
