#!/usr/bin/env bash
#
# DefenseClaw macOS uninstaller.
#
# Removes (current managed layout):
#   - LaunchDaemon (com.cisco.secureclient.defenseclaw)
#   - /opt/cisco/secureclient/defenseclaw/  (binary + config + runtime)
#   - /Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
#
# Also sweeps legacy DefenseClaw locations from pre-managed-layout installs:
#   - LaunchDaemon (com.defenseclaw.gateway)
#   - /Library/DefenseClaw/                        (binary)
#   - /Library/Application Support/DefenseClaw/    (config + runtime)
#   - /Library/Logs/DefenseClaw/                   (logs)
#   - /Library/LaunchDaemons/com.defenseclaw.gateway.plist
# so 'sudo ./uninstall.sh --purge' cleanly cuts over a pre-move install.
#
# By default, system runtime state is PRESERVED so reinstall keeps audit
# history. Pass --purge to wipe everything (system + per-user hook footprint).
#
# Per-user cleanup (with --purge):
#   - ~/.defenseclaw/                (DefenseClaw-owned hook scripts/tokens)
#   - DefenseClaw entries scrubbed from each native agent hook config:
#       ~/.codex/config.toml         (strip [hooks], [otel], notify=)
#       ~/.claude/settings.json      (strip DC entries from hooks map)
#       ~/.cursor/hooks.json         (strip DC entries from hooks map)
#       ~/.copilot/hooks/defenseclaw.json
#                                    (strip DC entries; the file is removed
#                                     once nothing else is left in it)
#       ~/.config/amp/plugins/defenseclaw.ts
#                                    (restore/remove only when the structured
#                                     backup identity + post hash still match)
#     Non-DefenseClaw user entries in those files are preserved verbatim.
#     Pass --keep-agent-configs to skip the scrub.
#
# Purge always completes. Every step is attempted for every user and
# every object; a step that still fails after repair and a bounded retry
# is logged with a marker (defenseclaw_skip / defenseclaw_prereq) in
# uninstall.log, the purge carries on, and the last line of the log
# summarises what was left. The purge exits 0 once it has done everything
# it can; a later install clears any leftover. The order makes a re-run
# safe: users are purged before the install tree (which holds the scrub
# binary and the manifest). When something was left behind the log folder
# keeps only uninstall.log; a clean purge removes the folder as well.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to the Python scrubber for the `amp` connector. Amp's plugin
# lives at ~/.config/amp/plugins/defenseclaw.ts and is signed-backup-
# managed by scrub_agent_configs.py — restoring the pre-install
# plugin content on uninstall requires SHA-256 verification against a
# manifest under ~/.defenseclaw/connector_backups/amp/config.json.
# The codex/claudecode/cursor/copilot connectors are scrubbed by the Go
# `defenseclaw-gateway enterprise hooks scrub` subcommand (no python3
# runtime dependency). See scrub_agent_config() below for the split.
SCRUB_PY="${SCRIPT_DIR}/lib/scrub_agent_configs.py"

# DC_UNINSTALL_TEST_ROOT re-roots every machine path below under a
# fixture tree so the packaging tests can drive a whole purge
# unprivileged. It is honoured only with DC_UNINSTALL_SKIP_ROOT_CHECK=1
# and never when run as root.
DC_ROOT=""
DC_OWNER="root"
DC_GROUP="wheel"
if [[ -n "${DC_UNINSTALL_TEST_ROOT:-}" && "${DC_UNINSTALL_SKIP_ROOT_CHECK:-}" == "1" && "${EUID}" -ne 0 ]]; then
  DC_ROOT="${DC_UNINSTALL_TEST_ROOT%/}"
  DC_OWNER="$(id -un)"
  DC_GROUP="$(id -gn)"
fi

INSTALL_PREFIX="${DC_ROOT}/opt/cisco/secureclient/defenseclaw"
SUPPORT_DIR="${INSTALL_PREFIX}"
LOGS_DIR="${DC_ROOT}/Library/Logs/Cisco/SecureClient/DefenseClaw"
PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"
LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw"
GUARDIAN_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist"
GUARDIAN_LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw.hook-guardian"
ENUMERATOR_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-enumerator.plist"
ENUMERATOR_LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw.hook-enumerator"
GUARDIAN_MANIFEST_PATH="${INSTALL_PREFIX}/hook-guardian/targets.yaml"
GUARDIAN_AUTH_DIR="${INSTALL_PREFIX}/hook-guardian-state"
USERS_ROOT="${DC_ROOT}/Users"
UNINSTALL_LOG="${LOGS_DIR}/uninstall.log"

# Legacy paths + labels from pre-managed-layout DefenseClaw installs.
# Kept so that running the new uninstall.sh on an old-layout host
# cleans up everything in one pass.
LEGACY_INSTALL_PREFIX="${DC_ROOT}/Library/DefenseClaw"
LEGACY_SUPPORT_DIR="${DC_ROOT}/Library/Application Support/DefenseClaw"
LEGACY_LOGS_DIR="${DC_ROOT}/Library/Logs/DefenseClaw"
LEGACY_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LEGACY_LAUNCHD_LABEL="com.defenseclaw.gateway"
LEGACY_GUARDIAN_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist"
LEGACY_GUARDIAN_LAUNCHD_LABEL="com.defenseclaw.hook-guardian"

# Legacy service-user names swept on --purge. Pre-root DefenseClaw
# installs created these accounts via ensure_service_user in install.sh.
# Modern (Cisco-path, root-mode) installs never create a service user.
SERVICE_USER_KNOWN=(defenseclaw)

PURGE="false"
ASSUME_YES="false"
TARGET_USER=""
KEEP_AGENT_CONFIGS="false"

# Everything the purge could not finish, one "path|reason" entry each,
# summarised on the last line of uninstall.log.
LEFTOVERS=()

# Source enumerate_local_users and the resilience helpers if the library
# is present. uninstall.sh runs in three contexts: from a shipped bundle
# (SCRIPT_DIR has lib/ beside it), from the managed install tree
# (SUPPORT_DIR/lib/), and from the repo tree during tests. Try each; a
# missing library (a re-run after a partial purge from a copy without
# lib/) falls back to the minimal helpers below, and the purge target set
# is still built from dscl, the manifest, the ledger and a home scan.
DC_MARKER_COMPONENT="uninstall"
DC_MARKER_LOG_FILE=""
_UNINSTALL_LIB=""
for _c in \
  "${SCRIPT_DIR}/lib/installer_lib.sh" \
  "${SUPPORT_DIR}/lib/installer_lib.sh" \
  "${SCRIPT_DIR}/../lib/installer_lib.sh"; do
  if [[ -f "${_c}" && ! -L "${_c}" ]]; then _UNINSTALL_LIB="${_c}"; break; fi
done
unset _c
if [[ -n "${_UNINSTALL_LIB}" ]]; then
  # shellcheck source=lib/installer_lib.sh
  . "${_UNINSTALL_LIB}"
fi

# ---- fallbacks when the library is missing -------------------------------
#
# Same contracts as the installer_lib.sh helpers, reduced to what purge
# needs. Marker values are quoted with backslash, quote and newline
# escaped, which matches the Go format for the paths and tokens purge logs.
if ! command -v dc_marker >/dev/null 2>&1; then
  DC_RETRY_ATTEMPTS="${DC_RETRY_ATTEMPTS:-3}"
  DC_RETRY_SLEEP="${DC_RETRY_SLEEP:-0.5}"
  _dc_emit() {
    printf '%s\n' "$1" >&2
    if [[ -n "${DC_MARKER_LOG_FILE}" ]]; then
      printf '%s\n' "$1" >> "${DC_MARKER_LOG_FILE}" 2>/dev/null || true
    fi
    return 0
  }
  dc_marker() {
    local marker="$1" arg key val line pairs=""
    shift
    for arg in "component=${DC_MARKER_COMPONENT}" "$@"; do
      key="${arg%%=*}"
      val="${arg#*=}"
      val="${val//\\/\\\\}"
      val="${val//\"/\\\"}"
      val="${val//$'\n'/\\n}"
      pairs="${pairs}${key}=\"${val}\""$'\n'
    done
    line="${marker}"
    while IFS= read -r arg; do
      [[ -n "${arg}" ]] && line="${line} ${arg}"
    done < <(printf '%s' "${pairs}" | LC_ALL=C sort -t= -k1,1 -u)
    _dc_emit "${line}"
  }
  dc_warn() {
    local message="${1:-}"
    shift || true
    _dc_emit "[${DC_MARKER_COMPONENT}] WARN: ${message}"
    if (( $# > 0 )); then dc_marker "$@"; fi
    return 0
  }
  dc_retry() {
    local attempt=1 rc=0
    while :; do
      rc=0
      "$@" || rc=$?
      (( rc == 0 )) && return 0
      (( attempt >= DC_RETRY_ATTEMPTS )) && return "${rc}"
      attempt=$((attempt + 1))
      sleep "${DC_RETRY_SLEEP}" 2>/dev/null || true
    done
  }
fi
if ! command -v dc_remove_path >/dev/null 2>&1; then
  dc_remove_path() {
    local path="${1:-}"
    [[ -n "${path}" && "${path}" != "/" ]] || return 2
    [[ -e "${path}" || -L "${path}" ]] || return 0
    if [[ -L "${path}" || ! -d "${path}" ]]; then
      chflags -h nouchg,nouappnd "${path}" 2>/dev/null || true
      dc_retry /bin/rm -f -- "${path}" 2>/dev/null || true
    else
      chflags -R -P nouchg,nouappnd "${path}" 2>/dev/null || true
      chflags -R -P noschg,nosappnd "${path}" 2>/dev/null || true
      chmod -R -P -N "${path}" 2>/dev/null || true
      dc_retry /bin/rm -rf -- "${path}" 2>/dev/null || true
    fi
    [[ ! -e "${path}" && ! -L "${path}" ]]
  }
fi

# ---- helpers ------------------------------------------------------------

# Every line also goes to uninstall.log once it is open (see below).
_ulog() {
  if [[ -n "${DC_MARKER_LOG_FILE}" ]]; then
    printf '%s\n' "$1" >> "${DC_MARKER_LOG_FILE}" 2>/dev/null || true
  fi
}
log()  { printf '[uninstall] %s\n' "$*"; _ulog "[uninstall] $*"; }
warn() { printf '[uninstall] WARN: %s\n' "$*" >&2; _ulog "[uninstall] WARN: $*"; }
# die is reserved for usage errors, a declined confirmation, and not
# running as root on macOS; nothing found on disk is ever fatal.
die()  { printf '[uninstall] ERROR: %s\n' "$*" >&2; _ulog "[uninstall] ERROR: $*"; exit 1; }

# leftover PATH REASON [MARKER key=value ...]: record something the purge
# could not finish and log it with a marker (a defenseclaw_skip naming
# the path and reason by default).
leftover() {
  local path="$1" reason="$2"
  shift 2
  LEFTOVERS+=("${path}|${reason}")
  if (( $# > 0 )); then
    dc_warn "left behind: ${path} (${reason})" "$@"
  else
    dc_warn "left behind: ${path} (${reason})" defenseclaw_skip unit="path:${path}" path="${path}" reason="${reason}"
  fi
}

# purge_remove PATH [UNIT]: delete one DefenseClaw-owned path (flags and
# ACLs cleared first, links never followed, bounded retry). A failure is
# recorded as a leftover; the purge continues.
purge_remove() {
  local path="$1" unit="${2:-path:$1}"
  [[ -e "${path}" || -L "${path}" ]] || return 0
  log "removing ${path}"
  if dc_remove_path "${path}"; then
    return 0
  fi
  LEFTOVERS+=("${path}|remove_failed")
  dc_warn "could not remove ${path}; a later install clears it" \
    defenseclaw_skip unit="${unit}" path="${path}" reason=remove_failed
  return 1
}

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Options:
  --purge               Also delete:
                          ${SUPPORT_DIR}/  (config + runtime — Cisco path)
                          ${LOGS_DIR}/     (gateway logs)
                          Legacy pre-Cisco-path locations if present:
                            /Library/Application Support/DefenseClaw/
                            /Library/Logs/DefenseClaw/
                          ~/.defenseclaw/ for every managed user (hook scripts)
                          Any legacy /Users/defenseclaw + /Groups/defenseclaw
                              dscl records from pre-root DefenseClaw installs
                        AND scrub DefenseClaw entries from:
                          ~/.codex/config.toml
                          ~/.claude/settings.json
                          ~/.cursor/hooks.json
                          ~/.config/amp/plugins/defenseclaw.ts
                        Non-DefenseClaw entries in those files are preserved.
                        Amp cleanup uses:
                          ~/.defenseclaw/connector_backups/amp/config.json
                        and refuses to change a drifted or unsafe plugin.
  --keep-agent-configs  With --purge, skip the agent-config scrub. Hook
                        scripts will be deleted, leaving dangling references
                        that fail-close every agent tool call. Use only if
                        you intend to immediately reinstall.
  --user USER           Per-user cleanup target for --purge (default: every
                        managed user)
  -y, --yes             Don't prompt for --purge confirmation
  -h, --help            Show this help

Default behavior preserves runtime state so reinstall keeps audit history.
EOF
}

# ---- arg parsing --------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)               PURGE="true"; shift;;
    --keep-agent-configs)  KEEP_AGENT_CONFIGS="true"; shift;;
    --user)                TARGET_USER="${2:?}"; shift 2;;
    -y|--yes)              ASSUME_YES="true"; shift;;
    -h|--help)             usage; exit 0;;
    # --service-user was a pre-root-switch install flag. Accepted here
    # (with a deprecation warning) for backward compat with legacy MDM
    # / release automation that still passes it — the legacy user is
    # already swept unconditionally via SERVICE_USER_KNOWN below, so
    # the flag's value is redundant but not harmful. Advance by 2 only
    # when a value actually follows and isn't the next flag; otherwise
    # advance by 1. Blindly calling `shift 2` would either fail under
    # `set -e` when --service-user is the last token or silently
    # swallow the next option.
    --service-user)
      warn "--service-user is deprecated and ignored; legacy 'defenseclaw' user is swept automatically on --purge"
      if [[ $# -ge 2 && "$2" != -* ]]; then
        shift 2
      else
        shift
      fi
      ;;
    *) die "unknown flag: $1 (try --help)";;
  esac
done

# ---- preflight ----------------------------------------------------------

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
if [[ "${DC_UNINSTALL_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  [[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 $*)"
fi

# ---- uninstall.log ------------------------------------------------------
#
# Every line from here on is also appended to uninstall.log beside the
# other DefenseClaw logs. Purge keeps that one file (and its folder) so
# the record of what was removed and what was left survives the purge.
# The log is never written through a link; without a usable log folder
# the uninstall runs with console output only.
open_uninstall_log() {
  if [[ ! -e "${LOGS_DIR}" && ! -L "${LOGS_DIR}" && -d "$(dirname "${LOGS_DIR}")" ]]; then
    mkdir "${LOGS_DIR}" 2>/dev/null || true
    chown "${DC_OWNER}:${DC_GROUP}" "${LOGS_DIR}" 2>/dev/null || true
    chmod 0750 "${LOGS_DIR}" 2>/dev/null || true
  fi
  [[ -d "${LOGS_DIR}" && ! -L "${LOGS_DIR}" ]] || return 0
  if [[ -L "${UNINSTALL_LOG}" || ( -e "${UNINSTALL_LOG}" && ! -f "${UNINSTALL_LOG}" ) ]]; then
    dc_remove_path "${UNINSTALL_LOG}" || return 0
  fi
  chflags -h nouchg,nouappnd "${UNINSTALL_LOG}" 2>/dev/null || true
  ( umask 077; : >> "${UNINSTALL_LOG}" ) 2>/dev/null || return 0
  chown -h "${DC_OWNER}:${DC_GROUP}" "${UNINSTALL_LOG}" 2>/dev/null || true
  chmod -h 0640 "${UNINSTALL_LOG}" 2>/dev/null || true
  DC_MARKER_LOG_FILE="${UNINSTALL_LOG}"
  _ulog "===== uninstall.sh start $(date -u +%FT%TZ) (purge=${PURGE}) ====="
}
open_uninstall_log

# ---- purge target set ---------------------------------------------------
#
# Newline-separated user:uid:gid:home lines, one per home. With --user,
# that one user. Otherwise the union of:
#   1. enumerate_local_users (when the library is present);
#   2. every dscl user with uid >= 500 and a real home folder, including
#      homes the enumerator filters out (group-writable, outside /Users);
#   3. the hook-guardian manifest rows (targets.yaml);
#   4. the guardian ledger rows (user_home / data_dir in the
#      hook-guardian-state JSON records);
#   5. every <users root>/*/.defenseclaw holding a managed hook script,
#      which also covers a user deleted with their home kept.
# Built before any service teardown, while the manifest and ledger exist,
# and without the library when it is missing. A symlinked home is never
# followed: that user is skipped with a marker.

PURGE_TARGETS=""

# _purge_add_home HOME [USER UID GID]: add one home to PURGE_TARGETS.
_purge_add_home() {
  local home="${1%/}" user="${2:-}" uid="${3:-}" gid="${4:-}"
  [[ -n "${home}" ]] || return 0
  case "${home}" in
    /*) ;;
    *) return 0 ;;
  esac
  case "/${home}/" in
    */../*|*/./*) return 0 ;;
  esac
  [[ "${home}" != "/" && "${home}" != "${DC_ROOT}" ]] || return 0
  if [[ -L "${home}" ]]; then
    dc_marker defenseclaw_skip unit="user:${user:-${home##*/}}" path="${home}" reason=home_symlink
    return 0
  fi
  [[ -d "${home}" ]] || return 0
  # One line per home.
  if [[ -n "${PURGE_TARGETS}" ]] && printf '%s\n' "${PURGE_TARGETS}" | awk -F: -v h="${home}" '
      { rest = $0; for (i = 0; i < 3; i++) sub(/^[^:]*:/, "", rest); if (rest == h) found = 1 }
      END { exit found ? 0 : 1 }'; then
    return 0
  fi
  if [[ -z "${user}" || -z "${uid}" || -z "${gid}" ]]; then
    local owner
    owner="$(stat -f '%Su:%u:%g' "${home}" 2>/dev/null || echo '')"
    [[ -n "${user}" ]] || user="${owner%%:*}"
    owner="${owner#*:}"
    [[ -n "${uid}" ]] || uid="${owner%%:*}"
    [[ -n "${gid}" ]] || gid="${owner#*:}"
  fi
  [[ -n "${user}" ]] || user="${home##*/}"
  PURGE_TARGETS="${PURGE_TARGETS:+${PURGE_TARGETS}$'\n'}${user}:${uid}:${gid}:${home}"
}

# _yaml_scalar VALUE: strip the double quotes and the \\ / \" escapes the
# installer and the enumerator write.
_yaml_scalar() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  if [[ "${v}" == \"*\" ]]; then
    v="${v#\"}"
    v="${v%\"}"
    v="${v//\\\"/\"}"
    v="${v//\\\\/\\}"
  fi
  printf '%s' "${v}"
}

_collect_from_dscl() {
  local names line name uid record home gid
  names="$(dscl . -list /Users UniqueID 2>/dev/null || true)"
  while IFS= read -r line; do
    name="$(printf '%s' "${line}" | awk '{print $1}')"
    uid="$(printf '%s' "${line}" | awk '{print $2}')"
    [[ -n "${name}" && "${uid}" =~ ^[0-9]+$ ]] || continue
    (( uid >= 500 )) || continue
    case "${name}" in _*|daemon|nobody|root) continue ;; esac
    record="$(dscl . -read "/Users/${name}" NFSHomeDirectory PrimaryGroupID 2>/dev/null || true)"
    home="$(printf '%s\n' "${record}" | sed -n 's/^NFSHomeDirectory: //p' | head -1)"
    gid="$(printf '%s\n' "${record}" | sed -n 's/^PrimaryGroupID: //p' | head -1)"
    [[ -n "${home}" ]] || continue
    [[ "${gid}" =~ ^[0-9]+$ ]] || gid=""
    _purge_add_home "${home}" "${name}" "${uid}" "${gid}"
  done <<< "${names}"
}

_collect_from_manifest() {
  [[ -f "${GUARDIAN_MANIFEST_PATH}" && ! -L "${GUARDIAN_MANIFEST_PATH}" ]] || return 0
  local line user="" home="" uid="" gid=""
  while IFS= read -r line; do
    case "${line}" in
      *"- user:"*)
        _purge_add_home "${home}" "${user}" "${uid}" "${gid}"
        user="$(_yaml_scalar "${line#*- user:}")"; home=""; uid=""; gid=""
        ;;
      *"user_home:"*) home="$(_yaml_scalar "${line#*user_home:}")" ;;
      *" uid:"*) uid="$(_yaml_scalar "${line#*uid:}")" ;;
      *" gid:"*) gid="$(_yaml_scalar "${line#*gid:}")" ;;
      *" data_dir:"*)
        local data_dir
        data_dir="$(_yaml_scalar "${line#*data_dir:}")"
        [[ -n "${home}" || "${data_dir}" != */.defenseclaw ]] || home="${data_dir%/.defenseclaw}"
        ;;
    esac
  done < "${GUARDIAN_MANIFEST_PATH}"
  _purge_add_home "${home}" "${user}" "${uid}" "${gid}"
}

_collect_from_ledger() {
  [[ -d "${GUARDIAN_AUTH_DIR}" && ! -L "${GUARDIAN_AUTH_DIR}" ]] || return 0
  local file value
  for file in "${GUARDIAN_AUTH_DIR}"/*.json; do
    [[ -f "${file}" && ! -L "${file}" ]] || continue
    while IFS= read -r value; do
      value="${value#*:}"
      value="$(_yaml_scalar "${value}")"
      case "${value}" in
        */.defenseclaw) value="${value%/.defenseclaw}" ;;
      esac
      _purge_add_home "${value}"
    done < <(grep -oE '"(user_home|data_dir)"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"' "${file}" 2>/dev/null || true)
  done
}

_collect_from_home_scan() {
  local dc_dir home script
  for dc_dir in "${USERS_ROOT}"/*/.defenseclaw; do
    [[ -d "${dc_dir}" && ! -L "${dc_dir}" ]] || continue
    home="${dc_dir%/.defenseclaw}"
    [[ "${home##*/}" != "Deleted Users" ]] || continue
    # Managed-runtime evidence: a guardian-rendered hook script. A
    # per-user (unmanaged) DefenseClaw install writes none, so its data
    # stays.
    for script in "${dc_dir}"/hooks/*.sh; do
      [[ -f "${script}" && ! -L "${script}" ]] || continue
      if grep -qx 'DEFENSECLAW_MANAGED_HOOK=1' "${script}" 2>/dev/null; then
        _purge_add_home "${home}"
        break
      fi
    done
  done
}

if [[ "${PURGE}" == "true" ]]; then
  if [[ -n "${TARGET_USER}" ]]; then
    TARGET_HOME="$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null \
      | sed -n 's/^NFSHomeDirectory: //p' | head -1 || true)"
    if [[ -z "${TARGET_HOME}" || ! -d "${TARGET_HOME}" ]]; then
      die "could not resolve home for --user ${TARGET_USER} (dscl returned '${TARGET_HOME}'); refusing to purge without a valid target"
    fi
    _purge_add_home "${TARGET_HOME}" "${TARGET_USER}" \
      "$(id -u "${TARGET_USER}" 2>/dev/null || echo "")" "$(id -g "${TARGET_USER}" 2>/dev/null || echo "")"
  else
    if command -v enumerate_local_users >/dev/null 2>&1; then
      while IFS=: read -r _u _uid _gid _h; do
        [[ -n "${_u}" ]] && _purge_add_home "${_h}" "${_u}" "${_uid}" "${_gid}"
      done < <(DC_INSTALLER_USERS_ROOT="${USERS_ROOT}" enumerate_local_users 2>/dev/null || true)
      unset _u _uid _gid _h
    fi
    _collect_from_dscl
    _collect_from_manifest
    _collect_from_ledger
    _collect_from_home_scan
  fi

  if [[ "${ASSUME_YES}" != "true" ]]; then
    printf '[uninstall] --purge will DELETE:\n'
    printf '  %s\n' "${SUPPORT_DIR}" "${LOGS_DIR}"
    if [[ -d "${LEGACY_SUPPORT_DIR}" || -d "${LEGACY_LOGS_DIR}" ]]; then
      printf '  (also sweeping legacy pre-Cisco-path locations)\n'
      [[ -d "${LEGACY_SUPPORT_DIR}" ]] && printf '  %s\n' "${LEGACY_SUPPORT_DIR}"
      [[ -d "${LEGACY_LOGS_DIR}" ]]    && printf '  %s\n' "${LEGACY_LOGS_DIR}"
    fi
    if [[ -n "${PURGE_TARGETS}" ]]; then
      printf '[uninstall] per-user cleanup targets (%d user(s)):\n' \
        "$(printf '%s\n' "${PURGE_TARGETS}" | grep -c . || true)"
      while IFS=: read -r _u _uid _gid _h; do
        [[ -z "${_u}" ]] && continue
        printf '  %s/.defenseclaw/\n' "${_h}"
      done <<< "${PURGE_TARGETS}"
      unset _u _uid _gid _h
      if [[ "${KEEP_AGENT_CONFIGS}" != "true" ]]; then
        printf '[uninstall] and will SCRUB DefenseClaw entries from each user'\''s:\n'
        printf '  ~/.codex/config.toml\n  ~/.claude/settings.json\n  ~/.cursor/hooks.json\n'
        printf '  ~/.copilot/hooks/defenseclaw.json\n'
        printf '  ~/.config/amp/plugins/defenseclaw.ts (exact backup authority required)\n'
        printf '  (non-DefenseClaw entries preserved)\n'
      fi
    fi
    printf '[uninstall] type yes to continue: '
    REPLY=""
    read -r REPLY || true
    [[ "${REPLY}" == "yes" ]] || die "purge declined"
  fi
fi

# ---- stop the daemon(s) -------------------------------------------------
#
# Sweep BOTH the current (Cisco-path) label and the legacy one so an
# upgrade from a pre-move install cleanly stops the old daemon before
# we delete its files.

stop_daemon() {
  local label="$1"
  local plist="$2"
  if launchctl print "system/${label}" >/dev/null 2>&1; then
    log "stopping LaunchDaemon (${label})"

    # Capture the child PID BEFORE bootout so we can wait for the
    # actual process to exit. bootout returns once launchd has
    # released the label, but the child may still be alive for a
    # moment. For hook-guardian this matters: while alive, its
    # fsnotify handler re-heals the very agent-config files the
    # subsequent scrub is about to strip, silently undoing the
    # uninstall. The label can exit between the probe above and this
    # read, so an empty answer is fine.
    local pid=""
    pid="$( (launchctl print "system/${label}" 2>/dev/null || true) \
      | awk '/^[[:space:]]*pid = / {print $3; exit}' || true)"

    # Try both bootout forms (target vs plist path); either works and
    # both are safe when the target is already gone.
    launchctl bootout "system/${label}" 2>/dev/null || \
      launchctl bootout system "${plist}" 2>/dev/null || \
      warn "bootout failed for ${label}; may already be stopped"

    # Wait briefly for launchd to fully release the service so a
    # subsequent install can bootstrap without seeing "already loaded".
    local settle=0
    while (( settle < 5 )); do
      launchctl print "system/${label}" >/dev/null 2>&1 || break
      sleep 1
      settle=$((settle + 1))
    done
    # Verify the label is gone; one more bootout through the other form,
    # then record it if it is still loaded (its plist is removed below,
    # so it will not come back at the next boot).
    if launchctl print "system/${label}" >/dev/null 2>&1; then
      launchctl bootout system "${plist}" >/dev/null 2>&1 || true
      launchctl bootout "system/${label}" >/dev/null 2>&1 || true
      sleep 1
      if launchctl print "system/${label}" >/dev/null 2>&1; then
        leftover "system/${label}" label_still_loaded \
          defenseclaw_skip unit="label:${label}" reason=label_still_loaded
      fi
    fi

    # Now wait for the child process itself to exit. bootout sends
    # SIGTERM; escalate to SIGKILL after 10s in case the process is
    # blocked in a syscall or ignoring the signal.
    if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
      local waited=0
      while (( waited < 10 )); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 1
        waited=$((waited + 1))
      done
      if kill -0 "${pid}" 2>/dev/null; then
        warn "PID ${pid} for ${label} did not exit within 10s; sending SIGKILL"
        kill -9 "${pid}" 2>/dev/null || true
        waited=0
        while (( waited < 3 )); do
          kill -0 "${pid}" 2>/dev/null || break
          sleep 1
          waited=$((waited + 1))
        done
        if kill -0 "${pid}" 2>/dev/null; then
          warn "PID ${pid} for ${label} still alive after SIGKILL; hooks scrub may race with the reconciler"
        fi
      fi
    fi
  fi
  return 0
}

# Stop the hook-guardian FIRST — it's the fsnotify-driven reconciler
# that re-heals scrubbed agent-config entries. Everything else can
# race with the scrub without corrupting the result, but the guardian
# will actively undo it if given even a ~1s window.
stop_daemon "${GUARDIAN_LAUNCHD_LABEL}"   "${GUARDIAN_PLIST_DST}"
stop_daemon "${ENUMERATOR_LAUNCHD_LABEL}" "${ENUMERATOR_PLIST_DST}"
stop_daemon "${LAUNCHD_LABEL}"            "${PLIST_DST}"
stop_daemon "${LEGACY_GUARDIAN_LAUNCHD_LABEL}" "${LEGACY_GUARDIAN_PLIST_DST}"
stop_daemon "${LEGACY_LAUNCHD_LABEL}"     "${LEGACY_PLIST_DST}"

# ---- agent-config scrub (BEFORE we delete ~/.defenseclaw) --------------
#
# We scrub the user's native agent hook configs first so the agent doesn't
# start hitting "command not found" + fail-close every tool call the moment
# we delete ~/.defenseclaw/hooks/*-hook.sh. The scrub runs as the target
# user (drop privileges via sudo -u) so file ownership is preserved.
#
# The scrub logic is baked into the DefenseClaw binary as
# `defenseclaw enterprise hooks scrub`; the previous Python helper
# crashed on stock macOS hosts where /usr/bin/python3 is a Xcode CLT
# stub that fails to launch without developer tools installed. Using
# our own Go binary sidesteps that dependency entirely.

# Discover the gateway binary. Managed installs land it at a known
# absolute path; bundle-fixture / dev-tree tests can override via
# DEFENSECLAW_SCRUB_BIN so they don't need the managed layout present.
#
# _scrub_bin_trusted PATH LABEL [--allow-non-root-owner]
#   Validates a candidate scrub-binary path. Returns 0 on success,
#   printing the path to stdout; returns 1 on any check failure,
#   emitting a WARN so the operator sees which check tripped. All
#   check failures write to stderr and never abort the shell — the
#   caller decides whether to fall through to the next candidate.
#
#   uninstall.sh runs under `sudo`, so the referenced binary is
#   executed as root; every candidate is treated as untrusted input
#   and must satisfy the checks below before it takes effect:
#
#     1. absolute path (relative could be rerooted by PWD)
#     2. exists as a regular file (not a directory, not a device,
#        not a symlink — a symlink swap is the exact race that
#        motivates this)
#     3. is executable
#     4. mode & 0022 == 0 (no group/other write bits — a compromised
#        umask cannot slip a writable binary through)
#     5. owned by uid 0 (matches the installer's "root-owned trusted
#        input" pattern for --plist)
#
#   `--allow-non-root-owner` skips check (5). The bundle-fixture /
#   dev-tree candidates under SCRIPT_DIR inherit the extracting
#   user's uid — that's expected for a `tar xzf` extraction and
#   matches the installer's two-tier PLIST_SRC policy where the
#   bundle default is accepted regardless of owner (its content came
#   from the trusted tarball). Managed-install candidates under
#   INSTALL_PREFIX must always be root-owned; the flag isn't used
#   there.
#
#   DC_UNINSTALL_SKIP_SCRUB_BIN_TRUST=1 is a test-side seam that
#   skips checks 4 & 5 entirely so bundle-fixture tests can drive
#   uninstall.sh against a non-root-owned binary in a tmpdir
#   (parallel to DC_INSTALLER_SKIP_ROOT_CHECK on the install side).
_scrub_bin_trusted() {
  local path="$1"
  local label="$2"
  local allow_non_root_owner="false"
  case "${3:-}" in
    --allow-non-root-owner) allow_non_root_owner="true" ;;
    "") ;;
    *) warn "${label} internal error: unknown flag ${3}"; return 1 ;;
  esac
  case "${path}" in
    /*) ;;
    *)
      warn "${label} must be an absolute path (got: ${path}); ignoring"
      return 1
      ;;
  esac
  if [[ -L "${path}" ]]; then
    warn "${label} is a symlink; refusing to follow (${path}); ignoring"
    return 1
  fi
  if [[ ! -f "${path}" ]]; then
    return 1
  fi
  if [[ ! -x "${path}" ]]; then
    warn "${label} is not executable: ${path}; ignoring"
    return 1
  fi
  if [[ "${DC_UNINSTALL_SKIP_SCRUB_BIN_TRUST:-}" == "1" ]]; then
    printf '%s' "${path}"
    return 0
  fi
  local _own_mode _own _mode
  _own_mode="$(stat -f '%Su %Lp' "${path}" 2>/dev/null || echo '')"
  if [[ -z "${_own_mode}" ]]; then
    warn "${label} cannot be stat'd: ${path}; ignoring"
    return 1
  fi
  _own="${_own_mode%% *}"
  _mode="${_own_mode##* }"
  if (( (8#${_mode} & 8#022) != 0 )); then
    warn "${label} is group/other writable (mode ${_mode}): ${path}; ignoring"
    return 1
  fi
  if [[ "${allow_non_root_owner}" != "true" && "${_own}" != "${DC_OWNER}" ]]; then
    warn "${label} must be owned by root (got: ${_own}): ${path}; ignoring"
    return 1
  fi
  # Strict tier: validate the containing directory too. A binary
  # can be root-owned + 0755 and still be swap-hijackable if the
  # DIRECTORY it lives in is writable by a non-root user — that
  # user can `mv the-file another; touch the-file` and replace the
  # trusted binary at will. The bundle-fixture tier stays exempt
  # because its extraction directory inherits the operator's uid
  # (documented in the installer's PLIST_SRC two-tier policy).
  if [[ "${allow_non_root_owner}" != "true" ]]; then
    local _dir _dir_own_mode _dir_own _dir_mode
    _dir="$(dirname -- "${path}")"
    _dir_own_mode="$(stat -f '%Su %Lp' "${_dir}" 2>/dev/null || echo '')"
    if [[ -z "${_dir_own_mode}" ]]; then
      warn "${label} containing dir cannot be stat'd: ${_dir}; ignoring"
      return 1
    fi
    _dir_own="${_dir_own_mode%% *}"
    _dir_mode="${_dir_own_mode##* }"
    if [[ "${_dir_own}" != "${DC_OWNER}" ]]; then
      warn "${label} containing dir must be owned by root (got: ${_dir_own}): ${_dir}; ignoring"
      return 1
    fi
    if (( (8#${_dir_mode} & 8#022) != 0 )); then
      warn "${label} containing dir is group/other writable (mode ${_dir_mode}): ${_dir}; ignoring"
      return 1
    fi
  fi
  printf '%s' "${path}"
  return 0
}

# _scrub_bin resolves the scrub-binary path by trying, in order:
#   1. DEFENSECLAW_SCRUB_BIN (operator override — strict trust)
#   2. SCRIPT_DIR/defenseclaw           (bundle default — relaxed owner tier)
#   3. SCRIPT_DIR/defenseclaw-gateway   (bundle/dev — relaxed owner tier)
#   4. INSTALL_PREFIX/bin/defenseclaw-gateway (managed install — strict trust)
#
# The bundle's own binary comes first so a re-run after a partial purge
# (install tree already gone) scrubs with the same binary as the first
# run. The installed binary and its folder are re-stamped root:wheel 0755
# before the strict check, so permission drift on them never disables
# the scrub. Any candidate that fails the trust check prints a WARN and
# is skipped; discovery falls through to the next candidate.
_scrub_bin() {
  local resolved=""
  if [[ -n "${DEFENSECLAW_SCRUB_BIN:-}" ]]; then
    resolved="$(_scrub_bin_trusted "${DEFENSECLAW_SCRUB_BIN}" "DEFENSECLAW_SCRUB_BIN" || true)"
    if [[ -n "${resolved}" ]]; then
      printf '%s' "${resolved}"
      return
    fi
    # Fall through: warn already printed by helper.
  fi
  # Bundle-fixture / dev-tree candidates: relaxed owner tier because
  # the bundle unpacks under the caller's uid. Mode + symlink checks
  # still apply.
  for cand in \
    "${SCRIPT_DIR}/defenseclaw" \
    "${SCRIPT_DIR}/defenseclaw-gateway"; do
    resolved="$(_scrub_bin_trusted "${cand}" "bundle scrub binary" --allow-non-root-owner || true)"
    if [[ -n "${resolved}" ]]; then
      printf '%s' "${resolved}"
      return
    fi
  done
  # Managed-install location: strict trust (root-owned + mode
  # tightened). Repair the metadata first; the content is never
  # changed here.
  if command -v dc_restamp >/dev/null 2>&1; then
    dc_restamp "${INSTALL_PREFIX}/bin" "${DC_OWNER}:${DC_GROUP}" 0755 -d >/dev/null || true
    dc_restamp "${INSTALL_PREFIX}/bin/defenseclaw-gateway" "${DC_OWNER}:${DC_GROUP}" 0755 -f >/dev/null || true
  fi
  resolved="$(_scrub_bin_trusted "${INSTALL_PREFIX}/bin/defenseclaw-gateway" "managed install gateway binary" || true)"
  if [[ -n "${resolved}" ]]; then
    printf '%s' "${resolved}"
    return
  fi
  printf ''
}

SCRUB_BIN=""
if [[ "${PURGE}" == "true" && "${KEEP_AGENT_CONFIGS}" != "true" ]]; then
  SCRUB_BIN="$(_scrub_bin)"
fi

# python3 resolver — used only by the `amp` connector's scrub path.
# The other connectors (codex / claudecode / cursor / copilot) route
# through the Go binary at ${SCRUB_BIN} and do not need python3.
# `amp` needs SHA-256 verification against a signed manifest to
# restore its plugin file safely, which the Go scrubber doesn't
# implement today; keeping python3 gated to this one connector
# preserves the QA rip-out for the common case without regressing
# Amp uninstall.
PY="$(command -v python3 || printf '/usr/bin/python3')"

# _run_scrub CONNECTOR CFG AUTHORITY [USER]: one scrub attempt, as USER
# when given, else as the caller (root). Prints the scrubber's output.
_run_scrub() {
  local connector="$1" cfg="$2" authority="$3" run_as="${4:-}"
  local -a cmd=()
  if [[ "${connector}" == "amp" ]]; then
    cmd=("${PY}" "${SCRUB_PY}" "${connector}" "${cfg}")
    [[ -z "${authority}" ]] || cmd+=("${authority}")
  else
    cmd=("${SCRUB_BIN}" enterprise hooks scrub --connector "${connector}" --file "${cfg}" --quiet-missing)
  fi
  if [[ -n "${run_as}" ]]; then
    sudo -u "${run_as}" "${cmd[@]}" 2>&1
  else
    "${cmd[@]}" 2>&1
  fi
}

# scrub_agent_config CONNECTOR CFG USER [AUTHORITY] [HOME]
#
# Scrubs one user × connector. The first attempt runs as the user. A
# failure gets one retry as root: user immutable/append flags on the
# exact file are cleared (no-follow) and restored afterwards, and the
# scrubber, run as root, edits through its own no-follow handle and keeps
# the file's owner. A config that is a symlink is never retried as root.
# Returns 1 when the user × connector is left unscrubbed; the caller
# logs it and carries on with everyone else.
scrub_agent_config() {
  local connector="$1"
  local cfg="$2"
  local run_as_user="$3"   # empty ⇒ run as caller (root)
  local authority="${4:-}"
  local home="${5:-}"      # the user's home: bounds the root retry
  if [[ "${connector}" == "amp" ]]; then
    if [[ ! -e "${cfg}" && ! -L "${cfg}" ]]; then
      return 0
    fi
  elif [[ ! -f "${cfg}" ]]; then
      return 0
  fi
  log "  scrubbing ${connector} entries from ${cfg}"

  # Split-route: `amp` uses the Python scrubber (signed-backup
  # restore of ~/.config/amp/plugins/defenseclaw.ts requires SHA-256
  # verification against the manifest under
  # ~/.defenseclaw/connector_backups/amp/config.json — logic that
  # lives in scrub_agent_configs.py). Everything else uses the Go
  # binary, which is python3-free per the QA rip-out.
  if [[ "${connector}" == "amp" ]]; then
    # Threat model parity with the Go binary path below: uninstall.sh
    # runs under `sudo`, and this branch executes SCRUB_PY as
    # root-or-target-user. Reuse the bundle tier of _scrub_bin_trusted
    # so a hostile symlink or a group/other-writable script under
    # SCRIPT_DIR cannot slip past. `--allow-non-root-owner` mirrors
    # the bundle-tier relaxation used elsewhere: SCRIPT_DIR extracts
    # under the operator's uid, which is documented behaviour, but
    # every OTHER check (absolute path, regular file, executable bit,
    # non-group-writable mode) must still pass. scrub_agent_configs.py
    # is shipped 0755, so the -x check is a positive assertion that
    # the tarball extraction preserved the mode.
    if ! _scrub_bin_trusted "${SCRUB_PY}" "python scrub helper" --allow-non-root-owner >/dev/null; then
      dc_marker defenseclaw_skip unit="user:${run_as_user}" connector=amp path="${cfg}" reason=scrub_helper_untrusted
      return 1
    fi
    if ! "${PY}" -c 'import sys' >/dev/null 2>&1; then
      dc_marker defenseclaw_prereq check=python3_available connector=amp path="${cfg}" \
        remedy="install the Xcode Command Line Tools (xcode-select --install) and rerun the purge"
      return 1
    fi
  elif [[ -z "${SCRUB_BIN}" ]]; then
    warn "defenseclaw binary not found; skipping scrub of ${cfg}"
    dc_marker defenseclaw_skip unit="user:${run_as_user}" connector="${connector}" path="${cfg}" reason=scrub_binary_missing
    return 1
  fi

  # Run as the user only when the account still exists and is not root;
  # a deleted user's leftover home is scrubbed as root directly.
  local as_user=""
  if [[ -n "${run_as_user}" ]]; then
    local _uid
    _uid="$(id -u "${run_as_user}" 2>/dev/null || echo "")"
    if [[ -n "${_uid}" && "${_uid}" != "0" ]]; then
      as_user="${run_as_user}"
    fi
  fi

  # --quiet-missing lets rc=2 (file missing) still count as success:
  # the outer if-guard already handled the "file doesn't exist" case,
  # but between that check and the scrub call the file could vanish
  # (rare, but possible), and treating it as clean is the right move.
  local rc=0 output=""
  output="$(_run_scrub "${connector}" "${cfg}" "${authority}" "${as_user}")" || rc=$?
  [[ -z "${output}" ]] || log "    ${output//$'\n'/$'\n'    }"
  if (( rc == 0 )); then
    return 0
  fi
  if [[ -z "${as_user}" ]]; then
    warn "  scrub exited ${rc} for ${cfg} (left unmodified)"
    return 1
  fi

  # One retry as root.
  if [[ -L "${cfg}" ]]; then
    warn "  scrub exited ${rc} for ${cfg}; it is a symlink, so it is not retried as root"
    return 1
  fi
  # Root must never follow a user-controlled symlink in the folders between
  # the home and the config either: they could point root at another
  # principal's files. (Not atomic; it narrows the window to a race.)
  if [[ -z "${home}" || "${cfg}" != "${home}"/* ]]; then
    warn "  scrub exited ${rc} for ${cfg}; it is outside the user home, so it is not retried as root"
    return 1
  fi
  local _dir="${cfg%/*}"
  while [[ "${_dir}" != "${home}" && -n "${_dir}" ]]; do
    if [[ -L "${_dir}" ]]; then
      warn "  scrub exited ${rc} for ${cfg}; ${_dir} is a symlink, so it is not retried as root"
      return 1
    fi
    _dir="${_dir%/*}"
  done
  warn "  scrub exited ${rc} for ${cfg} as ${as_user}; retrying once as root"
  local flags=""
  flags="$(stat -f '%Sf' "${cfg}" 2>/dev/null || echo '-')"
  if [[ "${flags}" == *uchg* || "${flags}" == *uappnd* ]]; then
    chflags -h nouchg,nouappnd "${cfg}" 2>/dev/null || true
  fi
  rc=0
  output="$(_run_scrub "${connector}" "${cfg}" "${authority}")" || rc=$?
  [[ -z "${output}" ]] || log "    ${output//$'\n'/$'\n'    }"
  if [[ "${flags}" == *uchg* || "${flags}" == *uappnd* ]] && [[ -e "${cfg}" && ! -L "${cfg}" ]]; then
    chflags -h "${flags}" "${cfg}" 2>/dev/null || true
  fi
  if (( rc == 0 )); then
    dc_marker defenseclaw_repair unit="user:${run_as_user}" connector="${connector}" path="${cfg}" reason=scrub_root_retry
    return 0
  fi
  warn "  scrub exited ${rc} for ${cfg} as root (left unmodified)"
  return 1
}

# purge_user USER HOME: scrub every connector, then delete ~/.defenseclaw.
# Each user is isolated: nothing here can stop the next user, and the
# per-user delete runs whatever the scrub outcome.
purge_user() {
  local user="$1" home="$2"
  if [[ "${KEEP_AGENT_CONFIGS}" != "true" ]]; then
    log "scrubbing per-user hook configs for ${user} (${home})"
    local spec connector cfg authority
    for spec in \
      "codex|${home}/.codex/config.toml|" \
      "claudecode|${home}/.claude/settings.json|" \
      "cursor|${home}/.cursor/hooks.json|" \
      "copilot|${home}/.copilot/hooks/defenseclaw.json|" \
      "amp|${home}/.config/amp/plugins/defenseclaw.ts|${home}/.defenseclaw/connector_backups/amp/config.json"; do
      connector="${spec%%|*}"
      cfg="${spec#*|}"; cfg="${cfg%%|*}"
      authority="${spec##*|}"
      if [[ "${connector}" == "amp" ]]; then
        scrub_agent_config amp \
          "${home}/.config/amp/plugins/defenseclaw.ts" "${user}" \
          "${home}/.defenseclaw/connector_backups/amp/config.json" "${home}" && continue
      else
        scrub_agent_config "${connector}" "${cfg}" "${user}" "${authority}" "${home}" && continue
      fi
      leftover "${cfg}" scrub_failed \
        defenseclaw_skip unit="user:${user}" connector="${connector}" path="${cfg}" reason=scrub_failed
    done
  fi
  purge_remove "${home}/.defenseclaw" "user:${user}" || true
  if [[ "${KEEP_AGENT_CONFIGS}" == "true" ]]; then
    for cfg in "${home}/.codex/config.toml" \
               "${home}/.claude/settings.json" \
               "${home}/.cursor/hooks.json" \
               "${home}/.copilot/hooks/defenseclaw.json" \
               "${home}/.config/amp/plugins/defenseclaw.ts"; do
      if [[ -f "${cfg}" ]]; then
        warn "--keep-agent-configs: ${cfg} remains after DefenseClaw runtime deletion (its managed hook/plugin may fail closed)"
      fi
    done
  fi
  return 0
}

# ---- per-user phase (purge) ----------------------------------------------
#
# Runs before the install tree is removed, so the managed scrub binary
# and the manifest are still there for a re-run of this phase.
if [[ "${PURGE}" == "true" && -n "${PURGE_TARGETS}" ]]; then
  while IFS=: read -r _pu _puid _pgid _phome; do
    [[ -z "${_pu}" || -z "${_phome}" ]] && continue
    purge_user "${_pu}" "${_phome}" || true
  done <<< "${PURGE_TARGETS}"
  unset _pu _puid _pgid _phome
fi

# ---- remove files we own unconditionally --------------------------------
#
# Sweep both the current and legacy plist / binary tree.

for plist in \
  "${PLIST_DST}" \
  "${GUARDIAN_PLIST_DST}" \
  "${ENUMERATOR_PLIST_DST}" \
  "${LEGACY_PLIST_DST}" \
  "${LEGACY_GUARDIAN_PLIST_DST}"; do
  purge_remove "${plist}" || true
done

# INSTALL_PREFIX is /opt/cisco/secureclient/defenseclaw/ — a
# DefenseClaw-owned subtree. Under the managed layout it holds bin/ AND
# etc/ + runtime/ + hook-guardian-state/. The default (non-purge)
# uninstall preserves runtime state so a reinstall keeps audit history
# (see usage text above), so on the non-purge path only the binary
# subtree is removed; the full tree drops on --purge, after the
# per-user phase above.
#
# LEGACY_INSTALL_PREFIX is /Library/DefenseClaw/ — binary-only in the
# old layout (runtime lived under LEGACY_SUPPORT_DIR), so it's safe to
# remove wholesale in either mode.
# `${var:?}` on the rm targets is defence-in-depth against an empty/unset
# INSTALL_PREFIX after a future refactor — a bare `rm -rf /` or `rm -rf
# /bin` would be catastrophic. Shellcheck SC2115.
if [[ "${PURGE}" == "true" ]]; then
  purge_remove "${INSTALL_PREFIX:?}" || true
else
  purge_remove "${INSTALL_PREFIX:?}/bin" || true
fi
purge_remove "${LEGACY_INSTALL_PREFIX:?}" || true

# ---- runtime state ------------------------------------------------------

if [[ "${PURGE}" == "true" ]]; then
  # SUPPORT_DIR equals INSTALL_PREFIX under the managed layout and was
  # already removed above on --purge, so we only need to sweep LOGS_DIR
  # here — everything in it except this run's uninstall.log. For legacy
  # installs, SUPPORT_DIR and LOGS_DIR are separate trees that still
  # need explicit removal.
  if [[ -L "${LOGS_DIR}" ]]; then
    purge_remove "${LOGS_DIR}" || true
  elif [[ -d "${LOGS_DIR}" ]]; then
    log "purging ${LOGS_DIR} (keeping uninstall.log)"
    for _entry in "${LOGS_DIR}"/* "${LOGS_DIR}"/.[!.]*; do
      [[ -e "${_entry}" || -L "${_entry}" ]] || continue
      [[ "${_entry}" != "${UNINSTALL_LOG}" ]] || continue
      purge_remove "${_entry}" || true
    done
    unset _entry
  fi
  for d in "${LEGACY_SUPPORT_DIR}" "${LEGACY_LOGS_DIR}"; do
    purge_remove "${d}" || true
  done

  # Modern (root-mode) installs let the managed cloud auth provider
  # create its own log file under a shared log tree; there's nothing
  # for us to sweep. But a pre-root install may have pre-created the
  # file with defenseclaw ownership, so remove it if present. Never
  # rm the parent dir — it's shared.
  CMID_LOG_FILE="/Library/Logs/Cisco/SecureClient/CloudManagement/defenseclaw-gateway_cmidapi.log"
  if [[ -f "${DC_ROOT}${CMID_LOG_FILE}" ]]; then
    log "removing legacy managed-auth log file: ${CMID_LOG_FILE}"
    purge_remove "${DC_ROOT}${CMID_LOG_FILE}" || true
  fi

  # NOTE: the daemon runs as root, so no service-user cleanup is
  # necessary here. Older DefenseClaw installs (pre-root switch)
  # created a dedicated 'defenseclaw' user via sysadminctl/dseditgroup
  # + a matching group. If this uninstall runs on a machine still
  # carrying those records, sweep them so the next re-install starts
  # clean and no orphan uid remains.
  if [[ -z "${DC_ROOT}" ]]; then
    for legacy_name in "${SERVICE_USER_KNOWN[@]}"; do
      if dscl /Local/Default -read "/Groups/${legacy_name}" >/dev/null 2>&1; then
        log "removing legacy DefenseClaw group ${legacy_name} (pre-root install)"
        /usr/sbin/dseditgroup -o delete "${legacy_name}" >/dev/null 2>&1 \
          || warn "dseditgroup delete ${legacy_name} failed"
      fi
      if dscl /Local/Default -read "/Users/${legacy_name}" >/dev/null 2>&1; then
        log "removing legacy DefenseClaw user ${legacy_name} (pre-root install)"
        /usr/sbin/sysadminctl -deleteUser "${legacy_name}" >/dev/null 2>&1 \
          || warn "sysadminctl deleteUser ${legacy_name} failed"
      fi
    done
  fi
else
  log "preserving ${SUPPORT_DIR} (config + audit DB)"
  log "preserving ${LOGS_DIR}"
  log "  (re-run with --purge to delete these and clean up per-user state)"
fi

# ---- sanity check -------------------------------------------------------

# _logs_dir_leftover: LOGS_DIR counts as left behind only when it holds
# anything besides uninstall.log.
_logs_dir_leftover() {
  [[ -e "${LOGS_DIR}" || -L "${LOGS_DIR}" ]] || return 1
  [[ -d "${LOGS_DIR}" && ! -L "${LOGS_DIR}" ]] || return 0
  local entry
  for entry in "${LOGS_DIR}"/* "${LOGS_DIR}"/.[!.]*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    [[ "${entry}" == "${UNINSTALL_LOG}" ]] || return 0
  done
  return 1
}

REMAINING=()
for _path in "${PLIST_DST}" "${GUARDIAN_PLIST_DST}" "${ENUMERATOR_PLIST_DST}" \
             "${LEGACY_PLIST_DST}" "${LEGACY_GUARDIAN_PLIST_DST}" \
             "${INSTALL_PREFIX}" "${LEGACY_INSTALL_PREFIX}"; do
  if [[ -e "${_path}" || -L "${_path}" ]]; then
    if [[ "${_path}" == "${INSTALL_PREFIX}" && "${PURGE}" != "true" ]]; then
      [[ -e "${INSTALL_PREFIX}/bin" ]] || continue
      _path="${INSTALL_PREFIX}/bin"
    fi
    REMAINING+=("${_path}")
  fi
done
if [[ "${PURGE}" == "true" ]]; then
  _logs_dir_leftover && REMAINING+=("${LOGS_DIR}")
  [[ -e "${LEGACY_SUPPORT_DIR}" ]] && REMAINING+=("${LEGACY_SUPPORT_DIR}")
  [[ -e "${LEGACY_LOGS_DIR}" ]]    && REMAINING+=("${LEGACY_LOGS_DIR}")
  if [[ -n "${PURGE_TARGETS}" ]]; then
    while IFS=: read -r _pu _puid _pgid _phome; do
      [[ -z "${_phome}" ]] && continue
      [[ -e "${_phome}/.defenseclaw" || -L "${_phome}/.defenseclaw" ]] && REMAINING+=("${_phome}/.defenseclaw")
    done <<< "${PURGE_TARGETS}"
    unset _pu _puid _pgid _phome
  fi
fi
unset _path

if [[ "${PURGE}" != "true" ]]; then
  # The non-purge path keeps its original contract: a leftover is an
  # error the operator resolves by hand.
  if (( ${#REMAINING[@]} > 0 )); then
    warn "the following paths still exist (manual cleanup needed):"
    printf '  - %s\n' "${REMAINING[@]}" >&2
    exit 1
  fi
  log "done."
  exit 0
fi

# Purge: every leftover was already logged with its marker where it
# happened; list anything the final sweep still sees, then summarise on
# the last line and exit 0.
_summary=()
if (( ${#LEFTOVERS[@]} > 0 )); then
  for _item in "${LEFTOVERS[@]}"; do
    _summary+=("${_item%%|*} (${_item#*|})")
  done
fi
if (( ${#REMAINING[@]} > 0 )); then
  warn "the following paths still exist; a later install clears them:"
  for _path in "${REMAINING[@]}"; do
    printf '  - %s\n' "${_path}" >&2
    _ulog "  - ${_path}"
    _already="false"
    if (( ${#LEFTOVERS[@]} > 0 )); then
      for _item in "${LEFTOVERS[@]}"; do
        [[ "${_item%%|*}" == "${_path}" ]] && _already="true"
      done
    fi
    if [[ "${_already}" != "true" ]]; then
      dc_marker defenseclaw_skip unit="path:${_path}" path="${_path}" reason=still_present
      _summary+=("${_path} (still_present)")
    fi
  done
  unset _path _already
fi
unset _item

if (( ${#_summary[@]} > 0 )); then
  _joined=""
  for _item in "${_summary[@]}"; do
    _joined="${_joined:+${_joined}; }${_item}"
  done
  log "done with ${#_summary[@]} warning(s); left behind: ${_joined}"
else
  log "done."
  # Nothing was left behind, so the record is not needed: the log folder
  # goes too, as it always did. It stays only when it holds something else,
  # and after a --user purge, which re-checked one user only: warnings that
  # earlier runs logged for other users are kept.
  if [[ -z "${TARGET_USER}" && -n "${DC_MARKER_LOG_FILE}" && -d "${LOGS_DIR}" && ! -L "${LOGS_DIR}" ]]; then
    DC_MARKER_LOG_FILE=""
    rm -f "${UNINSTALL_LOG}" 2>/dev/null || true
    rmdir "${LOGS_DIR}" 2>/dev/null || true
  fi
fi
exit 0
