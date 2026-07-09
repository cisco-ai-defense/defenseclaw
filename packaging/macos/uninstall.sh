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
#     Non-DefenseClaw user entries in those files are preserved verbatim.
#     Pass --keep-agent-configs to skip the scrub.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRUB_PY="${SCRIPT_DIR}/lib/scrub_agent_configs.py"

INSTALL_PREFIX="/opt/cisco/secureclient/defenseclaw"
SUPPORT_DIR="${INSTALL_PREFIX}"
LOGS_DIR="/Library/Logs/Cisco/SecureClient/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"
LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw"

# Legacy paths + labels from pre-managed-layout DefenseClaw installs.
# Kept so that running the new uninstall.sh on an old-layout host
# cleans up everything in one pass.
LEGACY_INSTALL_PREFIX="/Library/DefenseClaw"
LEGACY_SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LEGACY_LOGS_DIR="/Library/Logs/DefenseClaw"
LEGACY_PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LEGACY_LAUNCHD_LABEL="com.defenseclaw.gateway"

# Legacy service-user names swept on --purge. Pre-root DefenseClaw
# installs created these accounts via ensure_service_user in install.sh.
# Modern (Cisco-path, root-mode) installs never create a service user.
SERVICE_USER_KNOWN=(defenseclaw)

PURGE="false"
ASSUME_YES="false"
TARGET_USER=""
KEEP_AGENT_CONFIGS="false"
SCRUB_FAILED="false"

# ---- helpers ------------------------------------------------------------

log()  { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARN: %s\n' "$*" >&2; }
die()  { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

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
                          ~/.defenseclaw/ for the target user (hook scripts)
                          Any legacy /Users/defenseclaw + /Groups/defenseclaw
                              dscl records from pre-root DefenseClaw installs
                        AND scrub DefenseClaw entries from:
                          ~/.codex/config.toml
                          ~/.claude/settings.json
                          ~/.cursor/hooks.json
                        Non-DefenseClaw entries in those files are preserved.
  --keep-agent-configs  With --purge, skip the agent-config scrub. Hook
                        scripts will be deleted, leaving dangling references
                        that fail-close every agent tool call. Use only if
                        you intend to immediately reinstall.
  --user USER           Per-user cleanup target for --purge (default: \$SUDO_USER)
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
    *) die "unknown flag: $1 (try --help)";;
  esac
done

# ---- preflight ----------------------------------------------------------

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 $*)"

if [[ "${PURGE}" == "true" ]]; then
  if [[ -z "${TARGET_USER}" ]]; then
    TARGET_USER="${SUDO_USER:-}"
  fi
  if [[ -n "${TARGET_USER}" ]]; then
    TARGET_HOME="$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [[ -z "${TARGET_HOME}" || ! -d "${TARGET_HOME}" ]]; then
      die "could not resolve home for --user ${TARGET_USER} (dscl returned '${TARGET_HOME}'); refusing to purge without a valid target"
    fi
  fi
  if [[ "${ASSUME_YES}" != "true" ]]; then
    printf '[uninstall] --purge will DELETE:\n'
    printf '  %s\n' "${SUPPORT_DIR}" "${LOGS_DIR}"
    if [[ -d "${LEGACY_SUPPORT_DIR}" || -d "${LEGACY_LOGS_DIR}" ]]; then
      printf '  (also sweeping legacy pre-Cisco-path locations)\n'
      [[ -d "${LEGACY_SUPPORT_DIR}" ]] && printf '  %s\n' "${LEGACY_SUPPORT_DIR}"
      [[ -d "${LEGACY_LOGS_DIR}" ]]    && printf '  %s\n' "${LEGACY_LOGS_DIR}"
    fi
    if [[ -n "${TARGET_USER:-}" && -n "${TARGET_HOME:-}" ]]; then
      printf '  %s/.defenseclaw/\n' "${TARGET_HOME}"
      if [[ "${KEEP_AGENT_CONFIGS}" != "true" ]]; then
        printf '[uninstall] and will SCRUB DefenseClaw entries from:\n'
        for f in "${TARGET_HOME}/.codex/config.toml" \
                 "${TARGET_HOME}/.claude/settings.json" \
                 "${TARGET_HOME}/.cursor/hooks.json"; do
          [[ -f "${f}" ]] && printf '  %s\n' "${f}"
        done
        printf '  (non-DefenseClaw entries preserved)\n'
      fi
    fi
    printf '[uninstall] type yes to continue: '
    read -r REPLY
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
  fi
}

stop_daemon "${LAUNCHD_LABEL}"        "${PLIST_DST}"
stop_daemon "${LEGACY_LAUNCHD_LABEL}" "${LEGACY_PLIST_DST}"

# ---- agent-config scrub (BEFORE we delete ~/.defenseclaw) --------------
#
# We scrub the user's native agent hook configs first so the agent doesn't
# start hitting "command not found" + fail-close every tool call the moment
# we delete ~/.defenseclaw/hooks/*-hook.sh. The scrub runs as the target
# user (drop privileges via sudo -u) so file ownership is preserved.

PY="$(command -v python3 || printf '/usr/bin/python3')"

scrub_agent_config() {
  local connector="$1"
  local cfg="$2"
  if [[ ! -f "${cfg}" ]]; then
    return 0
  fi
  if [[ ! -f "${SCRUB_PY}" ]]; then
    warn "scrub helper missing: ${SCRUB_PY}; skipping ${cfg}"
    SCRUB_FAILED="true"
    return 0
  fi
  log "  scrubbing ${connector} entries from ${cfg}"
  local rc=0
  if [[ -n "${TARGET_USER:-}" && $(id -u "${TARGET_USER}" 2>/dev/null) != "0" ]]; then
    sudo -u "${TARGET_USER}" "${PY}" "${SCRUB_PY}" "${connector}" "${cfg}" || rc=$?
  else
    "${PY}" "${SCRUB_PY}" "${connector}" "${cfg}" || rc=$?
  fi
  case "${rc}" in
    0) ;;
    2) ;;  # file missing — fine
    *)
      warn "  scrub exited ${rc} for ${cfg} (left unmodified)"
      SCRUB_FAILED="true"
      ;;
  esac
}

if [[ "${PURGE}" == "true" \
   && "${KEEP_AGENT_CONFIGS}" != "true" \
   && -n "${TARGET_HOME:-}" ]]; then
  scrub_agent_config codex      "${TARGET_HOME}/.codex/config.toml"
  scrub_agent_config claudecode "${TARGET_HOME}/.claude/settings.json"
  scrub_agent_config cursor     "${TARGET_HOME}/.cursor/hooks.json"
fi

# ---- remove files we own unconditionally --------------------------------
#
# Sweep both the current and legacy plist / binary tree.

for plist in "${PLIST_DST}" "${LEGACY_PLIST_DST}"; do
  if [[ -f "${plist}" ]]; then
    log "removing ${plist}"
    rm -f "${plist}"
  fi
done

# INSTALL_PREFIX is /opt/cisco/secureclient/defenseclaw/ — a
# DefenseClaw-owned subtree. Under the managed layout it holds bin/ AND
# etc/ + runtime/ + hook-guardian-state/. The default (non-purge)
# uninstall preserves runtime state so a reinstall keeps audit history
# (see usage text above), so on the non-purge path only the binary
# subtree is removed; the full tree drops on --purge.
#
# LEGACY_INSTALL_PREFIX is /Library/DefenseClaw/ — binary-only in the
# old layout (runtime lived under LEGACY_SUPPORT_DIR), so it's safe to
# remove wholesale in either mode.
# `${var:?}` on the rm targets is defence-in-depth against an empty/unset
# INSTALL_PREFIX after a future refactor — a bare `rm -rf /` or `rm -rf
# /bin` would be catastrophic. Shellcheck SC2115. The `[[ -d ]]` guards
# already handle the empty case at runtime, but the shell-parameter form
# turns any unset-variable slip into a hard error instead of a delete.
if [[ "${PURGE}" == "true" ]]; then
  if [[ -d "${INSTALL_PREFIX:?}" ]]; then
    log "removing ${INSTALL_PREFIX}"
    rm -rf "${INSTALL_PREFIX:?}"
  fi
elif [[ -d "${INSTALL_PREFIX:?}/bin" ]]; then
  log "removing ${INSTALL_PREFIX}/bin (runtime/config preserved for reinstall)"
  rm -rf "${INSTALL_PREFIX:?}/bin"
fi
if [[ -d "${LEGACY_INSTALL_PREFIX:?}" ]]; then
  log "removing ${LEGACY_INSTALL_PREFIX}"
  rm -rf "${LEGACY_INSTALL_PREFIX:?}"
fi

# ---- runtime state ------------------------------------------------------

if [[ "${PURGE}" == "true" ]]; then
  # SUPPORT_DIR equals INSTALL_PREFIX under the managed layout and was
  # already removed above on --purge, so we only need to sweep LOGS_DIR
  # here. For legacy installs, SUPPORT_DIR and LOGS_DIR are separate
  # trees that still need explicit removal.
  for d in "${LOGS_DIR}" "${LEGACY_SUPPORT_DIR}" "${LEGACY_LOGS_DIR}"; do
    if [[ -d "${d}" ]]; then
      log "purging ${d}"
      rm -rf "${d}"
    fi
  done

  # Modern (root-mode) installs let the managed cloud auth provider
  # create its own log file under a shared log tree; there's nothing
  # for us to sweep. But a pre-root install may have pre-created the
  # file with defenseclaw ownership, so remove it if present. Never
  # rm the parent dir — it's shared.
  CMID_LOG_FILE="/Library/Logs/Cisco/SecureClient/CloudManagement/defenseclaw-gateway_cmidapi.log"
  if [[ -f "${CMID_LOG_FILE}" ]]; then
    log "removing legacy managed-auth log file: ${CMID_LOG_FILE}"
    rm -f "${CMID_LOG_FILE}"
  fi

  # NOTE: the daemon runs as root, so no service-user cleanup is
  # necessary here. Older DefenseClaw installs (pre-root switch)
  # created a dedicated 'defenseclaw' user via sysadminctl/dseditgroup
  # + a matching group. If this uninstall runs on a machine still
  # carrying those records, sweep them so the next re-install starts
  # clean and no orphan uid remains.
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

  if [[ -n "${TARGET_USER:-}" && -n "${TARGET_HOME:-}" && -d "${TARGET_HOME}/.defenseclaw" ]]; then
    if [[ "${SCRUB_FAILED}" == "true" && "${KEEP_AGENT_CONFIGS}" != "true" ]]; then
      # We're about to delete the hook scripts, but at least one agent
      # config still references them. Deleting now would leave every
      # future agent tool call fail-closed (exit 127 → block). Refuse
      # rather than paint the operator into that corner.
      die "one or more agent-config scrubs failed; refusing to delete ${TARGET_HOME}/.defenseclaw (rerun with --keep-agent-configs to force the delete, then repair or reinstall)"
    fi
    log "purging ${TARGET_HOME}/.defenseclaw"
    rm -rf "${TARGET_HOME}/.defenseclaw"
    if [[ "${KEEP_AGENT_CONFIGS}" == "true" ]]; then
      warn "--keep-agent-configs: agent configs still reference deleted hook scripts."
      warn "  agents will fail-close every tool call until reinstall or manual edit."
      for cfg in "${TARGET_HOME}/.codex/config.toml" \
                 "${TARGET_HOME}/.claude/settings.json" \
                 "${TARGET_HOME}/.cursor/hooks.json"; do
        [[ -f "${cfg}" ]] && warn "    ${cfg}"
      done
    fi
  fi
else
  log "preserving ${SUPPORT_DIR} (config + audit DB)"
  log "preserving ${LOGS_DIR}"
  log "  (re-run with --purge to delete these and clean up per-user state)"
fi

# ---- sanity check -------------------------------------------------------

REMAINING=()
[[ -e "${PLIST_DST}" ]]              && REMAINING+=("${PLIST_DST}")
[[ -e "${LEGACY_PLIST_DST}" ]]       && REMAINING+=("${LEGACY_PLIST_DST}")
[[ -e "${INSTALL_PREFIX}" ]]         && REMAINING+=("${INSTALL_PREFIX}")
[[ -e "${LEGACY_INSTALL_PREFIX}" ]]  && REMAINING+=("${LEGACY_INSTALL_PREFIX}")
if [[ "${PURGE}" == "true" ]]; then
  [[ -e "${LOGS_DIR}" ]]         && REMAINING+=("${LOGS_DIR}")
  [[ -e "${LEGACY_SUPPORT_DIR}" ]] && REMAINING+=("${LEGACY_SUPPORT_DIR}")
  [[ -e "${LEGACY_LOGS_DIR}" ]]    && REMAINING+=("${LEGACY_LOGS_DIR}")
  [[ -n "${TARGET_HOME:-}" && -e "${TARGET_HOME}/.defenseclaw" ]] && REMAINING+=("${TARGET_HOME}/.defenseclaw")
fi
if (( ${#REMAINING[@]} > 0 )); then
  warn "the following paths still exist (manual cleanup needed):"
  printf '  - %s\n' "${REMAINING[@]}" >&2
  exit 1
fi

log "done."
