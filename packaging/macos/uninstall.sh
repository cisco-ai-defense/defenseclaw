#!/usr/bin/env bash
#
# DefenseClaw macOS uninstaller.
#
# Removes:
#   - LaunchDaemon (com.defenseclaw.gateway)
#   - /Library/DefenseClaw/  (binary)
#   - /Library/LaunchDaemons/com.defenseclaw.gateway.plist
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

INSTALL_PREFIX="/Library/DefenseClaw"
SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LOGS_DIR="/Library/Logs/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LAUNCHD_LABEL="com.defenseclaw.gateway"
SERVICE_USER_DEFAULT="defenseclaw"
# Names we recognize as DefenseClaw-owned and safe to auto-delete on
# --purge. Matches the hostname the gateway binary hardcodes in
# trustedRuntimeOwner (see internal/managed/trust_unix.go).
SERVICE_USER_KNOWN=(defenseclaw)

PURGE="false"
ASSUME_YES="false"
TARGET_USER=""
KEEP_AGENT_CONFIGS="false"
SCRUB_FAILED="false"
SERVICE_USER=""

# ---- helpers ------------------------------------------------------------

log()  { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARN: %s\n' "$*" >&2; }
die()  { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Options:
  --purge               Also delete:
                          ${SUPPORT_DIR}  (config + audit DB)
                          ${LOGS_DIR}                       (gateway logs)
                          ~/.defenseclaw/ for the target user (hook scripts)
                          /Users/defenseclaw + /Groups/defenseclaw dscl
                              records (service principal — deleted even if
                              only half-provisioned by a prior failed run)
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
  --service-user NAME   macOS service user to delete on --purge
                        (default: read from the installed plist, else defenseclaw)
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
    --service-user)        SERVICE_USER="${2:?}"; shift 2;;
    -y|--yes)              ASSUME_YES="true"; shift;;
    -h|--help)             usage; exit 0;;
    *) die "unknown flag: $1 (try --help)";;
  esac
done

# Resolve which service user to delete on --purge. Precedence:
#   1. --service-user flag
#   2. UserName in the installed plist (matches whatever install.sh set)
#   3. _defenseclaw default
if [[ -z "${SERVICE_USER}" ]]; then
  if [[ -f "${PLIST_DST}" ]]; then
    SERVICE_USER="$(/usr/bin/plutil -extract UserName raw "${PLIST_DST}" 2>/dev/null || true)"
  fi
  SERVICE_USER="${SERVICE_USER:-${SERVICE_USER_DEFAULT}}"
fi

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

# ---- stop the daemon ----------------------------------------------------

if launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
  log "stopping LaunchDaemon (${LAUNCHD_LABEL})"
  # Try both bootout forms (target vs plist path); either works and
  # both are safe when the target is already gone.
  launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || \
    launchctl bootout system "${PLIST_DST}" 2>/dev/null || \
    warn "bootout failed; the daemon may already be stopped"

  # Wait briefly for launchd to fully release the service so a
  # subsequent install can bootstrap without seeing "already loaded".
  settle=0
  while (( settle < 5 )); do
    launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || break
    sleep 1
    settle=$((settle + 1))
  done
else
  log "daemon not loaded; skipping bootout"
fi

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

if [[ -f "${PLIST_DST}" ]]; then
  log "removing ${PLIST_DST}"
  rm -f "${PLIST_DST}"
fi

if [[ -d "${INSTALL_PREFIX}" ]]; then
  log "removing ${INSTALL_PREFIX}"
  rm -rf "${INSTALL_PREFIX}"
fi

# ---- runtime state ------------------------------------------------------

if [[ "${PURGE}" == "true" ]]; then
  for d in "${SUPPORT_DIR}" "${LOGS_DIR}"; do
    if [[ -d "${d}" ]]; then
      log "purging ${d}"
      rm -rf "${d}"
    fi
  done

  # Remove the service user + group if it looks like a DefenseClaw-created
  # one (prefixed with an underscore per the install.sh convention). We
  # refuse to delete an unprefixed name — an admin who used a custom
  # unprefixed user probably shares it with another service.
  #
  # Delete both /Users and /Groups records regardless of which reads
  # succeed. Prior failed installs can leave a half-provisioned record
  # (e.g. record exists with no PrimaryGroupID) where dscl -read fails
  # but the record still needs cleanup — so we delete unconditionally
  # when the name is underscore-prefixed.
  #
  # Pin to /Local/Default like install.sh does. Otherwise a Mac bound to
  # an unreachable network directory (AD/LDAP/managed OD) can hang or
  # ENETUNREACH us on the read/delete calls.
  # Auto-delete only if the service user matches one of our known
  # installer names — never delete a random admin-configured user
  # sharing the SERVICE_USER slot.
  is_known="no"
  for known in "${SERVICE_USER_KNOWN[@]}"; do
    if [[ "${SERVICE_USER}" == "${known}" ]]; then
      is_known="yes"; break
    fi
  done
  if [[ -n "${SERVICE_USER}" && "${is_known}" == "yes" ]]; then
    # SIP protects /var/db/dslocal, so `rm plist` returns "Operation
    # not permitted" even for root. Use the SIP-safe official tools:
    # dseditgroup for groups, sysadminctl for users. Both route through
    # opendirectoryd's authenticated API and atomically clean up the
    # on-disk plists.
    removed_any=no

    if dscl /Local/Default -read "/Groups/${SERVICE_USER}" >/dev/null 2>&1; then
      log "removing group ${SERVICE_USER} via dseditgroup"
      /usr/sbin/dseditgroup -o delete "${SERVICE_USER}" >/dev/null 2>&1 && \
        removed_any=yes || warn "dseditgroup delete ${SERVICE_USER} failed"
    fi
    if dscl /Local/Default -read "/Users/${SERVICE_USER}" >/dev/null 2>&1; then
      log "removing user ${SERVICE_USER} via sysadminctl"
      /usr/sbin/sysadminctl -deleteUser "${SERVICE_USER}" >/dev/null 2>&1 && \
        removed_any=yes || warn "sysadminctl deleteUser ${SERVICE_USER} failed"
    fi

    if [[ "${removed_any}" == "yes" ]]; then
      log "removed ${SERVICE_USER} service principal"
    else
      log "no ${SERVICE_USER} records to remove"
    fi
  elif [[ -n "${SERVICE_USER}" ]]; then
    warn "service user '${SERVICE_USER}' is not one of the known DefenseClaw installer names (${SERVICE_USER_KNOWN[*]}); refusing to auto-delete"
    warn "  delete it manually if it was created for DefenseClaw:"
    warn "    sudo dscl /Local/Default -delete /Users/${SERVICE_USER}"
    warn "    sudo dscl /Local/Default -delete /Groups/${SERVICE_USER}"
  fi

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
[[ -e "${PLIST_DST}" ]]      && REMAINING+=("${PLIST_DST}")
[[ -e "${INSTALL_PREFIX}" ]] && REMAINING+=("${INSTALL_PREFIX}")
if [[ "${PURGE}" == "true" ]]; then
  [[ -e "${SUPPORT_DIR}" ]] && REMAINING+=("${SUPPORT_DIR}")
  [[ -e "${LOGS_DIR}" ]]    && REMAINING+=("${LOGS_DIR}")
  [[ -n "${TARGET_HOME:-}" && -e "${TARGET_HOME}/.defenseclaw" ]] && REMAINING+=("${TARGET_HOME}/.defenseclaw")
fi
if (( ${#REMAINING[@]} > 0 )); then
  warn "the following paths still exist (manual cleanup needed):"
  printf '  - %s\n' "${REMAINING[@]}" >&2
  exit 1
fi

log "done."
