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
# Note: the user's native agent config files (~/.codex/config.toml,
# ~/.claude/settings.json, ~/.cursor/hooks.json) are NOT touched even on
# --purge because they may contain non-DefenseClaw entries the user owns.
# Those files will still contain DefenseClaw hook entries pointing at
# missing scripts — the user can re-run install, or remove those entries
# by hand.

set -euo pipefail

INSTALL_PREFIX="/Library/DefenseClaw"
SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LOGS_DIR="/Library/Logs/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LAUNCHD_LABEL="com.defenseclaw.gateway"

PURGE="false"
ASSUME_YES="false"
TARGET_USER=""

# ---- helpers ------------------------------------------------------------

log()  { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARN: %s\n' "$*" >&2; }
die()  { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Options:
  --purge      Also delete:
                 ${SUPPORT_DIR}  (config + audit DB)
                 ${LOGS_DIR}                       (gateway logs)
                 ~/.defenseclaw/ for the invoking user (hook scripts)
  --user USER  Per-user cleanup target for --purge (default: \$SUDO_USER)
  -y, --yes    Don't prompt for --purge confirmation
  -h, --help   Show this help

Default behavior preserves runtime state so reinstall keeps audit history.
EOF
}

# ---- arg parsing --------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)  PURGE="true"; shift;;
    --user)   TARGET_USER="${2:?}"; shift 2;;
    -y|--yes) ASSUME_YES="true"; shift;;
    -h|--help) usage; exit 0;;
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
  fi
  if [[ "${ASSUME_YES}" != "true" ]]; then
    printf '[uninstall] --purge will DELETE:\n'
    printf '  %s\n' "${SUPPORT_DIR}" "${LOGS_DIR}"
    [[ -n "${TARGET_USER:-}" && -n "${TARGET_HOME:-}" ]] && \
      printf '  %s/.defenseclaw/\n' "${TARGET_HOME}"
    printf '[uninstall] type yes to continue: '
    read -r REPLY
    [[ "${REPLY}" == "yes" ]] || die "purge declined"
  fi
fi

# ---- stop the daemon ----------------------------------------------------

if launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
  log "stopping LaunchDaemon (${LAUNCHD_LABEL})"
  launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || \
    launchctl bootout system "${PLIST_DST}" 2>/dev/null || \
    warn "bootout failed; the daemon may already be stopped"
else
  log "daemon not loaded; skipping bootout"
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

  if [[ -n "${TARGET_USER:-}" && -n "${TARGET_HOME:-}" && -d "${TARGET_HOME}/.defenseclaw" ]]; then
    log "purging ${TARGET_HOME}/.defenseclaw"
    rm -rf "${TARGET_HOME}/.defenseclaw"
    warn "your native agent configs still contain DefenseClaw hook entries:"
    for cfg in "${TARGET_HOME}/.codex/config.toml" "${TARGET_HOME}/.claude/settings.json" "${TARGET_HOME}/.cursor/hooks.json"; do
      [[ -f "${cfg}" ]] && warn "  ${cfg}"
    done
    warn "  (the hook scripts they reference are now gone; remove the entries"
    warn "   by hand or just re-run install.sh to overwrite them with valid wiring)"
  fi
else
  log "preserving ${SUPPORT_DIR} (config + audit DB)"
  log "preserving ${LOGS_DIR}"
  log "  (re-run with --purge to delete these and per-user ~/.defenseclaw)"
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
