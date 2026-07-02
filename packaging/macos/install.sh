#!/usr/bin/env bash
#
# DefenseClaw macOS installer (managed_enterprise + LaunchDaemon + per-user
# hook wiring via the enterprise hook guardian).
#
# System layout (root-owned):
#   /Library/DefenseClaw/bin/defenseclaw-gateway          (root:wheel 0755)
#   /Library/LaunchDaemons/com.defenseclaw.gateway.plist  (root:wheel 0644)
#   /Library/Application Support/DefenseClaw/             (root:wheel 0750)
#     config.yaml                                         (root:wheel 0640)
#   /Library/Logs/DefenseClaw/                            (root:wheel 0750)
#
# Per-user (target-user-owned, written by the guardian dropping euid/egid):
#   ~/.<agent>/<hook-config-file>                          (target-user 0600)
#   ~/.defenseclaw/hooks/<connector>-hook.sh               (target-user 0700)
#
# This script orchestrates side-effecting steps (sudo, launchctl, install(8))
# and delegates pure logic (arg parsing, config rendering, version probing,
# userspace prep) to lib/installer_lib.sh so the test suite under tests/
# can drive that logic without root.

set -euo pipefail

# ---- defaults -----------------------------------------------------------

DEFAULT_MODE="observe"
DEFAULT_CONNECTOR="codex"
DEFAULT_API_PORT="18970"
DISABLE_REDACTION="false"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY_SRC=""
PLIST_SRC="${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"
SKIP_BUILD="false"
SKIP_LAUNCHD="false"
SKIP_CONNECTOR="false"

INSTALL_PREFIX="/Library/DefenseClaw"
SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LOGS_DIR="/Library/Logs/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LAUNCHD_LABEL="com.defenseclaw.gateway"
GATEWAY_BIN="${INSTALL_PREFIX}/bin/defenseclaw-gateway"

TARGET_USER=""
AGENT_VERSION=""

# ---- helpers ------------------------------------------------------------

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

# shellcheck source=lib/installer_lib.sh
. "${SCRIPT_DIR}/lib/installer_lib.sh"

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Gateway options:
  --mode {observe|action}   Guardrail + asset_policy mode (default: ${DEFAULT_MODE})
  --connector LIST          Hook connector(s), comma-separated (default: ${DEFAULT_CONNECTOR})
                            Supported: codex, claudecode, cursor
                            Examples: --connector cursor
                                      --connector cursor,claudecode
  --port PORT               Loopback API port (default: ${DEFAULT_API_PORT})
  --redact                  Enable redaction in audit/sinks (default: on)
  --no-redact               Disable redaction in audit/sinks
  --binary PATH             Use prebuilt binary instead of 'go build'
  --skip-build              Reuse ./defenseclaw-gateway in the repo (no rebuild)
  --skip-launchd            Install files but don't bootstrap/enable launchd

Per-user hook wiring:
  --user USER               Target macOS user (default: \$SUDO_USER)
  --agent-version VERSION   Override agent version (auto-detected if omitted)
  --skip-connector          Don't wire user-space hooks (gateway only)

  -h, --help                Show this help

EOF
}

# ---- arg parsing --------------------------------------------------------

MODE="${DEFAULT_MODE}"
CONNECTOR="${DEFAULT_CONNECTOR}"
API_PORT="${DEFAULT_API_PORT}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)             MODE="${2:?}"; shift 2;;
    --connector)        CONNECTOR="${2:?}"; shift 2;;
    --port)             API_PORT="${2:?}"; shift 2;;
    --redact)           DISABLE_REDACTION="false"; shift;;
    --no-redact)        DISABLE_REDACTION="true"; shift;;
    --binary)           BINARY_SRC="${2:?}"; SKIP_BUILD="true"; shift 2;;
    --skip-build)       SKIP_BUILD="true"; shift;;
    --skip-launchd)     SKIP_LAUNCHD="true"; shift;;
    --user)             TARGET_USER="${2:?}"; shift 2;;
    --agent-version)    AGENT_VERSION="${2:?}"; shift 2;;
    --skip-connector)   SKIP_CONNECTOR="true"; shift;;
    -h|--help)          usage; exit 0;;
    *) die "unknown flag: $1 (try --help)";;
  esac
done

case "${MODE}" in
  observe|action) ;;
  *) die "--mode must be 'observe' or 'action' (got: ${MODE})";;
esac

CONNECTOR_LINES="$(parse_connectors "${CONNECTOR}")" || \
  die "--connector has an empty entry (check the comma list)"
CONNECTORS=()
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  CONNECTORS+=("${line}")
done <<< "${CONNECTOR_LINES}"
[[ ${#CONNECTORS[@]} -gt 0 ]] || die "--connector produced no entries"
PRIMARY_CONNECTOR="${CONNECTORS[0]}"

for c in "${CONNECTORS[@]}"; do
  if ! is_supported_connector "${c}"; then
    warn "connector '${c}' is not in the auto-wire list (codex|claudecode|cursor); will be written to config but per-user hooks won't be auto-wired"
  fi
done

# ---- preflight ----------------------------------------------------------

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (uname -s != Darwin)"
[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 $*)"
[[ -f "${PLIST_SRC}" ]] || die "missing plist source: ${PLIST_SRC}"

# Resolve target user (default: the user who invoked sudo)
if [[ -z "${TARGET_USER}" ]]; then
  TARGET_USER="${SUDO_USER:-}"
fi
if [[ -z "${TARGET_USER}" && "${SKIP_CONNECTOR}" != "true" ]]; then
  warn "no target user (run with sudo from a user shell, or pass --user); skipping per-user hook wiring"
  SKIP_CONNECTOR="true"
fi
if [[ -n "${TARGET_USER}" ]]; then
  TARGET_HOME="$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  [[ -n "${TARGET_HOME}" && -d "${TARGET_HOME}" ]] || \
    die "could not resolve home for --user ${TARGET_USER}"
fi

# Resolve the binary
if [[ -z "${BINARY_SRC}" ]]; then
  BINARY_SRC="${REPO_ROOT}/defenseclaw-gateway"
fi
if [[ "${SKIP_BUILD}" != "true" && ! -x "${BINARY_SRC}" ]]; then
  command -v go >/dev/null 2>&1 || die "go not in PATH; install Go or pass --binary"
  log "building gateway from ${REPO_ROOT}/cmd/defenseclaw"
  ( cd "${REPO_ROOT}" && go build -o defenseclaw-gateway ./cmd/defenseclaw )
fi
[[ -x "${BINARY_SRC}" ]] || die "binary not found or not executable: ${BINARY_SRC}"

# Refuse to clobber a running install silently
if launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
  warn "${LAUNCHD_LABEL} is currently loaded — bootouting before reinstall"
  launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || true
  launchctl bootout system "${PLIST_DST}" 2>/dev/null || true
fi

# ---- gateway file install ----------------------------------------------

log "installing binary -> ${GATEWAY_BIN}"
install -d -o root -g wheel -m 0755 "${INSTALL_PREFIX}/bin"
install    -o root -g wheel -m 0755 "${BINARY_SRC}" "${GATEWAY_BIN}"

log "creating support dirs"
install -d -o root -g wheel -m 0750 "${SUPPORT_DIR}"
install -d -o root -g wheel -m 0750 "${LOGS_DIR}"

CONFIG_PATH="${SUPPORT_DIR}/config.yaml"
if [[ -f "${CONFIG_PATH}" ]]; then
  BACKUP="${CONFIG_PATH}.$(date +%Y%m%d-%H%M%S).bak"
  cp -p "${CONFIG_PATH}" "${BACKUP}"
  log "backed up existing config to ${BACKUP}"
fi

log "writing config (mode=${MODE} connectors=${CONNECTORS[*]} port=${API_PORT} redaction_off=${DISABLE_REDACTION})"
render_config "${MODE}" "${PRIMARY_CONNECTOR}" "${API_PORT}" "${DISABLE_REDACTION}" "${SUPPORT_DIR}" "${CONNECTORS[@]}" > "${CONFIG_PATH}"
chown root:wheel "${CONFIG_PATH}"
chmod 0640 "${CONFIG_PATH}"

log "installing LaunchDaemon plist -> ${PLIST_DST}"
install -o root -g wheel -m 0644 "${PLIST_SRC}" "${PLIST_DST}"

if [[ "${SKIP_LAUNCHD}" == "true" ]]; then
  log "skipping launchctl bootstrap (--skip-launchd)"
  exit 0
fi

# ---- launchd ------------------------------------------------------------

log "loading LaunchDaemon"
launchctl bootstrap system "${PLIST_DST}"
launchctl enable "system/${LAUNCHD_LABEL}"

log "waiting for gateway to come up"
SETTLE_DEADLINE=$(( $(date +%s) + 15 ))
while (( $(date +%s) < SETTLE_DEADLINE )); do
  if launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | grep -qE '^[[:space:]]+state = running'; then
    break
  fi
  sleep 1
done

# ---- per-user hook wiring ----------------------------------------------

if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  log "wiring user-space hooks for ${TARGET_USER} (${CONNECTORS[*]})"
  TARGET_UID="$(id -u "${TARGET_USER}")"
  TARGET_GID="$(id -g "${TARGET_USER}")"

  if ! home_perms_ok "${TARGET_HOME}"; then
    HOME_MODE="$(stat -f '%Lp' "${TARGET_HOME}" 2>/dev/null || echo '?')"
    warn "home directory ${TARGET_HOME} is group/other writable (mode ${HOME_MODE})"
    warn "  the enterprise hook guardian will refuse to write into a loose home;"
    warn "  this is an administrator responsibility to fix. Suggested:"
    warn "    sudo chmod 0755 ${TARGET_HOME}"
    warn "  skipping user-space hook wiring. Gateway is still running."
    warn "  after fixing perms, finish wiring per-connector with:"
    for c in "${CONNECTORS[@]}"; do
      warn "    sudo DEFENSECLAW_CONFIG=\"${CONFIG_PATH}\" ${GATEWAY_BIN} enterprise hooks install --connector ${c} --user ${TARGET_USER} --agent-version 'X.Y.Z' --json"
    done
    SKIP_CONNECTOR="true"
  fi
fi

if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  # The CLI subcommand opens the audit DB writer; pause the daemon once,
  # run every per-connector install, then resume.
  log "  pausing LaunchDaemon (CLI subcommands hold the audit DB lock)"
  launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -fl "${GATEWAY_BIN}" >/dev/null 2>&1 || break
    sleep 1
  done

  for c in "${CONNECTORS[@]}"; do
    if ! is_supported_connector "${c}"; then
      log "  skipping unsupported connector ${c} (no userspace wiring)"
      continue
    fi

    log "  [${c}] preparing userspace"
    prepare_userspace_for "${c}" "${TARGET_HOME}"
    # Match the ownership of any newly created files to the target user.
    chown -R "${TARGET_UID}:${TARGET_GID}" \
      "${TARGET_HOME}/.${c%code}" 2>/dev/null || true
    # Special-case naming (claudecode -> .claude, codex -> .codex, cursor -> .cursor).
    case "${c}" in
      claudecode) chown -R "${TARGET_UID}:${TARGET_GID}" "${TARGET_HOME}/.claude" 2>/dev/null || true;;
      codex)      chown -R "${TARGET_UID}:${TARGET_GID}" "${TARGET_HOME}/.codex"  2>/dev/null || true;;
      cursor)     chown -R "${TARGET_UID}:${TARGET_GID}" "${TARGET_HOME}/.cursor" 2>/dev/null || true;;
    esac

    AGENT_VER="${AGENT_VERSION}"
    if [[ -z "${AGENT_VER}" ]]; then
      AGENT_VER="$(discover_agent_version "${c}" "${TARGET_HOME}" || true)"
    fi
    if [[ -z "${AGENT_VER}" ]]; then
      warn "  [${c}] could not auto-detect agent version; skipping. Resume with:"
      warn "    sudo DEFENSECLAW_CONFIG=\"${CONFIG_PATH}\" ${GATEWAY_BIN} enterprise hooks install --connector ${c} --user ${TARGET_USER} --agent-version 'X.Y.Z' --json"
      continue
    fi

    log "  [${c}] detected agent_version: ${AGENT_VER}"
    log "  [${c}] running: enterprise hooks install --connector ${c} --user ${TARGET_USER}"
    if DEFENSECLAW_CONFIG="${CONFIG_PATH}" "${GATEWAY_BIN}" enterprise hooks install \
         --connector "${c}" \
         --user "${TARGET_USER}" \
         --agent-version "${AGENT_VER}" \
         --json; then
      log "  [${c}] hook wiring OK"
    else
      warn "  [${c}] hook wiring failed; see JSON output above"
    fi
  done

  log "  resuming LaunchDaemon"
  launchctl bootstrap system "${PLIST_DST}"
  launchctl enable "system/${LAUNCHD_LABEL}"
  SETTLE_DEADLINE=$(( $(date +%s) + 15 ))
  while (( $(date +%s) < SETTLE_DEADLINE )); do
    if launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | grep -qE '^[[:space:]]+state = running'; then
      break
    fi
    sleep 1
  done
fi

# ---- summary ------------------------------------------------------------

cat <<EOF

[install] done.

Next steps:
  Gateway status:
    sudo DEFENSECLAW_CONFIG="${CONFIG_PATH}" ${GATEWAY_BIN} status

  Tail logs:
    sudo tail -f ${LOGS_DIR}/gateway.log ${LOGS_DIR}/gateway.err.log

  Query audit DB:
    sudo sqlite3 -header -column "${SUPPORT_DIR}/audit.db" \\
      "SELECT datetime(timestamp,'localtime'),action,severity,substr(details,1,80) \\
       FROM audit_events ORDER BY timestamp DESC LIMIT 10;"

  Master gateway token (for direct curl tests):
    sudo grep DEFENSECLAW_GATEWAY_TOKEN "${SUPPORT_DIR}/.env"

  Repair user-space hooks (per connector):
$(for c in "${CONNECTORS[@]}"; do
    printf '    sudo DEFENSECLAW_CONFIG="%s" %s enterprise hooks install --connector %s --user %s --agent-version "X.Y.Z" --json\n' \
      "${CONFIG_PATH}" "${GATEWAY_BIN}" "${c}" "${TARGET_USER:-USER}"
  done)

  Uninstall:
    sudo ${SCRIPT_DIR}/uninstall.sh
EOF
