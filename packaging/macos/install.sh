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
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd 2>/dev/null || echo "${SCRIPT_DIR}")"
BINARY_SRC=""
# Plist lookup order:
#   1. --plist / DEFENSECLAW_PLIST_SRC  (explicit override)
#   2. next to the script            (standalone-bundle layout)
#   3. under the repo tree           (dev-tree layout)
PLIST_SRC=""
for _candidate in \
  "${DEFENSECLAW_PLIST_SRC:-}" \
  "${SCRIPT_DIR}/com.defenseclaw.gateway.plist" \
  "${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"; do
  if [[ -n "${_candidate}" && -f "${_candidate}" ]]; then
    PLIST_SRC="${_candidate}"
    break
  fi
done
unset _candidate
SKIP_BUILD="false"
SKIP_LAUNCHD="false"
SKIP_CONNECTOR="false"

INSTALL_PREFIX="/Library/DefenseClaw"
SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LOGS_DIR="/Library/Logs/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LAUNCHD_LABEL="com.defenseclaw.gateway"
GATEWAY_BIN="${INSTALL_PREFIX}/bin/defenseclaw-gateway"

# macOS convention is a hidden system user prefixed with an underscore.
# We create this if it doesn't exist. Admins can override via
# --service-user; the plist we ship gets rewritten to match.
SERVICE_USER="_defenseclaw"
SERVICE_GROUP="_defenseclaw"

TARGET_USER=""
AGENT_VERSION=""

# ---- helpers ------------------------------------------------------------

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

# find_free_system_uid — returns an unused UID in the System range so we
# don't collide with an admin's existing service user. macOS reserves
# < 500 for the OS; we scan 400..499 and pick the first free slot.
#
# Uses a single `dscl -list` to enumerate all in-use UIDs, which is much
# faster than issuing 100 -search calls. On a laptop with a network
# directory attached, the per-candidate probe form could take 30s+.
find_free_system_uid() {
  local in_use
  # Query /Local/Default explicitly — using `.` (the meta-node) makes
  # dscl walk every attached directory (AD/LDAP/OD), which can hang or
  # return ENETUNREACH on a Mac bound to an unreachable domain. Service
  # users only ever live in /Local/Default, so this is both faster and
  # safer.
  in_use="$(dscl /Local/Default -list /Users UniqueID 2>/dev/null | awk '{print $2}')"
  local candidate
  for candidate in $(seq 400 499); do
    if ! printf '%s\n' "${in_use}" | grep -qxF "${candidate}"; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

# DS_NODE is the dscl node the service-user helpers target.
#
# We deliberately pin to /Local/Default instead of the meta-node `.` so
# that a Mac bound to an unreachable network directory (AD / LDAP /
# managed OD) doesn't hang or ENETUNREACH us during install. Service
# users always live in the local node — network directory users would
# never be candidates for the DefenseClaw daemon principal.
DS_NODE="/Local/Default"

# dscl_read_prop RECORD PROP — echoes the value of a single dscl property
# or empty when the record/property doesn't exist. Handles the "AttrName:
# value" one-liner shape dscl -read returns.
#
# NOTE: we swallow non-zero from `dscl -read` (record-not-found returns
# rc=1) so this helper is safe to use inside command substitutions under
# `set -o pipefail`. Callers check the returned value for emptiness.
dscl_read_prop() {
  local record="$1"
  local prop="$2"
  local raw
  raw="$(dscl "${DS_NODE}" -read "${record}" "${prop}" 2>/dev/null || true)"
  printf '%s\n' "${raw}" \
    | awk -v p="${prop}:" 'index($0, p) == 1 { $1=""; sub(/^ /, ""); print; exit }'
  return 0
}

# dscl_ensure_record RECORD — creates a dscl record idempotently.
# `dscl -create` will return eDSRecordAlreadyExists when the record is
# already there; that's exactly the state we want, so we treat it as
# success. Any other error is fatal. macOS's OpenDirectory can also be
# temporarily inconsistent (a -read says "not there" while a subsequent
# -create says "already there") for a few seconds after a prior create,
# so this helper is more reliable than gating on -read.
dscl_ensure_record() {
  local record="$1"
  local err
  err="$(dscl "${DS_NODE}" -create "${record}" 2>&1)"
  local rc=$?
  if (( rc == 0 )); then
    return 0
  fi
  if [[ "${err}" == *eDSRecordAlreadyExists* ]]; then
    return 0
  fi
  printf '%s\n' "${err}" >&2
  return "${rc}"
}

# dscl_ensure_prop RECORD PROP VALUE — sets a property on a dscl record
# to a specific value, treating "already has this exact value" as success.
#
# We try `-create` first with fallback to `-change`: on some macOS
# versions `dscl -create record prop value` returns eDSRecordAlreadyExists
# when the record itself already exists (even though the property might
# be unset), so we can't rely on read-then-create-or-change. Instead:
#
#   1. If the current value already matches, no-op.
#   2. Otherwise try `-create`. Success → done.
#   3. If -create failed with eDSRecordAlreadyExists, use `-change`.
#      -change tolerates a missing old value by passing empty.
dscl_ensure_prop() {
  local record="$1"
  local prop="$2"
  local value="$3"
  local current
  current="$(dscl_read_prop "${record}" "${prop}")"
  if [[ "${current}" == "${value}" ]]; then
    return 0
  fi

  local err rc=0
  err="$(dscl "${DS_NODE}" -create "${record}" "${prop}" "${value}" 2>&1)" || rc=$?
  if (( rc == 0 )); then
    return 0
  fi

  if [[ "${err}" == *eDSRecordAlreadyExists* ]]; then
    # Record already exists. The property may or may not be present.
    # Try -change first (works when the attribute is already there); if
    # dscl reports eDSAttributeNotFound, fall back to -append.
    local err2 rc2=0
    err2="$(dscl "${DS_NODE}" -change "${record}" "${prop}" "${current}" "${value}" 2>&1)" || rc2=$?
    if (( rc2 == 0 )); then
      return 0
    fi
    if [[ "${err2}" == *eDSAttributeNotFound* ]]; then
      dscl "${DS_NODE}" -append "${record}" "${prop}" "${value}"
      return $?
    fi
    printf '%s\n' "${err2}" >&2
    return "${rc2}"
  fi

  printf '%s\n' "${err}" >&2
  return "${rc}"
}

# ensure_service_user NAME — idempotently creates a hidden macOS system
# user + group so the LaunchDaemon has a real principal to drop into.
# Handles three states cleanly:
#   1. Neither user nor group exist        → create both, sharing a fresh UID
#   2. Group exists (orphan from a prior)  → adopt its existing GID for the user
#   3. Both exist                          → no-op, just log
#
# Uses Apple's convention for hidden system users: '_' prefix, /var/empty
# home, /usr/bin/false shell, IsHidden=1.
# SERVICE_UID / SERVICE_GID are populated by ensure_service_user for
# downstream chown calls. macOS's userdb cache can lag several seconds
# behind OpenDirectory after a `dscl -create`, so using numeric IDs is
# more reliable than relying on getpwnam/getgrnam right after creation.
SERVICE_UID=""
SERVICE_GID=""

# wait_for_id_resolves NAME [max_seconds] — polls until getpwnam sees the
# user in the running process's cache, up to max_seconds. Returns 0 on
# resolution, non-zero on timeout.
wait_for_id_resolves() {
  local name="$1"
  local max="${2:-5}"
  local deadline=$(( $(date +%s) + max ))
  while (( $(date +%s) < deadline )); do
    if id -u "${name}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

ensure_service_user() {
  local name="$1"

  # Detect a corrupt half-state from a prior failed install: dscl says
  # the record exists (-create → eDSRecordAlreadyExists) but its
  # PrimaryGroupID/UniqueID is neither readable (-read empty) nor
  # settable (-change → eDSAttributeNotFound, -append → also
  # eDSRecordAlreadyExists). This can happen when opendirectoryd's
  # in-memory state got out of sync with the on-disk /var/db/dslocal
  # plist during a prior interrupted install.
  #
  # Recovery: use sysadminctl -deleteUser / dscl -delete to hard-reset
  # BOTH records, then flush opendirectoryd's cache so subsequent
  # dscl -create calls see a clean slate.
  local existing_gid existing_uid
  existing_gid="$(dscl_read_prop "/Groups/${name}" PrimaryGroupID)"
  existing_uid="$(dscl_read_prop "/Users/${name}"  UniqueID)"

  local user_shell_present group_shell_present
  dscl "${DS_NODE}" -read "/Users/${name}"  >/dev/null 2>&1 && user_shell_present=yes  || user_shell_present=no
  dscl "${DS_NODE}" -read "/Groups/${name}" >/dev/null 2>&1 && group_shell_present=yes || group_shell_present=no

  local needs_reset=no
  if [[ "${user_shell_present}" == "yes" && -z "${existing_uid}" ]]; then
    log "  user ${name} record present but UniqueID missing; hard-resetting"
    needs_reset=yes
  fi
  if [[ "${group_shell_present}" == "yes" && -z "${existing_gid}" ]]; then
    log "  group ${name} record present but PrimaryGroupID missing; hard-resetting"
    needs_reset=yes
  fi

  if [[ "${needs_reset}" == "yes" ]]; then
    # sysadminctl is macOS's higher-level user API; it handles the
    # cache/plist synchronization more reliably than raw dscl.
    if [[ "${user_shell_present}" == "yes" ]]; then
      /usr/sbin/sysadminctl -deleteUser "${name}" 2>/dev/null || \
        dscl "${DS_NODE}" -delete "/Users/${name}" 2>/dev/null || true
    fi
    if [[ "${group_shell_present}" == "yes" ]]; then
      # No sysadminctl equivalent for groups; use dscl directly.
      dscl "${DS_NODE}" -delete "/Groups/${name}" 2>/dev/null || true
    fi

    # Flush opendirectoryd's cache so subsequent dscl calls don't see
    # the phantom record we just deleted.
    /usr/bin/dscacheutil -flushcache 2>/dev/null || true
    /usr/bin/killall -HUP opendirectoryd 2>/dev/null || true
    sleep 1

    # Reset the state trackers so the fresh-provision path runs.
    existing_gid=""
    existing_uid=""

    # If the record STILL exists after all that, the plist file
    # itself is corrupt. Bail with an actionable message rather than
    # loop forever.
    if dscl "${DS_NODE}" -read "/Users/${name}"  >/dev/null 2>&1 || \
       dscl "${DS_NODE}" -read "/Groups/${name}" >/dev/null 2>&1; then
      die "cannot reset corrupt ${name} records — manually run:
    sudo dscl /Local/Default -delete /Users/${name}
    sudo dscl /Local/Default -delete /Groups/${name}
    sudo rm -f /var/db/dslocal/nodes/Default/users/${name}.plist
    sudo rm -f /var/db/dslocal/nodes/Default/groups/${name}.plist
    sudo killall -HUP opendirectoryd
    ...then re-run install.sh"
    fi
  fi

  # Decide the id to use:
  #   - reuse an existing UID/GID whenever we have one (avoids fighting
  #     OD if either record is present)
  #   - otherwise, allocate a free UID and use it for both
  local uid=""
  if [[ -n "${existing_gid}" ]]; then
    uid="${existing_gid}"
    log "  reusing existing gid=${uid}"
  elif [[ -n "${existing_uid}" ]]; then
    uid="${existing_uid}"
    log "  reusing existing uid=${uid}"
  else
    log "  scanning UIDs 400..499 for a free slot"
    uid="$(find_free_system_uid)" \
      || die "no free UID in 400..499 for service user ${name}"
    log "  picked free uid=${uid}"
  fi

  log "  ensuring group ${name} (gid=${uid})"
  dscl_ensure_record "/Groups/${name}" \
    || die "create group ${name} failed"
  dscl_ensure_prop   "/Groups/${name}" PrimaryGroupID "${uid}" \
    || die "set group ${name} gid failed"
  dscl_ensure_prop   "/Groups/${name}" RealName "DefenseClaw Service Group" \
    || warn "  set group ${name} RealName failed (non-fatal)"

  log "  ensuring user ${name} (uid=${uid})"
  dscl_ensure_record "/Users/${name}" \
    || die "create user ${name} failed"
  dscl_ensure_prop   "/Users/${name}" UserShell        /usr/bin/false
  dscl_ensure_prop   "/Users/${name}" RealName         "DefenseClaw Service"
  dscl_ensure_prop   "/Users/${name}" UniqueID         "${uid}"
  dscl_ensure_prop   "/Users/${name}" PrimaryGroupID   "${uid}"
  dscl_ensure_prop   "/Users/${name}" NFSHomeDirectory /var/empty
  dscl_ensure_prop   "/Users/${name}" IsHidden         1

  SERVICE_UID="${uid}"
  SERVICE_GID="${uid}"

  # Wait for the OpenDirectory cache to see the new user. Downstream
  # chown/find commands go through getpwnam and can otherwise fail with
  # "illegal user name" for a few seconds after creation. Non-fatal —
  # the chown site uses numeric IDs so it works regardless.
  if ! wait_for_id_resolves "${name}" 5; then
    warn "  ${name} still not resolvable via id(1) after 5s — using numeric UID for chown"
  fi
}

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
  --disable-redaction       Disable redaction in audit/sinks (default: on)
  --binary PATH             Use prebuilt binary (default: alongside install.sh)
  --plist PATH              Use this LaunchDaemon plist (default: alongside install.sh)
  --service-user NAME       macOS service user for the daemon (default: _defenseclaw).
                            Created via dscl if missing. Also used as the group.
  --skip-build              Reuse an existing gateway binary (no rebuild)
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
    --disable-redaction|--no-redact) DISABLE_REDACTION="true"; shift;;
    --binary)           BINARY_SRC="${2:?}"; SKIP_BUILD="true"; shift 2;;
    --plist)            PLIST_SRC="${2:?}"; shift 2;;
    --service-user)     SERVICE_USER="${2:?}"; SERVICE_GROUP="${2:?}"; shift 2;;
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

if [[ ! "${API_PORT}" =~ ^[0-9]+$ ]] || (( API_PORT < 1 || API_PORT > 65535 )); then
  die "--port must be an integer between 1 and 65535 (got: ${API_PORT})"
fi

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

# Resolve the binary. Lookup order matches PLIST_SRC:
#   1. --binary                              (explicit override)
#   2. ${SCRIPT_DIR}/defenseclaw-gateway     (standalone bundle)
#   3. ${REPO_ROOT}/defenseclaw-gateway      (dev tree)
#   4. `go build` from ${REPO_ROOT}/cmd/defenseclaw  (dev-tree fallback)
if [[ -z "${BINARY_SRC}" ]]; then
  if [[ -x "${SCRIPT_DIR}/defenseclaw-gateway" ]]; then
    BINARY_SRC="${SCRIPT_DIR}/defenseclaw-gateway"
    SKIP_BUILD="true"
  elif [[ -x "${REPO_ROOT}/defenseclaw-gateway" ]]; then
    BINARY_SRC="${REPO_ROOT}/defenseclaw-gateway"
  else
    BINARY_SRC="${REPO_ROOT}/defenseclaw-gateway"
  fi
fi
if [[ "${SKIP_BUILD}" != "true" && ! -x "${BINARY_SRC}" ]]; then
  if [[ ! -d "${REPO_ROOT}/cmd/defenseclaw" ]]; then
    die "binary not found at ${BINARY_SRC} and no repo tree at ${REPO_ROOT}/cmd/defenseclaw to build from — ship the gateway binary next to install.sh, or pass --binary PATH"
  fi
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

log "ensuring service user ${SERVICE_USER}"
ensure_service_user "${SERVICE_USER}"

log "chowning runtime dirs to ${SERVICE_USER}:${SERVICE_GROUP} (uid=${SERVICE_UID} gid=${SERVICE_GID})"
# Config stays root-owned (managed_enterprise trust check requires it),
# but runtime state (audit DB, tokens, guardian state, logs) is owned
# by the service user so the daemon can write to it. Use numeric IDs so
# the chown doesn't depend on OpenDirectory cache warm-up — dscl -create
# writes are async and getpwnam can be stale for several seconds.
[[ -n "${SERVICE_UID}" && -n "${SERVICE_GID}" ]] \
  || die "service uid/gid unset after ensure_service_user (internal bug)"
chown -R "${SERVICE_UID}:${SERVICE_GID}" "${SUPPORT_DIR}" "${LOGS_DIR}"
# Re-tighten config ownership: the recursive chown above walked into
# it, so put it back to root:wheel 0640.
chown root:wheel "${CONFIG_PATH}"
chmod 0640 "${CONFIG_PATH}"

log "installing LaunchDaemon plist -> ${PLIST_DST}"
install -o root -g wheel -m 0644 "${PLIST_SRC}" "${PLIST_DST}"

# Rewrite the plist's UserName / GroupName to match the actual service
# user we ensured above. plutil is on every macOS install.
log "wiring plist to service user ${SERVICE_USER}"
/usr/bin/plutil -replace UserName  -string "${SERVICE_USER}"  "${PLIST_DST}" \
  || die "failed to set UserName in ${PLIST_DST}"
/usr/bin/plutil -replace GroupName -string "${SERVICE_GROUP}" "${PLIST_DST}" \
  || die "failed to set GroupName in ${PLIST_DST}"

if [[ "${SKIP_LAUNCHD}" == "true" ]]; then
  log "skipping launchctl bootstrap (--skip-launchd)"
  exit 0
fi

# ---- launchd ------------------------------------------------------------

log "loading LaunchDaemon"
launchctl bootstrap system "${PLIST_DST}"
launchctl enable "system/${LAUNCHD_LABEL}"

wait_for_launchd_running() {
  local deadline=$(( $(date +%s) + 15 ))
  while (( $(date +%s) < deadline )); do
    if launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | grep -qE '^[[:space:]]+state = running'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

log "waiting for gateway to come up"
if ! wait_for_launchd_running; then
  warn "gateway did not reach running state within 15s; recent stderr:"
  tail -20 "${LOGS_DIR}/gateway.err.log" 2>/dev/null | sed 's/^/    /' >&2 || true
  die "${LAUNCHD_LABEL} failed to start; see ${LOGS_DIR}/gateway.err.log"
fi

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
    if ! prepare_userspace_for "${c}" "${TARGET_HOME}"; then
      warn "  [${c}] refused to prepare userspace (symlinked or non-dir path); skipping"
      continue
    fi
    # Match the ownership of any newly created files to the target user.
    # -h so we chown the entry itself and never follow symlinks (defense
    # in depth alongside ensure_safe_userspace_path in the lib helpers).
    case "${c}" in
      claudecode) DC_AGENT_DIR="${TARGET_HOME}/.claude";;
      codex)      DC_AGENT_DIR="${TARGET_HOME}/.codex";;
      cursor)     DC_AGENT_DIR="${TARGET_HOME}/.cursor";;
      *)          DC_AGENT_DIR="";;
    esac
    if [[ -n "${DC_AGENT_DIR}" && -d "${DC_AGENT_DIR}" && ! -L "${DC_AGENT_DIR}" ]]; then
      if ! find "${DC_AGENT_DIR}" -exec chown -h "${TARGET_UID}:${TARGET_GID}" {} +; then
        die "[${c}] failed to set ownership on ${DC_AGENT_DIR}"
      fi
    fi

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
  if ! wait_for_launchd_running; then
    warn "gateway did not resume within 15s; recent stderr:"
    tail -20 "${LOGS_DIR}/gateway.err.log" 2>/dev/null | sed 's/^/    /' >&2 || true
    die "${LAUNCHD_LABEL} failed to resume after per-user wiring"
  fi
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
