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
#
# PLIST_SRC_ORIGIN records which lookup won so the ownership validator
# below can apply the right policy: an explicit --plist / env-var
# override MUST be root-owned (installer treats it as an untrusted
# operator input), whereas the bundle-local / repo-tree defaults are
# ship-controlled — a tarball extracted by a regular user owns the plist
# but its content came from the trusted bundle, so we only enforce
# "no group/other write bits" there.
PLIST_SRC=""
PLIST_SRC_ORIGIN=""
for _candidate_origin in \
  "override:${DEFENSECLAW_PLIST_SRC:-}" \
  "bundle:${SCRIPT_DIR}/com.defenseclaw.gateway.plist" \
  "repo:${REPO_ROOT}/packaging/launchd/com.defenseclaw.gateway.plist"; do
  _candidate="${_candidate_origin#*:}"
  if [[ -n "${_candidate}" && -f "${_candidate}" ]]; then
    PLIST_SRC="${_candidate}"
    PLIST_SRC_ORIGIN="${_candidate_origin%%:*}"
    break
  fi
done
unset _candidate _candidate_origin
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
SERVICE_USER="defenseclaw"
SERVICE_GROUP="defenseclaw"

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
  local in_use_uids in_use_gids in_use
  # Query /Local/Default explicitly — using `.` (the meta-node) makes
  # dscl walk every attached directory (AD/LDAP/OD), which can hang or
  # return ENETUNREACH on a Mac bound to an unreachable domain. Service
  # users only ever live in /Local/Default, so this is both faster and
  # safer.
  #
  # Check BOTH /Users UIDs and /Groups GIDs — since our service user
  # uses the same numeric ID for both, we can't pick a value that's
  # taken by either. Missing this check produced a live install failure
  # where UID 400 was free but GID 400 was taken by an unrelated group.
  in_use_uids="$(dscl /Local/Default -list /Users  UniqueID       2>/dev/null | awk '{print $2}')"
  in_use_gids="$(dscl /Local/Default -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}')"
  in_use="$(printf '%s\n%s\n' "${in_use_uids}" "${in_use_gids}" | sort -u)"
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
    # Recovering the corrupt "record exists but attribute is missing"
    # state. dscl can't fix what dscl (or a killed install) created,
    # and /var/db/dslocal/nodes/Default is SIP-protected on modern
    # macOS so `rm` returns "Operation not permitted" even as root.
    #
    # The tools that CAN modify SIP-protected local directory records
    # are the ones that route through opendirectoryd's authenticated
    # API: dseditgroup for groups, sysadminctl for users. Both were
    # verified in a live diagnostic:
    #
    #   sudo dseditgroup -o delete _defenseclaw  → exit 0, record gone
    #   sudo sysadminctl -deleteUser _defenseclaw → deletes if present
    if [[ "${group_shell_present}" == "yes" ]]; then
      log "  resetting group ${name} via dseditgroup"
      /usr/sbin/dseditgroup -o delete "${name}" >/dev/null 2>&1 || \
        warn "  dseditgroup -o delete ${name} failed"
    fi
    if [[ "${user_shell_present}" == "yes" ]]; then
      log "  resetting user ${name} via sysadminctl"
      /usr/sbin/sysadminctl -deleteUser "${name}" >/dev/null 2>&1 || \
        warn "  sysadminctl -deleteUser ${name} failed"
    fi

    # dseditgroup / sysadminctl already synchronize opendirectoryd, so
    # no cache-flush dance needed. Just verify the reset actually took.
    local settle=0
    while (( settle < 5 )); do
      if ! dscl "${DS_NODE}" -read "/Users/${name}"  >/dev/null 2>&1 && \
         ! dscl "${DS_NODE}" -read "/Groups/${name}" >/dev/null 2>&1; then
        break
      fi
      sleep 1
      settle=$((settle + 1))
    done

    # Reset the state trackers so the fresh-provision path runs.
    existing_gid=""
    existing_uid=""

    # If the record STILL exists after that, it's coming from a
    # network directory / MDM push that we can't manage locally.
    # Bail with an actionable error.
    if dscl "${DS_NODE}" -read "/Users/${name}"  >/dev/null 2>&1 || \
       dscl "${DS_NODE}" -read "/Groups/${name}" >/dev/null 2>&1; then
      die "cannot reset ${name} — record survives dseditgroup/sysadminctl and is likely coming from a directory service (AD/LDAP/MDM). Pass --service-user with a different name (e.g. --service-user _defenseclaw2)"
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
  # Use dseditgroup rather than dscl for group creation. On modern
  # macOS (SIP enabled) dscl -create /Local/Default -create /Groups/X
  # writes a plist under /var/db/dslocal — which is SIP-protected.
  # dscl "succeeds" but the write can be partially dropped, leaving
  # a phantom record with RecordName but no PrimaryGroupID. That's
  # exactly the corruption pattern the reset block above cleans up.
  #
  # dseditgroup routes through opendirectoryd's authenticated API,
  # which has entitlements to write SIP-protected records atomically
  # and correctly.
  if ! dscl "${DS_NODE}" -read "/Groups/${name}" >/dev/null 2>&1; then
    /usr/sbin/dseditgroup -o create -i "${uid}" -r "DefenseClaw Service Group" "${name}" \
      || die "dseditgroup -o create ${name} failed"
  fi
  # Verify the group ended up with the right GID (dseditgroup ignores
  # -i if a group with the same name already exists in another node).
  local actual_gid
  actual_gid="$(dscl_read_prop "/Groups/${name}" PrimaryGroupID)"
  if [[ "${actual_gid}" != "${uid}" ]]; then
    die "group ${name} exists but PrimaryGroupID=${actual_gid:-<unset>} does not match target ${uid}"
  fi

  log "  ensuring user ${name} (uid=${uid})"
  # For users, sysadminctl is the SIP-safe primitive, but it requires
  # a password argument and creates a full account. dscl still works
  # for creating a hidden system user because Users/ plists in
  # /var/db/dslocal are less restrictive than Groups/. We validate
  # the write after each dscl call.
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
  --service-user NAME       macOS service user for the daemon (default: defenseclaw).
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
    --plist)            PLIST_SRC="${2:?}"; PLIST_SRC_ORIGIN="override"; shift 2;;
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
# Env-var seam so tests can drive the arg-parsing / resolution paths
# without sudo. This is intentionally namespaced so it can't be set
# via a public DEFENSECLAW_* var and matches nothing in real deploys.
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  [[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 $*)"
fi
[[ -f "${PLIST_SRC}" ]] || die "missing plist source: ${PLIST_SRC}"

# Validate the plist source before we copy it into /Library/LaunchDaemons.
# The plist gets installed root:wheel 0644 and executed as the DefenseClaw
# service principal at boot, so a tampered plist is a privesc surface.
#
# Two-tier policy based on PLIST_SRC_ORIGIN:
#
#   override — the operator passed --plist or DEFENSECLAW_PLIST_SRC. We
#     treat that as an untrusted external path and require root:*
#     ownership plus no group/other-write bits.
#
#   bundle / repo — the plist came from the shipped installer bundle
#     (extracted from our tarball) or the repo tree. In the documented
#     `sudo ./install.sh` bundle flow the plist is owned by the
#     extracting user, not root — the content came from the trusted
#     tarball but the extraction inherits the operator's uid. Enforce
#     "no group/other-write bits" (a compromised umask can't slip a
#     writable plist through) but skip the root-owner requirement.
#
# DC_INSTALLER_SKIP_PLIST_VALIDATION lets bundle-fixture tests drive
# install.sh against a stub plist without also bypassing the euid check.
# This is a separate seam from DC_INSTALLER_SKIP_ROOT_CHECK so tests can
# exercise the validator against non-root-owned fixtures.
if [[ "${DC_INSTALLER_SKIP_PLIST_VALIDATION:-}" != "1" ]]; then
  _plist_stat="$(stat -f '%Su %Lp' "${PLIST_SRC}" 2>/dev/null || echo '')"
  if [[ -z "${_plist_stat}" ]]; then
    die "cannot stat plist source ${PLIST_SRC}; refusing to install"
  fi
  _plist_owner="${_plist_stat%% *}"
  _plist_mode="${_plist_stat##* }"
  if [[ "${PLIST_SRC_ORIGIN}" == "override" && "${_plist_owner}" != "root" ]]; then
    die "plist source ${PLIST_SRC} was passed via --plist / DEFENSECLAW_PLIST_SRC and must be owned by root (got: ${_plist_owner}); refusing to install a potentially-tampered plist"
  fi
  # Refuse group-write or other-write bits (mode & 0o022) regardless of
  # origin — an installer-bundle plist that's group/world-writable was
  # tampered with post-extraction and shouldn't be trusted either.
  if (( (8#${_plist_mode} & 8#022) != 0 )); then
    die "plist source ${PLIST_SRC} is group/other writable (mode ${_plist_mode}); refusing to install"
  fi
  unset _plist_stat _plist_owner _plist_mode
fi

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
    # Standalone bundle layout — trust the shipped binary.
    BINARY_SRC="${SCRIPT_DIR}/defenseclaw-gateway"
    SKIP_BUILD="true"
  else
    # Repo-tree layout — either a pre-built binary at REPO_ROOT
    # (skip-build flow) or `go build` produces it there.
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
# SUPPORT_DIR is root-owned 0750 — the config file at its root has to
# be trust-checked, and the check walks every ancestor requiring
# root ownership and no group/other write bits.
install -d -o root -g wheel -m 0750 "${SUPPORT_DIR}"
# RUNTIME_DIR lives INSIDE SUPPORT_DIR (matches render_config's data_dir).
# Chown'd to the service user after we ensure the user exists.
RUNTIME_DIR="${SUPPORT_DIR}/runtime"
# GUARDIAN_AUTH_DIR must match the shipped plist's
# DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR env var (see
# packaging/launchd/com.defenseclaw.gateway.plist and the
# test_launchd_gateway_plist_uses_managed_paths CI assertion).
# Root-owned per docs — "root-owned authorization-record directory".
GUARDIAN_AUTH_DIR="${SUPPORT_DIR}/hook-guardian-state"
install -d -o root -g wheel -m 0750 "${RUNTIME_DIR}"
install -d -o root -g wheel -m 0750 "${GUARDIAN_AUTH_DIR}"
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
# Only RUNTIME_DIR + LOGS_DIR get service-user ownership. SUPPORT_DIR
# itself and CONFIG_PATH stay root-owned so the managed_enterprise
# config trust check (which walks every ancestor of config.yaml)
# accepts them.
[[ -n "${SERVICE_UID}" && -n "${SERVICE_GID}" ]] \
  || die "service uid/gid unset after ensure_service_user (internal bug)"
chown -R "${SERVICE_UID}:${SERVICE_GID}" "${RUNTIME_DIR}" "${LOGS_DIR}"

# SUPPORT_DIR stays owned by root, but the service user needs group
# traverse (x) access so launchd can chdir into
# ${SUPPORT_DIR}/runtime as its WorkingDirectory. Without this the
# daemon exits with EX_CONFIG before opening stdout/stderr — we can't
# even see a log line explaining what happened.
#
# The trust check refuses (mode & 0o022) — group-WRITE or other-WRITE
# bits — but group-execute (0o010) is fine. chgrp to the service group
# and keep mode 0750: root has full access, service group has rx only,
# world has nothing.
chgrp "${SERVICE_GID}" "${SUPPORT_DIR}"
chmod 0750 "${SUPPORT_DIR}"
# Also make config.yaml readable by the service group (daemon needs
# to read it). Owner stays root, mode 0640 (owner rw, group r, other 0).
chgrp "${SERVICE_GID}" "${CONFIG_PATH}"
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
    # Match ownership on JUST the files DefenseClaw just pre-created.
    # A recursive chown over ~/.codex or ~/.cursor is wrong: those
    # dirs may contain unrelated user state (Codex ships a signed
    # `computer-use/*.app` bundle, Cursor stores signed extensions),
    # and SIP-protected files in those trees will fail chown with
    # "Operation not permitted" even as root.
    #
    # We only touch what prepare_userspace_for could have written:
    # the connector's hook config file + its parent .<agent> dir.
    case "${c}" in
      claudecode) DC_AGENT_TARGETS=( "${TARGET_HOME}/.claude" "${TARGET_HOME}/.claude/settings.json" );;
      codex)      DC_AGENT_TARGETS=( "${TARGET_HOME}/.codex"  "${TARGET_HOME}/.codex/config.toml" );;
      cursor)     DC_AGENT_TARGETS=( "${TARGET_HOME}/.cursor" "${TARGET_HOME}/.cursor/hooks.json" );;
      *)          DC_AGENT_TARGETS=();;
    esac
    for path in "${DC_AGENT_TARGETS[@]}"; do
      # Skip symlinks (guarded upstream by ensure_safe_userspace_path)
      # and missing paths. Any real chown failure aborts the connector.
      if [[ -e "${path}" && ! -L "${path}" ]]; then
        if ! chown -h "${TARGET_UID}:${TARGET_GID}" "${path}"; then
          die "[${c}] failed to set ownership on ${path}"
        fi
      fi
    done

    AGENT_VER="${AGENT_VERSION}"
    if [[ -z "${AGENT_VER}" ]]; then
      # Expose TARGET_USER to the lib so its Codex fallback can exec
      # `codex --version` as the user (not as root).
      AGENT_VER="$(DC_INSTALLER_TARGET_USER="${TARGET_USER}" \
        discover_agent_version "${c}" "${TARGET_HOME}" || true)"
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

  # The CLI subcommands ran as root and created audit.db / judge_bodies.db
  # + their -wal/-shm sidecars in RUNTIME_DIR. Even though RUNTIME_DIR's
  # ownership is defenseclaw:defenseclaw, the newly-written files
  # inherit the running uid/gid (root:defenseclaw) with mode 0644 — so
  # the daemon (running as defenseclaw) can READ but not WRITE the audit
  # DB when it comes back up. Result: every hook evaluation runs, but
  # the audit row silently drops. Fix by re-chowning after every CLI
  # invocation completes.
  log "  re-chowning runtime files created by CLI migrations"
  chown -R "${SERVICE_UID}:${SERVICE_GID}" "${RUNTIME_DIR}"

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
    sudo sqlite3 -header -column "${RUNTIME_DIR}/audit.db" \\
      "SELECT datetime(timestamp,'localtime'),action,severity,substr(details,1,80) \\
       FROM audit_events ORDER BY timestamp DESC LIMIT 10;"

  Master gateway token (for direct curl tests):
    sudo grep DEFENSECLAW_GATEWAY_TOKEN "${RUNTIME_DIR}/.env"

  Repair user-space hooks (per connector):
$(for c in "${CONNECTORS[@]}"; do
    printf '    sudo DEFENSECLAW_CONFIG="%s" %s enterprise hooks install --connector %s --user %s --agent-version "X.Y.Z" --json\n' \
      "${CONFIG_PATH}" "${GATEWAY_BIN}" "${c}" "${TARGET_USER:-USER}"
  done)

  Uninstall:
    sudo ${SCRIPT_DIR}/uninstall.sh
EOF
