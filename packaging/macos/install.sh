#!/usr/bin/env bash
#
# DefenseClaw macOS installer (managed_enterprise + LaunchDaemon + per-user
# hook wiring via the enterprise hook guardian).
#
# Managed install layout, all root-owned:
#   /opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway
#                                                             (root:wheel 0755)
#   /Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
#                                                             (root:wheel 0644)
#   /opt/cisco/secureclient/defenseclaw/                      (root:wheel 0755)
#     etc/config.yaml                                         (root:wheel 0640)
#     runtime/                                                (root:wheel 0750)
#     hook-guardian-state/                                    (root:wheel 0750)
#   /Library/Logs/Cisco/SecureClient/DefenseClaw/             (root:wheel 0750)
#
# Older DefenseClaw installs used /Library/DefenseClaw/,
# /Library/Application Support/DefenseClaw/, and /Library/Logs/DefenseClaw/
# with the LaunchDaemon labelled 'com.defenseclaw.gateway'. uninstall.sh
# sweeps both the legacy and current locations so 'sudo ./uninstall.sh --purge'
# on a pre-managed-layout install cleanly cuts over when this installer runs.
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
DEFAULT_ENV="prod"

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
# If an explicit override was given via env var, it MUST exist. Silently
# falling back to bundle/repo defaults would (a) install a different
# plist than the operator asked for, and (b) downgrade the ownership
# policy from the strict `override` tier (root-owned) to the relaxed
# `bundle` tier (any owner) — so a typo in DEFENSECLAW_PLIST_SRC could
# quietly bypass the very hardening the operator was trying to opt into.
if [[ -n "${DEFENSECLAW_PLIST_SRC:-}" && ! -f "${DEFENSECLAW_PLIST_SRC}" ]]; then
  printf '[install] ERROR: DEFENSECLAW_PLIST_SRC=%s does not exist; refusing to fall back to the default plist\n' \
    "${DEFENSECLAW_PLIST_SRC}" >&2
  exit 1
fi
for _candidate_origin in \
  "override:${DEFENSECLAW_PLIST_SRC:-}" \
  "bundle:${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" \
  "repo:${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.plist"; do
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

# Managed install prefix. Everything DefenseClaw owns lives under this
# one tree. SUPPORT_DIR and INSTALL_PREFIX are the same directory in
# this layout; the two variable names are kept so downstream code can
# distinguish "binary tree root" (INSTALL_PREFIX) from "administrator-
# owned state root" (SUPPORT_DIR) — a distinction that matters when
# running the managed_enterprise trust check.
INSTALL_PREFIX="/opt/cisco/secureclient/defenseclaw"
SUPPORT_DIR="${INSTALL_PREFIX}"
LOGS_DIR="/Library/Logs/Cisco/SecureClient/DefenseClaw"
PLIST_DST="/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist"
LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw"
GUARDIAN_PLIST_DST="/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist"
GUARDIAN_LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw.hook-guardian"
GATEWAY_BIN="${INSTALL_PREFIX}/bin/defenseclaw-gateway"

# Legacy paths + label from pre-Cisco-path DefenseClaw installs. These
# are only referenced by uninstall.sh for its migration sweep; install.sh
# never writes to them.
LEGACY_INSTALL_PREFIX="/Library/DefenseClaw"
LEGACY_SUPPORT_DIR="/Library/Application Support/DefenseClaw"
LEGACY_LOGS_DIR="/Library/Logs/DefenseClaw"
LEGACY_PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LEGACY_LAUNCHD_LABEL="com.defenseclaw.gateway"
LEGACY_GUARDIAN_PLIST_DST="/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist"
LEGACY_GUARDIAN_LAUNCHD_LABEL="com.defenseclaw.hook-guardian"

# The daemon runs as root — the managed cloud auth provider requires
# root to read its credential store. We therefore do NOT create a
# dedicated service user or group. Every install-time chown of a
# DefenseClaw-owned path uses root:wheel.
#
# Older DefenseClaw installs (pre-root switch) provisioned a hidden
# system user via a battery of dscl / dseditgroup / sysadminctl
# helpers. All of that machinery was removed alongside the plist
# change; uninstall.sh --purge still knows how to sweep the legacy
# account for upgrades from those installs.

TARGET_USER=""
TARGET_HOME=""
AGENT_VERSION=""

# ---- helpers ------------------------------------------------------------

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

INSTALL_TEMP_FILES=()
cleanup_install_temporaries() {
  local path
  for path in "${INSTALL_TEMP_FILES[@]-}"; do
    [[ -n "${path}" ]] || continue
    rm -f -- "${path}"
  done
}
trap cleanup_install_temporaries EXIT

forget_install_temporary() {
  local expected="$1" index
  for index in "${!INSTALL_TEMP_FILES[@]}"; do
    if [[ "${INSTALL_TEMP_FILES[${index}]}" == "${expected}" ]]; then
      unset "INSTALL_TEMP_FILES[${index}]"
      return
    fi
  done
}

install_file_no_replace() {
  local source="$1" destination="$2" owner="$3" group="$4" mode="$5"
  local temporary
  [[ ! -e "${destination}" && ! -L "${destination}" ]] \
    || die "install destination appeared after fresh-host preflight: ${destination}"
  temporary="$(mktemp "${destination}.new.XXXXXX")" \
    || die "could not reserve a private install file beside ${destination}"
  INSTALL_TEMP_FILES+=("${temporary}")
  install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${temporary}"
  ln "${temporary}" "${destination}" \
    || die "install destination appeared concurrently and was preserved: ${destination}"
  rm -f -- "${temporary}"
  forget_install_temporary "${temporary}"
}

create_install_directory_no_replace() {
  local path="$1" owner="$2" group="$3" mode="$4"
  [[ ! -e "${path}" && ! -L "${path}" ]] \
    || die "install directory appeared after fresh-host preflight: ${path}"
  mkdir "${path}" \
    || die "install directory appeared concurrently and was preserved: ${path}"
  chown "${owner}:${group}" "${path}"
  chmod "${mode}" "${path}"
}

ensure_shared_install_parent() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -d "${path}" && ! -L "${path}" ]] \
      || die "shared install parent is not a real directory: ${path}"
  else
    create_install_directory_no_replace "${path}" root wheel 0755
  fi
  local owner mode acl_output acl_line normalized permissions permission
  local -a acl_permissions
  owner="$(stat -f '%u' "${path}")" \
    || die "cannot inspect shared install parent owner: ${path}"
  mode="$(stat -f '%Lp' "${path}")" \
    || die "cannot inspect shared install parent mode: ${path}"
  [[ "${owner}" == "0" ]] \
    || die "shared install parent is not root-owned: ${path}"
  (( (8#${mode} & 8#022) == 0 )) \
    || die "shared install parent is group/other writable: ${path} (${mode})"
  acl_output="$(ls -lde -- "${path}")" \
    || die "cannot inspect shared install parent ACL: ${path}"
  while IFS= read -r acl_line; do
    normalized="$(printf '%s' "${acl_line}" | tr '[:upper:]' '[:lower:]')"
    normalized="${normalized#"${normalized%%[![:space:]]*}"}"
    [[ "${normalized}" =~ ^[0-9]+: ]] || continue
    [[ "${normalized}" == *" allow "* ]] || continue
    permissions="${normalized#* allow }"
    permissions="${permissions%% *}"
    IFS=',' read -r -a acl_permissions <<<"${permissions}"
    for permission in "${acl_permissions[@]}"; do
      case "${permission}" in
        write|add_file|append|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)
          die "shared install parent has a write-capable ACL: ${path}"
          ;;
      esac
    done
  done <<<"${acl_output}"
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
  --env {prod|preview}      AI Defense cloud environment (default: ${DEFAULT_ENV}).
                            Selects the cisco_ai_defense.endpoint that the
                            managed daemon uses to inspect content.
                            Use 'preview' only for internal validation against
                            the aiteam preview deployment.
  --binary PATH             Use prebuilt binary (default: alongside install.sh)
  --plist PATH              Use this LaunchDaemon plist (default: alongside install.sh)
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
AID_ENV="${DEFAULT_ENV}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)             MODE="${2:?}"; shift 2;;
    --connector)        CONNECTOR="${2:?}"; shift 2;;
    --port)             API_PORT="${2:?}"; shift 2;;
    --env)              AID_ENV="${2:?}"; shift 2;;
    --binary)           BINARY_SRC="${2:?}"; SKIP_BUILD="true"; shift 2;;
    --plist)            PLIST_SRC="${2:?}"; PLIST_SRC_ORIGIN="override"; shift 2;;
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

AID_ENDPOINT="$(aid_endpoint_for_env "${AID_ENV}")" || \
  die "--env must be 'prod' or 'preview' (got: ${AID_ENV})"

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

# This bundle is a fresh-install surface, not an updater.  Refuse an
# existing consumer, legacy-managed, or current-managed installation before
# building a replacement binary, unloading launchd, or writing any installed
# path.  In-place changes must be driven by a release-owned staged upgrader so
# the 0.8.4 controller bridge and rollback contract cannot be bypassed.
_existing_install_markers=(
  "${INSTALL_PREFIX}"
  "${LOGS_DIR}"
  "${PLIST_DST}"
  "${GUARDIAN_PLIST_DST}"
  "${LEGACY_INSTALL_PREFIX}"
  "${LEGACY_SUPPORT_DIR}"
  "${LEGACY_LOGS_DIR}"
  "${LEGACY_PLIST_DST}"
  "${LEGACY_GUARDIAN_PLIST_DST}"
)
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  for _installed_command in defenseclaw defenseclaw-gateway; do
    _installed_command_path="$(command -v "${_installed_command}" 2>/dev/null || true)"
    [[ -n "${_installed_command_path}" ]] \
      && _existing_install_markers+=("${_installed_command_path}")
  done
fi
if [[ -n "${TARGET_HOME}" ]]; then
  _existing_install_markers+=(
    "${TARGET_HOME}/.defenseclaw"
    "${TARGET_HOME}/.local/bin/defenseclaw"
    "${TARGET_HOME}/.local/bin/defenseclaw-gateway"
  )
fi
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  # A system-wide managed daemon would contend with a consumer gateway in any
  # account, including an account other than --user/SUDO_USER. Always enumerate
  # every local account's configured home instead of assuming /Users/<name>.
  _local_users="$(dscl . -list /Users 2>/dev/null)" \
    || die "could not enumerate local users to prove this is a fresh DefenseClaw host; no changes were made"
  while IFS= read -r _local_user; do
    [[ -n "${_local_user}" ]] || continue
    _candidate_home="$(dscl . -read "/Users/${_local_user}" NFSHomeDirectory 2>/dev/null \
      | sed -n 's/^NFSHomeDirectory: //p')"
    [[ -n "${_candidate_home}" ]] || continue
    _existing_install_markers+=(
      "${_candidate_home}/.defenseclaw"
      "${_candidate_home}/.local/bin/defenseclaw"
      "${_candidate_home}/.local/bin/defenseclaw-gateway"
    )
  done <<< "${_local_users}"
fi
for _marker in "${_existing_install_markers[@]}"; do
  if [[ -e "${_marker}" || -L "${_marker}" ]]; then
    die "existing DefenseClaw installation detected at ${_marker}; no changes were made. This installer is fresh-install-only. Use the release-owned staged upgrade path for that deployment; if no managed-enterprise staged upgrader is published, remain on the current version and contact the deployment owner. Do not uninstall or overwrite state to force the upgrade."
  fi
done
for _label in \
  "${LAUNCHD_LABEL}" \
  "${GUARDIAN_LAUNCHD_LABEL}" \
  "${LEGACY_LAUNCHD_LABEL}" \
  "${LEGACY_GUARDIAN_LAUNCHD_LABEL}"; do
  if launchctl print "system/${_label}" >/dev/null 2>&1; then
    die "existing DefenseClaw launchd job detected (${_label}); no changes were made. This installer is fresh-install-only. Use the release-owned staged upgrade path for that deployment; if no managed-enterprise staged upgrader is published, remain on the current version and contact the deployment owner."
  fi
done
unset _existing_install_markers _marker _label _local_users _local_user _candidate_home \
  _installed_command _installed_command_path

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

# Repeat the launchd/path boundary immediately before mutation. A deployment
# that appears after the first preflight belongs to the concurrent installer;
# never boot it out or remove its plist.
for _lbl_plist in \
  "${LAUNCHD_LABEL}:${PLIST_DST}" \
  "${GUARDIAN_LAUNCHD_LABEL}:${GUARDIAN_PLIST_DST}" \
  "${LEGACY_LAUNCHD_LABEL}:${LEGACY_PLIST_DST}" \
  "${LEGACY_GUARDIAN_LAUNCHD_LABEL}:${LEGACY_GUARDIAN_PLIST_DST}"; do
  _lbl="${_lbl_plist%%:*}"
  _plist="${_lbl_plist#*:}"
  if launchctl print "system/${_lbl}" >/dev/null 2>&1; then
    die "DefenseClaw launchd job appeared after fresh-host preflight and was preserved: ${_lbl}"
  fi
  [[ ! -e "${_plist}" && ! -L "${_plist}" ]] \
    || die "DefenseClaw plist appeared after fresh-host preflight and was preserved: ${_plist}"
done
unset _lbl_plist _lbl _plist

# ---- gateway file install ----------------------------------------------

log "installing binary -> ${GATEWAY_BIN}"
# Ensure every ancestor of INSTALL_PREFIX exists. macOS `install -d`
# reapplies owner/mode to existing directories, so we must not run it
# against /opt/cisco or /opt/cisco/secureclient when those paths are
# already present — they may be shared with other Cisco software whose
# permissions we shouldn't touch. Create them with `mkdir -p` only when
# absent; unconditionally create + own only the DefenseClaw subtree.
for parent in /opt /opt/cisco /opt/cisco/secureclient; do
  ensure_shared_install_parent "${parent}"
done
create_install_directory_no_replace "${INSTALL_PREFIX}" root wheel 0755
create_install_directory_no_replace "${INSTALL_PREFIX}/bin" root wheel 0755
install_file_no_replace "${BINARY_SRC}" "${GATEWAY_BIN}" root wheel 0755

log "creating support dirs under ${SUPPORT_DIR}"
# SUPPORT_DIR (= INSTALL_PREFIX) is root:wheel 0755. The
# managed_enterprise trust check walks every ancestor of config.yaml
# requiring root ownership and no group/other write bits — 0755 (owner
# rwx, group rx, world rx) passes.
CONFIG_DIR="${SUPPORT_DIR}/etc"
RUNTIME_DIR="${SUPPORT_DIR}/runtime"
# GUARDIAN_AUTH_DIR must match the shipped plist's
# DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR env var (see
# packaging/launchd/com.cisco.secureclient.defenseclaw.plist and the
# test_launchd_gateway_plist_uses_managed_paths CI assertion).
# Root-owned per docs — "root-owned authorization-record directory".
GUARDIAN_AUTH_DIR="${SUPPORT_DIR}/hook-guardian-state"
create_install_directory_no_replace "${CONFIG_DIR}" root wheel 0755
create_install_directory_no_replace "${RUNTIME_DIR}" root wheel 0750
create_install_directory_no_replace "${GUARDIAN_AUTH_DIR}" root wheel 0750
# LOGS_DIR — the /Library/Logs/Cisco/ and SecureClient/ ancestors may
# be pre-existing and shared with other Cisco software. Same reasoning
# as /opt/cisco above: only create them (with our default perms) when
# absent, and unconditionally create + own only our leaf DefenseClaw/
# directory.
for parent in /Library/Logs /Library/Logs/Cisco /Library/Logs/Cisco/SecureClient; do
  ensure_shared_install_parent "${parent}"
done
create_install_directory_no_replace "${LOGS_DIR}" root wheel 0750

CONFIG_PATH="${CONFIG_DIR}/config.yaml"
[[ ! -e "${CONFIG_PATH}" && ! -L "${CONFIG_PATH}" ]] \
  || die "managed config appeared after fresh-host preflight and was preserved: ${CONFIG_PATH}"

log "writing config (mode=${MODE} connectors=${CONNECTORS[*]} port=${API_PORT} env=${AID_ENV} redaction_profile=sensitive)"
CONFIG_TMP="$(mktemp "${CONFIG_PATH}.new.XXXXXX")" \
  || die "could not reserve a private managed-config staging file"
INSTALL_TEMP_FILES+=("${CONFIG_TMP}")
render_config "${MODE}" "${PRIMARY_CONNECTOR}" "${API_PORT}" "${SUPPORT_DIR}" "${AID_ENDPOINT}" "${CONNECTORS[@]}" > "${CONFIG_TMP}"
chown root:wheel "${CONFIG_TMP}"
chmod 0640 "${CONFIG_TMP}"
ln "${CONFIG_TMP}" "${CONFIG_PATH}" \
  || die "managed config appeared concurrently and was preserved: ${CONFIG_PATH}"
rm -f -- "${CONFIG_TMP}"
forget_install_temporary "${CONFIG_TMP}"

log "chowning runtime dirs to root:wheel (daemon runs as root)"
# Every DefenseClaw-owned directory is root:wheel. The daemon runs as
# root (see plist), so no service-user provisioning is needed. Runtime
# dirs stay owner-only writable (0750) to keep the surface tight for
# anything a future audit tool inspects.
chown -R root:wheel "${RUNTIME_DIR}" "${LOGS_DIR}"

# SUPPORT_DIR + CONFIG_PATH are already root:wheel from the install(1)
# calls above; managed_enterprise trust check accepts them unchanged.

log "installing LaunchDaemon plist -> ${PLIST_DST}"
install_file_no_replace "${PLIST_SRC}" "${PLIST_DST}" root wheel 0644

# The shipped plist deliberately omits UserName/GroupName so the daemon
# runs as root (uid 0). If a stale plist from a pre-root DefenseClaw
# install left those keys behind on this host, strip them now so the
# daemon doesn't get pinned to a legacy service user that no longer
# exists (or would fail on managed cloud auth, which needs root).
log "stripping any legacy UserName/GroupName from installed plist"
/usr/bin/plutil -remove UserName  "${PLIST_DST}" >/dev/null 2>&1 || true
/usr/bin/plutil -remove GroupName "${PLIST_DST}" >/dev/null 2>&1 || true

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
      warn "    sudo DEFENSECLAW_CONFIG=\"${CONFIG_PATH}\" DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=\"${GUARDIAN_AUTH_DIR}\" ${GATEWAY_BIN} enterprise hooks install --connector ${c} --user ${TARGET_USER} --agent-version 'X.Y.Z' --json"
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
      warn "    sudo DEFENSECLAW_CONFIG=\"${CONFIG_PATH}\" DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=\"${GUARDIAN_AUTH_DIR}\" ${GATEWAY_BIN} enterprise hooks install --connector ${c} --user ${TARGET_USER} --agent-version 'X.Y.Z' --json"
      continue
    fi

    log "  [${c}] detected agent_version: ${AGENT_VER}"
    log "  [${c}] running: enterprise hooks install --connector ${c} --user ${TARGET_USER}"
    # DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR MUST match what the plist sets
    # for the running daemon (see packaging/launchd/com.cisco.secureclient.defenseclaw.plist).
    # The CLI's default is `${data_dir}-hook-guardian` which resolves to
    # ${SUPPORT_DIR}/runtime-hook-guardian and doesn't exist in our
    # layout — the installer creates ${SUPPORT_DIR}/hook-guardian-state
    # instead so the trust check walks a root-owned SUPPORT_DIR ancestor.
    # Without explicitly passing this env var here, `enterprise hooks
    # install` fails with:
    #   authorization directory trust check failed: .../runtime-hook-guardian: no such file or directory
    if DEFENSECLAW_CONFIG="${CONFIG_PATH}" \
       DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR="${GUARDIAN_AUTH_DIR}" \
       "${GATEWAY_BIN}" enterprise hooks install \
         --connector "${c}" \
         --user "${TARGET_USER}" \
         --agent-version "${AGENT_VER}" \
         --json; then
      log "  [${c}] hook wiring OK"
    else
      warn "  [${c}] hook wiring failed; see JSON output above"
    fi
  done

  # The CLI subcommands ran as root and wrote audit.db / judge_bodies.db
  # + their -wal/-shm sidecars into RUNTIME_DIR. The daemon also runs as
  # root, so ownership already matches — no chown pass is needed. This
  # step used to fix a defenseclaw-uid inheritance issue that vanishes
  # when everything is root.
  log "  runtime files created by CLI are already root-owned (daemon runs as root)"

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
    printf '    sudo DEFENSECLAW_CONFIG="%s" DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR="%s" %s enterprise hooks install --connector %s --user %s --agent-version "X.Y.Z" --json\n' \
      "${CONFIG_PATH}" "${GUARDIAN_AUTH_DIR}" "${GATEWAY_BIN}" "${c}" "${TARGET_USER:-USER}"
  done)

  Uninstall:
    sudo ${SCRIPT_DIR}/uninstall.sh
EOF
