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

# Managed-enterprise installs default to enforcing (action) mode. This
# installer only ever writes deployment_mode: managed_enterprise (see
# installer_lib.sh:render_config), and the managed rollout contract is
# "hooks enforce the verdict by default" — every deployment currently
# requires an operator to flip mode by hand or by post-install YAML edit
# to reach that state, which is easy to forget. Flipping the default to
# `action` puts every managed_enterprise install on the enforcing side
# of the observe/action decision immediately. Operators who want the
# observe pilot behavior still get it by passing --mode observe.
#
# NB: this default is installer-scoped only. The unmanaged / BYOD
# installers (scripts/install.sh, scripts/install.ps1, defenseclaw
# quickstart) and the Go/Python config defaults keep `observe` — the
# consumer install experience is unchanged.
DEFAULT_MODE="action"
DEFAULT_CONNECTOR="codex"
DEFAULT_API_PORT="18970"
DISABLE_REDACTION="false"

# AVC ships a static env_config.json under the managed install tree
# with the AI Defense endpoint DefenseClaw should target. That file is
# the source of truth on managed_enterprise hosts; --config-file lets
# operators point at a different path (fleet override, test fixture).
# --override-endpoint remains as the release-owned adhoc-testing seam.
DEFAULT_CONFIG_FILE="/opt/cisco/secureclient/defenseclaw/env_config.json"

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

# Guardian plist source lookup — same order as the gateway plist above,
# minus the operator-override tier (there is no user-facing --guardian-plist
# flag; the guardian is a managed subsystem shipped in the bundle).
GUARDIAN_PLIST_SRC=""
for _candidate in \
  "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" \
  "${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.hook-guardian.plist"; do
  if [[ -f "${_candidate}" ]]; then
    GUARDIAN_PLIST_SRC="${_candidate}"
    break
  fi
done
unset _candidate

# Enumerator plist source — the re-render-users-manifest daemon.
ENUMERATOR_PLIST_SRC=""
for _candidate in \
  "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-enumerator.plist" \
  "${REPO_ROOT}/packaging/launchd/com.cisco.secureclient.defenseclaw.hook-enumerator.plist"; do
  if [[ -f "${_candidate}" ]]; then
    ENUMERATOR_PLIST_SRC="${_candidate}"
    break
  fi
done
unset _candidate

# render-targets.sh source — the per-tick manifest renderer.
RENDER_TARGETS_SRC=""
for _candidate in \
  "${SCRIPT_DIR}/lib/render-targets.sh" \
  "${SCRIPT_DIR}/render-targets.sh" \
  "${REPO_ROOT}/packaging/macos/lib/render-targets.sh"; do
  if [[ -f "${_candidate}" ]]; then
    RENDER_TARGETS_SRC="${_candidate}"
    break
  fi
done
unset _candidate

# Library source — installer_lib.sh is copied into the managed tree so
# render-targets.sh (launchd-invoked) can source it independently of the
# repo/bundle layout.
INSTALLER_LIB_SRC=""
for _candidate in \
  "${SCRIPT_DIR}/lib/installer_lib.sh" \
  "${REPO_ROOT}/packaging/macos/lib/installer_lib.sh"; do
  if [[ -f "${_candidate}" ]]; then
    INSTALLER_LIB_SRC="${_candidate}"
    break
  fi
done
unset _candidate

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
ENUMERATOR_PLIST_DST="/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-enumerator.plist"
ENUMERATOR_LAUNCHD_LABEL="com.cisco.secureclient.defenseclaw.hook-enumerator"
GATEWAY_BIN="${INSTALL_PREFIX}/bin/defenseclaw-gateway"
RENDER_TARGETS_BIN="${INSTALL_PREFIX}/lib/render-targets.sh"
INSTALLER_LIB_DST="${INSTALL_PREFIX}/lib/installer_lib.sh"
GUARDIAN_MANIFEST_DIR="${INSTALL_PREFIX}/hook-guardian"
GUARDIAN_MANIFEST_PATH="${GUARDIAN_MANIFEST_DIR}/targets.yaml"

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

# The persistent install.log sink is set up LATER (after the fresh-host
# preflight passes and after LOGS_DIR has been created by
# create_install_directory_reconcile). Creating LOGS_DIR here (before
# the marker classification runs) would still be valid on a reinstall
# because the reconcile helper is idempotent, but the current ordering
# preserves the pre-reconcile invariant that all filesystem writes
# happen AFTER the marker loop has classified current-vs-legacy. Do
# not move this up without also revalidating the marker loop's
# read-only assumptions. Historical note: earlier fresh-install-only
# preflight would trip the "install directory appeared after fresh-host
# preflight" check on the very next line, and creating install.log
# before the preflight also required a special-case exemption that made
# the preflight harder to reason about. See the "install.log sink" block
# further down for the delayed setup.
:

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

install_file_reconcile() {
  # install_file_reconcile SRC DST OWNER GROUP MODE
  #
  # Atomically writes DST from SRC with the requested owner/group/mode.
  # Overwrites an existing regular file at DST (this is the idempotent
  # reinstall contract for managed_enterprise — see the marker-loop
  # comment above).
  #
  # Symlinks at DST are STILL refused: a symlink under a root-owned
  # install path can only get there via privileged tampering, and
  # renaming a temp file over a symlink target would attack whatever
  # the symlink points at. Fail loud instead.
  local source="$1" destination="$2" owner="$3" group="$4" mode="$5"
  local temporary
  if [[ -L "${destination}" ]]; then
    die "install destination is a symlink; refusing to overwrite: ${destination}"
  fi
  temporary="$(mktemp "${destination}.new.XXXXXX")" \
    || die "could not reserve a private install file beside ${destination}"
  INSTALL_TEMP_FILES+=("${temporary}")
  install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${temporary}"
  # rename(2) is atomic across paths on the same filesystem; the two
  # files are guaranteed to live in the same directory (see mktemp
  # template above), so mv here is a metadata swap the observer will
  # see as either "old file" or "new file", never partial.
  /bin/mv -f -- "${temporary}" "${destination}" \
    || die "could not atomically replace ${destination}"
  forget_install_temporary "${temporary}"
}

# ---- AVC env_config.json trust helpers ---------------------------------
# The AI Defense endpoint config file is authored by AVC (a signed
# system component) and dropped under a root-owned tree. Verify the
# managed-enterprise trust invariants before reading its contents:
# root-owned, no group/other write, no symlinks anywhere in the
# ancestor chain, no write-capable macOS ACL. These mirror the checks
# packaging/launchd/install-enterprise.sh applies to its --config source
# (see :100-151 in that file). Kept inline here (rather than in
# installer_lib.sh) so installer_lib.sh's pure-function contract stays
# intact and its test harness does not accidentally invoke the
# die-emitting trust path on a tmpdir fixture.
_refuse_symlink_or_die() {
  local path="$1" label="$2"
  [[ ! -L "${path}" ]] || die "${label} must not be a symlink: ${path}"
}

_assert_no_write_acl_or_die() {
  local path="$1" label="$2"
  local output line normalized permissions permission
  local -a acl_permissions
  output="$(/bin/ls -lde -- "${path}" 2>/dev/null)" \
    || die "${label} cannot be inspected for ACLs: ${path}"
  while IFS= read -r line; do
    normalized="$(printf '%s' "${line}" | /usr/bin/tr '[:upper:]' '[:lower:]')"
    normalized="${normalized#"${normalized%%[![:space:]]*}"}"
    [[ "${normalized}" =~ ^[0-9]+: ]] || continue
    [[ "${normalized}" == *" allow "* ]] || continue
    permissions="${normalized#* allow }"
    permissions="${permissions%% *}"
    [[ -n "${permissions}" ]] \
      || die "${label} has an unparseable macOS allow ACL: ${path}"
    IFS=',' read -r -a acl_permissions <<<"${permissions}"
    for permission in "${acl_permissions[@]}"; do
      case "${permission}" in
        write|add_file|append|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)
          die "${label} has a write-capable macOS ACL entry (${permission}): ${path}"
          ;;
      esac
    done
  done <<<"${output}"
}

_assert_trusted_dir_or_die() {
  local path="$1" label="$2" uid mode
  _refuse_symlink_or_die "${path}" "${label}"
  [[ -d "${path}" ]] || die "${label} ancestor is missing: ${path}"
  _assert_no_write_acl_or_die "${path}" "${label}"
  uid="$(/usr/bin/stat -f '%u' "${path}" 2>/dev/null || echo '')"
  mode="$(/usr/bin/stat -f '%Lp' "${path}" 2>/dev/null || echo '')"
  [[ "${uid}" == "0" ]] \
    || die "${label} ancestor is not root-owned: ${path} (uid=${uid})"
  (( (8#${mode} & 8#022) == 0 )) \
    || die "${label} ancestor is group/other writable: ${path} (mode=${mode})"
}

# _assert_trusted_env_config_file_or_die PATH
#   Enforces the managed-enterprise trust contract on a file authored
#   by AVC and dropped under a root-owned tree. Dies with a labelled
#   message on any violation. Walks every ancestor of PATH (absolute
#   path only; relative paths are rejected). Skipped when
#   DC_INSTALLER_SKIP_ROOT_CHECK=1 (the same seam that bypasses the
#   euid check for tests operating on tmpdir fixtures).
_assert_trusted_env_config_file_or_die() {
  local path="$1" label="AVC env_config.json"
  if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" == "1" ]]; then
    return 0
  fi
  case "${path}" in
    /*) ;;
    *) die "${label} must be an absolute path: ${path}" ;;
  esac
  _refuse_symlink_or_die "${path}" "${label}"
  [[ -f "${path}" ]] || die "${label} is not a regular file: ${path}"
  _assert_no_write_acl_or_die "${path}" "${label}"
  local uid mode
  uid="$(/usr/bin/stat -f '%u' "${path}" 2>/dev/null || echo '')"
  mode="$(/usr/bin/stat -f '%Lp' "${path}" 2>/dev/null || echo '')"
  [[ "${uid}" == "0" ]] \
    || die "${label} is not root-owned: ${path} (uid=${uid})"
  (( (8#${mode} & 8#022) == 0 )) \
    || die "${label} is group/other writable: ${path} (mode=${mode})"
  # Walk every ancestor and apply the same trust checks. The install-
  # enterprise.sh trust helper does the same at :112-138.
  local parent current="/" trimmed_parent component
  local -a source_parts
  parent="$(dirname "${path}")"
  _assert_trusted_dir_or_die "${current}" "${label}"
  trimmed_parent="${parent#/}"
  IFS='/' read -r -a source_parts <<<"${trimmed_parent}"
  for component in "${source_parts[@]}"; do
    [[ -n "${component}" ]] || continue
    case "${component}" in
      .) continue ;;
      ..) die "${label} path must not contain parent traversal: ${path}" ;;
    esac
    if [[ "${current}" == "/" ]]; then
      current="/${component}"
    else
      current="${current}/${component}"
    fi
    _assert_trusted_dir_or_die "${current}" "${label}"
  done
}

create_install_directory_reconcile() {
  # create_install_directory_reconcile PATH OWNER GROUP MODE
  #
  # Ensures PATH exists as a directory with the requested owner/group
  # and mode. Existing directory contents are left in place — the
  # idempotent-reinstall contract for managed_enterprise treats a
  # runtime dir with an existing audit.db / device.key / hook-guardian
  # state as data-carrying and NEVER wipes it.
  #
  # Symlinks at PATH are refused for the same reason as
  # install_file_reconcile: a symlink under a root-owned install path
  # can only be there via tampering.
  local path="$1" owner="$2" group="$3" mode="$4"
  if [[ -L "${path}" ]]; then
    die "install directory is a symlink; refusing to reconcile: ${path}"
  fi
  if [[ -e "${path}" ]]; then
    [[ -d "${path}" ]] \
      || die "install directory path exists but is not a directory: ${path}"
  else
    mkdir "${path}" \
      || die "could not create install directory: ${path}"
  fi
  chown "${owner}:${group}" "${path}"
  chmod "${mode}" "${path}"
}

ensure_shared_install_parent() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -d "${path}" && ! -L "${path}" ]] \
      || die "shared install parent is not a real directory: ${path}"
  else
    create_install_directory_reconcile "${path}" root wheel 0755
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
  --config-file PATH        Path to the AVC-authored env_config.json that
                            supplies cisco_ai_defense.endpoint. Default:
                            ${DEFAULT_CONFIG_FILE}
                            The file must be root-owned and non-writable by
                            group/other, per the managed_enterprise trust
                            contract. Expected JSON shape:
                            {"cisco_ai_defense_endpoint": "https://..."}
  --override-endpoint URL   Point cisco_ai_defense.endpoint at an arbitrary AI
                            Defense host for adhoc testing. Takes precedence
                            over --config-file. Must be an HTTPS bare origin
                            (no userinfo, path, query, or fragment), e.g.
                            https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com
  --disable-redaction       Disable redaction in audit/sinks (default: on)
  --binary PATH             Use prebuilt binary (default: alongside install.sh)
  --plist PATH              Use this LaunchDaemon plist (default: alongside install.sh)
  --skip-build              Reuse an existing gateway binary (no rebuild)
  --skip-launchd            Install files but don't bootstrap/enable launchd

Per-user hook wiring:
  --user USER               Target macOS user (default: \$SUDO_USER)
  --agent-version VERSION   Override agent version (auto-detected if omitted)
  --skip-connector          Don't wire user-space hooks (gateway only)
  --allow-empty-users       Proceed even when no eligible local users are
                            found. Only pass this on lab / demo boxes where
                            zero user coverage is intentional; production
                            installs should fail loud (default) so admins
                            notice broken enumeration before the guardian
                            silently ships a zero-target manifest.

  -h, --help                Show this help

EOF
}

# ---- arg parsing --------------------------------------------------------

MODE="${DEFAULT_MODE}"
CONNECTOR="${DEFAULT_CONNECTOR}"
API_PORT="${DEFAULT_API_PORT}"
CONFIG_FILE="${DEFAULT_CONFIG_FILE}"
OVERRIDE_ENDPOINT=""
ALLOW_EMPTY_USERS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)             MODE="${2:?}"; shift 2;;
    --connector)        CONNECTOR="${2:?}"; shift 2;;
    --port)             API_PORT="${2:?}"; shift 2;;
    --config-file)      CONFIG_FILE="${2:?}"; shift 2;;
    --override-endpoint) OVERRIDE_ENDPOINT="${2:?}"; shift 2;;
    --disable-redaction|--no-redact) DISABLE_REDACTION="true"; shift;;
    --binary)           BINARY_SRC="${2:?}"; SKIP_BUILD="true"; shift 2;;
    --plist)            PLIST_SRC="${2:?}"; PLIST_SRC_ORIGIN="override"; shift 2;;
    --skip-build)       SKIP_BUILD="true"; shift;;
    --skip-launchd)     SKIP_LAUNCHD="true"; shift;;
    --user)             TARGET_USER="${2:?}"; shift 2;;
    --agent-version)    AGENT_VERSION="${2:?}"; shift 2;;
    --skip-connector)   SKIP_CONNECTOR="true"; shift;;
    --allow-empty-users) ALLOW_EMPTY_USERS="true"; shift;;
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

# AI Defense endpoint resolution runs AFTER purely-syntactic flag
# validation (--mode / --port / --connector) so a stale automation
# passing a bad port or connector list still gets its per-flag error
# message rather than being masked by the endpoint resolver's
# fail-closed on a missing env_config.json.
#
# --override-endpoint (when set) wins over --config-file. When the
# resolver falls through to the config file we ALSO run the managed-
# enterprise trust check (root ownership, no group/other write, no
# symlink, no write-capable macOS ACL) on the file and every ancestor
# before reading it — this matches
# packaging/launchd/install-enterprise.sh's --config trust contract.
#
# Distinct return codes let us report exactly which input was wrong so
# operators don't chase the wrong flag:
#   rc 0 - success (endpoint on stdout).
#   rc 1 - config file missing / unreadable.
#   rc 2 - config file malformed (bad JSON, missing field, bad URL).
#   rc 3 - --override-endpoint supplied but malformed.
if [[ -z "${OVERRIDE_ENDPOINT}" && -e "${CONFIG_FILE}" ]]; then
  # Trust check runs before the resolver reads the file so a
  # tamper-suspect file is rejected loudly (rather than silently
  # feeding its contents into config.yaml). A missing file preempts
  # the trust check — the resolver's rc-1 branch below gives a nicer
  # "AVC module must drop this file" message in that case.
  _assert_trusted_env_config_file_or_die "${CONFIG_FILE}"
fi
_ep_rc=0
AID_ENDPOINT="$(resolve_aid_endpoint "${OVERRIDE_ENDPOINT}" "${CONFIG_FILE}")" || _ep_rc=$?
if (( _ep_rc == 3 )); then
  die "--override-endpoint must be an HTTPS bare origin (no userinfo, path, query, or fragment) — got: ${OVERRIDE_ENDPOINT}"
elif (( _ep_rc == 2 )); then
  die "--config-file ${CONFIG_FILE} is malformed: expected a JSON object with a valid \"cisco_ai_defense_endpoint\" URL. If AVC's drop is missing, pass --override-endpoint URL for adhoc testing."
elif (( _ep_rc == 1 )); then
  die "env_config.json not found at ${CONFIG_FILE}; the AVC module must drop this file before installing, or pass --override-endpoint URL for adhoc testing."
elif (( _ep_rc != 0 )); then
  die "could not resolve AI Defense endpoint (rc=${_ep_rc})"
fi
unset _ep_rc
# _valid_aid_endpoint_url already rejects http:// / userinfo / paths /
# queries / fragments at rc-3 time, so past this point the endpoint is
# guaranteed to be an HTTPS bare origin. No plaintext-http warning path
# is needed.
if [[ -n "${OVERRIDE_ENDPOINT}" ]]; then
  log "AI Defense endpoint overridden for adhoc testing: ${AID_ENDPOINT} (ignoring --config-file ${CONFIG_FILE})"
else
  log "AI Defense endpoint resolved from ${CONFIG_FILE}: ${AID_ENDPOINT}"
fi

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

# Per-user hook wiring is no longer scoped to a single TARGET_USER: the
# installer renders a machine-wide `targets.yaml` covering every eligible
# local user, and the hook-guardian LaunchDaemon reconciles that manifest
# reactively via fsnotify — user tampering with a hook config or hook
# script under a watched dir triggers a repair within ~1 s. A 5 min
# periodic reconcile is retained as a backstop for missed events. Fresh
# users added after install are picked up by the hook-enumerator daemon
# that re-renders the same manifest on its own 5 min tick. --user is
# preserved as a backward-compat no-op so operators / CI that still pass
# it don't error out; --agent-version is likewise ignored (each user's
# agent version is discovered per-connector by installer_lib.sh at
# manifest-render time).
if [[ -n "${TARGET_USER}" ]]; then
  warn "--user ${TARGET_USER} is ignored: hook wiring is now machine-wide via the hook guardian"
  TARGET_USER=""
fi
if [[ -n "${AGENT_VERSION}" ]]; then
  warn "--agent-version ${AGENT_VERSION} is ignored: per-user versions are discovered by the guardian at each tick"
  AGENT_VERSION=""
fi

# Idempotent-reinstall contract (see PR notes for the drift analysis):
# this installer is designed to be run repeatedly against a managed host
# without needing an out-of-band uninstall/upgrade path. The refuse-on-
# existing behavior that used to live here (a die() on any marker,
# including a stray ~/.defenseclaw in ANY local account) left drifted
# hosts stuck — the operator's second `sudo ./install.sh` did nothing
# and machine-wide state stayed whatever the first install produced.
#
# Reinstall is scoped to machine-wide state that this installer owns:
#   - gateway binary, config.yaml, plists, launchd bootstrap.
#   - hook-guardian manifest + state dir.
#   - LOGS_DIR (leaf) and its install.log.
#
# What is NEVER touched:
#   - Any user's ~/.defenseclaw (reconciled by the hook-guardian
#     daemon on its 60s tick; wiping it would drop audit history).
#   - RUNTIME_DIR contents (audit.db, judge_bodies.db, device.key,
#     hook-guardian-state) — data-carrying.
#
# What IS relocated (best-effort, not deleted):
#   - Legacy paths from the pre-Cisco layout (/Library/DefenseClaw/
#     etc.). Moved aside under LOGS_DIR with a timestamped suffix so
#     the operator can inspect / recover forensics if needed.
#   - Legacy launchd labels (com.defenseclaw.*) are unloaded via
#     launchctl bootout before the plist file itself is relocated.

# Detect ambient state so we can log a single line describing what we
# are reconciling vs freshly installing. The per-user marker enumeration
# is kept (and logged) so operators still see "user X had ~/.defenseclaw"
# in install.log, but it no longer aborts the install — the hook-guardian
# owns per-user reconciliation.
_current_managed_markers=(
  "${INSTALL_PREFIX}"
  "${LOGS_DIR}"
  "${PLIST_DST}"
  "${GUARDIAN_PLIST_DST}"
  "${ENUMERATOR_PLIST_DST}"
)
_legacy_managed_paths=(
  "${LEGACY_INSTALL_PREFIX}"
  "${LEGACY_SUPPORT_DIR}"
  "${LEGACY_LOGS_DIR}"
  "${LEGACY_PLIST_DST}"
  "${LEGACY_GUARDIAN_PLIST_DST}"
)
_current_launchd_labels=(
  "${LAUNCHD_LABEL}"
  "${GUARDIAN_LAUNCHD_LABEL}"
  "${ENUMERATOR_LAUNCHD_LABEL}"
)
_legacy_launchd_labels=(
  "${LEGACY_LAUNCHD_LABEL}"
  "${LEGACY_GUARDIAN_LAUNCHD_LABEL}"
)

_reconcile_current="false"
for _marker in "${_current_managed_markers[@]}"; do
  if [[ -e "${_marker}" || -L "${_marker}" ]]; then
    _reconcile_current="true"
    break
  fi
done
if [[ "${_reconcile_current}" == "false" ]]; then
  for _label in "${_current_launchd_labels[@]}"; do
    if launchctl print "system/${_label}" >/dev/null 2>&1; then
      _reconcile_current="true"
      break
    fi
  done
fi

if [[ "${_reconcile_current}" == "true" ]]; then
  log "reconciling existing DefenseClaw installation in place (idempotent reinstall)"
else
  log "fresh managed_enterprise install (no existing markers detected)"
fi

# Enumerate per-user consumer markers strictly for install.log
# forensics. The hook-guardian daemon owns the per-user reconcile
# loop, so we do NOT delete these — the guardian will pick them up
# after the machine-wide reinstall lands.
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  _local_users="$(dscl . -list /Users 2>/dev/null || true)"
  if [[ -z "${_local_users}" ]]; then
    warn "could not enumerate local users via dscl; per-user hook wiring will still be reconciled by the guardian on its 60s tick"
  else
    while IFS= read -r _local_user; do
      [[ -n "${_local_user}" ]] || continue
      _candidate_home="$(dscl . -read "/Users/${_local_user}" NFSHomeDirectory 2>/dev/null \
        | sed -n 's/^NFSHomeDirectory: //p')"
      [[ -n "${_candidate_home}" ]] || continue
      for _u_marker in \
        "${_candidate_home}/.defenseclaw" \
        "${_candidate_home}/.local/bin/defenseclaw" \
        "${_candidate_home}/.local/bin/defenseclaw-gateway"; do
        if [[ -e "${_u_marker}" || -L "${_u_marker}" ]]; then
          log "  (informational) per-user artifact present, will be reconciled by hook-guardian: ${_u_marker}"
        fi
      done
    done <<< "${_local_users}"
  fi
fi

# Unload current-generation launchd jobs BEFORE we start writing plists
# and binaries. Without this the later `launchctl bootstrap system` would
# race an already-loaded job, and even in the racing-doesn't-lose case
# the running daemon holds an open file descriptor on the old binary —
# unloading now guarantees the atomic-replace hits a quiescent target.
# Best-effort; failure is logged, not fatal (the bootstrap retry below
# would surface a real failure loudly).
for _label in "${_current_launchd_labels[@]}"; do
  if launchctl print "system/${_label}" >/dev/null 2>&1; then
    log "unloading current launchd job for reinstall: ${_label}"
    launchctl bootout "system/${_label}" >/dev/null 2>&1 \
      || warn "launchctl bootout system/${_label} failed; bootstrap below may still succeed"
  fi
done

# Legacy launchd cleanup: unload the pre-Cisco-path labels if any are
# still loaded. These plists point at binaries that no longer exist on
# a current install, so leaving them loaded produces log noise (repeated
# spawn-and-crash) but is otherwise inert. bootout + move the plist
# file aside (below) so uninstall.sh --purge and future upgrades see a
# clean state.
for _label in "${_legacy_launchd_labels[@]}"; do
  if launchctl print "system/${_label}" >/dev/null 2>&1; then
    log "unloading legacy launchd job: ${_label}"
    launchctl bootout "system/${_label}" >/dev/null 2>&1 \
      || warn "launchctl bootout system/${_label} failed; the legacy plist will still be relocated below"
  fi
done

# Ensure LOGS_DIR exists early so move_legacy_aside has a landing zone.
# On a reinstall we need the backup path BEFORE the mutation phase to
# relocate legacy artifacts. The reconcile helper further down is
# idempotent — a second creation is a no-op chown/chmod.
#
# Ancestor trust check: before ANY mkdir/chown/chmod on the
# /Library/Logs/Cisco/SecureClient/DefenseClaw chain, walk every
# ancestor and enforce the same no-symlink / root-owned /
# no-group-other-write / no-write-capable-ACL invariant applied to
# every other trusted install path. Without this a symlinked
# /Library/Logs/Cisco would let a root-owned mkdir -p / mv follow
# the link and relocate legacy config / audit material into an
# attacker-controlled location before any later validation catches
# the drift. Skipped under DC_INSTALLER_SKIP_ROOT_CHECK=1 the same
# way as the env_config trust check — tests under tmpdir fixtures
# can't be root-owned, and the check re-runs end-to-end in the
# manual verification path.
_assert_trusted_logs_chain_or_die() {
  if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" == "1" ]]; then
    return 0
  fi
  local _current="/" _leaf
  _assert_trusted_dir_or_die "${_current}" "logs ancestor"
  local -a _components=("Library" "Logs" "Cisco" "SecureClient")
  local _c
  for _c in "${_components[@]}"; do
    if [[ "${_current}" == "/" ]]; then
      _current="/${_c}"
    else
      _current="${_current}/${_c}"
    fi
    # Some ancestors may not exist yet on a fresh CI-clean host; that
    # is fine — the mkdir -p below creates them with the right perms.
    # We only trust-check an ancestor that already exists.
    if [[ -e "${_current}" || -L "${_current}" ]]; then
      _assert_trusted_dir_or_die "${_current}" "logs ancestor"
    fi
  done
  # LOGS_DIR itself is the leaf we're about to write into. Same
  # policy — existence check first, then trust check.
  _leaf="${LOGS_DIR}"
  if [[ -e "${_leaf}" || -L "${_leaf}" ]]; then
    _assert_trusted_dir_or_die "${_leaf}" "logs backup root"
  fi
}
_assert_trusted_logs_chain_or_die

for _parent in /Library/Logs /Library/Logs/Cisco /Library/Logs/Cisco/SecureClient; do
  if [[ ! -d "${_parent}" ]]; then
    mkdir -p "${_parent}" 2>/dev/null || true
  fi
done
if [[ ! -d "${LOGS_DIR}" ]]; then
  mkdir -p "${LOGS_DIR}" 2>/dev/null || true
  chown root:wheel "${LOGS_DIR}" 2>/dev/null || true
  chmod 0750 "${LOGS_DIR}" 2>/dev/null || true
fi
# Re-verify LOGS_DIR is trusted AFTER creation — a concurrent racer
# could have raced us to a symlink; refuse to move legacy material
# through it.
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  _assert_trusted_dir_or_die "${LOGS_DIR}" "logs backup root"
fi

# Version tag for legacy backup paths. Pulled from the gateway binary
# when available so a re-run against a mixed-legacy host produces a
# distinct backup dir per attempt.
_installer_version_tag="$("${SCRIPT_DIR}/defenseclaw" --version 2>/dev/null | head -1 || true)"
[[ -z "${_installer_version_tag}" ]] && _installer_version_tag="unknown"
_installer_version_tag="$(printf '%s' "${_installer_version_tag}" | tr -c '[:alnum:]._-' '_' | head -c 32)"
[[ -z "${_installer_version_tag}" ]] && _installer_version_tag="unknown"

for _legacy in "${_legacy_managed_paths[@]}"; do
  if [[ -e "${_legacy}" || -L "${_legacy}" ]]; then
    if ! move_legacy_aside "${_legacy}" "${LOGS_DIR}" "${_installer_version_tag}"; then
      warn "could not relocate legacy path ${_legacy}; leaving it in place"
    fi
  fi
done

unset _current_managed_markers _legacy_managed_paths _current_launchd_labels \
  _legacy_launchd_labels _marker _label _local_users _local_user _candidate_home \
  _u_marker _installer_version_tag _legacy _parent _reconcile_current

# Resolve the binary. Lookup order matches PLIST_SRC:
#   1. --binary                              (explicit override)
#   2. ${SCRIPT_DIR}/defenseclaw             (standalone bundle artifact)
#   3. ${REPO_ROOT}/defenseclaw-gateway      (dev tree)
#   4. `go build` from ${REPO_ROOT}/cmd/defenseclaw  (dev-tree fallback)
#
# The shipped bundle names the artifact "defenseclaw" (see
# scripts/build-macos-bundle.sh); the dev-tree build keeps the
# "defenseclaw-gateway" name to match `make gateway`. Either way it is
# installed to the runtime path ${GATEWAY_BIN} (.../bin/defenseclaw-gateway).
if [[ -z "${BINARY_SRC}" ]]; then
  if [[ -x "${SCRIPT_DIR}/defenseclaw" ]]; then
    # Standalone bundle layout — trust the shipped binary.
    BINARY_SRC="${SCRIPT_DIR}/defenseclaw"
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

# The pre-reinstall block above (marker classification + bootout of
# current-generation labels + relocation of legacy paths) is the single
# point where existing state is reconciled. A repeat-check at this
# choke point used to guard the fresh-install-only invariant; under the
# idempotent-reinstall contract the invariant is "we own reconciliation
# of current-gen paths / labels", not "no current-gen state ever
# exists". A concurrent second installer racing us is diagnosed by the
# ln/rename atomicity in install_file_reconcile below (both invocations
# will atomically swap the same destination; the last one wins with a
# consistent triple of binary+config+plist).

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
create_install_directory_reconcile "${INSTALL_PREFIX}" root wheel 0755
create_install_directory_reconcile "${INSTALL_PREFIX}/bin" root wheel 0755
install_file_reconcile "${BINARY_SRC}" "${GATEWAY_BIN}" root wheel 0755

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
create_install_directory_reconcile "${CONFIG_DIR}" root wheel 0755
create_install_directory_reconcile "${RUNTIME_DIR}" root wheel 0750
create_install_directory_reconcile "${GUARDIAN_AUTH_DIR}" root wheel 0750
# Multi-user hook wiring: the hook-guardian LaunchDaemon reads its
# per-tick manifest from ${GUARDIAN_MANIFEST_DIR}/targets.yaml. Creating
# the directory unconditionally keeps the guardian's LoadManifest happy
# even if the enumerator hasn't run yet.
create_install_directory_reconcile "${GUARDIAN_MANIFEST_DIR}" root wheel 0755
create_install_directory_reconcile "${INSTALL_PREFIX}/lib" root wheel 0755
# render-targets.sh is invoked by the hook-enumerator LaunchDaemon and
# sources installer_lib.sh from a fixed path; both must land under the
# managed tree so the daemon doesn't need to see the bundle layout.
[[ -f "${RENDER_TARGETS_SRC}" ]] \
  || die "render-targets.sh source not found (expected ${SCRIPT_DIR}/lib/render-targets.sh)"
[[ -f "${INSTALLER_LIB_SRC}" ]] \
  || die "installer_lib.sh source not found (expected ${SCRIPT_DIR}/lib/installer_lib.sh)"
install_file_reconcile "${RENDER_TARGETS_SRC}" "${RENDER_TARGETS_BIN}" root wheel 0755
install_file_reconcile "${INSTALLER_LIB_SRC}"  "${INSTALLER_LIB_DST}" root wheel 0644
# LOGS_DIR — the /Library/Logs/Cisco/ and SecureClient/ ancestors may
# be pre-existing and shared with other Cisco software. Same reasoning
# as /opt/cisco above: only create them (with our default perms) when
# absent, and unconditionally create + own only our leaf DefenseClaw/
# directory.
for parent in /Library/Logs /Library/Logs/Cisco /Library/Logs/Cisco/SecureClient; do
  ensure_shared_install_parent "${parent}"
done
create_install_directory_reconcile "${LOGS_DIR}" root wheel 0750

# install.log sink — mirrored copy of every stdout / stderr line from
# this point onward, beside gateway.log. Under `.pkg` postinstall /
# installd the caller's stderr is closed and warn/die messages would
# otherwise disappear; the tee gives admins a durable per-session
# record of what the installer did.
#
# Only fires when running as root under a real install (we already
# passed the fresh-host preflight above). Non-root test invocations and
# DC_INSTALLER_SKIP_INSTALL_LOG=1 (bundle-fixture tests) leave the sink
# off. File is root:wheel 0640 so it never becomes a
# reader-writable side channel.
#
# NOT set up earlier: creating LOGS_DIR before the preflight would trip
# "install directory appeared after fresh-host preflight" and creating
# install.log there would require an ugly special case in the marker
# loop. Uninstall wipes LOGS_DIR wholesale on --purge, which cleanly
# removes install.log too — no persistence across install/uninstall
# cycles is desired.
if [[ "${DC_INSTALLER_SKIP_INSTALL_LOG:-}" != "1" ]]; then
  _install_log_path="${LOGS_DIR}/install.log"
  touch "${_install_log_path}" 2>/dev/null || true
  chown root:wheel "${_install_log_path}" 2>/dev/null || true
  chmod 0640       "${_install_log_path}" 2>/dev/null || true
  printf '===== install.sh start %s (argv: %s) =====\n' "$(date -u +%FT%TZ)" "$*" \
    >> "${_install_log_path}" 2>/dev/null || true
  exec  > >(tee -a "${_install_log_path}")
  exec 2> >(tee -a "${_install_log_path}" >&2)
  unset _install_log_path
fi

CONFIG_PATH="${CONFIG_DIR}/config.yaml"
if [[ -L "${CONFIG_PATH}" ]]; then
  die "managed config is a symlink; refusing to overwrite: ${CONFIG_PATH}"
fi
if [[ -e "${CONFIG_PATH}" ]]; then
  log "reconciling managed config (existing ${CONFIG_PATH} will be replaced)"
fi

log "writing config (mode=${MODE} connectors=${CONNECTORS[*]} port=${API_PORT} endpoint=${AID_ENDPOINT} redaction_off=${DISABLE_REDACTION})"
CONFIG_TMP="$(mktemp "${CONFIG_PATH}.new.XXXXXX")" \
  || die "could not reserve a private managed-config staging file"
INSTALL_TEMP_FILES+=("${CONFIG_TMP}")
render_config "${MODE}" "${PRIMARY_CONNECTOR}" "${API_PORT}" "${DISABLE_REDACTION}" "${SUPPORT_DIR}" "${AID_ENDPOINT}" "${CONNECTORS[@]}" > "${CONFIG_TMP}"
chown root:wheel "${CONFIG_TMP}"
chmod 0640 "${CONFIG_TMP}"
# rename(2) is atomic across paths on the same filesystem; the mktemp
# template guarantees the two paths share a parent, so an observer sees
# either the old config or the new one, never a partial write.
/bin/mv -f -- "${CONFIG_TMP}" "${CONFIG_PATH}" \
  || die "could not atomically replace managed config: ${CONFIG_PATH}"
forget_install_temporary "${CONFIG_TMP}"

# Enumerate eligible local users NOW (before the hook-guardian
# manifest render below reuses the same set) so we can also seed
# ai_discovery.home_dirs in the rendered config. Without this,
# the discovery service under launchd/root walks /var/root only
# and misses every user's per-user dotfiles (editor extensions,
# MCP configs, shell history) — see internal/inventory/ai_discovery.go
# for the detectors that key off HomeDir.
log "enumerating eligible local users (for hook-guardian + ai_discovery.home_dirs)"
USER_LINES="$(DC_INSTALLER_ENUMERATE_VERBOSE=1 enumerate_local_users || true)"
USER_COUNT="$(printf '%s\n' "${USER_LINES}" | grep -c . || true)"
if [[ -z "${USER_LINES}" ]]; then
  if [[ "${ALLOW_EMPTY_USERS}" == "true" ]]; then
    warn "no eligible local users detected on this host (--allow-empty-users given)"
    warn "  hooks + ai_discovery will wire for users that log in later once the enumerator's next tick runs"
  else
    die "no eligible local users detected on this host — refusing to install with a zero-target hook-guardian manifest and empty ai_discovery.home_dirs. If this box legitimately has no local users (lab / demo), rerun with --allow-empty-users to proceed; otherwise investigate why enumerate_local_users returned empty (check dscl, home dir perms, /Users layout)."
  fi
else
  log "  found ${USER_COUNT} eligible user(s):"
  while IFS=: read -r _u _uid _gid _home; do
    [[ -z "${_u}" ]] && continue
    log "    ${_u} (uid=${_uid}, home=${_home})"
  done <<< "${USER_LINES}"
  unset _u _uid _gid _home
fi

log "seeding ai_discovery.home_dirs from ${USER_COUNT:-0} eligible user(s)"
apply_ai_discovery_home_dirs "${CONFIG_PATH}" "${USER_LINES}" \
  || die "failed to seed ai_discovery.home_dirs in ${CONFIG_PATH}"

log "chowning runtime dirs to root:wheel (daemon runs as root)"
# Every DefenseClaw-owned directory is root:wheel. The daemon runs as
# root (see plist), so no service-user provisioning is needed. Runtime
# dirs stay owner-only writable (0750) to keep the surface tight for
# anything a future audit tool inspects.
chown -R root:wheel "${RUNTIME_DIR}" "${LOGS_DIR}"

# SUPPORT_DIR + CONFIG_PATH are already root:wheel from the install(1)
# calls above; managed_enterprise trust check accepts them unchanged.

log "installing LaunchDaemon plist -> ${PLIST_DST}"
install_file_reconcile "${PLIST_SRC}" "${PLIST_DST}" root wheel 0644

# Guardian + enumerator plists: the two subsystems together do all
# per-user hook wiring (enumerator re-renders targets.yaml on a 5 min
# tick; guardian is long-running under `enterprise hooks watch` — fsnotify
# on every per-user hook artifact with a 5-min periodic backstop).
[[ -f "${GUARDIAN_PLIST_SRC}" ]] \
  || die "hook-guardian plist source not found (expected ${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist)"
[[ -f "${ENUMERATOR_PLIST_SRC}" ]] \
  || die "hook-enumerator plist source not found (expected ${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-enumerator.plist)"
log "installing hook-guardian plist -> ${GUARDIAN_PLIST_DST}"
install_file_reconcile "${GUARDIAN_PLIST_SRC}" "${GUARDIAN_PLIST_DST}" root wheel 0644
log "installing hook-enumerator plist -> ${ENUMERATOR_PLIST_DST}"
install_file_reconcile "${ENUMERATOR_PLIST_SRC}" "${ENUMERATOR_PLIST_DST}" root wheel 0644

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

# ---- per-user hook wiring (multi-user, via hook guardian) --------------
#
# The pre-2026.7.3 flow ran the per-connector CLI subcommand inline here
# for a single --user or $SUDO_USER, which silently no-op'd whenever
# $SUDO_USER was empty (e.g. under a pkg postinstall) and only covered
# one user even when populated. The customer-shipping pkg therefore
# wired hooks for nobody on a multi-user Mac.
#
# The current flow uses the hook-guardian LaunchDaemon (long-running
# `enterprise hooks watch`: fsnotify on every per-user hook artifact +
# 5-min backstop reconcile) with a machine-wide `targets.yaml` manifest
# that lists every eligible local user × requested connector. A
# companion hook-enumerator LaunchDaemon (5-min tick) re-renders the
# manifest so users provisioned AFTER install are picked up on the next
# reconcile without any per-user login-time action. User tampering with
# a hook config or the per-user hook scripts is repaired within ~1 s of
# the fsnotify event.
#
# Bootstrapping order:
#   1. Render an initial targets.yaml so the guardian's RunAtLoad has
#      real content to reconcile (avoids a 5-min delay before the first
#      user's hooks land on a demo box).
#   2. Bootstrap the hook-enumerator daemon (RunAtLoad will re-render,
#      but our initial file is already good).
#   3. Bootstrap the hook-guardian daemon (RunAtLoad triggers immediate
#      reconcile — hooks land within seconds on the eligible users).

if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  # USER_LINES / USER_COUNT were captured above (see the
  # "enumerating eligible local users" block right after render_config)
  # so both the hook-guardian manifest here and ai_discovery.home_dirs
  # up there see the same eligible-user snapshot.
  log "rendering initial hook-guardian manifest -> ${GUARDIAN_MANIFEST_PATH}"
  MANIFEST_TMP="$(mktemp "${GUARDIAN_MANIFEST_PATH}.new.XXXXXX")" \
    || die "could not reserve a private manifest staging file"
  INSTALL_TEMP_FILES+=("${MANIFEST_TMP}")
  render_targets_manifest "${SUPPORT_DIR}" "${CONNECTOR}" "${USER_LINES}" > "${MANIFEST_TMP}"
  # Belt-and-suspenders: catch the case where user_lines was non-empty
  # AND the connector CSV was non-empty but the rendered cross product
  # still produced zero targets (e.g. every connector was filtered out
  # as unsupported). Without this check the guardian would happily
  # reconcile a "0 targets, all ok" manifest and the daemon would look
  # green while enforcing nothing.
  MANIFEST_TARGETS="$(grep -c '^  - user:' "${MANIFEST_TMP}" || true)"
  if [[ "${MANIFEST_TARGETS}" == "0" ]] && [[ -n "${USER_LINES}" ]] && [[ "${ALLOW_EMPTY_USERS}" != "true" ]]; then
    die "rendered hook-guardian manifest has zero targets despite ${USER_COUNT} eligible user(s) and connectors=${CONNECTOR} — every connector may be unsupported (only codex/claudecode/cursor auto-wire today). Fix --connector or pass --allow-empty-users to proceed anyway."
  fi
  chown root:wheel "${MANIFEST_TMP}"
  chmod 0640 "${MANIFEST_TMP}"
  if [[ -L "${GUARDIAN_MANIFEST_PATH}" ]]; then
    die "guardian manifest is a symlink; refusing to overwrite: ${GUARDIAN_MANIFEST_PATH}"
  fi
  # Atomic replace under the reinstall contract; see the config.yaml
  # rename above for the rationale.
  /bin/mv -f -- "${MANIFEST_TMP}" "${GUARDIAN_MANIFEST_PATH}" \
    || die "could not atomically replace guardian manifest: ${GUARDIAN_MANIFEST_PATH}"
  forget_install_temporary "${MANIFEST_TMP}"

  log "loading hook-enumerator LaunchDaemon"
  launchctl bootstrap system "${ENUMERATOR_PLIST_DST}"
  launchctl enable "system/${ENUMERATOR_LAUNCHD_LABEL}"

  log "loading hook-guardian LaunchDaemon"
  launchctl bootstrap system "${GUARDIAN_PLIST_DST}"
  launchctl enable "system/${GUARDIAN_LAUNCHD_LABEL}"

  # Kick both daemons so the first reconcile happens immediately rather
  # than at the next tick (RunAtLoad already fired, but kickstart is a
  # defence-in-depth in case the daemon was already loaded from a
  # previous state). For the guardian this also forces re-registration
  # of the fsnotify watch set against the freshly rendered manifest.
  log "kickstarting hook-enumerator + hook-guardian for immediate first pass"
  launchctl kickstart -k "system/${ENUMERATOR_LAUNCHD_LABEL}" 2>/dev/null || true
  launchctl kickstart -k "system/${GUARDIAN_LAUNCHD_LABEL}"   2>/dev/null || true
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

  Hook-guardian status (per-user hook wiring):
    sudo launchctl print system/${GUARDIAN_LAUNCHD_LABEL}   | head -20
    sudo launchctl print system/${ENUMERATOR_LAUNCHD_LABEL} | head -20
    sudo cat ${GUARDIAN_MANIFEST_PATH}
    sudo cat ${GUARDIAN_AUTH_DIR}/protected_targets.json

  Force a fresh reconcile after adding a user account:
    sudo launchctl kickstart -k system/${ENUMERATOR_LAUNCHD_LABEL}
    sudo launchctl kickstart -k system/${GUARDIAN_LAUNCHD_LABEL}

  Uninstall:
    sudo ${SCRIPT_DIR}/uninstall.sh
EOF
