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
#   ~/.config/amp/plugins/defenseclaw.ts                   (target-user 0600)
#     Amp's TypeScript plugin is rendered by connector reconciliation; the
#     package never precreates it.
#
# This script orchestrates side-effecting steps (sudo, launchctl, install(8))
# and delegates pure logic (arg parsing, config rendering, version probing,
# userspace prep) to lib/installer_lib.sh so the test suite under tests/
# can drive that logic without root.

set -euo pipefail

readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"

macos_hardware_machine() {
  local machine="$1"
  if [[ "${machine}" == "x86_64" || "${machine}" == "amd64" ]] \
    && [[ -x "${MACOS_SYSCTL_BIN}" && ! -L "${MACOS_SYSCTL_BIN}" ]] \
    && [[ "$("${MACOS_SYSCTL_BIN}" -in sysctl.proc_translated 2>/dev/null || true)" == "1" ]]; then
    printf '%s\n' "arm64"
    return 0
  fi
  printf '%s\n' "${machine}"
}

# ---- defaults -----------------------------------------------------------

DEFAULT_MODE="observe"
DEFAULT_CONNECTOR="codex"
DEFAULT_API_PORT="18970"
DEFAULT_ENV="prod"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd 2>/dev/null || echo "${SCRIPT_DIR}")"
BINARY_SRC=""
ACP_BINARY_SRC=""
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

# Guardrail rule packs source — the sidecar loads them from
# ${DataDir}/policies/guardrail/<profile>/ on cold start. Without them
# the gateway fails init with:
#   rule pack directory_not_found at .: rule-pack directory does not exist
# Bundle layout ships them beside install.sh; dev/CI runs source from
# the repo tree.
POLICIES_SRC=""
for _candidate in \
  "${SCRIPT_DIR}/policies" \
  "${REPO_ROOT}/policies"; do
  if [[ -d "${_candidate}/guardrail/default" ]]; then
    POLICIES_SRC="${_candidate}"
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
#
# DC_INSTALLER_TEST_ROOT re-roots every machine path below under a fixture
# tree and stamps the invoking user instead of root:wheel, so the packaging
# tests can drive a whole install unprivileged. It is honoured only with
# the DC_INSTALLER_SKIP_ROOT_CHECK test seam and never when run as root.
DC_ROOT=""
DC_OWNER="root"
DC_GROUP="wheel"
if [[ -n "${DC_INSTALLER_TEST_ROOT:-}" && "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" == "1" && "${EUID}" -ne 0 ]]; then
  DC_ROOT="${DC_INSTALLER_TEST_ROOT%/}"
  DC_OWNER="$(id -un)"
  DC_GROUP="$(id -gn)"
  export DC_INSTALLER_USERS_ROOT="${DC_ROOT}/Users"
  # The OS folders every Mac has.
  mkdir -p "${DC_ROOT}/Library/LaunchDaemons" "${DC_ROOT}/Users" 2>/dev/null || true
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
GATEWAY_BIN="${INSTALL_PREFIX}/bin/defenseclaw-gateway"
ACP_GUARD_BIN="${INSTALL_PREFIX}/bin/defenseclaw-acp"
RENDER_TARGETS_BIN="${INSTALL_PREFIX}/lib/render-targets.sh"
INSTALLER_LIB_DST="${INSTALL_PREFIX}/lib/installer_lib.sh"
GUARDIAN_MANIFEST_DIR="${INSTALL_PREFIX}/hook-guardian"
GUARDIAN_MANIFEST_PATH="${GUARDIAN_MANIFEST_DIR}/targets.yaml"

# Legacy paths + label from pre-Cisco-path DefenseClaw installs. These
# are only referenced by uninstall.sh for its migration sweep; install.sh
# never writes to them.
LEGACY_INSTALL_PREFIX="${DC_ROOT}/Library/DefenseClaw"
LEGACY_SUPPORT_DIR="${DC_ROOT}/Library/Application Support/DefenseClaw"
LEGACY_LOGS_DIR="${DC_ROOT}/Library/Logs/DefenseClaw"
LEGACY_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.defenseclaw.gateway.plist"
LEGACY_LAUNCHD_LABEL="com.defenseclaw.gateway"
LEGACY_GUARDIAN_PLIST_DST="${DC_ROOT}/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist"
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

# die is reserved for the conditions AVC never triggers: not root, not
# arm64, a bundle missing its own files, and usage errors. Every
# permission, ownership, flag, attribute, structural or prerequisite
# condition is repaired, retried, then logged with a marker (dc_warn /
# dc_marker from installer_lib.sh) and the install continues.
log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

process_machine="$(uname -m)"
hardware_machine="$(macos_hardware_machine "${process_machine}")"
if [[ "$(uname -s)" == "Darwin" && "${hardware_machine}" != "arm64" ]]; then
  printf 'defenseclaw_prereq check="root_installer" component="install" reason="unsupported_arch"\n' >&2
  die "Intel macOS (${process_machine}) is unsupported; the managed macOS package requires Apple Silicon (arm64)"
fi

# The persistent install.log sink is set up LATER (after the fresh-host
# preflight passes and after LOGS_DIR has been created by
# create_install_directory_no_replace). Creating LOGS_DIR before the
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
    rm -f -- "${path}" 2>/dev/null || true
  done
}

# _BOOTED_OUT_PLISTS records the plist paths of launchd jobs this run
# unloaded during the pre-mutation quiesce. If install exits before
# reaching the mutation boundary (binary build failure, missing --binary,
# ensure_shared_install_parent trust refusal, config render failure, …),
# the EXIT trap re-bootstraps each one from the plist still on disk so
# the host does not sit with gateway + guardian + enumerator all stopped
# until reboot. Same failure class as AIFW-34262: services quiesced,
# install aborted mid-flight, no recovery. The list is cleared the
# instant we enter the mutation section (line below marked "clear
# bootout-restore"), because once a new binary has been laid down,
# restoring an old job would mis-match the plist's binary path against
# what is actually installed.
_BOOTED_OUT_PLISTS=()
restore_booted_out_jobs() {
  local plist
  for plist in "${_BOOTED_OUT_PLISTS[@]-}"; do
    [[ -n "${plist}" && -f "${plist}" ]] || continue
    # Best-effort: a supervisor that re-registered the job behind our
    # back will cause this to fail; swallow the error so cleanup_install_
    # temporaries still runs.
    launchctl bootstrap system "${plist}" 2>/dev/null || true
  done
}

install_exit_trap() {
  local status=$?
  if (( status != 0 )); then
    restore_booted_out_jobs
  fi
  cleanup_install_temporaries
}
trap install_exit_trap EXIT

forget_install_temporary() {
  local expected="$1" index
  for index in "${!INSTALL_TEMP_FILES[@]}"; do
    if [[ "${INSTALL_TEMP_FILES[${index}]}" == "${expected}" ]]; then
      unset "INSTALL_TEMP_FILES[${index}]"
      return
    fi
  done
}

# _RECONCILE_REINSTALL flips to "true" in the reconcile-preflight block
# below when this run is reinstalling over an existing DefenseClaw
# machine-wide install. On a fresh install a destination that appears
# anyway (a leftover from a killed install or partial purge, or a
# concurrent writer) is logged as defenseclaw_recover and replaced in
# place; the fresh path still publishes through `ln` first so a
# concurrent writer is noticed rather than silently overwritten.
_RECONCILE_REINSTALL="false"

# Paths whose publication decides the exit status: install exits 0 once
# the binary, the config and the gateway plist are in place, even when
# other components run degraded. Anything recorded here is a core
# artifact that could not be published after repair and retry.
CORE_PUBLISH_FAILED=()

# exit_install_status: exit 0 once the core artifacts are published, even
# when components run degraded (the markers above say which); exit 1 only
# when a core artifact could not be published after repair and retry,
# because then nothing usable was installed.
exit_install_status() {
  if (( ${#CORE_PUBLISH_FAILED[@]} > 0 )); then
    dc_warn "core artifacts could not be published after repair and retry: ${CORE_PUBLISH_FAILED[*]}" \
      defenseclaw_degraded subsystem=install reason=core_publish_failed paths="${CORE_PUBLISH_FAILED[*]}"
    exit 1
  fi
  exit 0
}

# install_file_no_replace SOURCE DESTINATION OWNER GROUP MODE
#
# Publishes SOURCE at DESTINATION through a private temp file and an
# atomic rename. A symlink or wrong-type object at DESTINATION is moved
# aside (never followed); flags and ACLs on an existing destination are
# cleared first so rename(2) over it succeeds. Never exits: a failure is
# logged with a marker and returned as 1.
install_file_no_replace() {
  local source="$1" destination="$2" owner="$3" group="$4" mode="$5"
  local temporary=""
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    if [[ "${_RECONCILE_REINSTALL}" != "true" ]]; then
      log "install destination appeared after fresh-host preflight; replacing it in place: ${destination}"
      dc_marker defenseclaw_recover what=leftover_file path="${destination}"
    fi
    dc_restamp "${destination}" "${owner}:${group}" "${mode}" -f || true
    # A symlink or wrong-type object that could not be moved aside must
    # never be published over: mv onto a folder would land inside it.
    if [[ -L "${destination}" || ( -e "${destination}" && ! -f "${destination}" ) ]]; then
      dc_warn "could not clear structural install destination ${destination}" \
        defenseclaw_accept path="${destination}" reason=replace_failed
      return 1
    fi
  fi
  temporary="$(dc_retry mktemp "${destination}.new.XXXXXX" 2>/dev/null)" || temporary=""
  if [[ -z "${temporary}" ]]; then
    dc_warn "could not reserve a private install file beside ${destination}" \
      defenseclaw_accept path="${destination}" reason=staging_failed
    return 1
  fi
  INSTALL_TEMP_FILES+=("${temporary}")
  if ! install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${temporary}" 2>/dev/null; then
    # install(1) fails outright when it cannot set the owner; copy the
    # bytes and re-stamp instead, which logs whatever it cannot fix.
    if ! /bin/cp -f -- "${source}" "${temporary}"; then
      dc_warn "could not stage ${source} for ${destination}" \
        defenseclaw_accept path="${destination}" reason=staging_failed
      rm -f -- "${temporary}" 2>/dev/null || true
      forget_install_temporary "${temporary}"
      return 1
    fi
    dc_restamp "${temporary}" "${owner}:${group}" "${mode}" -f -q || true
  fi
  # A temp file inherits any inheritable ACL entry on its folder.
  chmod -h -N "${temporary}" 2>/dev/null || true
  if [[ -e "${destination}" ]]; then
    # Reconcile branch: replace the DefenseClaw-owned file atomically.
    # rename(2) inside the same directory is a metadata swap the observer
    # sees as either the old or new file, never partial.
    if ! dc_retry /bin/mv -f -- "${temporary}" "${destination}"; then
      dc_warn "could not atomically replace ${destination}" \
        defenseclaw_accept path="${destination}" reason=replace_failed
      rm -f -- "${temporary}" 2>/dev/null || true
      forget_install_temporary "${temporary}"
      return 1
    fi
  elif ln "${temporary}" "${destination}" 2>/dev/null; then
    rm -f -- "${temporary}" 2>/dev/null || true
  else
    # The destination appeared concurrently (another writer published
    # first). This installer owns the path, so replace it atomically.
    log "install destination appeared concurrently and was preserved by rename: ${destination}"
    dc_marker defenseclaw_recover what=concurrent_publish path="${destination}"
    if ! dc_retry /bin/mv -f -- "${temporary}" "${destination}"; then
      dc_warn "could not atomically replace ${destination}" \
        defenseclaw_accept path="${destination}" reason=replace_failed
      rm -f -- "${temporary}" 2>/dev/null || true
      forget_install_temporary "${temporary}"
      return 1
    fi
  fi
  forget_install_temporary "${temporary}"
  return 0
}

_dc_mkdir_dir() {
  mkdir "$1" 2>/dev/null || [[ -d "$1" && ! -L "$1" ]]
}

# create_install_directory_no_replace PATH OWNER GROUP MODE
#
# Creates or adopts a DefenseClaw-owned directory and stamps it. An
# existing one is re-stamped (flags, ACL, owner, mode); a symlink or
# wrong-type object is moved aside and the directory recreated. Never
# exits: returns 1 only when the directory still does not exist.
create_install_directory_no_replace() {
  local path="$1" owner="$2" group="$3" mode="$4"
  if [[ -e "${path}" || -L "${path}" ]]; then
    if [[ "${_RECONCILE_REINSTALL}" != "true" ]]; then
      log "install directory appeared after fresh-host preflight; adopting it: ${path}"
      dc_marker defenseclaw_recover what=leftover_directory path="${path}"
    fi
    dc_restamp "${path}" "${owner}:${group}" "${mode}" -d || true
    if [[ -d "${path}" && ! -L "${path}" ]]; then
      return 0
    fi
  fi
  if ! dc_retry _dc_mkdir_dir "${path}"; then
    dc_warn "could not create install directory ${path}" \
      defenseclaw_accept path="${path}" reason=mkdir_failed
    return 1
  fi
  dc_restamp "${path}" "${owner}:${group}" "${mode}" -d -q || true
  return 0
}

# AIFW-34262: permission verdicts on a *shared* install parent are advisory.
# That directory belongs to whoever created it (Cisco Secure Client / AVC on a
# managed host), it is re-ACLed on that installer's schedule, and DefenseClaw's
# own directories below it are created and locked down by this script. Failing
# here aborts the install for a condition we do not own and cannot repair.
# Export DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1 to make them fatal again;
# the Go-side pin of the same name is managed.TrustStrictAncestorsEnv.
trust_strict_ancestors() {
  case "$(printf '%s' "${DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

# Mirrors managed.PlatformInstallerOwnedPath: /opt/cisco and /Library/Logs/Cisco
# are ACLed by the Cisco Secure Client installer, so a permission verdict on
# those paths is always advisory. Kept as a named predicate rather than folded
# into the caller because the Go-side twin (managed.PlatformInstallerOwnedPath)
# uses the same list — grep-parity matters for future audits.
platform_installer_owned_path() {
  local path="$1"
  case "${path}" in
    /opt/cisco|/opt/cisco/*|/Library/Logs/Cisco|/Library/Logs/Cisco/*) return 0 ;;
    *) return 1 ;;
  esac
}

# install_time_ancestor_advisory: permission-shaped drift on a
# platform-installer-owned ancestor (/opt/cisco or /Library/Logs/Cisco and
# their descendants) is advisory during install. AVC 5.1.21.3862 regression:
# postinstall re-runs this script after preinstall has already removed
# machine-wide state, and refusing on a shared /Library/Logs/Cisco leaf
# permission left the host with no gateway at all. The Go trust walk is
# symmetric — see managed.AdvisoryAncestorPath and
# managed.TrustStrictAncestorsEnv. Drift on any other ancestor (/opt,
# /Library/Logs) is accepted and logged as defenseclaw_accept by
# trust_ancestor_verdict; only strict mode keeps a verdict fatal.
# Structural drift (missing element, symlink, wrong type) is logged as a
# boundary finding by the callers.
install_time_ancestor_advisory() {
  local path="$1"
  platform_installer_owned_path "${path}"
}

trust_ancestor_verdict() {
  local path="$1"
  local reason="$2"
  # Strict ancestors is an opt-in regression mode that deployments never
  # enable; it alone keeps a permission verdict fatal.
  if trust_strict_ancestors; then
    die "${reason}"
  fi
  if ! install_time_ancestor_advisory "${path}"; then
    dc_warn "${reason}; continuing" defenseclaw_accept path="${path}" reason=ancestor_permissions
    return 0
  fi
  warn "managed_trust_ancestor_advisory: ${reason}; continuing (install-time ancestor permissions are advisory)"
  dc_marker defenseclaw_accept path="${path}" reason=ancestor_permissions
}

# ensure_shared_install_parent PATH: an ancestor of a DefenseClaw tree
# that other software (AVC, the OS) owns. It is created when absent and
# never re-permissioned. A symlink or non-directory there is AVC's or the
# OS's layout choice: it is logged as defenseclaw_boundary with its
# resolved target and the install proceeds. Permission verdicts are
# advisory.
ensure_shared_install_parent() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    if [[ -L "${path}" || ! -d "${path}" ]]; then
      local resolved
      resolved="$(cd -P -- "${path}" 2>/dev/null && pwd -P || echo '?')"
      dc_warn "shared install parent is not a real directory: ${path}; proceeding with the existing layout" \
        defenseclaw_boundary path="${path}" reason=ancestor_not_real_directory resolved="${resolved}"
      return 0
    fi
  else
    create_install_directory_no_replace "${path}" "${DC_OWNER}" "${DC_GROUP}" 0755 || return 0
  fi
  local owner mode acl_output acl_line normalized permissions permission
  local -a acl_permissions
  owner="$(stat -f '%u' "${path}" 2>/dev/null)" || owner=""
  mode="$(stat -f '%Lp' "${path}" 2>/dev/null)" || mode=""
  if [[ -z "${owner}" || ! "${mode}" =~ ^[0-7]+$ ]]; then
    dc_warn "cannot inspect shared install parent: ${path}; continuing" \
      defenseclaw_accept path="${path}" reason=ancestor_uninspectable
    return 0
  fi
  [[ "${owner}" == "0" ]] \
    || trust_ancestor_verdict "${path}" "shared install parent is not root-owned: ${path}"
  (( (8#${mode} & 8#022) == 0 )) \
    || trust_ancestor_verdict "${path}" "shared install parent is group/other writable: ${path} (${mode})"
  acl_output="$(ls -lde -- "${path}" 2>/dev/null)" || {
    dc_warn "cannot inspect shared install parent ACL: ${path}; continuing" \
      defenseclaw_accept path="${path}" reason=ancestor_uninspectable
    return 0
  }
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
          trust_ancestor_verdict "${path}" "shared install parent has a write-capable ACL: ${path}"
          break 2
          ;;
      esac
    done
  done <<<"${acl_output}"
}

DC_MARKER_COMPONENT="install"
# shellcheck source=lib/installer_lib.sh
. "${SCRIPT_DIR}/lib/installer_lib.sh"

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Gateway options:
  --mode {observe|action}   Guardrail + asset_policy mode (default: ${DEFAULT_MODE})
  --connector LIST          Hook connector(s), comma-separated (default: ${DEFAULT_CONNECTOR})
                            Supported: amp, codex, claudecode, copilot, cursor, opencode
                            Examples: --connector amp
                                      --connector amp,cursor,claudecode
  --port PORT               Loopback API port (default: ${DEFAULT_API_PORT})
  --env {prod|preview}      AI Defense cloud environment (default: ${DEFAULT_ENV}).
                            Selects the cisco_ai_defense.endpoint that the
                            managed daemon uses to inspect content.
                            Use 'preview' only for internal validation against
                            the aiteam preview deployment.
  --override-endpoint URL   Point cisco_ai_defense.endpoint at an arbitrary AI
                            Defense HTTPS origin. Takes precedence over --env.
                            Paths, credentials, query, and fragments are refused,
                            e.g.
                            https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com
  --binary PATH             Use prebuilt binary (default: alongside install.sh)
  --plist PATH              Use this LaunchDaemon plist (default: alongside install.sh)
  --skip-build              Reuse an existing gateway binary (no rebuild)
  --skip-launchd            Install files but don't bootstrap/enable launchd

Per-user hook wiring:
  --user USER               Target macOS user (default: \$SUDO_USER)
  --agent-version VERSION   Override agent version (auto-detected if omitted)
  --skip-connector          Don't wire user-space hooks (gateway only)
  --allow-empty-users       Accepted for compatibility; this is now the
                            default. With no eligible local users (a
                            pre-staged Mac) the install logs it and
                            continues, and the hook enumerator enrolls
                            users as they appear.

  -h, --help                Show this help

EOF
}

# ---- arg parsing --------------------------------------------------------

MODE="${DEFAULT_MODE}"
CONNECTOR="${DEFAULT_CONNECTOR}"
API_PORT="${DEFAULT_API_PORT}"
AID_ENV="${DEFAULT_ENV}"
OVERRIDE_ENDPOINT=""
# Zero eligible users is normal on a pre-staged Mac, so this is the
# default; --allow-empty-users is still accepted and changes nothing.
ALLOW_EMPTY_USERS="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)             MODE="${2:?}"; shift 2;;
    --connector)        CONNECTOR="${2:?}"; shift 2;;
    --port)             API_PORT="${2:?}"; shift 2;;
    --env)              AID_ENV="${2:?}"; shift 2;;
    --override-endpoint) OVERRIDE_ENDPOINT="${2:?}"; shift 2;;
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

# --override-endpoint (when set) wins over --env; resolve_aid_endpoint
# validates it and strips a trailing slash. Distinct return codes let us
# report exactly which flag was wrong.
_ep_rc=0
AID_ENDPOINT="$(resolve_aid_endpoint "${AID_ENV}" "${OVERRIDE_ENDPOINT}")" || _ep_rc=$?
if (( _ep_rc == 2 )); then
  die "--override-endpoint must be an HTTPS bare origin (host with optional port; no credentials, path, query, fragment, whitespace, quotes, or backslash; got: ${OVERRIDE_ENDPOINT})"
elif (( _ep_rc != 0 )); then
  die "--env must be 'prod' or 'preview' (got: ${AID_ENV})"
fi
unset _ep_rc
if [[ -n "${OVERRIDE_ENDPOINT}" ]]; then
  log "AI Defense HTTPS endpoint overridden: ${AID_ENDPOINT} (ignoring --env ${AID_ENV})"
fi

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
    warn "connector '${c}' is not in the auto-wire list (amp|codex|claudecode|copilot|cursor|opencode); will be written to config but per-user hooks won't be auto-wired"
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
# Every file the install publishes must be present in the bundle before
# anything is mutated: a bundle missing its own files is the one install
# failure that repair cannot fix.
[[ -f "${GUARDIAN_PLIST_SRC}" ]] \
  || die "hook-guardian plist source not found (expected ${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist)"
[[ -f "${ENUMERATOR_PLIST_SRC}" ]] \
  || die "hook-enumerator plist source not found (expected ${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-enumerator.plist)"
[[ -f "${RENDER_TARGETS_SRC}" ]] \
  || die "render-targets.sh source not found (expected ${SCRIPT_DIR}/lib/render-targets.sh)"
[[ -f "${INSTALLER_LIB_SRC}" ]] \
  || die "installer_lib.sh source not found (expected ${SCRIPT_DIR}/lib/installer_lib.sh)"
[[ -n "${POLICIES_SRC}" ]] \
  || die "guardrail policies source not found (expected ${SCRIPT_DIR}/policies/guardrail/default or ${REPO_ROOT}/policies/guardrail/default)"

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
# Code integrity is advisory: a failed check is logged as
# defenseclaw_boundary and the install continues. The installed copy is
# always published root:wheel 0644, so source permission drift (an
# extraction under umask 002, a re-permissioned bundle folder) never
# reaches launchd.
#
# DC_INSTALLER_SKIP_PLIST_VALIDATION lets bundle-fixture tests drive
# install.sh against a stub plist without also bypassing the euid check.
# This is a separate seam from DC_INSTALLER_SKIP_ROOT_CHECK so tests can
# exercise the validator against non-root-owned fixtures.
if [[ "${DC_INSTALLER_SKIP_PLIST_VALIDATION:-}" != "1" ]]; then
  _plist_stat="$(stat -f '%Su %Lp' "${PLIST_SRC}" 2>/dev/null || echo '')"
  _plist_owner="${_plist_stat%% *}"
  _plist_mode="${_plist_stat##* }"
  if [[ -z "${_plist_stat}" || ! "${_plist_mode}" =~ ^[0-7]+$ ]]; then
    dc_warn "cannot stat plist source ${PLIST_SRC}; publishing it with canonical permissions" \
      defenseclaw_boundary path="${PLIST_SRC}" reason=source_uninspectable origin="${PLIST_SRC_ORIGIN}"
  else
    if [[ "${PLIST_SRC_ORIGIN}" == "override" && "${_plist_owner}" != "root" ]]; then
      dc_warn "plist source ${PLIST_SRC} was passed via --plist / DEFENSECLAW_PLIST_SRC and is not owned by root (got: ${_plist_owner}); publishing it with canonical permissions" \
        defenseclaw_boundary path="${PLIST_SRC}" reason=source_not_root_owned principal="${_plist_owner}" origin=override
    fi
    if (( (8#${_plist_mode} & 8#022) != 0 )); then
      dc_warn "plist source ${PLIST_SRC} is group/other writable (mode ${_plist_mode}); publishing it with canonical permissions" \
        defenseclaw_boundary path="${PLIST_SRC}" reason=source_group_writable mode="${_plist_mode}" origin="${PLIST_SRC_ORIGIN}"
    fi
  fi
  unset _plist_stat _plist_owner _plist_mode
fi

# Per-user hook wiring is no longer scoped to a single TARGET_USER: the
# installer renders a machine-wide `targets.yaml` covering every eligible
# local user, and the hook-guardian LaunchDaemon reconciles that manifest
# reactively via fsnotify — user tampering with a hook config or hook
# script under a watched dir triggers a repair within ~1 s. A 60 s
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

# Idempotent-reinstall contract (managed_enterprise): this installer is
# designed to be run repeatedly against a managed host without needing an
# out-of-band uninstall/upgrade path. The refuse-on-existing behavior
# that used to live here (a die() on any marker, including a stray
# ~/.defenseclaw or ~/.local/bin/defenseclaw in any local account) left
# drifted hosts stuck — AVC's postinstall re-runs this script
# unconditionally after its own preinstall has already removed
# machine-wide state, and a stray per-user file from a prior run was
# aborting a legitimate reinstall (see the AVC 5.1.21.3862 DART).
#
# Reinstall reconciles machine-wide state this installer owns (gateway
# binary, config.yaml, plists, launchd bootstrap, hook-guardian manifest
# and state dir, LOGS_DIR). It never touches per-user ~/.defenseclaw
# (the hook-guardian owns per-user reconciliation on its 60 s tick),
# never touches RUNTIME_DIR data (audit.db, judge_bodies.db, device.key,
# hook-guardian-state), and enumerates per-user consumer markers
# strictly for install.log forensics.
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

# A purge keeps only its own uninstall.log in LOGS_DIR, so a log folder
# holding nothing else is not evidence of an installation.
_logs_dir_is_purge_residue() {
  [[ -d "${LOGS_DIR}" && ! -L "${LOGS_DIR}" ]] || return 1
  local entry
  for entry in "${LOGS_DIR}"/* "${LOGS_DIR}"/.[!.]*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    [[ "${entry##*/}" == "uninstall.log" ]] || return 1
  done
  return 0
}

_found_markers=""
for _marker in "${_current_managed_markers[@]}"; do
  if [[ -e "${_marker}" || -L "${_marker}" ]]; then
    if [[ "${_marker}" == "${LOGS_DIR}" ]] && _logs_dir_is_purge_residue; then
      continue
    fi
    _RECONCILE_REINSTALL="true"
    _found_markers="${_found_markers:+${_found_markers},}${_marker}"
  fi
done
for _label in "${_current_launchd_labels[@]}"; do
  if launchctl print "system/${_label}" >/dev/null 2>&1; then
    _RECONCILE_REINSTALL="true"
    _found_markers="${_found_markers:+${_found_markers},}system/${_label}"
  fi
done
if [[ -n "${_found_markers}" ]]; then
  dc_marker defenseclaw_recover what=existing_install found="${_found_markers}"
fi
unset _found_markers

if [[ "${_RECONCILE_REINSTALL}" == "true" ]]; then
  log "reconciling existing DefenseClaw installation in place (idempotent reinstall)"
else
  log "fresh managed_enterprise install (no existing markers detected)"
fi

# Enumerate per-user consumer markers strictly for install.log
# forensics. The hook-guardian daemon owns the per-user reconcile
# loop, so we do NOT delete these — the guardian will pick them up
# after the machine-wide reinstall lands.
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" || -n "${DC_ROOT}" ]]; then
  # A system-wide managed daemon interacts with a consumer gateway in any
  # account, including an account other than --user/SUDO_USER. Always
  # enumerate every local account's configured home instead of assuming
  # /Users/<name>. dscl failure is not fatal in reconcile mode: the
  # guardian's 60 s tick still reconciles per-user hook wiring even
  # without an install-time enumeration.
  _local_users="$(dscl . -list /Users 2>/dev/null || true)"
  if [[ -z "${_local_users}" ]]; then
    warn "could not enumerate local users via dscl; per-user hook wiring will still be reconciled by the guardian on its 60s tick"
  else
    # Per-user step: a record that vanishes between -list and -read, or
    # has no home, skips that user only.
    while IFS= read -r _local_user; do
      [[ -n "${_local_user}" ]] || continue
      if ! _dscl_record="$(dscl . -read "/Users/${_local_user}" NFSHomeDirectory 2>/dev/null)"; then
        dc_marker defenseclaw_skip unit="user:${_local_user}" reason=dscl_read_failed
        continue
      fi
      _candidate_home="$(printf '%s\n' "${_dscl_record}" | sed -n 's/^NFSHomeDirectory: //p')"
      [[ -n "${_candidate_home}" ]] || continue
      for _u_marker in \
        "${_candidate_home}/.defenseclaw" \
        "${_candidate_home}/.local/bin/defenseclaw" \
        "${_candidate_home}/.local/bin/defenseclaw-gateway" \
        "${_candidate_home}/.local/bin/defenseclaw-acp"; do
        if [[ -e "${_u_marker}" || -L "${_u_marker}" ]]; then
          log "  (informational) per-user artifact present, will be reconciled by hook-guardian: ${_u_marker}"
        fi
      done
    done <<< "${_local_users}"
  fi
fi
if [[ -n "${TARGET_HOME}" ]]; then
  for _u_marker in \
    "${TARGET_HOME}/.defenseclaw" \
    "${TARGET_HOME}/.local/bin/defenseclaw" \
    "${TARGET_HOME}/.local/bin/defenseclaw-gateway" \
    "${TARGET_HOME}/.local/bin/defenseclaw-acp"; do
    if [[ -e "${_u_marker}" || -L "${_u_marker}" ]]; then
      log "  (informational) per-user artifact present in --target-home, will be reconciled by hook-guardian: ${_u_marker}"
    fi
  done
fi

# Package-manager / custom-PATH residue (Homebrew, /usr/local/bin,
# user-installed pip wheels). Same treatment as per-user markers: log,
# don't die. Uninstall.sh cleans these up on the reverse path.
if [[ "${DC_INSTALLER_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  for _installed_command in defenseclaw defenseclaw-gateway defenseclaw-acp; do
    _installed_command_path="$(command -v "${_installed_command}" 2>/dev/null || true)"
    if [[ -n "${_installed_command_path}" ]]; then
      log "  (informational) prior ${_installed_command} on PATH: ${_installed_command_path}"
    fi
  done
fi

# launchd_bootout_until_gone label
#
# Bootout the given system-domain launchd label and verify it's actually
# gone before returning. Some Cisco Secure Client components re-bootstrap
# DefenseClaw's plist on disk shortly after we tear it down (the plist
# file is still present at this point — we haven't rewritten it yet),
# and a back-to-back reinstall can race an external supervisor into
# reappearing the label ~1 s after our initial bootout returned success.
# Retry a few times with short sleeps so the caller can rely on the
# post-condition "label is unloaded".
#
# Prints one log line per retry. Never dies; the caller checks return.
# Returns 0 if the label is gone after the retry budget, non-zero if it
# is still loaded (indicating something is actively re-registering it).
launchd_bootout_until_gone() {
  local _label="$1" _tries=0 _max=6
  # Require _quiet_target consecutive "absent" probes ~0.5 s apart before
  # returning success. A supervisor may re-register the plist a beat
  # after our bootout returned; the initial absence probe would be a
  # false positive (the label was momentarily gone) and the caller's
  # file mutation would then race the re-registration. Two consecutive
  # absent probes prove the label is stably gone through the observed
  # re-registration delay.
  local _quiet_target=2
  while (( _tries < _max )); do
    local _p=0 _seen_present=false
    while (( _p < _quiet_target )); do
      if launchctl print "system/${_label}" >/dev/null 2>&1; then
        _seen_present=true
        break
      fi
      (( _p++ ))
      sleep 0.5
    done
    if [[ "${_seen_present}" == "false" ]]; then
      return 0
    fi
    if (( _tries > 0 )); then
      log "  re-bootout attempt ${_tries} for ${_label} (something re-registered it after quiesce)"
    fi
    launchctl bootout "system/${_label}" >/dev/null 2>&1 || true
    (( _tries++ ))
    sleep 0.5
  done
  # Final probe with the retry budget exhausted.
  launchctl print "system/${_label}" >/dev/null 2>&1 && return 1 || return 0
}

# Unload current-generation launchd jobs BEFORE writing plists and
# binaries. Without this the later `launchctl bootstrap system` races
# an already-loaded job, and even in the racing-doesn't-lose case the
# running daemon holds an open file descriptor on the old binary —
# unloading now guarantees the atomic-replace hits a quiescent target.
# The retry helper handles a supervisor re-bootstrapping the plist
# behind our back on a back-to-back reinstall.
#
# Match each bootout to the bootstrap path this run will actually
# execute. Without this gate, a reconcile with --skip-launchd would
# stop every current-gen job and exit at the SKIP_LAUNCHD short-circuit
# below without re-bootstrapping anything; a reconcile with
# --skip-connector would stop guardian/enumerator whose bootstrap sits
# inside the SKIP_CONNECTOR block. Preserve a loaded job when the
# matching restart path won't run — the operator's running services
# stay running through a partial install.
for _label in "${_current_launchd_labels[@]}"; do
  if ! launchctl print "system/${_label}" >/dev/null 2>&1; then
    continue
  fi
  _label_plist=""
  case "${_label}" in
    "${LAUNCHD_LABEL}")
      # Gateway is bootstrapped at the end of this script unless
      # SKIP_LAUNCHD.
      if [[ "${SKIP_LAUNCHD}" == "true" ]]; then
        log "preserving loaded ${_label} (--skip-launchd will skip its restart)"
        continue
      fi
      _label_plist="${PLIST_DST}"
      ;;
    "${GUARDIAN_LAUNCHD_LABEL}")
      # Guardian/enumerator bootstrap sits inside the SKIP_CONNECTOR
      # block, which itself only runs when SKIP_LAUNCHD is off (the
      # SKIP_LAUNCHD short-circuit exits before it).
      if [[ "${SKIP_LAUNCHD}" == "true" || "${SKIP_CONNECTOR}" == "true" ]]; then
        log "preserving loaded ${_label} (--skip-launchd/--skip-connector will skip its restart)"
        continue
      fi
      _label_plist="${GUARDIAN_PLIST_DST}"
      ;;
    "${ENUMERATOR_LAUNCHD_LABEL}")
      if [[ "${SKIP_LAUNCHD}" == "true" || "${SKIP_CONNECTOR}" == "true" ]]; then
        log "preserving loaded ${_label} (--skip-launchd/--skip-connector will skip its restart)"
        continue
      fi
      _label_plist="${ENUMERATOR_PLIST_DST}"
      ;;
  esac
  log "unloading current launchd job for reinstall: ${_label}"
  if launchd_bootout_until_gone "${_label}"; then
    # Only record the plist for restore on EXIT once the bootout
    # actually succeeded; a failed bootout left the job in place and
    # does not need to be bootstrapped again.
    [[ -n "${_label_plist}" ]] && _BOOTED_OUT_PLISTS+=("${_label_plist}")
  else
    warn "launchctl bootout system/${_label} failed after retries; bootstrap below may still surface a real failure"
  fi
done

# Legacy launchd cleanup: unload pre-Cisco-path labels here on the
# reconcile path. On a fresh install the pre-mutation boundary below
# boots out any loaded legacy job and removes its plist as a recovered
# leftover. Legacy bootout here is also gated on the same SKIP flags as
# its current-gen counterparts — we never stop a service we won't
# replace.
if [[ "${_RECONCILE_REINSTALL}" == "true" && "${SKIP_LAUNCHD}" != "true" ]]; then
  for _label in "${_legacy_launchd_labels[@]}"; do
    if launchctl print "system/${_label}" >/dev/null 2>&1; then
      _label_plist=""
      case "${_label}" in
        "${LEGACY_LAUNCHD_LABEL}") _label_plist="${LEGACY_PLIST_DST}" ;;
        "${LEGACY_GUARDIAN_LAUNCHD_LABEL}") _label_plist="${LEGACY_GUARDIAN_PLIST_DST}" ;;
      esac
      log "unloading legacy launchd job: ${_label}"
      if launchd_bootout_until_gone "${_label}"; then
        [[ -n "${_label_plist}" ]] && _BOOTED_OUT_PLISTS+=("${_label_plist}")
      else
        warn "launchctl bootout system/${_label} failed after retries; legacy plist will be superseded below"
      fi
    fi
  done
fi

unset _current_managed_markers _legacy_managed_paths _current_launchd_labels \
  _legacy_launchd_labels _marker _label _label_plist _local_users _local_user \
  _candidate_home _u_marker _installed_command _installed_command_path _dscl_record

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
  ( cd "${REPO_ROOT}" && go build -o defenseclaw-gateway ./cmd/defenseclaw ) \
    || die "go build of the gateway failed in ${REPO_ROOT}; ship the gateway binary next to install.sh, or pass --binary PATH"
fi
[[ -x "${BINARY_SRC}" ]] || die "binary not found or not executable: ${BINARY_SRC}"

if [[ -x "${SCRIPT_DIR}/defenseclaw-acp" ]]; then
  ACP_BINARY_SRC="${SCRIPT_DIR}/defenseclaw-acp"
elif [[ -x "${REPO_ROOT}/defenseclaw-acp" ]]; then
  ACP_BINARY_SRC="${REPO_ROOT}/defenseclaw-acp"
elif [[ -d "${REPO_ROOT}/cmd/defenseclaw-acp" ]]; then
  command -v go >/dev/null 2>&1 || die "go not in PATH; the ACP guard is required"
  ACP_BINARY_SRC="${REPO_ROOT}/defenseclaw-acp"
  log "building ACP guard from ${REPO_ROOT}/cmd/defenseclaw-acp"
  ( cd "${REPO_ROOT}" && go build -o defenseclaw-acp ./cmd/defenseclaw-acp )
else
  die "required ACP guard is missing; ship defenseclaw-acp next to install.sh"
fi
[[ -x "${ACP_BINARY_SRC}" ]] || die "ACP guard not found or not executable: ${ACP_BINARY_SRC}"

# Repeat the launchd/path boundary immediately before mutation.
#
# The current-generation labels were booted out above (reconcile), and
# this second check catches an external supervisor (typically Cisco
# Secure Client's watchdog) that re-bootstrapped a plist behind our back
# during the local build / binary resolution window, or a job that
# appeared on a fresh host. Each is booted out with the bounded retry.
# A label that survives the budget is logged and the install continues
# with the current state: the plist is still re-published and the
# bootstrap below treats an already-loaded job as loaded.
#
# Legacy (pre-Cisco-path) jobs and plists are leftovers from an older
# install or a partial purge: they are booted out and their plists moved
# aside, then logged as defenseclaw_recover, on fresh and reconcile runs
# alike. A current-generation plist on a fresh host is adopted and
# replaced in place.
for _lbl_plist in \
  "${LAUNCHD_LABEL}:${PLIST_DST}" \
  "${GUARDIAN_LAUNCHD_LABEL}:${GUARDIAN_PLIST_DST}" \
  "${ENUMERATOR_LAUNCHD_LABEL}:${ENUMERATOR_PLIST_DST}" \
  "${LEGACY_LAUNCHD_LABEL}:${LEGACY_PLIST_DST}" \
  "${LEGACY_GUARDIAN_LAUNCHD_LABEL}:${LEGACY_GUARDIAN_PLIST_DST}"; do
  _lbl="${_lbl_plist%%:*}"
  _plist="${_lbl_plist#*:}"
  _is_legacy="false"
  case "${_lbl}" in
    "${LEGACY_LAUNCHD_LABEL}"|"${LEGACY_GUARDIAN_LAUNCHD_LABEL}") _is_legacy="true" ;;
  esac
  # Preserve a loaded job whose restart (or, for legacy jobs, whose
  # replacement) this run will skip.
  if [[ "${_is_legacy}" == "true" && "${SKIP_LAUNCHD}" == "true" ]]; then
    continue
  fi
  if [[ "${_is_legacy}" != "true" ]]; then
    if [[ "${SKIP_LAUNCHD}" == "true" ]] \
       || { [[ "${SKIP_CONNECTOR}" == "true" ]] && [[ "${_lbl}" != "${LAUNCHD_LABEL}" ]]; }; then
      continue
    fi
  fi
  if launchctl print "system/${_lbl}" >/dev/null 2>&1; then
    if [[ "${_RECONCILE_REINSTALL}" == "true" ]]; then
      log "  ${_lbl} reappeared after quiesce; re-bootout before mutation"
    else
      log "  ${_lbl} is loaded on a fresh host; re-bootout before mutation"
      dc_marker defenseclaw_recover what=loaded_label label="${_lbl}"
    fi
    launchd_bootout_until_gone "${_lbl}" \
      || dc_warn "DefenseClaw launchd job ${_lbl} keeps re-registering after quiesce; a supervisor (e.g. Cisco Secure Client watchdog) is holding it. Continuing: the plist at ${_plist} is re-published and an already-loaded job is kickstarted." \
        defenseclaw_degraded subsystem=launchd label="${_lbl}" reason=label_reregistered
  fi
  if [[ "${_is_legacy}" == "true" && ( -e "${_plist}" || -L "${_plist}" ) ]]; then
    # Removed rather than renamed: launchd would load a renamed copy left
    # in /Library/LaunchDaemons at the next boot.
    log "  removing legacy plist: ${_plist}"
    chflags -h nouchg,nouappnd "${_plist}" 2>/dev/null || true
    if dc_retry /bin/rm -f -- "${_plist}"; then
      dc_marker defenseclaw_recover what=legacy_plist path="${_plist}"
    else
      dc_warn "could not remove legacy plist ${_plist}" \
        defenseclaw_accept path="${_plist}" reason=legacy_plist_kept
    fi
  elif [[ "${_RECONCILE_REINSTALL}" != "true" && ( -e "${_plist}" || -L "${_plist}" ) ]]; then
    log "DefenseClaw plist appeared after fresh-host preflight; replacing it in place: ${_plist}"
    dc_marker defenseclaw_recover what=leftover_plist path="${_plist}"
  fi
done
unset _lbl_plist _lbl _plist _is_legacy

# ---- gateway file install ----------------------------------------------

# clear bootout-restore: past this point we start replacing the gateway
# binary and other on-disk state. Re-bootstrapping an old launchd job
# would re-exec stale binaries or race the mutation half-way through, so
# we drop the restore list and rely on the end-of-script bootstrap calls
# to bring the new generation up.
_BOOTED_OUT_PLISTS=()

log "installing binary -> ${GATEWAY_BIN}"
# Ensure every ancestor of INSTALL_PREFIX exists. macOS `install -d`
# reapplies owner/mode to existing directories, so we must not run it
# against /opt/cisco or /opt/cisco/secureclient when those paths are
# already present — they may be shared with other Cisco software whose
# permissions we shouldn't touch. Create them with `mkdir -p` only when
# absent; unconditionally create + own only the DefenseClaw subtree.
#
# Every step from here on repairs, retries, then logs and continues; the
# install tree root also loses any inheritable ACL entry (dc_restamp
# strips the ACL) so newly written files are not re-infected.
for parent in "${DC_ROOT}/opt" "${DC_ROOT}/opt/cisco" "${DC_ROOT}/opt/cisco/secureclient"; do
  ensure_shared_install_parent "${parent}"
done
create_install_directory_no_replace "${INSTALL_PREFIX}" "${DC_OWNER}" "${DC_GROUP}" 0755 || true
create_install_directory_no_replace "${INSTALL_PREFIX}/bin" "${DC_OWNER}" "${DC_GROUP}" 0755 || true
if install_file_no_replace "${BINARY_SRC}" "${GATEWAY_BIN}" "${DC_OWNER}" "${DC_GROUP}" 0755; then
  dc_strip_quarantine "${GATEWAY_BIN}"
else
  CORE_PUBLISH_FAILED+=("${GATEWAY_BIN}")
fi
# The ACP guard is required like the gateway binary, so a failed publish
# is a core failure too.
if install_file_no_replace "${ACP_BINARY_SRC}" "${ACP_GUARD_BIN}" "${DC_OWNER}" "${DC_GROUP}" 0755; then
  dc_strip_quarantine "${ACP_GUARD_BIN}"
else
  CORE_PUBLISH_FAILED+=("${ACP_GUARD_BIN}")
fi

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
create_install_directory_no_replace "${CONFIG_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0755 || true
create_install_directory_no_replace "${RUNTIME_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0750 || true
# Leftover hook-guardian-state entries are not wiped here: the guardian
# repairs its own ledger before its first read.
create_install_directory_no_replace "${GUARDIAN_AUTH_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0750 || true

# Stage the shipped guardrail rule packs under runtime/policies/. The
# gateway's cold-start sidecar init reads
# ${DataDir}/policies/guardrail/default/ (see config default in
# internal/config/config.go:3573). Ship all three profiles so an
# operator can retarget rule_pack_dir at strict/permissive without a
# reinstall.
POLICIES_DST="${RUNTIME_DIR}/policies"
create_install_directory_no_replace "${POLICIES_DST}" "${DC_OWNER}" "${DC_GROUP}" 0750 || true
log "installing guardrail rule packs -> ${POLICIES_DST}/guardrail"
# Stage the replacement rule-pack tree in a sibling directory and swap
# atomically so the gateway is never left with a partially-copied
# policy tree if cp fails mid-copy (macOS cp(1) can leave a partial
# destination on I/O error) and so the old tree is available for
# rollback until the new one is in place.
#
# The rule-pack tree carries no operator state — it's fully re-rendered
# from the shipped bundle every install — so wholesale replacement is
# safe. A symlink at the destination is never written through: it is
# unlinked (its target untouched) and the tree is published in its place.
# Any failure below keeps the current rule packs and the install goes on.
if [[ -L "${POLICIES_DST}/guardrail" ]]; then
  log "guardrail policies destination is a symlink; refusing to overwrite through it: ${POLICIES_DST}/guardrail"
  dc_move_aside "${POLICIES_DST}/guardrail" symlink || true
elif [[ -e "${POLICIES_DST}/guardrail" && ! -d "${POLICIES_DST}/guardrail" ]]; then
  dc_move_aside "${POLICIES_DST}/guardrail" wrong_type || true
fi
_guardrail_stage="${POLICIES_DST}/guardrail.new"
# Unique-per-run rescue path. Rationale: a prior invocation whose swap
# succeeded but whose gateway startup was NOT verified (--skip-launchd,
# aborted run, or a doubly-broken swap+rollback) leaves its rescue
# tree at `${POLICIES_DST}/guardrail.old-<its pid>-<its ts>/`. If we
# reused a single `.old` path here, the next live-to-old mv would
# overwrite that prior baseline with the (possibly bad) current live
# tree — losing the last-known-good copy. A fresh path per run means
# any accumulated rescue trees survive intact through this swap and
# are all cleaned in a single sweep after wait_for_launchd_running
# succeeds — i.e., only once verified startup confirms the freshly-
# published rule packs actually work.
_guardrail_old="${POLICIES_DST}/guardrail.old-$$-$(date +%Y%m%d%H%M%S)"
# Clean stray staging from an aborted prior install. Any `.old-*`
# trees present are prior rescue baselines and are DELIBERATELY not
# touched here — they're cleaned by the post-verification sweep
# further down, after the freshly-published tree has proven to boot
# the gateway. `_guardrail_stage` is always safe to wipe.
publish_guardrail_tree() {
  # A stale stage from an aborted run may carry flags; dc_remove_path
  # clears them before deleting.
  if ! dc_remove_path "${_guardrail_stage}"; then
    dc_warn "could not remove stale guardrail stage ${_guardrail_stage}; keeping the current rule packs" \
      defenseclaw_accept path="${_guardrail_stage}" reason=stale_stage_kept
    return 1
  fi
  if ! cp -R "${POLICIES_SRC}/guardrail" "${_guardrail_stage}"; then
    dc_remove_path "${_guardrail_stage}" || true
    dc_warn "could not stage guardrail rule packs at ${_guardrail_stage}; keeping the current rule packs" \
      defenseclaw_accept path="${_guardrail_stage}" reason=stage_failed
    return 1
  fi
  dc_restamp "${_guardrail_stage}" "${DC_OWNER}:${DC_GROUP}" 0750 -R -d -q || true
  /usr/bin/find "${_guardrail_stage}" -type d -exec chmod 0750 {} + 2>/dev/null || true
  /usr/bin/find "${_guardrail_stage}" -type f -exec chmod 0640 {} + 2>/dev/null || true
  # Sanity-check the staged tree before touching the running tree. The
  # `default/` profile is required by the gateway's cold-start sidecar
  # init (see internal/config/config.go:3573). A cp that ended with an
  # I/O error would leave a tree without it.
  if [[ ! -d "${_guardrail_stage}/default" ]]; then
    dc_remove_path "${_guardrail_stage}" || true
    dc_warn "staged guardrail rule packs are missing the required default profile at ${_guardrail_stage}/default; refusing to swap, keeping the current rule packs" \
      defenseclaw_accept path="${_guardrail_stage}" reason=stage_incomplete
    return 1
  fi
  # Move any existing tree aside first, then move the staged tree into
  # place. Both moves are atomic rename(2) calls within the same parent
  # directory; a flag on the live tree is cleared first so the rename
  # succeeds. If the second move fails, restore the old tree so the
  # gateway keeps its working rule packs.
  if [[ -e "${POLICIES_DST}/guardrail" ]]; then
    dc_restamp "${POLICIES_DST}/guardrail" "${DC_OWNER}:${DC_GROUP}" 0750 -R -d >/dev/null 2>&1 || true
    if ! dc_retry /bin/mv -f -- "${POLICIES_DST}/guardrail" "${_guardrail_old}"; then
      dc_remove_path "${_guardrail_stage}" || true
      dc_warn "could not move current guardrail tree aside at ${POLICIES_DST}/guardrail; keeping the current rule packs" \
        defenseclaw_accept path="${POLICIES_DST}/guardrail" reason=swap_failed
      return 1
    fi
  fi
  if ! dc_retry /bin/mv -f -- "${_guardrail_stage}" "${POLICIES_DST}/guardrail"; then
    # Best-effort rollback so the gateway keeps its working rule packs.
    # If the rollback ALSO fails, the previous tree survives only at
    # ${_guardrail_old}: name it, and the next install keeps it because
    # rescue trees are swept only after a verified gateway start.
    if [[ -d "${_guardrail_old}" ]] \
       && ! dc_retry /bin/mv -f -- "${_guardrail_old}" "${POLICIES_DST}/guardrail"; then
      dc_remove_path "${_guardrail_stage}" || true
      dc_warn "could not publish new guardrail tree at ${POLICIES_DST}/guardrail and could not restore previous tree; previous rule packs are preserved at ${_guardrail_old}" \
        defenseclaw_degraded subsystem=guardrail_rule_packs reason=publish_and_restore_failed path="${_guardrail_old}"
      return 1
    fi
    dc_remove_path "${_guardrail_stage}" || true
    dc_warn "could not publish new guardrail tree at ${POLICIES_DST}/guardrail; keeping the current rule packs" \
      defenseclaw_accept path="${POLICIES_DST}/guardrail" reason=publish_failed
    return 1
  fi
  return 0
}
publish_guardrail_tree || true
# Rescue tree cleanup is DEFERRED to after wait_for_launchd_running
# succeeds — see the sweep below the gateway-up probe. Removing
# ${_guardrail_old} here would strand the operator without a rollback
# path if the gateway then fails to start with the new rule packs.
unset _guardrail_stage
# Multi-user hook wiring: the hook-guardian LaunchDaemon reads its
# per-tick manifest from ${GUARDIAN_MANIFEST_DIR}/targets.yaml. Creating
# the directory unconditionally keeps the guardian's LoadManifest happy
# even if the enumerator hasn't run yet.
create_install_directory_no_replace "${GUARDIAN_MANIFEST_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0755 || true
create_install_directory_no_replace "${INSTALL_PREFIX}/lib" "${DC_OWNER}" "${DC_GROUP}" 0755 || true
# render-targets.sh is invoked by the hook-enumerator LaunchDaemon and
# sources installer_lib.sh from a fixed path; both must land under the
# managed tree so the daemon doesn't need to see the bundle layout. Both
# sources were checked in the preflight.
install_file_no_replace "${RENDER_TARGETS_SRC}" "${RENDER_TARGETS_BIN}" "${DC_OWNER}" "${DC_GROUP}" 0755 \
  || dc_warn "hook enumerator script not refreshed; the enumerator keeps its previous copy" \
       defenseclaw_degraded subsystem=enumerator reason=script_not_published path="${RENDER_TARGETS_BIN}"
install_file_no_replace "${INSTALLER_LIB_SRC}"  "${INSTALLER_LIB_DST}" "${DC_OWNER}" "${DC_GROUP}" 0644 \
  || dc_warn "installer library not refreshed; the enumerator keeps its previous copy" \
       defenseclaw_degraded subsystem=enumerator reason=library_not_published path="${INSTALLER_LIB_DST}"
dc_strip_quarantine "${RENDER_TARGETS_BIN}" "${INSTALLER_LIB_DST}"
# LOGS_DIR — the /Library/Logs/Cisco/ and SecureClient/ ancestors may
# be pre-existing and shared with other Cisco software. Same reasoning
# as /opt/cisco above: only create them (with our default perms) when
# absent, and unconditionally create + own only our leaf DefenseClaw/
# directory.
for parent in "${DC_ROOT}/Library/Logs" "${DC_ROOT}/Library/Logs/Cisco" "${DC_ROOT}/Library/Logs/Cisco/SecureClient"; do
  ensure_shared_install_parent "${parent}"
done
create_install_directory_no_replace "${LOGS_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0750 || true

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
# Without a usable LOGS_DIR (already logged above) the install runs with
# console output only.
if [[ "${DC_INSTALLER_SKIP_INSTALL_LOG:-}" != "1" && -d "${LOGS_DIR}" && ! -L "${LOGS_DIR}" ]]; then
  _install_log_path="${LOGS_DIR}/install.log"
  # Never append through a link; clear a flag that would block appends.
  dc_restamp "${_install_log_path}" "${DC_OWNER}:${DC_GROUP}" 0640 -f || true
  touch "${_install_log_path}" 2>/dev/null || true
  chown "${DC_OWNER}:${DC_GROUP}" "${_install_log_path}" 2>/dev/null || true
  chmod 0640       "${_install_log_path}" 2>/dev/null || true
  printf '===== install.sh start %s (argv: %s) =====\n' "$(date -u +%FT%TZ)" "$*" \
    >> "${_install_log_path}" 2>/dev/null || true
  exec  > >(tee -a "${_install_log_path}")
  exec 2> >(tee -a "${_install_log_path}" >&2)
  unset _install_log_path
fi

CONFIG_PATH="${CONFIG_DIR}/config.yaml"
# Under reconcile, config.yaml legitimately exists from the prior install
# and will be atomically replaced by the rendered version below. On a
# fresh install a pre-existing config is a leftover: it is logged and
# replaced in place. A symlink is never written through in either mode:
# it is unlinked (target untouched) and the config is published there.
if [[ -L "${CONFIG_PATH}" ]]; then
  log "managed config is a symlink; refusing to overwrite through it: ${CONFIG_PATH}"
  dc_move_aside "${CONFIG_PATH}" symlink || true
elif [[ -e "${CONFIG_PATH}" && ! -f "${CONFIG_PATH}" ]]; then
  dc_move_aside "${CONFIG_PATH}" wrong_type || true
fi
if [[ -e "${CONFIG_PATH}" && "${_RECONCILE_REINSTALL}" != "true" ]]; then
  log "managed config appeared after fresh-host preflight and was preserved until replaced: ${CONFIG_PATH}"
fi

# Enumerate eligible local user homes so the sidecar's per-user AI-discovery
# detectors (skills / rules / plugins / MCP under ~/.claude, ~/.codex, …) can
# scan every real user rather than just the launchd-daemon HOME (/var/root
# under root, where no operator has any real agent state). We pass the list
# to render_config which writes it as `ai_discovery.home_dirs` in the
# managed config so the daemon's `~/.claude/skills`-style expansions resolve
# to each user's actual home. Uses the same enumerate_local_users filter
# that populates targets.yaml so per-user detection and per-user hook
# wiring stay in lockstep.
HOME_DIRS=()
if _user_lines_for_home_dirs="$(enumerate_local_users 2>/dev/null || true)"; then
  while IFS=: read -r _u _uid _gid _home; do
    [[ -z "${_home}" ]] && continue
    HOME_DIRS+=("${_home}")
  done <<< "${_user_lines_for_home_dirs}"
  unset _u _uid _gid _home _user_lines_for_home_dirs
fi

log "writing config (mode=${MODE} connectors=${CONNECTORS[*]} port=${API_PORT} env=${AID_ENV} redaction_profile=sensitive home_dirs=${#HOME_DIRS[@]})"
publish_config() {
  local rendered=""
  rendered="$(dc_retry mktemp "${CONFIG_PATH}.new.XXXXXX" 2>/dev/null)" || rendered=""
  if [[ -z "${rendered}" ]]; then
    dc_warn "could not reserve a private managed-config staging file beside ${CONFIG_PATH}" \
      defenseclaw_accept path="${CONFIG_PATH}" reason=staging_failed
    return 1
  fi
  INSTALL_TEMP_FILES+=("${rendered}")
  if ! render_config "${MODE}" "${PRIMARY_CONNECTOR}" "${API_PORT}" "${SUPPORT_DIR}" "${AID_ENDPOINT}" \
      "${#HOME_DIRS[@]}" "${HOME_DIRS[@]+"${HOME_DIRS[@]}"}" \
      "${CONNECTORS[@]}" > "${rendered}"; then
    dc_warn "could not render the managed config" \
      defenseclaw_accept path="${CONFIG_PATH}" reason=render_failed
    return 1
  fi
  # The same no-follow publication as every other installed file: clears
  # flags and ACLs on the old config, renames atomically, and replaces a
  # leftover or concurrently published copy in place.
  install_file_no_replace "${rendered}" "${CONFIG_PATH}" "${DC_OWNER}" "${DC_GROUP}" 0640 || {
    dc_warn "could not atomically replace managed config: ${CONFIG_PATH}" \
      defenseclaw_accept path="${CONFIG_PATH}" reason=replace_failed
    return 1
  }
  rm -f -- "${rendered}" 2>/dev/null || true
  forget_install_temporary "${rendered}"
  return 0
}
publish_config || CORE_PUBLISH_FAILED+=("${CONFIG_PATH}")

log "re-stamping runtime dirs to root:wheel (daemon runs as root)"
# Every DefenseClaw-owned directory is root:wheel. The daemon runs as
# root (see plist), so no service-user provisioning is needed. Runtime
# dirs stay owner-only writable (0750) to keep the surface tight for
# anything a future audit tool inspects. Flags and ACLs are cleared
# across both trees first, so one flagged audit.db or log file is
# repaired instead of aborting the install; nothing inside runtime/ is
# wiped (the gateway and guardian repair their own state).
dc_restamp "${RUNTIME_DIR}" "${DC_OWNER}:${DC_GROUP}" 0750 -R -d || true
dc_restamp "${LOGS_DIR}" "${DC_OWNER}:${DC_GROUP}" 0750 -R -d || true

log "installing LaunchDaemon plist -> ${PLIST_DST}"
install_file_no_replace "${PLIST_SRC}" "${PLIST_DST}" "${DC_OWNER}" "${DC_GROUP}" 0644 \
  || CORE_PUBLISH_FAILED+=("${PLIST_DST}")

# Guardian + enumerator plists: the two subsystems together do all
# per-user hook wiring (enumerator re-renders targets.yaml on a 5 min
# tick; guardian is long-running under `enterprise hooks watch` — fsnotify
# on every per-user hook artifact with a 60 s periodic backstop). Their
# sources were checked in the preflight.
log "installing hook-guardian plist -> ${GUARDIAN_PLIST_DST}"
install_file_no_replace "${GUARDIAN_PLIST_SRC}" "${GUARDIAN_PLIST_DST}" "${DC_OWNER}" "${DC_GROUP}" 0644 \
  || dc_warn "hook-guardian plist not refreshed" \
       defenseclaw_degraded subsystem=guardian reason=plist_not_published path="${GUARDIAN_PLIST_DST}"
log "installing hook-enumerator plist -> ${ENUMERATOR_PLIST_DST}"
install_file_no_replace "${ENUMERATOR_PLIST_SRC}" "${ENUMERATOR_PLIST_DST}" "${DC_OWNER}" "${DC_GROUP}" 0644 \
  || dc_warn "hook-enumerator plist not refreshed" \
       defenseclaw_degraded subsystem=enumerator reason=plist_not_published path="${ENUMERATOR_PLIST_DST}"

# The shipped plist deliberately omits UserName/GroupName so the daemon
# runs as root (uid 0). If a stale plist from a pre-root DefenseClaw
# install left those keys behind on this host, strip them now so the
# daemon doesn't get pinned to a legacy service user that no longer
# exists (or would fail on managed cloud auth, which needs root).
log "stripping any legacy UserName/GroupName from installed plist"
/usr/bin/plutil -remove UserName  "${PLIST_DST}" >/dev/null 2>&1 || true
/usr/bin/plutil -remove GroupName "${PLIST_DST}" >/dev/null 2>&1 || true

# ---- canonical plist copies and integrity manifest -----------------------
#
# Internal reference copies the root services repair from; the bundle
# file set and the published plists are unchanged.
#
#   etc/launchd/<label>.plist         the plist exactly as published here
#                                     (after the legacy-key strip)
#   etc/launchd/<label>.plist.sha256  its SHA-256: bare lowercase hex
#   etc/integrity.sha256              `shasum -a 256` lines ("<hex>  <path>")
#                                     for every file in bin/, lib/*.sh
#                                     and libexec/
#
# A copy or manifest that cannot be written is logged; never fatal.
CANONICAL_LAUNCHD_DIR="${CONFIG_DIR}/launchd"
INTEGRITY_MANIFEST="${CONFIG_DIR}/integrity.sha256"

# write_install_text_file DESTINATION MODE: publish stdin at DESTINATION.
write_install_text_file() {
  local destination="$1" mode="$2" staged=""
  staged="$(mktemp "${TMPDIR:-/tmp}/defenseclaw-install.XXXXXX" 2>/dev/null)" || return 1
  INSTALL_TEMP_FILES+=("${staged}")
  if ! cat > "${staged}"; then
    rm -f -- "${staged}" 2>/dev/null || true
    forget_install_temporary "${staged}"
    return 1
  fi
  local rc=0
  install_file_no_replace "${staged}" "${destination}" "${DC_OWNER}" "${DC_GROUP}" "${mode}" || rc=1
  rm -f -- "${staged}" 2>/dev/null || true
  forget_install_temporary "${staged}"
  return "${rc}"
}

publish_canonical_plists() {
  create_install_directory_no_replace "${CANONICAL_LAUNCHD_DIR}" "${DC_OWNER}" "${DC_GROUP}" 0755 || return 1
  local pair label published digest failed=""
  for pair in \
    "${LAUNCHD_LABEL}:${PLIST_DST}" \
    "${GUARDIAN_LAUNCHD_LABEL}:${GUARDIAN_PLIST_DST}" \
    "${ENUMERATOR_LAUNCHD_LABEL}:${ENUMERATOR_PLIST_DST}"; do
    label="${pair%%:*}"
    published="${pair#*:}"
    if [[ ! -f "${published}" || -L "${published}" ]]; then
      failed="${failed:+${failed},}${label}"
      continue
    fi
    if ! install_file_no_replace "${published}" "${CANONICAL_LAUNCHD_DIR}/${label}.plist" \
        "${DC_OWNER}" "${DC_GROUP}" 0644; then
      failed="${failed:+${failed},}${label}"
      continue
    fi
    digest="$(dc_sha256_hex "${CANONICAL_LAUNCHD_DIR}/${label}.plist")" || digest=""
    if [[ -z "${digest}" ]] \
       || ! printf '%s' "${digest}" | write_install_text_file "${CANONICAL_LAUNCHD_DIR}/${label}.plist.sha256" 0644; then
      failed="${failed:+${failed},}${label}"
    fi
  done
  if [[ -n "${failed}" ]]; then
    dc_warn "canonical plist copies not written for: ${failed}" \
      defenseclaw_degraded subsystem=canonical_plists reason=write_failed labels="${failed}" path="${CANONICAL_LAUNCHD_DIR}"
    return 1
  fi
  return 0
}

publish_integrity_manifest() {
  local -a files=()
  local f
  while IFS= read -r f; do
    [[ -n "${f}" ]] && files+=("${f}")
  done < <(
    {
      /usr/bin/find "${INSTALL_PREFIX}/bin" -type f 2>/dev/null
      /usr/bin/find "${INSTALL_PREFIX}/lib" -maxdepth 1 -type f -name '*.sh' 2>/dev/null
      /usr/bin/find "${INSTALL_PREFIX}/libexec" -type f 2>/dev/null
    } | LC_ALL=C sort
  )
  if (( ${#files[@]} == 0 )); then
    dc_warn "no installed files found for the integrity manifest" \
      defenseclaw_degraded subsystem=integrity_manifest reason=no_files path="${INTEGRITY_MANIFEST}"
    return 1
  fi
  local listing=""
  if ! listing="$(/usr/bin/shasum -a 256 "${files[@]}")" \
     || ! printf '%s\n' "${listing}" | write_install_text_file "${INTEGRITY_MANIFEST}" 0644; then
    dc_warn "could not write the integrity manifest ${INTEGRITY_MANIFEST}" \
      defenseclaw_degraded subsystem=integrity_manifest reason=write_failed path="${INTEGRITY_MANIFEST}"
    return 1
  fi
  return 0
}

log "recording canonical plist copies -> ${CANONICAL_LAUNCHD_DIR}"
publish_canonical_plists || true
log "recording installed file digests -> ${INTEGRITY_MANIFEST}"
publish_integrity_manifest || true

if [[ "${SKIP_LAUNCHD}" == "true" ]]; then
  log "skipping launchctl bootstrap (--skip-launchd)"
  exit_install_status
fi

# ---- launchd ------------------------------------------------------------

# bootstrap_launchd_job LABEL PLIST: load one LaunchDaemon. The label is
# enabled first, because a persisted `launchctl disable` override makes
# bootstrap fail. Never aborts the install: an already-loaded job (a
# supervisor re-registered it) is kickstarted; any other failure gets one
# retry, then is logged as defenseclaw_degraded and the remaining jobs
# are still loaded.
bootstrap_launchd_job() {
  local label="$1" plist="$2" err=""
  launchctl enable "system/${label}" >/dev/null 2>&1 || true
  if err="$(launchctl bootstrap system "${plist}" 2>&1)"; then
    return 0
  fi
  if launchctl print "system/${label}" >/dev/null 2>&1; then
    log "  ${label} is already loaded; kickstarting it"
    launchctl kickstart -k "system/${label}" >/dev/null 2>&1 || true
    return 0
  fi
  sleep "${DC_RETRY_SLEEP}" 2>/dev/null || true
  if err="$(launchctl bootstrap system "${plist}" 2>&1)"; then
    return 0
  fi
  dc_warn "launchctl bootstrap failed for ${label}: ${err}" \
    defenseclaw_degraded subsystem=launchd label="${label}" reason=bootstrap_failed detail="${err}"
  return 1
}

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
# 60 s backstop reconcile) with a machine-wide `targets.yaml` manifest
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
#   2. Bootstrap the hook-guardian daemon (RunAtLoad triggers immediate
#      reconcile — hooks land within seconds on the eligible users).
#   3. Bootstrap the gateway and wait for it.
#   4. Bootstrap the hook-enumerator daemon (RunAtLoad will re-render,
#      but our initial file is already good), then confirm the guardian
#      and enumerator are loaded.

if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  log "enumerating eligible local users"
  # DC_INSTALLER_ENUMERATE_VERBOSE=1 makes enumerate_local_users emit a
  # WARN for every user it drops with the specific filter reason (system
  # account, home not under /Users, mode bits, etc.). Piped into
  # install.log via the tee at the top of this script, so admins can
  # diagnose "why isn't user X in targets.yaml?" after the fact.
  USER_LINES="$(DC_INSTALLER_ENUMERATE_VERBOSE=1 enumerate_local_users || true)"
  USER_COUNT="$(printf '%s\n' "${USER_LINES}" | grep -c . || true)"
  if [[ -z "${USER_LINES}" ]]; then
    # Normal on a pre-staged Mac (no user exists yet): the guardian and
    # enumerator are still bootstrapped and enroll users as they appear.
    warn "no eligible local users detected on this host; continuing with an empty hook-guardian manifest"
    warn "  hooks will be wired for users that log in later once the enumerator's next 5-min tick runs"
    dc_marker defenseclaw_accept reason=no_eligible_users path="${GUARDIAN_MANIFEST_PATH}"
  else
    log "  found ${USER_COUNT} eligible user(s):"
    while IFS=: read -r _u _uid _gid _home; do
      [[ -z "${_u}" ]] && continue
      log "    ${_u} (uid=${_uid}, home=${_home})"
    done <<< "${USER_LINES}"
    unset _u _uid _gid _home
  fi

  log "rendering initial hook-guardian manifest -> ${GUARDIAN_MANIFEST_PATH}"
  # A manifest that cannot be staged or rendered is not fatal: the
  # guardian keeps the previous targets.yaml (or starts with none) and
  # the enumerator renders a fresh one on its first tick.
  MANIFEST_PUBLISHABLE="true"
  MANIFEST_TMP="$(dc_retry mktemp "${GUARDIAN_MANIFEST_PATH}.new.XXXXXX" 2>/dev/null)" || MANIFEST_TMP=""
  if [[ -z "${MANIFEST_TMP}" ]]; then
    dc_warn "could not reserve a private manifest staging file; the hook enumerator renders the manifest on its first tick" \
      defenseclaw_degraded subsystem=manifest reason=staging_failed path="${GUARDIAN_MANIFEST_PATH}"
    MANIFEST_PUBLISHABLE="false"
    MANIFEST_TMP="/dev/null"
  else
    INSTALL_TEMP_FILES+=("${MANIFEST_TMP}")
  fi
  # Discovery-error side channel: discover_agent_version's per-connector
  # probes distinguish "metadata absent" (file not there → connector not
  # installed) from "metadata present but malformed" (JSON parse fails)
  # by appending a record to this file. Each record is one user ×
  # connector unit: it is skipped and logged, and every other unit is
  # still rendered.
  DISCOVERY_ERRORS_LOG="$(mktemp "${TMPDIR:-/tmp}/defenseclaw-discovery-errors.XXXXXX" 2>/dev/null)" \
    || DISCOVERY_ERRORS_LOG=""
  if [[ -n "${DISCOVERY_ERRORS_LOG}" ]]; then
    INSTALL_TEMP_FILES+=("${DISCOVERY_ERRORS_LOG}")
  fi
  if [[ "${MANIFEST_PUBLISHABLE}" == "true" ]] \
     && ! DC_DISCOVERY_ERRORS_LOG="${DISCOVERY_ERRORS_LOG}" \
       render_targets_manifest "${SUPPORT_DIR}" "${CONNECTOR}" "${USER_LINES}" \
       > "${MANIFEST_TMP}"; then
    dc_warn "rendering the hook-guardian manifest failed; the hook enumerator renders it on its first tick" \
      defenseclaw_degraded subsystem=manifest reason=render_failed path="${GUARDIAN_MANIFEST_PATH}"
    MANIFEST_PUBLISHABLE="false"
  fi

  # Count rendered target rows up-front so the discovery-error report
  # below can distinguish "corrupt metadata blocked every target" from
  # "corrupt metadata affected one connector but others still resolved".
  # The prior implementation die()'d on ANY discovery error, which would
  # fail an install for the whole box just because one user had a
  # single truncated package.json — the reconciler never got a chance
  # to run for the connectors that DID resolve cleanly.
  MANIFEST_TARGETS="0"
  if [[ "${MANIFEST_PUBLISHABLE}" == "true" ]]; then
    MANIFEST_TARGETS="$(grep -c '^  - user:' "${MANIFEST_TMP}" || true)"
  fi

  # Report per-record discovery errors (operator visibility into what
  # needs repair): each affected user × connector is skipped and logged,
  # and the install proceeds even when that left the manifest empty —
  # an agent auto-update mid-write is transient, and the enumerator's
  # tick wires the affected connectors once the metadata parses again.
  # De-duplicated so a shared-metadata failure (e.g. a system-wide
  # /usr/local/lib/node_modules/... corrupted across every user) does not
  # spam one line per user.
  if [[ -n "${DISCOVERY_ERRORS_LOG}" && -s "${DISCOVERY_ERRORS_LOG}" ]]; then
    warn "hook-guardian manifest rendering hit connector metadata errors:"
    while IFS=$'\t' read -r user connector reason path; do
      warn "  user=${user:-<none>} connector=${connector} reason=${reason} path=${path}"
      dc_marker defenseclaw_skip unit="user:${user:-<none>}" connector="${connector}" \
        reason="${reason}" path="${path}"
    done < <(sort -u "${DISCOVERY_ERRORS_LOG}")
    warn "  proceeding — repair the listed file(s) so the affected connectors get wired on the next enumerator tick"
  fi
  unset DC_DISCOVERY_ERRORS_LOG

  # A user_lines-non-empty × connector-non-empty cross product that
  # still resolves to zero targets means either (a) every requested
  # connector is unsupported (not in amp/codex/claudecode/copilot/cursor/opencode) or
  # (b) no eligible user has any of the requested connector CLIs
  # installed yet (AIFW-31486: the AVC-shipped .pkg lands on boxes
  # where amp/Codex/ClaudeCode/Cursor haven't been installed yet).
  #
  # We do NOT fail the install here — bootstrapping the daemons with
  # an empty manifest is still useful: the hook-enumerator LaunchDaemon
  # re-renders targets.yaml on a 5-min tick, so as soon as a user
  # installs a supported connector the guardian picks it up and wires
  # hooks without any operator action. Failing the install would leave
  # the customer with no reconciler running at all.
  #
  # classify_zero_target_reason distinguishes the two modes above so an
  # operator scanning install.log knows whether to (a) rerun with a
  # supported --connector value or (b) just wait for the enumerator's
  # tick to pick up the connector once someone installs it. Units with
  # corrupt metadata were already reported and skipped above.
  if [[ "${MANIFEST_TARGETS}" == "0" ]] && [[ -n "${USER_LINES}" ]]; then
    ZERO_TARGET_REASON="$(classify_zero_target_reason "${CONNECTOR}" || true)"
    case "${ZERO_TARGET_REASON}" in
      all-unsupported)
        warn "hook-guardian manifest has zero targets: no requested connector is auto-wireable (supported today: amp|codex|claudecode|copilot|cursor|opencode; got connectors=${CONNECTOR})"
        warn "  proceeding anyway — the hook-enumerator's tick will NOT fix this on its own; rerun the installer with --connector picking a supported entry"
        ;;
      *)
        warn "hook-guardian manifest has zero targets (users=${USER_COUNT}, connectors=${CONNECTOR}); no supported connector CLI is installed for any eligible user yet"
        warn "  proceeding anyway — the hook-enumerator's 5-min tick will re-render targets.yaml and the hook-guardian will wire hooks automatically once a connector appears"
        ;;
    esac
    unset ZERO_TARGET_REASON
  fi
  # Reconcile: atomically replace the existing targets.yaml (the guardian
  # reads it via fsnotify and reconciles on the next tick). The same
  # publication as every installed file: a symlink there is never written
  # through (it is unlinked, target untouched), flags and ACLs are
  # cleared, and the rename is atomic.
  if [[ "${MANIFEST_PUBLISHABLE}" == "true" ]]; then
    if [[ -L "${GUARDIAN_MANIFEST_PATH}" ]]; then
      log "hook-guardian manifest is a symlink; refusing to overwrite through it: ${GUARDIAN_MANIFEST_PATH}"
    fi
    install_file_no_replace "${MANIFEST_TMP}" "${GUARDIAN_MANIFEST_PATH}" "${DC_OWNER}" "${DC_GROUP}" 0640 \
      || dc_warn "could not atomically replace hook-guardian manifest: ${GUARDIAN_MANIFEST_PATH}; the hook enumerator renders it on its first tick" \
           defenseclaw_degraded subsystem=manifest reason=publish_failed path="${GUARDIAN_MANIFEST_PATH}"
    rm -f -- "${MANIFEST_TMP}" 2>/dev/null || true
    forget_install_temporary "${MANIFEST_TMP}"
  fi
fi

# ---- host prerequisites --------------------------------------------------
#
# Logged as defenseclaw_prereq; a missing prerequisite never stops the
# install (the affected component runs degraded and the services re-check
# on every tick). Run here, with the binary installed and the services
# quiesced, so the port check never mistakes the previous gateway for a
# foreign listener.
dc_run_prereq_checks "${GATEWAY_BIN}" "${INSTALL_PREFIX}" "${API_PORT}" || true

# Bootstrap order: the guardian first (the repair authority must run
# even when the gateway cannot start), then the gateway, then the
# enumerator. Each job is enabled before its bootstrap (a persisted
# disable override makes bootstrap fail) and loaded on its own: a
# failure to load one is logged and never keeps the next from loading.
if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  log "loading hook-guardian LaunchDaemon"
  bootstrap_launchd_job "${GUARDIAN_LAUNCHD_LABEL}" "${GUARDIAN_PLIST_DST}" || true
fi

log "loading LaunchDaemon"
bootstrap_launchd_job "${LAUNCHD_LABEL}" "${PLIST_DST}" || true

GATEWAY_WAIT_SECONDS="${DC_INSTALLER_GATEWAY_WAIT_SECONDS:-15}"
wait_for_launchd_running() {
  local deadline=$(( $(date +%s) + GATEWAY_WAIT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | grep -qE '^[[:space:]]+state = running'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

log "waiting for gateway to come up"
GATEWAY_VERIFIED="false"
if wait_for_launchd_running; then
  GATEWAY_VERIFIED="true"
else
  warn "gateway did not reach running state within ${GATEWAY_WAIT_SECONDS}s; recent stderr:"
  tail -20 "${LOGS_DIR}/gateway.err.log" 2>/dev/null | sed 's/^/    /' >&2 || true
  # Never abort here: the services were quiesced above, and the guardian
  # and enumerator below are the repair authority. launchd KeepAlive keeps
  # retrying the gateway, which starts degraded rather than not at all.
  #
  # Do NOT clean the guardrail rescue tree(s) here — if the gateway
  # did not come up with the freshly-published rule packs, the operator
  # may want to roll back to the last known-good tree at ${_guardrail_old}
  # (and to any older `.old-*` trees preserved by prior unverified runs).
  dc_warn "${LAUNCHD_LABEL} is not running yet; see ${LOGS_DIR}/gateway.err.log — freshly-published guardrail rule packs are at ${POLICIES_DST}/guardrail; prior-run rescue trees preserved under ${POLICIES_DST}/guardrail.old-*" \
    defenseclaw_degraded subsystem=gateway label="${LAUNCHD_LABEL}" reason=not_running_after_bootstrap
fi

# Verified live: the gateway is running with the freshly-published
# rule packs. Only now is it safe to delete the rescue tree(s) —
# earlier deletion would strand the operator without a rollback path
# if startup panicked on the new packs.
#
# Filter the sweep to trees whose encoded PID is NOT currently alive
# so a concurrent install.sh whose own `wait_for_launchd_running`
# hasn't finished yet keeps its rescue tree at `.old-<its-pid>-<its-ts>`.
# Without this filter, whichever run finishes first would wipe every
# other in-flight run's rescue.
#
# find is used rather than a shell glob so `nullglob` state doesn't
# matter and unmatched patterns are silent. The rescue tree name
# format is `guardrail.old-<pid>-<utc-timestamp>` (see the swap block
# above), so the PID is the first `-`-delimited field after the
# `guardrail.old-` prefix.
if [[ "${GATEWAY_VERIFIED}" == "true" && -n "${_guardrail_old:-}" ]]; then
  while IFS= read -r _rescue; do
    [[ -n "${_rescue}" ]] || continue
    _rescue_base="$(/usr/bin/basename -- "${_rescue}")"
    _rescue_pid="${_rescue_base#guardrail.old-}"
    _rescue_pid="${_rescue_pid%%-*}"
    # A tree owned by THIS process is always safe to clean — we've
    # just verified our own startup. Only other-PID trees need the
    # liveness check.
    if [[ "${_rescue_pid}" != "$$" ]] \
        && [[ "${_rescue_pid}" =~ ^[0-9]+$ ]] \
        && /bin/kill -0 "${_rescue_pid}" 2>/dev/null; then
      log "  preserving concurrent-run rescue tree ${_rescue} (pid ${_rescue_pid} still active)"
      continue
    fi
    rm -rf -- "${_rescue}" 2>/dev/null || true
  done < <(/usr/bin/find "${POLICIES_DST}" -mindepth 1 -maxdepth 1 -type d -name 'guardrail.old-*' 2>/dev/null)
  unset _guardrail_old _rescue _rescue_base _rescue_pid
fi

# Enumerator last: it re-renders the manifest the guardian already
# loaded, so it starts once the guardian and gateway are up.
if [[ "${SKIP_CONNECTOR}" != "true" ]]; then
  log "loading hook-enumerator LaunchDaemon"
  bootstrap_launchd_job "${ENUMERATOR_LAUNCHD_LABEL}" "${ENUMERATOR_PLIST_DST}" || true

  # Kick both daemons so the first reconcile happens immediately rather
  # than at the next tick (RunAtLoad already fired, but kickstart is a
  # defence-in-depth in case the daemon was already loaded from a
  # previous state). For the guardian this also forces re-registration
  # of the fsnotify watch set against the freshly rendered manifest.
  log "kickstarting hook-enumerator + hook-guardian for immediate first pass"
  launchctl kickstart -k "system/${ENUMERATOR_LAUNCHD_LABEL}" 2>/dev/null || true
  launchctl kickstart -k "system/${GUARDIAN_LAUNCHD_LABEL}"   2>/dev/null || true

  # The guardian is the repair authority and the enumerator enrolls new
  # users: a job that is not loaded now is reported, never fatal.
  for _label in "${GUARDIAN_LAUNCHD_LABEL}" "${ENUMERATOR_LAUNCHD_LABEL}"; do
    if ! launchctl print "system/${_label}" >/dev/null 2>&1; then
      dc_warn "${_label} is not loaded after bootstrap" \
        defenseclaw_degraded subsystem=launchd label="${_label}" reason=not_loaded_after_bootstrap
    fi
  done
  unset _label
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

exit_install_status
