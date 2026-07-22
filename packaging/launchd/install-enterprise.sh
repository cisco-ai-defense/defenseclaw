#!/usr/bin/env bash

set -euo pipefail
umask 077

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

BINARY_ROOT=/opt/cisco/secureclient/defenseclaw
BIN_DIR="${BINARY_ROOT}/bin"
ETC_DIR="/opt/cisco/secureclient/defenseclaw/etc"
RUNTIME_DIR="/opt/cisco/secureclient/defenseclaw/runtime"
GUARDIAN_DIR="/opt/cisco/secureclient/defenseclaw/hook-guardian"
AUTH_DIR="/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
LOG_VENDOR_DIR=/Library/Logs/Cisco
LOG_PRODUCT_DIR=/Library/Logs/Cisco/SecureClient
LOG_DIR=/Library/Logs/Cisco/SecureClient/DefenseClaw
CONFIG_DEST="/opt/cisco/secureclient/defenseclaw/etc/config.yaml"
MANIFEST_DEST="/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml"
GATEWAY_LABEL=com.cisco.secureclient.defenseclaw
GUARDIAN_LABEL=com.cisco.secureclient.defenseclaw.hook-guardian
GATEWAY_PLIST_DEST=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
GUARDIAN_PLIST_DEST=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist
LEGACY_BINARY_ROOT=/Library/DefenseClaw
LEGACY_MANAGED_ROOT="/Library/Application Support/DefenseClaw"
LEGACY_LOG_DIR=/Library/Logs/DefenseClaw
LEGACY_GATEWAY_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.gateway.plist
LEGACY_GUARDIAN_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist

die() {
    printf 'defenseclaw enterprise install: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'defenseclaw enterprise install: warning: %s\n' "$*" >&2
}

usage() {
    cat <<'EOF'
Usage:
  sudo ./packaging/launchd/install-enterprise.sh \
    --config /path/to/config.yaml \
    --manifest /path/to/targets.yaml \
    [--binary /path/to/defenseclaw] [--no-start]

Installs the macOS managed-enterprise gateway and guardian. The managed
config is atomically installed as root:wheel with mode 0640 and is
verified before either LaunchDaemon can start.

Both LaunchDaemons run as root. No dedicated service user or group is created
or required.

Options:
  --config PATH    Administrator-approved managed config (required)
  --manifest PATH  Administrator-approved guardian targets (required)
  --binary PATH    Gateway binary (default: release archive root/defenseclaw)
  --no-start       Install and verify files without loading LaunchDaemons
  --help           Show this help
EOF
}

refuse_symlink() {
    local path="$1"
    [ ! -L "$path" ] || die "refusing symlink path: $path"
}

assert_no_write_acl() {
    local path="$1"
    local output line normalized permissions permission
    local -a acl_permissions
    output="$(/bin/ls -lde -- "$path")" || die "cannot inspect macOS ACL: $path"
    while IFS= read -r line; do
        normalized="$(printf '%s' "$line" | /usr/bin/tr '[:upper:]' '[:lower:]')"
        normalized="${normalized#"${normalized%%[![:space:]]*}"}"
        [[ "$normalized" =~ ^[0-9]+: ]] || continue
        [[ "$normalized" == *" allow "* ]] || continue
        permissions="${normalized#* allow }"
        permissions="${permissions%% *}"
        [ -n "$permissions" ] || die "cannot parse macOS allow ACL: $path"
        IFS=',' read -r -a acl_permissions <<<"$permissions"
        for permission in "${acl_permissions[@]}"; do
            case "$permission" in
                write|add_file|append|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)
                    die "write-capable macOS ACL is not trusted: $path"
                    ;;
            esac
        done
    done <<<"$output"
}

require_regular_source() {
    local path="$1"
    local label="$2"
    [ -n "$path" ] || die "$label path is required"
    refuse_symlink "$path"
    [ -f "$path" ] || die "$label is not a regular file: $path"
}

assert_trusted_file_source() {
    local path="$1"
    local label="$2"
    local uid mode parent current component trimmed_parent
    local -a source_parts
    require_regular_source "$path" "$label"
    assert_no_write_acl "$path"
    uid="$(/usr/bin/stat -f '%u' "$path")"
    mode="$(/usr/bin/stat -f '%Lp' "$path")"
    [ "$uid" = 0 ] || die "$label is not root-owned: $path"
    [ $((8#$mode & 8#022)) -eq 0 ] || die "$label is group/other writable: $path ($mode)"

    parent="$(dirname "$path")"
    case "$path" in
        /*)
            current="/"
            assert_trusted_system_dir "$current"
            trimmed_parent="${parent#/}"
            ;;
        *)
            current="$(pwd -P)"
            assert_trusted_system_dir "$current"
            trimmed_parent="$parent"
            ;;
    esac
    IFS='/' read -r -a source_parts <<<"$trimmed_parent"
    for component in "${source_parts[@]}"; do
        [ -n "$component" ] || continue
        case "$component" in
            .) continue ;;
            ..) die "$label path must not contain parent traversal: $path" ;;
        esac
        if [ "$current" = "/" ]; then
            current="/${component}"
        else
            current="${current}/${component}"
        fi
        assert_trusted_system_dir "$current"
    done
}

assert_trusted_system_dir() {
    local path="$1"
    local uid mode
    refuse_symlink "$path"
    [ -d "$path" ] || die "required system directory is missing: $path"
    assert_no_write_acl "$path"
    uid="$(/usr/bin/stat -f '%u' "$path")"
    mode="$(/usr/bin/stat -f '%Lp' "$path")"
    [ "$uid" = 0 ] || die "system directory is not root-owned: $path"
    [ $((8#$mode & 8#022)) -eq 0 ] || die "system directory is group/other writable: $path ($mode)"
}

assert_existing_secure_dir_or_absent() {
    local path="$1"
    [ -e "$path" ] || {
        refuse_symlink "$path"
        return
    }
    assert_trusted_system_dir "$path"
}

assert_path_metadata() {
    local path="$1"
    local kind="$2"
    local expected_uid="$3"
    local expected_gid="$4"
    local expected_mode="$5"
    local uid gid mode
    refuse_symlink "$path"
    case "$kind" in
        file) [ -f "$path" ] || die "installed path is not a regular file: $path" ;;
        dir) [ -d "$path" ] || die "installed path is not a directory: $path" ;;
        *) die "unknown metadata kind: $kind" ;;
    esac
    assert_no_write_acl "$path"
    uid="$(/usr/bin/stat -f '%u' "$path")"
    gid="$(/usr/bin/stat -f '%g' "$path")"
    mode="$(/usr/bin/stat -f '%Lp' "$path")"
    [ "$uid" = "$expected_uid" ] || die "unexpected owner uid for $path: $uid"
    [ "$gid" = "$expected_gid" ] || die "unexpected group gid for $path: $gid"
    [ "$mode" = "$expected_mode" ] || die "unexpected mode for $path: $mode"
}

TEMP_FILES=()
ROLLBACK_DESTINATIONS=()
ROLLBACK_BACKUPS=()
ROLLBACK_EXISTED=()
ROLLBACK_DIR=
ROLLBACK_ARMED=false
GATEWAY_WAS_LOADED=false
GUARDIAN_WAS_LOADED=false

snapshot_file() {
    local destination="$1"
    local index="${#ROLLBACK_DESTINATIONS[@]}"
    local backup="${ROLLBACK_DIR}/${index}"
    ROLLBACK_DESTINATIONS+=("$destination")
    if [ -e "$destination" ]; then
        refuse_symlink "$destination"
        [ -f "$destination" ] || die "existing destination is not a regular file: $destination"
        ROLLBACK_BACKUPS+=("$backup")
        ROLLBACK_EXISTED+=(true)
        /bin/cp -p "$destination" "$backup"
    else
        ROLLBACK_BACKUPS+=("")
        ROLLBACK_EXISTED+=(false)
    fi
}

restore_snapshots() {
    local index destination backup temporary
    local failed=false
    for ((index = ${#ROLLBACK_DESTINATIONS[@]} - 1; index >= 0; index--)); do
        destination="${ROLLBACK_DESTINATIONS[$index]}"
        if [ "${ROLLBACK_EXISTED[$index]}" = true ]; then
            backup="${ROLLBACK_BACKUPS[$index]}"
            temporary="${destination}.rollback.$$"
            if [ -e "$temporary" ] || [ -L "$temporary" ]; then
                warn "cannot restore $destination: rollback temporary path exists"
                failed=true
                continue
            fi
            if ! /bin/cp -p "$backup" "$temporary" || ! /bin/mv -f -- "$temporary" "$destination"; then
                warn "failed to restore $destination"
                /bin/rm -f -- "$temporary" || true
                failed=true
            fi
        elif ! /bin/rm -f -- "$destination"; then
            warn "failed to remove newly installed file: $destination"
            failed=true
        fi
    done
    [ "$failed" = false ]
}

rebootstrap_previously_loaded_job() {
    local was_loaded="$1"
    local label="$2"
    local plist="$3"
    [ "$was_loaded" = true ] || return 0
    if [ ! -f "$plist" ]; then
        warn "cannot restore loaded job ${label}: plist was not restored"
        return 1
    fi
    if ! /bin/launchctl bootstrap system "$plist"; then
        warn "failed to restore loaded job ${label}"
        return 1
    fi
    if ! /bin/launchctl kickstart -k "system/${label}"; then
        warn "restored but could not restart job ${label}"
        return 1
    fi
}

rollback_install() {
    local failed=false
    ROLLBACK_ARMED=false
    /bin/launchctl bootout "system/${GUARDIAN_LABEL}" >/dev/null 2>&1 || true
    /bin/launchctl bootout "system/${GATEWAY_LABEL}" >/dev/null 2>&1 || true
    restore_snapshots || failed=true
    rebootstrap_previously_loaded_job "$GATEWAY_WAS_LOADED" "$GATEWAY_LABEL" "$GATEWAY_PLIST_DEST" || failed=true
    rebootstrap_previously_loaded_job "$GUARDIAN_WAS_LOADED" "$GUARDIAN_LABEL" "$GUARDIAN_PLIST_DEST" || failed=true
    if [ "$failed" = true ]; then
        warn "rollback was incomplete; inspect the installation before retrying"
    fi
}

cleanup() {
    local status=$?
    local path
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$ROLLBACK_ARMED" = true ]; then
        rollback_install
    fi
    for path in "${TEMP_FILES[@]-}" "${ROLLBACK_BACKUPS[@]-}"; do
        [ -n "$path" ] || continue
        /bin/rm -f -- "$path" || true
    done
    if [ -n "$ROLLBACK_DIR" ]; then
        /bin/rmdir "$ROLLBACK_DIR" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

forget_temporary() {
    local expected="$1"
    local index
    for index in "${!TEMP_FILES[@]}"; do
        if [ "${TEMP_FILES[${index}]}" = "$expected" ]; then
            unset "TEMP_FILES[${index}]"
            return
        fi
    done
}

install_file_atomic() {
    # install_file_atomic SRC DST OWNER GROUP MODE
    #
    # Overwrites DST from SRC with the requested owner/group/mode via
    # rename(2) — atomic on the same filesystem, so an observer sees
    # either the old file or the new one, never a partial write. This
    # implements the idempotent-reinstall contract; an existing regular
    # file is expected on a second install and is replaced.
    #
    # Symlinks at DST are refused: a symlink under a root-owned install
    # path can only be there via privileged tampering, and the atomic
    # rename would otherwise clobber whatever the symlink points at.
    local source="$1"
    local destination="$2"
    local owner="$3"
    local group="$4"
    local mode="$5"
    local temporary
    refuse_symlink "$destination"
    temporary="$(/usr/bin/mktemp "${destination}.new.XXXXXX")" \
        || die "could not reserve a private install file beside $destination"
    TEMP_FILES+=("$temporary")
    /usr/bin/install -o "$owner" -g "$group" -m "$mode" "$source" "$temporary"
    /bin/mv -f -- "$temporary" "$destination" \
        || die "could not atomically replace $destination"
    forget_temporary "$temporary"
}

create_directory_no_replace() {
    # create_directory_no_replace PATH OWNER GROUP MODE
    #
    # Ensures PATH exists as a directory with the requested owner/group
    # and mode. Existing directory contents are preserved — the
    # idempotent-reinstall contract treats runtime dirs (audit.db,
    # device.key, hook-guardian-state) as data-carrying and NEVER wipes
    # them. Symlinks at PATH are refused for the same reason as
    # install_file_atomic.
    #
    # Name kept as-is (rather than renamed to _reconcile) because the
    # existing callers and tests reference this exact identifier; the
    # "_no_replace" suffix now describes "existing directory contents
    # are not replaced" rather than "the directory itself must not
    # exist".
    local path="$1"
    local owner="$2"
    local group="$3"
    local mode="$4"
    refuse_symlink "$path"
    if [ -e "$path" ]; then
        [ -d "$path" ] || die "install directory path exists but is not a directory: $path"
    else
        /bin/mkdir -- "$path" \
            || die "could not create install directory: $path"
    fi
    /usr/sbin/chown "$owner:$group" "$path"
    /bin/chmod "$mode" "$path"
}

plist_pins_managed_mode() {
    local path="$1"
    local mode
    /usr/bin/plutil -lint "$path" >/dev/null || return 1
    mode="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:DEFENSECLAW_DEPLOYMENT_MODE' "$path" 2>/dev/null)" || return 1
    [ "$mode" = managed_enterprise ]
}

stop_job_if_loaded() {
    local label="$1"
    if /bin/launchctl print "system/${label}" >/dev/null 2>&1; then
        /bin/launchctl bootout "system/${label}" || die "failed to unload ${label}"
    fi
}

SCRIPT_PATH="$0"
case "$SCRIPT_PATH" in
    /*) ;;
    *) SCRIPT_PATH="$(pwd -P)/${SCRIPT_PATH}" ;;
esac
refuse_symlink "$SCRIPT_PATH"
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_PATH")" && pwd)"

CONFIG_SOURCE=
MANIFEST_SOURCE=
BINARY_SOURCE="$(cd -P "${SCRIPT_DIR}/../.." && pwd)/defenseclaw"
START_JOBS=true

while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)
            [ "$#" -ge 2 ] || die "--config requires a path"
            CONFIG_SOURCE="$2"
            shift 2
            ;;
        --manifest)
            [ "$#" -ge 2 ] || die "--manifest requires a path"
            MANIFEST_SOURCE="$2"
            shift 2
            ;;
        --binary)
            [ "$#" -ge 2 ] || die "--binary requires a path"
            BINARY_SOURCE="$2"
            shift 2
            ;;
        --no-start)
            START_JOBS=false
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[ "$(/usr/bin/uname -s)" = Darwin ] || die "this installer supports macOS only"
[ "$EUID" -eq 0 ] || die "run this installer as root"

# Idempotent-reinstall contract (see PR notes for the drift analysis):
# this installer is designed to be run repeatedly against a managed host.
# The refuse-on-existing behavior that used to live here (a die() on any
# marker, including a stray ~/.defenseclaw in ANY local account) left
# drifted hosts stuck — a second run made no changes and machine-wide
# state stayed whatever the first install produced. The rollback
# machinery further down (snapshot_file + restore_snapshots) is designed
# to handle overlapping runs safely, and the install_file_atomic writer
# now overwrites existing regular files under the reinstall contract.
#
# Reinstall reconciles machine-wide state this installer owns (binary,
# config, manifest, plists, launchd bootstrap). It never touches
# per-user ~/.defenseclaw — those are owned by the hook-guardian daemon
# on its 60s reconcile tick. It relocates legacy paths from the
# pre-Cisco layout under LOG_DIR with a timestamped suffix (best-effort;
# not deleted) so operators keep forensic access.

_reconcile_current=false
for _current_path in \
    "$BINARY_ROOT" \
    "$LOG_DIR" \
    "$GATEWAY_PLIST_DEST" \
    "$GUARDIAN_PLIST_DEST"; do
    if [ -e "$_current_path" ] || [ -L "$_current_path" ]; then
        _reconcile_current=true
        break
    fi
done
if [ "$_reconcile_current" = false ]; then
    for _current_label in \
        com.cisco.secureclient.defenseclaw \
        com.cisco.secureclient.defenseclaw.hook-guardian; do
        if /bin/launchctl print "system/${_current_label}" >/dev/null 2>&1; then
            _reconcile_current=true
            break
        fi
    done
fi
if [ "$_reconcile_current" = true ]; then
    printf 'defenseclaw enterprise install: reconciling existing DefenseClaw installation in place (idempotent reinstall)\n'
else
    printf 'defenseclaw enterprise install: fresh managed_enterprise install (no existing markers detected)\n'
fi
unset _reconcile_current _current_path _current_label

# Per-user consumer markers are informational only. The hook-guardian
# daemon (bootstrapped below) reconciles the per-user layer on its own
# 60s tick; deleting or refusing on them here would rip audit history
# out from under users.
local_users="$(/usr/bin/dscl . -list /Users 2>/dev/null || true)"
if [ -z "$local_users" ]; then
    warn "could not enumerate local users via dscl; per-user hook wiring will still be reconciled by the guardian on its 60s tick"
else
    while IFS= read -r local_user; do
        [ -n "$local_user" ] || continue
        local_home="$(/usr/bin/dscl . -read "/Users/${local_user}" NFSHomeDirectory 2>/dev/null \
            | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')"
        [ -n "$local_home" ] || continue
        case "$local_home" in
            /*) ;;
            *) continue ;;
        esac
        for _user_marker in \
            "${local_home}/.defenseclaw" \
            "${local_home}/.local/bin/defenseclaw" \
            "${local_home}/.local/bin/defenseclaw-gateway"; do
            if [ -e "$_user_marker" ] || [ -L "$_user_marker" ]; then
                printf 'defenseclaw enterprise install: (informational) per-user artifact present, will be reconciled by hook-guardian: %s\n' "$_user_marker"
            fi
        done
    done <<<"$local_users"
fi
unset local_users local_user local_home _user_marker

# Unload legacy launchd labels (pre-Cisco path). Their plists point at
# binaries that no longer exist on a current install, so leaving them
# loaded produces spawn-and-crash log noise. Best-effort; the legacy
# plist files themselves are relocated below.
for _legacy_label in \
    com.defenseclaw.gateway \
    com.defenseclaw.hook-guardian; do
    if /bin/launchctl print "system/${_legacy_label}" >/dev/null 2>&1; then
        printf 'defenseclaw enterprise install: unloading legacy launchd job: %s\n' "$_legacy_label"
        /bin/launchctl bootout "system/${_legacy_label}" >/dev/null 2>&1 \
            || warn "launchctl bootout system/${_legacy_label} failed; the legacy plist will still be relocated below"
    fi
done
unset _legacy_label

# Ensure LOG_DIR exists early so the legacy relocation below has a
# landing zone. Recreated with the right ownership later during the
# mutation phase; a bare directory here is enough.
for _log_parent in /Library/Logs "$LOG_VENDOR_DIR" "$LOG_PRODUCT_DIR"; do
    if [ ! -d "$_log_parent" ]; then
        /bin/mkdir -p "$_log_parent" 2>/dev/null || true
    fi
done
if [ ! -d "$LOG_DIR" ]; then
    /bin/mkdir -p "$LOG_DIR" 2>/dev/null || true
    /usr/sbin/chown root:wheel "$LOG_DIR" 2>/dev/null || true
    /bin/chmod 0750 "$LOG_DIR" 2>/dev/null || true
fi
unset _log_parent

# Move legacy paths aside (best-effort, timestamped, never deleted).
# Version tag comes from the binary source when available so the backup
# path is distinguishable across attempts.
_installer_version_tag="$("$BINARY_SOURCE" --version 2>/dev/null | head -1 || true)"
[ -z "$_installer_version_tag" ] && _installer_version_tag="unknown"
_installer_version_tag="$(printf '%s' "$_installer_version_tag" | /usr/bin/tr -c '[:alnum:]._-' '_' | /usr/bin/head -c 32)"
[ -z "$_installer_version_tag" ] && _installer_version_tag="unknown"
_legacy_timestamp="$(/bin/date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo unknown)"
for _legacy_path in \
    "$LEGACY_BINARY_ROOT" \
    "$LEGACY_MANAGED_ROOT" \
    "$LEGACY_LOG_DIR" \
    "$LEGACY_GATEWAY_PLIST_DEST" \
    "$LEGACY_GUARDIAN_PLIST_DEST"; do
    if [ -e "$_legacy_path" ] || [ -L "$_legacy_path" ]; then
        _legacy_base="$(/usr/bin/basename -- "$_legacy_path")"
        _legacy_target="${LOG_DIR}/${_legacy_base}.pre-${_installer_version_tag}-${_legacy_timestamp}"
        _legacy_suffix=""
        _legacy_i=0
        while [ -e "${_legacy_target}${_legacy_suffix}" ] || [ -L "${_legacy_target}${_legacy_suffix}" ]; do
            _legacy_suffix=".${_legacy_i}"
            _legacy_i=$((_legacy_i + 1))
            [ "$_legacy_i" -lt 100 ] || break
        done
        _legacy_target="${_legacy_target}${_legacy_suffix}"
        if /bin/mv -- "$_legacy_path" "$_legacy_target" 2>/dev/null; then
            printf 'defenseclaw enterprise install: moved legacy path aside: %s -> %s\n' "$_legacy_path" "$_legacy_target"
        else
            warn "could not relocate legacy path $_legacy_path; leaving it in place"
        fi
    fi
done
unset _installer_version_tag _legacy_timestamp _legacy_path _legacy_base \
    _legacy_target _legacy_suffix _legacy_i

assert_trusted_file_source "$CONFIG_SOURCE" "managed config"
assert_trusted_file_source "$MANIFEST_SOURCE" "guardian manifest"
require_regular_source "$BINARY_SOURCE" "gateway binary"
require_regular_source "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" "gateway plist"
require_regular_source "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" "guardian plist"

plist_pins_managed_mode "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" || die "gateway plist does not pin managed_enterprise"
plist_pins_managed_mode "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" || die "guardian plist does not pin managed_enterprise"

WHEEL_GID="$(/usr/bin/stat -f '%g' /Library)"

assert_trusted_system_dir /Library
assert_trusted_system_dir /Library/LaunchDaemons
assert_trusted_system_dir /Library/Logs
assert_existing_secure_dir_or_absent "$LOG_VENDOR_DIR"
assert_existing_secure_dir_or_absent "$LOG_PRODUCT_DIR"
assert_existing_secure_dir_or_absent /opt
assert_existing_secure_dir_or_absent /opt/cisco
assert_existing_secure_dir_or_absent /opt/cisco/secureclient
assert_existing_secure_dir_or_absent "$BINARY_ROOT"
assert_existing_secure_dir_or_absent "$BIN_DIR"
assert_existing_secure_dir_or_absent "$ETC_DIR"
assert_existing_secure_dir_or_absent "$RUNTIME_DIR"
assert_existing_secure_dir_or_absent "$GUARDIAN_DIR"
assert_existing_secure_dir_or_absent "$AUTH_DIR"
assert_existing_secure_dir_or_absent "$LOG_DIR"
refuse_symlink "$CONFIG_DEST"

INSTALL_DESTINATIONS=(
    "${BIN_DIR}/defenseclaw-gateway"
    "$CONFIG_DEST"
    "$MANIFEST_DEST"
    "$GATEWAY_PLIST_DEST"
    "$GUARDIAN_PLIST_DEST"
)
for destination in "${INSTALL_DESTINATIONS[@]}"; do
    refuse_symlink "$destination"
    if [ -e "$destination" ]; then
        assert_no_write_acl "$destination"
    fi
done

if /bin/launchctl print "system/${GATEWAY_LABEL}" >/dev/null 2>&1; then
    GATEWAY_WAS_LOADED=true
    [ -f "$GATEWAY_PLIST_DEST" ] || die "loaded gateway job has no restorable plist"
fi
if /bin/launchctl print "system/${GUARDIAN_LABEL}" >/dev/null 2>&1; then
    GUARDIAN_WAS_LOADED=true
    [ -f "$GUARDIAN_PLIST_DEST" ] || die "loaded hook guardian job has no restorable plist"
fi

ROLLBACK_DIR="$(/usr/bin/mktemp -d "/private/tmp/defenseclaw-enterprise-rollback.XXXXXX")"
/bin/chmod 0700 "$ROLLBACK_DIR"
for destination in "${INSTALL_DESTINATIONS[@]}"; do
    snapshot_file "$destination"
done
ROLLBACK_ARMED=true

stop_job_if_loaded "$GUARDIAN_LABEL"
stop_job_if_loaded "$GATEWAY_LABEL"

for parent in /opt /opt/cisco /opt/cisco/secureclient "$LOG_VENDOR_DIR" "$LOG_PRODUCT_DIR"; do
    if [ ! -d "$parent" ]; then
        create_directory_no_replace "$parent" root wheel 0755
    fi
    assert_trusted_system_dir "$parent"
done
create_directory_no_replace "$BINARY_ROOT" root wheel 0755
create_directory_no_replace "$BIN_DIR" root wheel 0755
create_directory_no_replace "$ETC_DIR" root wheel 0755
create_directory_no_replace "$RUNTIME_DIR" root wheel 0750
create_directory_no_replace "$GUARDIAN_DIR" root wheel 0750
create_directory_no_replace "$AUTH_DIR" root wheel 0750
create_directory_no_replace "$LOG_DIR" root wheel 0750
assert_trusted_system_dir /opt
assert_trusted_system_dir /opt/cisco
assert_trusted_system_dir /opt/cisco/secureclient

install_file_atomic "$BINARY_SOURCE" "${BIN_DIR}/defenseclaw-gateway" root wheel 0755
install_file_atomic "$CONFIG_SOURCE" "$CONFIG_DEST" root wheel 0640
install_file_atomic "$MANIFEST_SOURCE" "$MANIFEST_DEST" root wheel 0640
install_file_atomic "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" "$GATEWAY_PLIST_DEST" root wheel 0644
install_file_atomic "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" "$GUARDIAN_PLIST_DEST" root wheel 0644

assert_path_metadata "$BINARY_ROOT" dir 0 "$WHEEL_GID" 755
assert_path_metadata "$BIN_DIR" dir 0 "$WHEEL_GID" 755
assert_path_metadata "$ETC_DIR" dir 0 "$WHEEL_GID" 755
assert_path_metadata "$RUNTIME_DIR" dir 0 "$WHEEL_GID" 750
assert_path_metadata "$GUARDIAN_DIR" dir 0 "$WHEEL_GID" 750
assert_path_metadata "$AUTH_DIR" dir 0 "$WHEEL_GID" 750
assert_path_metadata "$LOG_DIR" dir 0 "$WHEEL_GID" 750
assert_path_metadata "${BIN_DIR}/defenseclaw-gateway" file 0 "$WHEEL_GID" 755
assert_path_metadata "$CONFIG_DEST" file 0 "$WHEEL_GID" 640
assert_path_metadata "$MANIFEST_DEST" file 0 "$WHEEL_GID" 640
assert_path_metadata "$GATEWAY_PLIST_DEST" file 0 "$WHEEL_GID" 644
assert_path_metadata "$GUARDIAN_PLIST_DEST" file 0 "$WHEEL_GID" 644

if [ "$START_JOBS" = true ]; then
    /bin/launchctl bootstrap system "$GATEWAY_PLIST_DEST" || die "failed to bootstrap gateway LaunchDaemon"
    /bin/launchctl bootstrap system "$GUARDIAN_PLIST_DEST" || die "failed to bootstrap hook guardian LaunchDaemon"
    /bin/launchctl enable "system/${GATEWAY_LABEL}" || die "failed to enable gateway LaunchDaemon"
    /bin/launchctl enable "system/${GUARDIAN_LABEL}" || die "failed to enable hook guardian LaunchDaemon"
    /bin/launchctl kickstart -k "system/${GATEWAY_LABEL}" || die "failed to start gateway LaunchDaemon"
    /bin/launchctl kickstart -k "system/${GUARDIAN_LABEL}" || die "failed to start hook guardian LaunchDaemon"
fi

ROLLBACK_ARMED=false
printf 'DefenseClaw managed enterprise installation verified.\n'
