#!/usr/bin/env bash

set -euo pipefail
umask 077

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

SERVICE_USER=defenseclaw
SERVICE_GROUP=defenseclaw
BINARY_ROOT=/opt/cisco/secureclient/defenseclaw
BIN_DIR="${BINARY_ROOT}/bin"
MANAGED_ROOT="/opt/cisco/secureclient/defenseclaw"
ETC_DIR="/opt/cisco/secureclient/defenseclaw/etc"
RUNTIME_DIR="/opt/cisco/secureclient/defenseclaw/runtime"
GUARDIAN_DIR="/opt/cisco/secureclient/defenseclaw/hook-guardian"
AUTH_DIR="/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
LOG_DIR=/Library/Logs/Cisco/SecureClient/DefenseClaw
CONFIG_DEST="/opt/cisco/secureclient/defenseclaw/etc/config.yaml"
MANIFEST_DEST="/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml"
GATEWAY_LABEL=com.cisco.secureclient.defenseclaw
GUARDIAN_LABEL=com.cisco.secureclient.defenseclaw.hook-guardian
GATEWAY_PLIST_DEST=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
GUARDIAN_PLIST_DEST=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist

die() {
    printf 'defenseclaw enterprise install: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  sudo ./packaging/launchd/install-enterprise.sh \
    --config /path/to/config.yaml \
    --manifest /path/to/targets.yaml \
    [--binary /path/to/defenseclaw] [--no-start]

Installs the macOS managed-enterprise gateway and guardian. The managed
config is atomically installed as root:defenseclaw with mode 0640 and is
verified before either LaunchDaemon can start.

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

assert_existing_acl_safe_dir_or_absent() {
    local path="$1"
    [ -e "$path" ] || {
        refuse_symlink "$path"
        return
    }
    refuse_symlink "$path"
    [ -d "$path" ] || die "required directory path is not a directory: $path"
    assert_no_write_acl "$path"
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

cleanup() {
    local path
    for path in "${TEMP_FILES[@]-}"; do
        [ -n "$path" ] || continue
        /bin/rm -f -- "$path"
    done
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

install_file_atomic() {
    local source="$1"
    local destination="$2"
    local owner="$3"
    local group="$4"
    local mode="$5"
    local temporary="${destination}.new.$$"
    refuse_symlink "$destination"
    [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || die "temporary install path already exists: $temporary"
    TEMP_FILES+=("$temporary")
    /usr/bin/install -o "$owner" -g "$group" -m "$mode" "$source" "$temporary"
    /bin/mv -f -- "$temporary" "$destination"
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

require_regular_source "$CONFIG_SOURCE" "managed config"
require_regular_source "$MANIFEST_SOURCE" "guardian manifest"
require_regular_source "$BINARY_SOURCE" "gateway binary"
require_regular_source "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" "gateway plist"
require_regular_source "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" "guardian plist"

plist_pins_managed_mode "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" || die "gateway plist does not pin managed_enterprise"
plist_pins_managed_mode "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" || die "guardian plist does not pin managed_enterprise"

SERVICE_UID="$(/usr/bin/id -u "$SERVICE_USER" 2>/dev/null)" || die "service user does not exist: $SERVICE_USER"
SERVICE_GID="$(/usr/bin/id -g "$SERVICE_USER" 2>/dev/null)" || die "service group does not exist: $SERVICE_GROUP"
[ "$(/usr/bin/id -gn "$SERVICE_USER")" = "$SERVICE_GROUP" ] || die "service user primary group must be $SERVICE_GROUP"
WHEEL_GID="$(/usr/bin/stat -f '%g' /Library)"

assert_trusted_system_dir /Library
assert_trusted_system_dir /Library/LaunchDaemons
assert_trusted_system_dir /Library/Logs
assert_existing_secure_dir_or_absent /opt
assert_existing_secure_dir_or_absent /opt/cisco
assert_existing_secure_dir_or_absent /opt/cisco/secureclient
assert_existing_secure_dir_or_absent "$BINARY_ROOT"
assert_existing_secure_dir_or_absent "$BIN_DIR"
assert_existing_secure_dir_or_absent "$ETC_DIR"
assert_existing_secure_dir_or_absent "$MANAGED_ROOT"
assert_existing_secure_dir_or_absent "$GUARDIAN_DIR"
assert_existing_secure_dir_or_absent "$AUTH_DIR"
assert_existing_acl_safe_dir_or_absent "$RUNTIME_DIR"
assert_existing_acl_safe_dir_or_absent "$LOG_DIR"
refuse_symlink "$CONFIG_DEST"

for destination in \
    "${BIN_DIR}/defenseclaw-gateway" \
    "$CONFIG_DEST" \
    "$MANIFEST_DEST" \
    "$GATEWAY_PLIST_DEST" \
    "$GUARDIAN_PLIST_DEST"; do
    refuse_symlink "$destination"
    if [ -e "$destination" ]; then
        assert_no_write_acl "$destination"
    fi
done

stop_job_if_loaded com.cisco.secureclient.defenseclaw.hook-guardian
stop_job_if_loaded com.cisco.secureclient.defenseclaw

/usr/bin/install -d -o root -g wheel -m 0755 "$BINARY_ROOT" "$BIN_DIR"
/usr/bin/install -d -o root -g "$SERVICE_GROUP" -m 0750 "$ETC_DIR" "$GUARDIAN_DIR" "$AUTH_DIR"
/usr/bin/install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$RUNTIME_DIR" "$LOG_DIR"

install_file_atomic "$BINARY_SOURCE" "${BIN_DIR}/defenseclaw-gateway" root wheel 0755
install_file_atomic "$CONFIG_SOURCE" "$CONFIG_DEST" root "$SERVICE_GROUP" 0640
install_file_atomic "$MANIFEST_SOURCE" "$MANIFEST_DEST" root "$SERVICE_GROUP" 0640
install_file_atomic "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.plist" "$GATEWAY_PLIST_DEST" root wheel 0644
install_file_atomic "${SCRIPT_DIR}/com.cisco.secureclient.defenseclaw.hook-guardian.plist" "$GUARDIAN_PLIST_DEST" root wheel 0644

assert_path_metadata "$BINARY_ROOT" dir 0 "$WHEEL_GID" 755
assert_path_metadata "$BIN_DIR" dir 0 "$WHEEL_GID" 755
assert_path_metadata "$ETC_DIR" dir 0 "$SERVICE_GID" 750
assert_path_metadata "$RUNTIME_DIR" dir "$SERVICE_UID" "$SERVICE_GID" 750
assert_path_metadata "$GUARDIAN_DIR" dir 0 "$SERVICE_GID" 750
assert_path_metadata "$AUTH_DIR" dir 0 "$SERVICE_GID" 750
assert_path_metadata "$LOG_DIR" dir "$SERVICE_UID" "$SERVICE_GID" 750
assert_path_metadata "${BIN_DIR}/defenseclaw-gateway" file 0 "$WHEEL_GID" 755
assert_path_metadata "$CONFIG_DEST" file 0 "$SERVICE_GID" 640
assert_path_metadata "$MANIFEST_DEST" file 0 "$SERVICE_GID" 640
assert_path_metadata "$GATEWAY_PLIST_DEST" file 0 "$WHEEL_GID" 644
assert_path_metadata "$GUARDIAN_PLIST_DEST" file 0 "$WHEEL_GID" 644

if [ "$START_JOBS" = true ]; then
    /bin/launchctl bootstrap system "$GATEWAY_PLIST_DEST" || die "failed to bootstrap gateway LaunchDaemon"
    if ! /bin/launchctl bootstrap system "$GUARDIAN_PLIST_DEST"; then
        /bin/launchctl bootout "system/${GATEWAY_LABEL}" >/dev/null 2>&1 || true
        die "failed to bootstrap hook guardian LaunchDaemon"
    fi
    /bin/launchctl enable "system/${GATEWAY_LABEL}"
    /bin/launchctl enable "system/${GUARDIAN_LABEL}"
    /bin/launchctl kickstart -k "system/${GATEWAY_LABEL}"
    /bin/launchctl kickstart -k "system/${GUARDIAN_LABEL}"
fi

printf 'DefenseClaw managed enterprise installation verified.\n'
