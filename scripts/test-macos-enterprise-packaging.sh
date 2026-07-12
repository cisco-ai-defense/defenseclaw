#!/usr/bin/env bash

set -euo pipefail

fail() {
    printf 'macOS enterprise packaging smoke failed: %s\n' "$*" >&2
    exit 1
}

assert_no_defenseclaw_identity() {
    local message="$1"
    if id defenseclaw >/dev/null 2>&1 || dscl . -read /Groups/defenseclaw >/dev/null 2>&1; then
        fail "$message"
    fi
}

[ "$(uname -s)" = Darwin ] || fail "this smoke test requires macOS"
[ "$(id -u)" -ne 0 ] || fail "run as a non-root CI user"
[ "${MACOS_ENTERPRISE_PACKAGING_SMOKE:-}" = 1 ] || fail "set MACOS_ENTERPRISE_PACKAGING_SMOKE=1 on a disposable host"
[ "$#" -eq 1 ] || fail "usage: $0 <defenseclaw-gateway-binary>"

binary="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || fail "binary must be a regular executable"
sudo -n true || fail "passwordless sudo is required"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
installer="${root}/packaging/launchd/install-enterprise.sh"
managed_root="/opt/cisco/secureclient/defenseclaw"
config_dest="${managed_root}/etc/config.yaml"
gateway_plist=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
guardian_plist=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist
log_dir=/Library/Logs/Cisco/SecureClient/DefenseClaw
fixture="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-packaging.XXXXXX")"
installation_owned=false

cleanup() {
    local status=$?
    trap - EXIT
    if [ "$installation_owned" = true ]; then
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw.hook-guardian >/dev/null 2>&1 || true
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw >/dev/null 2>&1 || true
        sudo -n rm -rf -- "$managed_root" "$log_dir"
        sudo -n rm -f -- "$gateway_plist" "$guardian_plist"
    fi
    rm -rf -- "$fixture"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for path in "$managed_root" "$log_dir" "$gateway_plist" "$guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "refusing to overwrite pre-existing path: $path"
done
for label in com.cisco.secureclient.defenseclaw com.cisco.secureclient.defenseclaw.hook-guardian; do
    if sudo -n launchctl print "system/${label}" >/dev/null 2>&1; then
        fail "refusing to unload pre-existing job: $label"
    fi
done
installation_owned=true
assert_no_defenseclaw_identity "cannot verify service-user-free install while a defenseclaw identity exists"

config_source="${fixture}/config.yaml"
manifest_source="${fixture}/targets.yaml"
cat >"$config_source" <<'EOF'
config_version: 7
deployment_mode: managed_enterprise
data_dir: /opt/cisco/secureclient/defenseclaw/runtime
audit_db: /opt/cisco/secureclient/defenseclaw/runtime/audit.db
judge_bodies_db: /opt/cisco/secureclient/defenseclaw/runtime/judge_bodies.db
plugin_dir: /opt/cisco/secureclient/defenseclaw/runtime/plugins
policy_dir: /opt/cisco/secureclient/defenseclaw/runtime/policies
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
application_protection:
  enabled: false
EOF
printf 'version: 1\ntargets: []\n' >"$manifest_source"
chmod 0666 "$config_source" "$manifest_source"

sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start

wheel_gid="$(stat -f '%g' /Library)"
[ "$(sudo -n stat -f '%u' "$config_dest")" = 0 ] || fail "managed config is not root-owned"
[ "$(sudo -n stat -f '%g' "$config_dest")" = "$wheel_gid" ] || fail "managed config group is not wheel"
[ "$(sudo -n stat -f '%Lp' "$config_dest")" = 640 ] || fail "managed config mode is not 0640"
[ ! -w "$config_dest" ] || fail "standard user can write managed config"
assert_no_defenseclaw_identity "installer created a defenseclaw identity during fresh install"

config_hash_before_acl="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
sudo -n chmod +a "everyone allow add_file,add_subdirectory,delete_child,writeattr,writeextattr,writesecurity,chown" "$managed_root"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/acl.stdout" 2>"${fixture}/acl.stderr"; then
    fail "installer accepted a write-capable managed-root ACL"
fi
grep -Fq "write-capable macOS ACL is not trusted: $managed_root" "${fixture}/acl.stderr" || fail "ACL refusal was not explicit"
[ "$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')" = "$config_hash_before_acl" ] || fail "ACL preflight failure modified managed config"
sudo -n chmod -N "$managed_root"

sudo -n chown "$(id -u):$(id -g)" "$config_dest"
sudo -n chmod 0666 "$config_dest"
sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start
[ "$(sudo -n stat -f '%u:%g:%Lp' "$config_dest")" = "0:${wheel_gid}:640" ] || fail "installer did not repair config metadata"
assert_no_defenseclaw_identity "installer created a defenseclaw identity during repair"

decoy="${fixture}/decoy.yaml"
printf 'decoy must remain unchanged\n' >"$decoy"
decoy_hash="$(shasum -a 256 "$decoy" | awk '{print $1}')"
sudo -n rm -f "$config_dest"
sudo -n ln -s "$decoy" "$config_dest"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/symlink.stdout" 2>"${fixture}/symlink.stderr"; then
    fail "installer accepted a symlink managed config"
fi
grep -Fq "refusing symlink path: $config_dest" "${fixture}/symlink.stderr" || fail "symlink refusal was not explicit"
[ "$(shasum -a 256 "$decoy" | awk '{print $1}')" = "$decoy_hash" ] || fail "symlink decoy was modified"

printf 'macOS enterprise packaging smoke passed\n'
