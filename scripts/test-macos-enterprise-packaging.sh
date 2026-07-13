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
gateway_dest="${managed_root}/bin/defenseclaw-gateway"
legacy_binary_root=/Library/DefenseClaw
legacy_managed_root="/Library/Application Support/DefenseClaw"
legacy_log_dir=/Library/Logs/DefenseClaw
legacy_gateway_plist=/Library/LaunchDaemons/com.defenseclaw.gateway.plist
legacy_guardian_plist=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist
fixture="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-packaging.XXXXXX")"
trusted_fixture="/Library/Caches/DefenseClawPackagingSmoke.$$"
probe_marker=""
probe_owned=false
installation_owned=false
trusted_fixture_owned=false

cleanup() {
    local status=$?
    trap - EXIT
    if [ "$installation_owned" = true ]; then
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw.hook-guardian >/dev/null 2>&1 || true
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw >/dev/null 2>&1 || true
        sudo -n rm -rf -- "$managed_root" "$log_dir"
        sudo -n rm -f -- "$gateway_plist" "$guardian_plist"
    fi
    if [ "$probe_owned" = true ]; then
        rm -f -- "${probe_marker}/existing-state" >/dev/null 2>&1 || true
        rmdir -- "$probe_marker" >/dev/null 2>&1 || true
    fi
    if [ "$trusted_fixture_owned" = true ]; then
        sudo -n rm -rf -- "$trusted_fixture"
    fi
    rm -rf -- "$fixture"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for path in \
    "$managed_root" "$log_dir" \
    "$legacy_binary_root" "$legacy_managed_root" "$legacy_log_dir" \
    "$gateway_plist" "$guardian_plist" \
    "$legacy_gateway_plist" "$legacy_guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "refusing to overwrite pre-existing path: $path"
done
for label in \
    com.cisco.secureclient.defenseclaw \
    com.cisco.secureclient.defenseclaw.hook-guardian \
    com.defenseclaw.gateway \
    com.defenseclaw.hook-guardian; do
    if sudo -n launchctl print "system/${label}" >/dev/null 2>&1; then
        fail "refusing to unload pre-existing job: $label"
    fi
done
installation_owned=true
assert_no_defenseclaw_identity "cannot verify service-user-free install while a defenseclaw identity exists"

probe_user="$(id -un)"
probe_home="$(
    dscl . -read "/Users/${probe_user}" NFSHomeDirectory 2>/dev/null \
        | sed -n 's/^NFSHomeDirectory: //p'
)"
[ -n "$probe_home" ] || fail "could not resolve the CI user's Directory Services home"
case "$probe_home" in
    /*) ;;
    *) fail "the CI user's Directory Services home is not absolute: $probe_home" ;;
esac
probe_marker="${probe_home}/.defenseclaw"
[ ! -e "$probe_marker" ] && [ ! -L "$probe_marker" ] \
    || fail "refusing to overwrite the CI user's existing DefenseClaw marker: $probe_marker"

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

# A PATH-independent consumer install in any Directory Services home must stop
# this system installer before source validation, launchd, or destination
# mutation. Use the disposable CI user's real dscl-resolved home so the probe
# does not create or depend on the retired DefenseClaw service identity.
mkdir -- "$probe_marker"
probe_owned=true
printf 'preserve\n' >"${probe_marker}/existing-state"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/per-user.stdout" 2>"${fixture}/per-user.stderr"; then
    fail "enterprise package ignored a per-user DefenseClaw installation"
fi
grep -Fq "$probe_marker" "${fixture}/per-user.stderr" || fail "per-user refusal did not name the dscl-resolved home marker"
grep -Fq "no changes were made" "${fixture}/per-user.stderr" || fail "per-user refusal did not attest no changes"
[ "$(cat "${probe_marker}/existing-state")" = preserve ] || fail "per-user refusal changed consumer state"
for path in \
    "$managed_root" "$log_dir" \
    "$legacy_binary_root" "$legacy_managed_root" "$legacy_log_dir" \
    "$gateway_plist" "$guardian_plist" \
    "$legacy_gateway_plist" "$legacy_guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "per-user refusal mutated managed destination: $path"
done
rm -f -- "${probe_marker}/existing-state"
rmdir -- "$probe_marker"
probe_owned=false

if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/untrusted-source.stdout" 2>"${fixture}/untrusted-source.stderr"; then
    fail "enterprise package accepted writable config and manifest sources"
fi
grep -Fq "managed config is not root-owned" "${fixture}/untrusted-source.stderr" \
    || grep -Fq "managed config is group/other writable" "${fixture}/untrusted-source.stderr" \
    || fail "untrusted source refusal did not identify managed config trust"
for path in \
    "$managed_root" "$log_dir" \
    "$legacy_binary_root" "$legacy_managed_root" "$legacy_log_dir" \
    "$gateway_plist" "$guardian_plist" \
    "$legacy_gateway_plist" "$legacy_guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "untrusted-source refusal mutated managed destination: $path"
done

sudo -n mkdir -m 0700 -- "$trusted_fixture"
trusted_fixture_owned=true
sudo -n cp -- "$config_source" "${trusted_fixture}/config.yaml"
sudo -n cp -- "$manifest_source" "${trusted_fixture}/targets.yaml"
sudo -n chown root:wheel "${trusted_fixture}/config.yaml" "${trusted_fixture}/targets.yaml"
sudo -n chmod 0644 "${trusted_fixture}/config.yaml" "${trusted_fixture}/targets.yaml"
config_source="${trusted_fixture}/config.yaml"
manifest_source="${trusted_fixture}/targets.yaml"

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

config_hash_before_refusal="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
gateway_hash_before_refusal="$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/reinstall.stdout" 2>"${fixture}/reinstall.stderr"; then
    fail "fresh-install-only enterprise package overwrote an existing deployment"
fi
grep -Fq "existing DefenseClaw installation detected" "${fixture}/reinstall.stderr" || fail "existing-install refusal was not explicit"
grep -Fq "no changes were made" "${fixture}/reinstall.stderr" || fail "existing-install refusal did not attest no changes"
grep -Fq "remain on the current version" "${fixture}/reinstall.stderr" || fail "existing-install refusal did not give the fail-closed managed path"
[ "$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')" = "$config_hash_before_refusal" ] || fail "existing-install refusal modified managed config"
[ "$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')" = "$gateway_hash_before_refusal" ] || fail "existing-install refusal modified gateway binary"
assert_no_defenseclaw_identity "existing-install refusal created a defenseclaw identity"

# A write-capable ACL must not turn a fresh-only reinstall into a repair path.
# Preserve main's ACL safety probe while expecting the earlier existing-install
# refusal introduced by the bridge release.
sudo -n chmod +a "everyone allow add_file,add_subdirectory,delete_child,writeattr,writeextattr,writesecurity,chown" "$managed_root"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/acl.stdout" 2>"${fixture}/acl.stderr"; then
    fail "fresh-install-only enterprise package accepted a write-capable existing root"
fi
grep -Fq "existing DefenseClaw installation detected" "${fixture}/acl.stderr" || fail "ACL-state refusal was not explicit"
grep -Fq "no changes were made" "${fixture}/acl.stderr" || fail "ACL-state refusal did not attest no changes"
[ "$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')" = "$config_hash_before_refusal" ] || fail "ACL-state refusal modified managed config"
[ "$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')" = "$gateway_hash_before_refusal" ] || fail "ACL-state refusal modified gateway binary"
sudo -n chmod -N "$managed_root"

# Even damaged installed metadata must not turn this package installer into an
# implicit repair/upgrade path. It refuses before replacing state; recovery is
# owned by the staged managed upgrader.
sudo -n chown "$(id -u):$(id -g)" "$config_dest"
sudo -n chmod 0666 "$config_dest"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/damaged.stdout" 2>"${fixture}/damaged.stderr"; then
    fail "enterprise package repaired/overwrote existing damaged metadata"
fi
grep -Fq "fresh-install-only" "${fixture}/damaged.stderr" || fail "damaged-state refusal was not explicit"
[ "$(sudo -n stat -f '%u:%g:%Lp' "$config_dest")" = "$(id -u):$(id -g):666" ] || fail "refusal mutated damaged config metadata"
[ "$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')" = "$gateway_hash_before_refusal" ] || fail "damaged-state refusal modified gateway binary"
assert_no_defenseclaw_identity "damaged-state refusal created a defenseclaw identity"

# Preserve main's symlink-decoy safety coverage under the new fail-closed
# reinstall contract. The decoy must remain untouched even though the managed
# root makes the installer refuse before destination validation.
sudo -n chown "0:${wheel_gid}" "$config_dest"
sudo -n chmod 0640 "$config_dest"
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
    fail "fresh-install-only enterprise package accepted an existing symlink config"
fi
grep -Fq "existing DefenseClaw installation detected" "${fixture}/symlink.stderr" || fail "symlink-state refusal was not explicit"
grep -Fq "no changes were made" "${fixture}/symlink.stderr" || fail "symlink-state refusal did not attest no changes"
[ "$(shasum -a 256 "$decoy" | awk '{print $1}')" = "$decoy_hash" ] || fail "symlink decoy was modified"
[ "$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')" = "$gateway_hash_before_refusal" ] || fail "symlink-state refusal modified gateway binary"
assert_no_defenseclaw_identity "symlink-state refusal created a defenseclaw identity"

printf 'macOS enterprise packaging smoke passed\n'
