#!/usr/bin/env bash

set -euo pipefail

fail() {
    printf 'macOS enterprise packaging smoke failed: %s\n' "$*" >&2
    exit 1
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
managed_root="/Library/Application Support/DefenseClaw"
config_dest="${managed_root}/config.yaml"
binary_root=/Library/DefenseClaw
gateway_plist=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist
guardian_plist=/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.hook-guardian.plist
log_dir=/Library/Logs/DefenseClaw
current_managed_root=/opt/cisco/secureclient/defenseclaw
current_log_dir=/Library/Logs/Cisco/SecureClient/DefenseClaw
legacy_gateway_plist=/Library/LaunchDaemons/com.defenseclaw.gateway.plist
legacy_guardian_plist=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist
fixture="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-packaging.XXXXXX")"
user_created=false
group_created=false
installation_owned=false

cleanup() {
    local status=$?
    trap - EXIT
    if [ "$installation_owned" = true ]; then
        sudo -n launchctl bootout system/com.defenseclaw.hook-guardian >/dev/null 2>&1 || true
        sudo -n launchctl bootout system/com.defenseclaw.gateway >/dev/null 2>&1 || true
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw.hook-guardian >/dev/null 2>&1 || true
        sudo -n launchctl bootout system/com.cisco.secureclient.defenseclaw >/dev/null 2>&1 || true
        sudo -n rm -rf -- \
            "$binary_root" "$managed_root" "$log_dir" \
            "$current_managed_root" "$current_log_dir"
        sudo -n rm -f -- \
            "$gateway_plist" "$guardian_plist" \
            "$legacy_gateway_plist" "$legacy_guardian_plist"
    fi
    if [ "$user_created" = true ]; then
        sudo -n dscl . -delete /Users/defenseclaw >/dev/null 2>&1 || true
    fi
    if [ "$group_created" = true ]; then
        sudo -n dscl . -delete /Groups/defenseclaw >/dev/null 2>&1 || true
    fi
    sudo -n dscacheutil -flushcache >/dev/null 2>&1 || true
    rm -rf -- "$fixture"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for path in \
    "$binary_root" "$managed_root" "$log_dir" \
    "$current_managed_root" "$current_log_dir" \
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
if id defenseclaw >/dev/null 2>&1 || dscl . -read /Groups/defenseclaw >/dev/null 2>&1; then
    fail "refusing to reuse a pre-existing defenseclaw identity"
fi

used_ids="$(
    dscl . -list /Users UniqueID 2>/dev/null | awk '{print $NF}'
    dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $NF}'
)"
service_id=499
while printf '%s\n' "$used_ids" | grep -qx "$service_id"; do
    service_id=$((service_id - 1))
    [ "$service_id" -ge 400 ] || fail "no free service uid/gid available"
done

sudo -n dscl . -create /Groups/defenseclaw
group_created=true
sudo -n dscl . -create /Groups/defenseclaw RealName "DefenseClaw Service"
sudo -n dscl . -create /Groups/defenseclaw PrimaryGroupID "$service_id"
sudo -n dscl . -create /Users/defenseclaw
user_created=true
sudo -n dscl . -create /Users/defenseclaw RealName "DefenseClaw Service"
sudo -n dscl . -create /Users/defenseclaw UniqueID "$service_id"
sudo -n dscl . -create /Users/defenseclaw PrimaryGroupID "$service_id"
probe_home="${fixture}/local-user-home"
mkdir -p "$probe_home"
sudo -n dscl . -create /Users/defenseclaw NFSHomeDirectory "$probe_home"
sudo -n dscl . -create /Users/defenseclaw UserShell /usr/bin/false
sudo -n dscl . -create /Users/defenseclaw IsHidden 1
sudo -n dscacheutil -flushcache

attempt=0
until id defenseclaw >/dev/null 2>&1 && [ "$(id -gn defenseclaw 2>/dev/null)" = defenseclaw ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || fail "service identity did not become visible"
    sleep 0.1
done

config_source="${fixture}/config.yaml"
manifest_source="${fixture}/targets.yaml"
cat >"$config_source" <<'EOF'
config_version: 7
deployment_mode: managed_enterprise
data_dir: /Library/Application Support/DefenseClaw/runtime
audit_db: /Library/Application Support/DefenseClaw/runtime/audit.db
judge_bodies_db: /Library/Application Support/DefenseClaw/runtime/judge_bodies.db
plugin_dir: /Library/Application Support/DefenseClaw/runtime/plugins
policy_dir: /Library/Application Support/DefenseClaw/runtime/policies
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
# mutation. The service account is also a real local dscl record, making it a
# deterministic disposable probe without touching the CI user's home.
mkdir -p "${probe_home}/.defenseclaw"
printf 'preserve\n' >"${probe_home}/.defenseclaw/existing-state"
if sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/per-user.stdout" 2>"${fixture}/per-user.stderr"; then
    fail "enterprise package ignored a per-user DefenseClaw installation"
fi
grep -Fq "${probe_home}/.defenseclaw" "${fixture}/per-user.stderr" || fail "per-user refusal did not name the dscl-resolved home marker"
grep -Fq "no changes were made" "${fixture}/per-user.stderr" || fail "per-user refusal did not attest no changes"
[ "$(cat "${probe_home}/.defenseclaw/existing-state")" = preserve ] || fail "per-user refusal changed consumer state"
for path in \
    "$binary_root" "$managed_root" "$log_dir" \
    "$current_managed_root" "$current_log_dir" \
    "$gateway_plist" "$guardian_plist" \
    "$legacy_gateway_plist" "$legacy_guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "per-user refusal mutated managed destination: $path"
done
rm -f "${probe_home}/.defenseclaw/existing-state"
rmdir "${probe_home}/.defenseclaw"

sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start

service_gid="$(id -g defenseclaw)"
[ "$(sudo -n stat -f '%u' "$config_dest")" = 0 ] || fail "managed config is not root-owned"
[ "$(sudo -n stat -f '%g' "$config_dest")" = "$service_gid" ] || fail "managed config group is not defenseclaw"
[ "$(sudo -n stat -f '%Lp' "$config_dest")" = 640 ] || fail "managed config mode is not 0640"
[ ! -w "$config_dest" ] || fail "standard user can write managed config"

config_hash_before_refusal="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
gateway_hash_before_refusal="$(sudo -n shasum -a 256 "${binary_root}/bin/defenseclaw-gateway" | awk '{print $1}')"
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
[ "$(sudo -n shasum -a 256 "${binary_root}/bin/defenseclaw-gateway" | awk '{print $1}')" = "$gateway_hash_before_refusal" ] || fail "existing-install refusal modified gateway binary"

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

printf 'macOS enterprise packaging smoke passed\n'
