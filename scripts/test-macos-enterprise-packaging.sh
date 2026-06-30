#!/usr/bin/env bash

set -euo pipefail

fail() {
    printf 'macOS enterprise packaging smoke failed: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Darwin ] || fail "this smoke test requires macOS"
[ "$(id -u)" -ne 0 ] || fail "run as a non-root CI user"
[ "${DEFENSECLAW_PACKAGING_SMOKE:-}" = 1 ] || fail "set DEFENSECLAW_PACKAGING_SMOKE=1 on a disposable host"
[ "$#" -eq 1 ] || fail "usage: $0 <defenseclaw-gateway-binary>"

binary="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || fail "binary must be a regular executable"
sudo -n true || fail "passwordless sudo is required"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
installer="${root}/packaging/launchd/install-enterprise.sh"
managed_root="/Library/Application Support/DefenseClaw"
config_dest="${managed_root}/config.yaml"
binary_root=/Library/DefenseClaw
gateway_plist=/Library/LaunchDaemons/com.defenseclaw.gateway.plist
guardian_plist=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist
log_dir=/Library/Logs/DefenseClaw
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
        sudo -n rm -rf -- "$binary_root" "$managed_root" "$log_dir"
        sudo -n rm -f -- "$gateway_plist" "$guardian_plist"
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

for path in "$binary_root" "$managed_root" "$log_dir" "$gateway_plist" "$guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "refusing to overwrite pre-existing path: $path"
done
for label in com.defenseclaw.gateway com.defenseclaw.hook-guardian; do
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
sudo -n dscl . -create /Users/defenseclaw NFSHomeDirectory /var/empty
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

sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start

service_gid="$(id -g defenseclaw)"
[ "$(stat -f '%u' "$config_dest")" = 0 ] || fail "managed config is not root-owned"
[ "$(stat -f '%g' "$config_dest")" = "$service_gid" ] || fail "managed config group is not defenseclaw"
[ "$(stat -f '%Lp' "$config_dest")" = 640 ] || fail "managed config mode is not 0640"
[ ! -w "$config_dest" ] || fail "standard user can write managed config"

sudo -n chown "$(id -u):$(id -g)" "$config_dest"
sudo -n chmod 0666 "$config_dest"
sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start
[ "$(stat -f '%u:%g:%Lp' "$config_dest")" = "0:${service_gid}:640" ] || fail "installer did not repair config metadata"

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
