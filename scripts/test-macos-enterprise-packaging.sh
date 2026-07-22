#!/usr/bin/env bash
#
# End-to-end smoke test for packaging/launchd/install-enterprise.sh.
#
# Contract (post idempotent-reinstall rework):
#   1. Fresh install on a clean host lands the managed layout at
#      /opt/cisco/secureclient/defenseclaw with the expected owners/modes.
#   2. Rerunning the installer on the same host is a reconcile — the
#      binary + config + manifest + plists are atomically replaced with
#      the new source content, no legacy-fail message is emitted, and
#      any pre-existing per-user ~/.defenseclaw is left untouched.
#   3. Legacy paths (pre-Cisco layout) are relocated under LOG_DIR with
#      a timestamped suffix rather than being deleted or triggering a
#      hard refusal.
#   4. Untrusted (world-writable / non-root) config sources are still
#      refused — the trust contract on --config / --manifest sources is
#      independent of the reinstall behavior.

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
trusted_fixture="/Library/DefenseClawPackagingSmoke.$$"
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
        rm -rf -- "$probe_marker" >/dev/null 2>&1 || true
    fi
    if [ "$trusted_fixture_owned" = true ]; then
        sudo -n rm -rf -- "$trusted_fixture"
    fi
    rm -rf -- "$fixture"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Preflight — refuse to run on a host that already has any DefenseClaw
# state so the smoke test doesn't clobber a real install. The idempotent-
# reinstall contract is validated in step 3 below with a controlled
# fresh->reinstall sequence; this preflight is only about NOT starting
# from an ambient dirty state on the CI host.
for path in \
    "$managed_root" "$log_dir" \
    "$legacy_binary_root" "$legacy_managed_root" "$legacy_log_dir" \
    "$gateway_plist" "$guardian_plist" \
    "$legacy_gateway_plist" "$legacy_guardian_plist"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "preflight: unexpected pre-existing path on CI host: $path"
done
for label in \
    com.cisco.secureclient.defenseclaw \
    com.cisco.secureclient.defenseclaw.hook-guardian \
    com.defenseclaw.gateway \
    com.defenseclaw.hook-guardian; do
    if sudo -n launchctl print "system/${label}" >/dev/null 2>&1; then
        fail "preflight: unexpected pre-existing launchd job on CI host: $label"
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
    || fail "preflight: CI user already has ${probe_marker}"

# Build a *trusted* config + manifest first — the untrusted-source case
# below tests refusal by demoting these back to writable copies.
sudo -n mkdir -m 0700 -- "$trusted_fixture"
trusted_fixture_owned=true
sudo -n bash -c "cat >'${trusted_fixture}/config.yaml'" <<'EOF'
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
  mode: action
application_protection:
  enabled: false
EOF
sudo -n bash -c "printf 'version: 1\ntargets: []\n' >'${trusted_fixture}/targets.yaml'"
sudo -n chown root:wheel "${trusted_fixture}/config.yaml" "${trusted_fixture}/targets.yaml"
sudo -n chmod 0644 "${trusted_fixture}/config.yaml" "${trusted_fixture}/targets.yaml"
config_source="${trusted_fixture}/config.yaml"
manifest_source="${trusted_fixture}/targets.yaml"

# ---- 1. Fresh install lands the managed layout --------------------------

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

# Record hashes so we can prove the reinstall below actually swapped the files.
config_hash_after_install="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
gateway_hash_after_install="$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')"

# Drop a marker inside the per-user probe home so we can verify a
# reinstall doesn't touch it.
mkdir -- "$probe_marker"
probe_owned=true
printf 'preserve\n' >"${probe_marker}/existing-state"

# ---- 2. Reinstall reconciles machine-wide state ------------------------

# Mutate the managed config on disk so the fresh render will produce a
# different sha256 — proves the reinstall is not a no-op.
sudo -n bash -c "printf '\n# reinstall-should-overwrite\n' >>'$config_dest'"
config_hash_before_reinstall="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
[ "$config_hash_before_reinstall" != "$config_hash_after_install" ] \
    || fail "test setup bug: config hash did not change after appending mutation"

sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/reinstall.stdout" 2>"${fixture}/reinstall.stderr" \
    || fail "idempotent reinstall failed: see ${fixture}/reinstall.stderr"

grep -Fq "reconciling existing DefenseClaw installation in place" \
    "${fixture}/reinstall.stdout" "${fixture}/reinstall.stderr" \
    || fail "reinstall did not emit the reconcile log line"

# The reinstalled config must equal the freshly-rendered content (i.e.,
# our earlier mutation was overwritten).
config_hash_after_reinstall="$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')"
[ "$config_hash_after_reinstall" = "$config_hash_after_install" ] \
    || fail "reinstall did not restore config to freshly-rendered content"

# Binary should also match the original.
gateway_hash_after_reinstall="$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')"
[ "$gateway_hash_after_reinstall" = "$gateway_hash_after_install" ] \
    || fail "reinstall did not restore gateway binary to source content"

# Per-user probe home must be untouched.
[ "$(cat "${probe_marker}/existing-state")" = preserve ] \
    || fail "reinstall mutated per-user ~/.defenseclaw"

assert_no_defenseclaw_identity "reinstall created a defenseclaw identity"

# ---- 3. Untrusted config source is still refused ------------------------
# The reinstall contract does NOT weaken the source-trust contract. A
# world-writable / non-root config source must still be rejected.

writable_config_dir="${fixture}/writable"
mkdir -- "$writable_config_dir"
cp -- "$config_source" "${writable_config_dir}/config.yaml"
cp -- "$manifest_source" "${writable_config_dir}/targets.yaml"
chmod 0666 "${writable_config_dir}/config.yaml" "${writable_config_dir}/targets.yaml"

if sudo -n "$installer" \
    --binary "$binary" \
    --config "${writable_config_dir}/config.yaml" \
    --manifest "${writable_config_dir}/targets.yaml" \
    --no-start >"${fixture}/untrusted-source.stdout" 2>"${fixture}/untrusted-source.stderr"; then
    fail "installer accepted writable config source (source-trust contract broken)"
fi
grep -Fq "managed config is not root-owned" "${fixture}/untrusted-source.stderr" \
    || grep -Fq "managed config is group/other writable" "${fixture}/untrusted-source.stderr" \
    || fail "untrusted source refusal did not identify managed config trust"

# The untrusted-source refusal must not have mutated the installed state.
[ "$(sudo -n shasum -a 256 "$config_dest" | awk '{print $1}')" = "$config_hash_after_reinstall" ] \
    || fail "untrusted-source refusal modified managed config"
[ "$(sudo -n shasum -a 256 "$gateway_dest" | awk '{print $1}')" = "$gateway_hash_after_reinstall" ] \
    || fail "untrusted-source refusal modified gateway binary"

# ---- 4. Legacy path relocation -----------------------------------------
# Pre-create a legacy path and re-run; the reinstaller should relocate
# it under LOG_DIR with a timestamped suffix rather than refuse.

sudo -n mkdir -p -- "$legacy_binary_root"
sudo -n bash -c "printf 'legacy-content\n' >'${legacy_binary_root}/marker'"
sudo -n "$installer" \
    --binary "$binary" \
    --config "$config_source" \
    --manifest "$manifest_source" \
    --no-start >"${fixture}/legacy.stdout" 2>"${fixture}/legacy.stderr" \
    || fail "reinstall with legacy marker failed: see ${fixture}/legacy.stderr"

grep -Fq "moved legacy path aside" \
    "${fixture}/legacy.stdout" "${fixture}/legacy.stderr" \
    || fail "reinstall did not emit legacy-relocation log line"

[ ! -e "$legacy_binary_root" ] \
    || fail "legacy path was not relocated: $legacy_binary_root still exists"

# The relocated content must be discoverable under LOG_DIR.
if ! sudo -n bash -c "ls '${log_dir}' | grep -q '^DefenseClaw\.pre-'"; then
    fail "legacy content not found under ${log_dir} with pre- prefix"
fi

assert_no_defenseclaw_identity "legacy-relocation reinstall created a defenseclaw identity"

printf 'macOS enterprise packaging smoke passed\n'
