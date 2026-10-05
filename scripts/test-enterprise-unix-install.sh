#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# test-enterprise-unix-install.sh - CI install lane for the standalone
# managed-enterprise Linux packages (.deb, .rpm) and the macOS package
# (.pkg). On a real systemd or launchd host it:
#
#   1. installs the package; its postinstall runs `ensure --from-package`
#      (on Linux it then checks what this systemd reports loading the units)
#   2. applies a config that enables two connectors (a real config change)
#   3. runs ensure again, which must be a no-op
#   4. runs verify and status, checks the services and runs the MDM detect.sh
#   5. uninstalls (dpkg -r / rpm -e run the lifecycle from preremove; macOS
#      runs `enterprise macos uninstall`) and checks nothing is left running,
#      the machine config and state are gone with it and no DefenseClaw
#      machine-policy entry is left behind
#   6. purges (dpkg -P, or `uninstall --purge`, which must also succeed on a
#      machine the uninstall already cleared) and checks nothing is left
#
# Every lifecycle result is saved under --results and checked with
# scripts/check_enterprise_lifecycle_result.py. For the lifecycle commands the
# lane runs itself, the process exit status must also be 0 and equal the
# result's exit_code.
#
# It installs and removes system services: run it as root only on a
# disposable host (a CI runner or a container), never on a workstation.
#
# Usage:
#   test-enterprise-unix-install.sh --package FILE --version VERSION [--results DIR]
#
#   --package FILE     defenseclaw-enterprise-<version>-linux-<arch>.deb|.rpm or
#                      defenseclaw-enterprise-<version>-darwin-arm64.pkg
#   --version VERSION  the product version the package's binaries report
#   --results DIR      where to keep the lifecycle results (default: a new
#                      temporary directory)

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
checker="$repo/scripts/check_enterprise_lifecycle_result.py"

package=""
version=""
results=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --package) package=${2:?--package needs a value}; shift 2 ;;
        --version) version=${2:?--version needs a value}; shift 2 ;;
        --results) results=${2:?--results needs a value}; shift 2 ;;
        -h | --help) sed -n '4,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$package" ] && [ -n "$version" ] || {
    echo "usage: $0 --package FILE --version VERSION [--results DIR]" >&2
    exit 2
}

die() {
    echo "FAIL: $*" >&2
    exit 1
}

step_number=0
step() {
    step_number=$((step_number + 1))
    printf '\n== %02d %s\n' "$step_number" "$*"
}

[ "$(id -u)" = 0 ] || die "run as root on a disposable host"
[ -f "$package" ] || die "$package does not exist"
package=$(cd "$(dirname "$package")" && pwd)/$(basename "$package")
# RHEL 8 has only the platform Python; the checker supports 3.6.
python=$(command -v python3 2>/dev/null || true)
if [ -z "$python" ] && [ -x /usr/libexec/platform-python ]; then
    python=/usr/libexec/platform-python
fi
[ -n "$python" ] || die "python3 is required to check the lifecycle results"

case "$package" in
    *.deb) kind=deb platform=linux ;;
    *.rpm) kind=rpm platform=linux ;;
    *.pkg) kind=pkg platform=darwin ;;
    *) die "--package must be a .deb, .rpm or .pkg" ;;
esac
case "$platform-$(uname -s)" in
    linux-Linux | darwin-Darwin) ;;
    *) die "a .$kind installs on $platform, not on $(uname -s)" ;;
esac

readonly linux_package_name=defenseclaw-enterprise
readonly macos_package_id=com.cisco.defenseclaw.enterprise
if [ "$platform" = linux ]; then
    [ -d /run/systemd/system ] || die "systemd is not running (PID 1); use a host or a container booted with systemd"
    install_root=/opt/defenseclaw
    config_dir=/etc/defenseclaw
    data_dir=/var/lib/defenseclaw
    lifecycle_dir=/var/lib/defenseclaw-enterprise
    purged_dirs=(/etc/defenseclaw /var/lib/defenseclaw /var/lib/defenseclaw-hook-guardian /var/lib/defenseclaw-enterprise /var/log/defenseclaw /opt/defenseclaw)
    policy_dirs=(/etc/claude-code /etc/codex)
    services=(defenseclaw-gateway-api.socket defenseclaw-gateway-hook.socket defenseclaw-gateway.service
        defenseclaw-hook-guardian.service defenseclaw-hook-enumerator.service defenseclaw-sensor-helper.service)
    detect="$repo/packaging/mdm/linux/detect.sh"
    unit_dir=/usr/lib/systemd/system
else
    install_root=/opt/cisco/defenseclaw
    config_dir=$install_root/etc
    data_dir=$install_root/runtime
    lifecycle_dir=$install_root/lifecycle
    purged_dirs=("$install_root" /Library/Logs/Cisco/DefenseClaw)
    policy_dirs=("/Library/Application Support/ClaudeCode" /private/etc/codex)
    services=(com.cisco.defenseclaw.gateway com.cisco.defenseclaw.hook-guardian
        com.cisco.defenseclaw.hook-enumerator com.cisco.defenseclaw.sensor-helper)
    detect="$repo/packaging/mdm/macos/detect.sh"
fi
gateway=$install_root/bin/defenseclaw-gateway
config=$config_dir/config.yaml
vendor_policy_dir=$install_root/share/policies

results=${results:-$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-install-lane.XXXXXX")}
mkdir -p "$results"
results=$(cd "$results" && pwd)
# A status file left by an earlier run in the same directory would be
# compared with this run's result.
rm -f "$results"/*.rc
stage=$(mktemp -d /var/tmp/defenseclaw-install-lane.XXXXXX)
chmod 0700 "$stage"

diagnostics() {
    echo "-- diagnostics (bounded)" >&2
    if [ -f "$lifecycle_dir/last-package-result.log" ]; then
        tail -n 40 "$lifecycle_dir/last-package-result.log" >&2 || true
    fi
    if [ "$platform" = linux ]; then
        systemctl --no-pager --full status 'defenseclaw*' 2>&1 | tail -n 60 >&2 || true
        journalctl --no-pager -n 80 -u 'defenseclaw*' 2>&1 | tail -n 80 >&2 || true
    else
        for log in /Library/Logs/Cisco/DefenseClaw/gateway/*.log /Library/Logs/Cisco/DefenseClaw/*.log; do
            if [ -f "$log" ]; then
                echo "--- $log" >&2
                tail -n 30 "$log" >&2 || true
            fi
        done
        for label in "${services[@]}"; do
            launchctl print "system/$label" 2>/dev/null | grep -E '^[[:space:]]*(state|last exit code|pid) =' >&2 || true
        done
    fi
}
finish() {
    status=$?
    rm -rf "$stage"
    if [ "$status" -ne 0 ]; then
        diagnostics
        echo "install lane FAILED ($kind, results in $results)" >&2
    fi
    exit "$status"
}
trap finish EXIT

# check <result-file> <label> <checker arguments...>: the step fails on any
# error and on any warning the arguments do not allow (--allow-warning), and,
# for a lifecycle the lane ran itself, when the process status disagrees with
# the result (exit_status_matches).
check() {
    local file=$1 label=$2
    shift 2
    "$python" "$checker" "$file" --label "$label" --platform "$platform" "$@"
    exit_status_matches "$file" "$label"
}

# exit_status_matches <result-file> <label>: MDM scripts and remediation act
# on the process exit status, not on the JSON, so the status run_lifecycle
# kept beside the result must be 0 and equal the result's exit_code. Results
# written by the package scripts have no status file; the lane checks the
# package manager's own exit status for those.
exit_status_matches() {
    local file=$1 label=$2 status_file=${1%.json}.rc rc reported
    [ -f "$status_file" ] || return 0
    rc=$(cat "$status_file")
    reported=$("$python" -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8-sig")).get("exit_code"))' "$file")
    if [ "$rc" != 0 ] || [ "$rc" != "$reported" ]; then
        die "$label: the lifecycle process exited $rc, its result reports exit_code $reported"
    fi
}

# lifecycle <result-name> <action> [arguments...]: run the installed gateway's
# lifecycle (run_lifecycle).
lifecycle() {
    run_lifecycle "$gateway" "$@"
}

# run_lifecycle <gateway> <result-name> <action> [arguments...]: run the
# lifecycle with --json; keep stdout as the result, stderr beside it and the
# process exit status in <result-name>.rc for check().
run_lifecycle() {
    local binary=$1 name=$2 action=$3 rc=0
    shift 3
    "$binary" enterprise "$([ "$platform" = linux ] && echo linux || echo macos)" "$action" "$@" --json \
        >"$results/$name.json" 2>"$results/$name.log" || rc=$?
    echo "$rc" >"$results/$name.rc"
    echo "$action exited $rc"
}

services_running() {
    local name
    for name in "${services[@]}"; do
        if [ "$platform" = linux ]; then
            systemctl is-active --quiet "$name" || die "$name is $(systemctl is-active "$name" 2>/dev/null || true), want active"
        else
            local job
            job=$(launchctl print "system/$name" 2>/dev/null || true)
            grep -Eq '^[[:space:]]*state = running' <<<"$job" || die "launchd job $name is not running"
        fi
    done
    echo "services running: ${services[*]}"
}

services_gone() {
    local name
    if [ "$platform" = linux ]; then
        local listed
        listed=$(systemctl list-units --all --plain --no-legend 'defenseclaw*' 2>/dev/null || true)
        [ -z "$listed" ] || die "systemd still lists DefenseClaw units after uninstall: $listed"
        listed=$(systemctl list-unit-files --no-legend 'defenseclaw*' 2>/dev/null || true)
        [ -z "$listed" ] || die "DefenseClaw unit files remain after uninstall: $listed"
    else
        for name in "${services[@]}"; do
            if launchctl print "system/$name" >/dev/null 2>&1; then
                die "launchd job $name is still loaded after uninstall"
            fi
        done
        if ls /Library/LaunchDaemons/com.cisco.defenseclaw.*.plist >/dev/null 2>&1; then
            die "DefenseClaw LaunchDaemons remain after uninstall: $(ls /Library/LaunchDaemons/com.cisco.defenseclaw.*.plist)"
        fi
    fi
    echo "no DefenseClaw service is loaded"
}

# directive_minimum <Section.Directive>: the systemd release that added a
# directive the packaged units set, for each one an older supported systemd
# does not know (RHEL 8 ships systemd 239, the package's minimum). systemd
# loads such a unit and ignores the directive, so the unit runs with a weaker
# sandbox there; docs/LINUX-ENTERPRISE-THREAT-MODEL.md lists them.
directive_minimum() {
    case "$1" in
        Service.ProtectHostname) echo 242 ;;
        Service.ProtectKernelLogs) echo 244 ;;
        Service.ProtectClock) echo 245 ;;
        Service.ProtectProc | Service.ProcSubset) echo 247 ;;
        Path.TriggerLimitIntervalSec | Path.TriggerLimitBurst) echo 250 ;;
        *) return 1 ;;
    esac
}

# unit_diagnostics: systemd-analyze verify the installed DefenseClaw units
# with this host's systemd. A directive this systemd does not know passes
# only when directive_minimum names a newer release for it, and is reported.
# Any other diagnostic about a DefenseClaw unit, or a failed verify, fails.
unit_diagnostics() {
    local version unit line key minimum output rc=0 unexpected="" ignored=""
    local units=()
    version=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
    [ -n "$version" ] || die "cannot read the systemd version from systemctl --version"
    for unit in "$unit_dir"/defenseclaw*; do
        case "$unit" in *.service | *.socket | *.path | *.timer) units+=("$unit") ;; esac
    done
    [ "${#units[@]}" -gt 0 ] || die "no DefenseClaw units in $unit_dir"
    output=$(systemd-analyze verify "${units[@]}" 2>&1) || rc=$?
    while IFS= read -r line; do
        case "$line" in *defenseclaw*) ;; *) continue ;; esac
        key=$(printf '%s\n' "$line" |
            sed -n -E "s/.*Unknown (lvalue|key name|key) '([^']+)' in section (\\[|')([^]']+).*/\\4.\\2/p")
        if [ -n "$key" ] && minimum=$(directive_minimum "$key") && [ "$version" -lt "$minimum" ]; then
            ignored="$ignored$key (systemd $minimum)"$'\n'
        else
            unexpected="$unexpected  $line"$'\n'
        fi
    done <<<"$output"
    if [ "$rc" -ne 0 ] || [ -n "$unexpected" ]; then
        printf 'systemd-analyze verify exited %s on systemd %s:\n%s\n' "$rc" "$version" "$output" >&2
        die "unit diagnostics outside the systemd $version allow list:"$'\n'"${unexpected:-  (none; verify failed)}"
    fi
    echo "${#units[@]} DefenseClaw units load on systemd $version"
    if [ -n "$ignored" ]; then
        echo "systemd $version ignores these directives (added in a later release):"
        printf '%s' "$ignored" | sort -u | sed 's/^/  /'
    fi
}

policy_entries() {
    local dir
    for dir in "${policy_dirs[@]}"; do
        if [ -d "$dir" ]; then
            grep -rIli defenseclaw "$dir" 2>/dev/null || true
        fi
    done
}

detect_value() {
    sh "$detect" --format value "$@" 2>/dev/null
}

# ---- preflight ---------------------------------------------------------------
step "preflight: this host has no DefenseClaw deployment"
[ ! -e "$gateway" ] || die "$gateway already exists; run the lane on a clean host"
[ ! -e "$lifecycle_dir/deployment.json" ] || die "a deployment record already exists in $lifecycle_dir"
case "$kind" in
    deb) ! dpkg-query -W "$linux_package_name" >/dev/null 2>&1 || die "$linux_package_name is already installed" ;;
    rpm) ! rpm -q "$linux_package_name" >/dev/null 2>&1 || die "$linux_package_name is already installed" ;;
    pkg) ! pkgutil --pkg-info "$macos_package_id" >/dev/null 2>&1 || die "$macos_package_id is already installed" ;;
esac
[ -z "$(policy_entries)" ] || die "DefenseClaw machine-policy entries already exist: $(policy_entries)"
echo "package: $package"
echo "version: $version"

# ---- install -----------------------------------------------------------------
step "install the $kind (postinstall runs ensure --from-package)"
install_rc=0
case "$kind" in
    deb) DEBIAN_FRONTEND=noninteractive dpkg -i "$package" || install_rc=$? ;;
    rpm) rpm -U "$package" || install_rc=$? ;;
    pkg) installer -pkg "$package" -target / || install_rc=$? ;;
esac
[ -f "$lifecycle_dir/last-package-result.json" ] || die "the postinstall left no lifecycle result (package manager exited $install_rc)"
cp "$lifecycle_dir/last-package-result.json" "$results/01-package-install.json"
check "$results/01-package-install.json" package-install --action ensure --changed --installed --version "$version" --ready \
    --complete
[ "$install_rc" -eq 0 ] || die "the package manager exited $install_rc"
[ -x "$gateway" ] || die "$gateway was not installed"
[ -f "$config" ] || die "the lifecycle did not write $config"
case "$kind" in
    deb)
        dpkg_status=$(dpkg-query -W -f='${Status}' "$linux_package_name" 2>/dev/null || true)
        [ "$dpkg_status" = "install ok installed" ] || die "dpkg reports '$dpkg_status' after install"
        ;;
    rpm) rpm -q "$linux_package_name" ;;
    pkg) pkgutil --pkg-info "$macos_package_id" >/dev/null || die "the package receipt $macos_package_id is missing" ;;
esac
services_running
if [ "$platform" = linux ]; then
    step "the packaged units load on this systemd (systemd-analyze verify)"
    unit_diagnostics
fi

# ---- reconfigure ---------------------------------------------------------------
step "ensure with an administrator config that enables Claude Code and Codex"
cat >"$stage/config.yaml" <<EOF
config_version: 8
deployment_mode: managed_enterprise
data_dir: $data_dir
policy_dir: $vendor_policy_dir
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  rule_pack_dir: $vendor_policy_dir/guardrail/default
  connectors:
    claudecode: {enabled: true}
    codex: {enabled: true}
EOF
chmod 0600 "$stage/config.yaml"
lifecycle 02-ensure-config ensure --from-package --config "$stage/config.yaml" --reason ci-install-lane
# Both connectors' machine policy is written, owned by DefenseClaw and locked.
policy_checks=(--machine-policy claudecode --machine-policy codex
    --machine-policy-enforced claudecode --machine-policy-enforced codex)
check "$results/02-ensure-config.json" ensure-config --action ensure --changed --installed --version "$version" --ready \
    --complete "${policy_checks[@]}"
[ "$(cksum <"$stage/config.yaml")" = "$(cksum <"$config")" ] || die "$config is not the applied administrator config"
[ -n "$(policy_entries)" ] || die "no DefenseClaw machine-policy entry was written under ${policy_dirs[*]}"
echo "machine policy entries: $(policy_entries | tr '\n' ' ')"

# ---- converge ----------------------------------------------------------------
step "ensure again (must be a no-op)"
lifecycle 03-ensure-noop ensure --from-package --reason ci-install-lane
check "$results/03-ensure-noop.json" ensure-noop --action ensure --noop --installed --version "$version" --ready \
    --complete

step "verify"
lifecycle 04-verify verify
# verify reports whether unprivileged user namespaces are open, a setting of
# the host's kernel (the runner's, or the container host's), not of the package.
check "$results/04-verify.json" verify --action verify --installed --version "$version" --ready \
    --complete "${policy_checks[@]}" --allow-warning unprivileged_user_namespaces

step "status"
lifecycle 05-status status
check "$results/05-status.json" status --action status --installed --version "$version" \
    --complete "${policy_checks[@]}"
services_running

step "MDM detection (detect.sh --require-healthy)"
detected=$(detect_value --require-healthy --min-version "$version" || true)
[ "$detected" = "$version" ] || die "detect.sh printed '$detected', want '$version'"
echo "detect.sh: $detected"

# ---- uninstall ---------------------------------------------------------------
step "uninstall (the machine config and state go too)"
# macOS removes the binaries with the deployment; keep a root-only copy of the
# gateway for the purge step. The Linux package manager runs the lifecycle.
cp -p "$gateway" "$stage/defenseclaw-gateway"
rm -f "$lifecycle_dir/last-package-result.json"
case "$kind" in
    deb) dpkg -r "$linux_package_name" ;;
    rpm) rpm -e "$linux_package_name" ;;
    pkg) lifecycle 06-uninstall uninstall ;;
esac
if [ "$kind" = pkg ]; then
    check "$results/06-uninstall.json" uninstall --action uninstall --changed --not-installed
elif [ -f "$lifecycle_dir/last-package-result.json" ]; then
    # The preremove keeps its result only when the uninstall reported a problem.
    cp "$lifecycle_dir/last-package-result.json" "$results/06-uninstall.json"
    cat "$results/06-uninstall.json" "$lifecycle_dir/last-package-result.log" >&2 2>/dev/null || true
    die "the preremove uninstall reported a problem (result kept in $lifecycle_dir)"
fi
services_gone
[ ! -e "$gateway" ] || die "$gateway remains after uninstall"
# The default uninstall removes the machine state too; only --keep-state keeps it.
[ ! -e "$config" ] || die "$config remains after uninstall"
[ ! -e "$lifecycle_dir/deployment.json" ] || die "the deployment record remains after uninstall"
leftover=$(policy_entries)
[ -z "$leftover" ] || die "DefenseClaw machine-policy entries remain after uninstall: $leftover"
case "$kind" in
    deb)
        dpkg_status=$(dpkg-query -W -f='${Status}' "$linux_package_name" 2>/dev/null || true)
        [ "$dpkg_status" = "deinstall ok config-files" ] || die "dpkg reports '$dpkg_status' after remove"
        ;;
    rpm) ! rpm -q "$linux_package_name" >/dev/null 2>&1 || die "rpm still reports $linux_package_name installed" ;;
    pkg) ! pkgutil --pkg-info "$macos_package_id" >/dev/null 2>&1 || die "the package receipt $macos_package_id remains" ;;
esac
detected=$(detect_value || true)
[ "$detected" = not-installed ] || die "detect.sh printed '$detected' after uninstall, want 'not-installed'"
echo "detect.sh: $detected"

# ---- purge -------------------------------------------------------------------
step "purge (removes whatever the uninstall left)"
case "$kind" in
    deb) dpkg -P "$linux_package_name" ;;
    *)
        run_lifecycle "$stage/defenseclaw-gateway" 07-purge uninstall --purge
        check "$results/07-purge.json" purge --action uninstall --not-installed
        ;;
esac
for dir in "${purged_dirs[@]}"; do
    [ ! -e "$dir" ] || die "$dir remains after purge"
done
[ "$kind" != deb ] || ! dpkg-query -W "$linux_package_name" >/dev/null 2>&1 || die "dpkg still knows $linux_package_name after purge"
services_gone

echo
echo "install lane passed: $kind $version (results in $results)"
