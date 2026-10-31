#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: stop and unregister the managed deployment
# before its files are removed. An upgrade is left to the new package's
# postinstall. The removal fails, and the package keeps its files, in three
# cases, each matched by its exact result:
#   - another lifecycle run keeps the lock for the whole wait (exit 75);
#   - the hook-removal precheck refuses (uninstall_precheck_refused): nothing
#     was changed;
#   - the uninstall stopped before removing the binaries because per-user
#     hook registrations or vendor machine policy still name them
#     (uninstall_incomplete): it started the services again (GAP-1519).
# Removing the files then would leave machine policy or per-user hooks
# naming a deleted binary. After the uninstall, the removal also fails when
# an account's user service manager still runs a sandbox user unit, or does
# not answer whether it does (#1210): deleting the unit files and the binary
# would leave a loaded socket that starts a deleted daemon. Other lifecycle problems are reported without
# stopping the package transaction. When the run it waited for was an
# uninstall (an MDM purge, say) that removed the deployment and its lock, the
# uninstall is a no-op and exits 0, and the removal goes on (GAP-0112).
#
# To finish a removal that stopped, fix the cause the result names (a
# read-only or immutable vendor policy or hook config file, for example; the
# result names the account and connector) and run `apt remove` or
# `dnf remove` again. A package that must go while the cause stays: on RHEL
# `rpm -e --nopreun defenseclaw-enterprise` skips this script; the listed
# registrations then name a deleted binary until they are removed by hand.
#
# This uninstall never purges: dpkg passes "remove" here for both apt remove
# and apt purge, and rpm has no purge. It removes the config, secrets, most
# gateway and guardian state, logs, lifecycle state and the service account.
# When an account keeps sandboxes, the sandbox registration store and key
# stay with their root-owned setup record for the next ensure. Administrator
# policies in /etc/defenseclaw/policies also stay (apt purge deletes them),
# and each enrolled account keeps ~/.defenseclaw and per-user binaries.
# postremove.sh removes /var/lib/defenseclaw on apt purge. To remove user data
# and the kept sandbox state before package removal, run
# `defenseclaw-gateway enterprise linux uninstall --purge` before removing
# the package; it names every account it purged or left alone.
#
# The result goes to a temporary file first: a removal that succeeds leaves
# nothing behind, while one that reports a problem keeps its result in
# /var/lib/defenseclaw-enterprise for the administrator.
#
# Tetragon: on a host that runs it, the sensor helper may have loaded
# DefenseClaw's kernel policies into Tetragon. They outlive the helper, so
# a package change that leaves a helper behind that does not manage them
# removes them first, with a binary that can (the removal itself is the
# lifecycle uninstall's job):
#   - deb upgrade (this old prerm runs before the new files unpack, $2 is the
#     new version): on a downgrade, stop the helper and run its cleanup. The
#     older package's postinstall starts its own helper, which loads its own
#     policies again only if it manages any. An upgrade or a reinstall is
#     left alone: the newer helper takes the record over.
#   - rpm upgrade or downgrade ($1 = 1: this old %preun runs after the new
#     files are in place): when the new helper does not answer
#     `--tetragon-cleanup --check`, it cannot manage the recorded policies,
#     so each recorded name is deleted with tetra when it is installed, or
#     printed with the restart that drops it.
# Only names the helper recorded loading, in DefenseClaw's exact shape, are
# ever touched. None of this fails the package transaction.

set -u

gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise
helper=/opt/defenseclaw/bin/defenseclaw-sensor-helper
sensor_state=/var/lib/defenseclaw-sensor
policy_names='defenseclaw-(observe|connect|controls|controls-burnin)-[0-9a-f]{8}'
# Every systemd unit the package ships in /usr/lib/systemd/system (the
# packaging tests compare the list with .goreleaser.yaml).
package_units="defenseclaw-enterprise-apply.path defenseclaw-enterprise-verify.timer
defenseclaw-hook-guardian.service defenseclaw-hook-enumerator.service
defenseclaw-gateway-api.socket defenseclaw-gateway-hook.socket defenseclaw-gateway.service
defenseclaw-sensor-helper.service defenseclaw-enterprise-apply.service
defenseclaw-enterprise-verify.service defenseclaw-hook-guardian-reconcile.service"
# The transient timer the preinstall starts to recover the apply trigger.
recovery_timer=defenseclaw-enterprise-apply-recovery.timer
# The sandbox subsystem's user units the package ships in
# /usr/lib/systemd/user (the packaging tests compare the list too).
user_units="defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service"
# Where each account's user service manager keeps its runtime directory.
user_runtime=/run/user

# user_systemctl DIR UID GID NAME ARG...: `systemctl --user ARG...` in the
# user service manager that runs in DIR, as its account: by name, or, when
# the account lookup gave no name (a directory service outage, say), by the
# uid and gid that own DIR. Without a way to switch to the account it fails.
user_systemctl() {
    us_dir=$1 us_uid=$2 us_gid=$3 us_name=$4
    shift 4
    if [ -n "$us_name" ]; then
        runuser -u "$us_name" -- env XDG_RUNTIME_DIR="$us_dir" DBUS_SESSION_BUS_ADDRESS="unix:path=$us_dir/bus" \
            systemctl --user "$@"
    elif command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$us_uid" --regid="$us_gid" --clear-groups \
            env XDG_RUNTIME_DIR="$us_dir" DBUS_SESSION_BUS_ADDRESS="unix:path=$us_dir/bus" systemctl --user "$@"
    else
        return 1
    fi
}

# user_units_stopped DIR UID GID NAME succeeds only when it is established
# that no user unit of the package runs in that manager: the manager answers
# a state for every unit and each is inactive or failed (is-active exits 3
# for any other state too, activating and deactivating included), or the
# manager has exited (its private socket is gone). A manager that does not
# answer, or a state it does not establish, is not "stopped".
user_units_stopped() {
    # shellcheck disable=SC2086 # unit names have no spaces or globs
    states=$(user_systemctl "$@" is-active $user_units 2>/dev/null)
    rc=$?
    if [ "$rc" = 3 ]; then
        want=0
        for unit in $user_units; do want=$((want + 1)); done
        got=0
        for unit_state in $states; do
            case "$unit_state" in
                inactive | failed) got=$((got + 1)) ;;
                *)
                    got=-1
                    break
                    ;;
            esac
        done
        [ "$got" = "$want" ] && return 0
    fi
    [ ! -S "$1/systemd/private" ]
}

# stop_user_units stops the package's user units in the user service manager
# of every account that runs one, as that account, so no sandbox daemon or
# OpenShell gateway keeps running from a unit file the removal deletes (a
# socket left listening started the daemon again, which then failed 203/EXEC
# on the deleted binary in a loop: #1210). Stopping the daemon runs its
# ExecStop, which stops the account's sandboxes first. The uninstall above
# stopped the units of the accounts it knows; this also covers an account it
# did not know and a removal whose uninstall did not run. Then the global
# enable link of the socket goes, so no later sign-in starts it. It fails,
# naming the accounts, when a manager still runs a unit after three tries or
# does not establish that none runs; the package then keeps its files.
stop_user_units() {
    left=""
    for dir in "$user_runtime"/*; do
        uid=${dir##*/}
        case "$uid" in '' | *[!0-9]*) continue ;; esac
        [ "$uid" -gt 0 ] || continue
        # Only a runtime directory the account owns, with its manager's
        # private socket: the account has a running user manager.
        if [ ! -d "$dir" ] || [ -L "$dir" ] || [ ! -S "$dir/systemd/private" ]; then
            continue
        fi
        [ "$(stat -c %u "$dir" 2>/dev/null)" = "$uid" ] || continue
        gid=$(stat -c %g "$dir" 2>/dev/null)
        name=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
        tries=0
        while :; do
            # shellcheck disable=SC2086 # unit names have no spaces or globs
            user_systemctl "$dir" "$uid" "$gid" "$name" stop $user_units >/dev/null 2>&1
            if user_units_stopped "$dir" "$uid" "$gid" "$name"; then
                # A unit that ended failed (a daemon that exited 78 once the
                # uninstall removed the deployment, or an ExecStop the removed
                # deployment refused) leaves with the package as inactive, not
                # failed (GAP-0137).
                # shellcheck disable=SC2086 # unit names have no spaces or globs
                user_systemctl "$dir" "$uid" "$gid" "$name" reset-failed $user_units >/dev/null 2>&1 || true
                break
            fi
            tries=$((tries + 1))
            if [ "$tries" -ge 3 ]; then
                left="$left, ${name:-uid $uid}"
                break
            fi
        done
    done
    systemctl --global disable defenseclaw-sandbox.socket >/dev/null 2>&1 || true
    [ -n "$left" ] || return 0
    echo "defenseclaw-enterprise: could not stop, or confirm stopped, the sandbox user units of ${left#, }; package files were kept. As each user run \`systemctl --user stop $user_units\` (or sign the user out), then retry the removal." >&2
    return 1
}

# recorded_policies prints the DefenseClaw policy names the sensor helper
# recorded loading, one per line.
recorded_policies() {
    [ -f "$sensor_state/tetragon-loaded" ] || return 0
    grep -E -x "$policy_names" "$sensor_state/tetragon-loaded" 2>/dev/null || true
}

# root_tetra prints a root-owned tetra binary, or nothing.
root_tetra() {
    for candidate in "$(command -v tetra 2>/dev/null)" /usr/local/bin/tetra /usr/bin/tetra; do
        if [ -n "$candidate" ] && [ -x "$candidate" ] && [ "$(stat -L -c %u "$candidate" 2>/dev/null)" = 0 ]; then
            echo "$candidate"
            return 0
        fi
    done
}

# A package handoff must not delete policies under a live reconciler. If
# systemd cannot stop the helper, keep the names for later cleanup.
stop_helper_for_cleanup() {
    [ -d /run/systemd/system ] || return 1
    systemctl stop defenseclaw-sensor-helper.service >/dev/null 2>&1
}

# deb_upgrade_handoff NEW_VERSION
deb_upgrade_handoff() {
    [ -n "${1:-}" ] || return 0
    [ -n "$(recorded_policies)" ] || return 0
    current=$(dpkg-query -W -f='${Version}' defenseclaw-enterprise 2>/dev/null) || current=""
    if [ -n "$current" ] && ! dpkg --compare-versions "$1" lt "$current" 2>/dev/null; then
        return 0
    fi
    # A running helper would load its policies again before the older
    # package's postinstall replaces it.
    if ! stop_helper_for_cleanup; then
        echo "defenseclaw-enterprise: could not stop the sensor helper; recorded Tetragon policies stay for later cleanup" >&2
        return 0
    fi
    if [ -x "$helper" ] && "$helper" --tetragon-cleanup; then
        return 0
    fi
    echo "defenseclaw-enterprise: could not remove DefenseClaw's Tetragon policies before the downgrade; still recorded: $(recorded_policies | tr '\n' ' ')" >&2
    echo "  Delete each with \`tetra tracingpolicy delete <name>\`, or run \`systemctl restart tetragon\`, which drops policies added over its API." >&2
}

rpm_upgrade_handoff() {
    names=$(recorded_policies)
    [ -n "$names" ] || return 0
    if [ -x "$helper" ] && "$helper" --tetragon-cleanup --check >/dev/null 2>&1; then
        return 0
    fi
    if ! stop_helper_for_cleanup; then
        echo "defenseclaw-enterprise: could not stop the sensor helper; recorded Tetragon policies stay for later cleanup" >&2
        return 0
    fi
    tetra=$(root_tetra)
    left=""
    for name in $names; do
        if [ -n "$tetra" ] && "$tetra" tracingpolicy delete "$name" >/dev/null 2>&1; then
            echo "defenseclaw-enterprise: removed the Tetragon policy $name"
        else
            left="$left $name"
        fi
    done
    if [ -z "$left" ]; then
        : >"$sensor_state/tetragon-loaded"
        return 0
    fi
    # shellcheck disable=SC2086 # names match $policy_names: no spaces or globs
    printf '%s\n' $left >"$sensor_state/tetragon-loaded"
    echo "defenseclaw-enterprise: the installed sensor helper does not manage DefenseClaw's Tetragon policies, and these are still loaded:$left" >&2
    echo "  Delete each with \`tetra tracingpolicy delete <name>\`, or run \`systemctl restart tetragon\`, which drops policies added over its API." >&2
}

case "${1:-}" in
    remove | 0) ;;
    upgrade)
        deb_upgrade_handoff "${2:-}"
        exit 0
        ;;
    1)
        rpm_upgrade_handoff
        exit 0
        ;;
    *) exit 0 ;; # deb deconfigure, failed-upgrade
esac

if [ -x "$gateway" ] && [ -d /run/systemd/system ]; then
    umask 077
    work=$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-preremove.XXXXXX") || exit 1
    "$gateway" enterprise linux uninstall --json --lock-wait 8m >"$work/last-package-result.json" 2>"$work/last-package-result.log"
    status=$?
    precheck_refused=0
    incomplete=0
    if [ "$status" != 0 ]; then
        if grep -Eq '"code"[[:space:]]*:[[:space:]]*"uninstall_precheck_refused"' "$work/last-package-result.json"; then
            precheck_refused=1
        elif grep -Eq '"code"[[:space:]]*:[[:space:]]*"uninstall_incomplete"' "$work/last-package-result.json"; then
            incomplete=1
        fi
    fi
    if [ "$status" != 0 ]; then
        mkdir -p "$state" &&
            mv -f "$work/last-package-result.json" "$work/last-package-result.log" "$state/"
    fi
    rm -rf "$work"
    if [ "$status" = 75 ]; then
        echo "defenseclaw-enterprise: another DefenseClaw lifecycle run held the lock for 8 minutes; nothing was removed. Retry the removal." >&2
        exit 1
    fi
    if [ "$precheck_refused" = 1 ]; then
        echo "defenseclaw-enterprise: hook-removal precheck refused; package files were kept. See $state/last-package-result.json and retry removal after fixing the listed accounts." >&2
        exit 1
    fi
    if [ "$incomplete" = 1 ]; then
        echo "defenseclaw-enterprise: the uninstall stopped before removing the binaries, because per-user hook registrations or vendor machine policy still name them; package files were kept and the services started again. See $state/last-package-result.json, fix the cause it names and retry the removal." >&2
        exit 1
    fi
    [ "$status" = 0 ] ||
        echo "defenseclaw-enterprise: uninstall reported a problem; see $state/last-package-result.json" >&2
fi

# The package's files go next, whatever the uninstall did: an uninstall that
# reported a problem starts the services again, and one that did not run
# (no gateway binary) stopped nothing. A unit left running after its file is
# gone stays loaded "not-found" and keeps listening until a reboot: the
# gateway API socket did (GAP-0112). Stop and disable every unit the package
# ships, in one systemctl call (systemd queues every stop job first, so a
# socket cannot start the gateway again in between), and repeat while one
# still runs. Only a removal gets here; an upgrade left above.
if [ -d /run/systemd/system ]; then
    units="$package_units $recovery_timer"
    tries=0
    while :; do
        # shellcheck disable=SC2086 # unit names have no spaces or globs
        systemctl stop $units >/dev/null 2>&1
        running=""
        for unit in $units; do
            if systemctl is-active --quiet "$unit" >/dev/null 2>&1; then
                running="$running $unit"
            fi
        done
        tries=$((tries + 1))
        if [ -z "$running" ] || [ "$tries" -ge 3 ]; then
            break
        fi
    done
    # shellcheck disable=SC2086
    systemctl disable $package_units >/dev/null 2>&1 || true
    if [ -n "$running" ]; then
        echo "defenseclaw-enterprise: could not stop$running; stop them with \`systemctl stop$running\` after the removal" >&2
    fi
    stop_user_units || exit 1
fi
exit 0
