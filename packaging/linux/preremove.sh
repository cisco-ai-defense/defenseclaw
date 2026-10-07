#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: stop and unregister the managed deployment
# before its files are removed. An upgrade is left to the new package's
# postinstall. The removal fails only when another lifecycle run keeps the
# lock for the whole wait: removing the files then would leave machine
# policy and per-user hooks naming a deleted binary. Any other lifecycle
# problem is reported and does not stop the package transaction.
#
# This uninstall never purges: dpkg passes "remove" here for both apt remove
# and apt purge, and rpm has no purge. It removes the machine state (config,
# secrets, gateway and guardian state, logs, lifecycle state) and the
# service account; each enrolled account keeps its ~/.defenseclaw and
# per-user binaries. To remove those too, run
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
    "$gateway" enterprise linux uninstall --json --lock-wait 10m >"$work/last-package-result.json" 2>"$work/last-package-result.log"
    status=$?
    if [ "$status" != 0 ]; then
        mkdir -p "$state" &&
            mv -f "$work/last-package-result.json" "$work/last-package-result.log" "$state/"
    fi
    rm -rf "$work"
    if [ "$status" = 75 ]; then
        echo "defenseclaw-enterprise: another DefenseClaw lifecycle run held the lock for 10 minutes; nothing was removed. Retry the removal." >&2
        exit 1
    fi
    [ "$status" = 0 ] ||
        echo "defenseclaw-enterprise: uninstall reported a problem; see $state/last-package-result.json" >&2
fi
exit 0
