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

set -u
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise

case "${1:-}" in
    remove | 0) ;;
    *) exit 0 ;; # deb upgrade and deconfigure, rpm upgrade ($1 = 1)
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
