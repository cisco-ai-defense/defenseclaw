#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: before the package manager replaces any
# file (deb preinst, rpm %pre).
#
# MDM pushes config.yaml and then the package. The config write starts the
# apply unit, whose ensure ran the old binary while the package replaced the
# files under it: verify saw the binaries change, rolled back and marked the
# config edit rejected, and the package ensure then kept the previous config
# (GAP-0268). Hold the apply trigger until the postinstall has applied the
# package, and let an apply run that already started finish first.
#
# This script never fails the package transaction.

set -u
case "${1:-}" in
    install | upgrade | [1-9]*) ;;
    *) exit 0 ;;
esac

state=/var/lib/defenseclaw-enterprise
apply_path=defenseclaw-enterprise-apply.path
# The postinstall starts the trigger again when this marker is present.
held=/run/defenseclaw-enterprise-apply-path.held
recovery=defenseclaw-enterprise-apply-recovery

[ -d /run/systemd/system ] || exit 0

if systemctl is-active --quiet "$apply_path" >/dev/null 2>&1 || [ -e "$held" ]; then
    # rpm has no guaranteed failed-unpack callback. Arm an independent
    # recovery before stopping the trigger, including on 0.8.x upgrades.
    # The successful postinstall clears the marker and cancels the timer.
    systemctl stop "$recovery.timer" >/dev/null 2>&1 || true
    if systemd-run --quiet --unit="$recovery" --on-active=30m /bin/sh -c \
        '[ ! -e /run/defenseclaw-enterprise-apply-path.held ] || { systemctl start defenseclaw-enterprise-apply.path && rm -f /run/defenseclaw-enterprise-apply-path.held; }' \
        >/dev/null 2>&1; then
        if : >"$held" 2>/dev/null; then
            systemctl stop "$apply_path" >/dev/null 2>&1 || true
        else
            echo "defenseclaw-enterprise: could not mark the config apply hold; leaving the trigger active." >&2
        fi
    else
        systemctl start "$apply_path" >/dev/null 2>&1 || true
        rm -f "$held"
        echo "defenseclaw-enterprise: could not arm the config apply recovery; leaving the trigger active." >&2
    fi
fi

# A running lifecycle run (the apply unit, an MDM ensure) holds the lock for
# its whole transaction; wait for it, as the postinstall ensure would.
if [ -f "$state/lifecycle.lock" ] && command -v flock >/dev/null 2>&1; then
    if ! flock -w 600 "$state/lifecycle.lock" true >/dev/null 2>&1; then
        echo "defenseclaw-enterprise: another DefenseClaw lifecycle run held the lock for 10 minutes; the upgrade continues, and the postinstall waits for that run before it applies the package." >&2
    fi
fi
exit 0
