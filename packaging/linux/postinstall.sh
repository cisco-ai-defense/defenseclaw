#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: apply the standalone managed deployment
# after an install or upgrade (deb configure, rpm %post).
#
# This script never fails the package transaction. The lifecycle validates
# the administrator config, activates the services and rolls back on its
# own; its JSON result is kept in the lifecycle directory and
# `defenseclaw-gateway enterprise linux verify` reports any problem.

set -u
# dpkg runs "postinst abort-remove" after preremove refused a removal because
# another lifecycle run kept the lock: nothing was removed, so there is
# nothing to apply, and a second 10-minute wait on the same busy lock would
# only stall apt.
case "${1:-}" in
    abort-remove) exit 0 ;;
esac

gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise

if [ ! -d /run/systemd/system ]; then
    echo "defenseclaw-enterprise: systemd is not running; run '$gateway enterprise linux ensure --from-package' on a systemd host." >&2
    exit 0
fi

# The config-apply path unit watches /etc/defenseclaw, so the tmpfiles and
# daemon-reload below would start an apply run that races this scriptlet's
# ensure for the lifecycle lock (every upgrade then reported busy). Hold the
# trigger while the scriptlet applies, and put it back afterwards.
apply_path=defenseclaw-enterprise-apply.path
apply_path_was_active=0
if systemctl is-active --quiet "$apply_path" >/dev/null 2>&1; then
    apply_path_was_active=1
    systemctl stop "$apply_path" >/dev/null 2>&1 || true
fi

systemd-sysusers /usr/lib/sysusers.d/defenseclaw.conf >/dev/null 2>&1 || true
systemd-tmpfiles --create /usr/lib/tmpfiles.d/defenseclaw.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true

umask 077
mkdir -p "$state" && chmod 0700 "$state"
# An apply run that started before the trigger was held may hold the lock
# for a whole transaction; wait for it like the apply trigger does. When it
# already applied this package, ensure is a no-op and reports success.
"$gateway" enterprise linux ensure --from-package --reason package --json --lock-wait 10m \
    >"$state/last-package-result.json" 2>"$state/last-package-result.log"
status=$?
if [ "$apply_path_was_active" = 1 ]; then
    systemctl start "$apply_path" >/dev/null 2>&1 || true
fi
case "$status" in
    0) echo "defenseclaw-enterprise: the managed deployment is active." ;;
    75)
        echo "defenseclaw-enterprise: installed, but another DefenseClaw lifecycle run held the lock for 10 minutes." >&2
        echo "  Apply this package with: sudo $gateway enterprise linux ensure --from-package" >&2
        ;;
    *)
        echo "defenseclaw-enterprise: installed, but the lifecycle reported a problem." >&2
        echo "  See $state/last-package-result.json or run: sudo $gateway enterprise linux verify" >&2
        ;;
esac
exit 0
