#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: the preremove uninstall already removed the
# administrator config, protected credentials, state and the service
# account; a deb purge also removes what a failed or skipped uninstall left
# of the machine directories. Each enrolled account's ~/.defenseclaw and
# per-user binaries stay, since the gateway that removes them as each account
# is gone by now. Run `enterprise linux uninstall --purge` before the package
# removal to remove those too.

set -u
# dpkg can invoke the new package's postrm after a failed unpack.
case "${1:-}" in
    failed-upgrade|abort-install)
        if [ -e /run/defenseclaw-enterprise-apply-path.held ]; then
            if systemctl start defenseclaw-enterprise-apply.path >/dev/null 2>&1; then
                rm -f /run/defenseclaw-enterprise-apply-path.held
                systemctl stop defenseclaw-enterprise-apply-recovery.timer >/dev/null 2>&1 || true
            fi
        fi
        exit 0
        ;;
esac
if [ "${1:-}" = purge ]; then
    rm -rf /etc/defenseclaw /var/lib/defenseclaw /var/lib/defenseclaw-hook-guardian \
        /var/lib/defenseclaw-enterprise /var/log/defenseclaw
fi
# deb passes "remove"/"purge", rpm passes 0 when the package is erased (and 1
# on upgrade). Drop the now-empty install directories the package does not
# own as files; an upgrade keeps them.
case "${1:-}" in
    remove|purge|0)
        rmdir /opt/defenseclaw/bin /opt/defenseclaw >/dev/null 2>&1 || true
        # The override `enterprise linux uninstall` wrote over this package's
        # tmpfiles.d entries leaves with the package.
        if head -n 1 /etc/tmpfiles.d/defenseclaw.conf 2>/dev/null | grep -qx '# defenseclaw-uninstall-override'; then
            rm -f /etc/tmpfiles.d/defenseclaw.conf
        fi
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
