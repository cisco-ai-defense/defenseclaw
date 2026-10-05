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
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
