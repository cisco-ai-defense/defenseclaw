#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: after removal, a deb purge also removes the
# administrator config, protected credentials and state. The service account
# is kept (removing it risks uid reuse); delete it deliberately if needed.

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
