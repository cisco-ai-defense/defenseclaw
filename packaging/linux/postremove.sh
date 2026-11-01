#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: the preremove uninstall already removed the
# administrator config, protected credentials, state and the service
# account, and stopped the package's units; a deb purge also removes what a
# failed or skipped uninstall left of the machine directories. A removal
# drops the lifecycle lock and its directory once nothing else is in it.
# Each enrolled account's ~/.defenseclaw and per-user binaries stay, since
# the gateway that removes them as each account is gone by now. Run
# `enterprise linux uninstall --purge` before the package removal to remove
# those too.

set -u
lifecycle=/var/lib/defenseclaw-enterprise
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
        /var/log/defenseclaw
    # The lock goes below, under its own flock.
    find "$lifecycle" -mindepth 1 -maxdepth 1 ! -name lifecycle.lock -exec rm -rf -- {} + 2>/dev/null || true
fi
# deb passes "remove"/"purge", rpm passes 0 when the package is erased (and 1
# on upgrade). Drop the now-empty install directories the package does not
# own as files; an upgrade keeps them.
case "${1:-}" in
    remove|purge|0)
        # The vendor policies are written by the lifecycle, not shipped as
        # package files. The uninstall removes them on a package host and
        # keeps only a file an administrator put there (GAP-1582); what is
        # left leaves with the package, but only once the
        # preremove uninstall removed the deployment. An uninstall that
        # failed (machine policy or a registration not removed) keeps the
        # deployment record, the config and the registrations that name
        # these policies for a rerun, so the policies stay with them.
        if [ ! -e "$lifecycle/deployment.json" ]; then
            rm -rf /opt/defenseclaw/share/policies
            # The OpenCode plugin 1.0.5 and earlier wrote under its old
            # name; this release ships share/opencode/index.js (rel-1-0-6
            # GAP-0175).
            rm -f /opt/defenseclaw/share/opencode/defenseclaw.js
        fi
        # What the package removal leaves of the scanner runtime is the
        # bytecode its Python wrote while it ran, not package files: with the
        # package gone nothing runs it (rel-1-0-6 GAP-0175).
        rm -rf /opt/defenseclaw/scanner-runtime
        rmdir /opt/defenseclaw/share/opencode /opt/defenseclaw/share/fleet /opt/defenseclaw/share /opt/defenseclaw/bin /opt/defenseclaw >/dev/null 2>&1 || true
        # The override `enterprise linux uninstall` wrote over this package's
        # tmpfiles.d entries leaves with the package.
        if head -n 1 /etc/tmpfiles.d/defenseclaw.conf 2>/dev/null | grep -qx '# defenseclaw-uninstall-override'; then
            rm -f /etc/tmpfiles.d/defenseclaw.conf
        fi
        # The lifecycle uninstall removes the lock with the last lifecycle
        # state; this covers a removal whose uninstall did not run (no
        # gateway binary). A kept result (a failed uninstall) keeps the
        # directory and its lock. The lock is removed while flock holds it:
        # a lifecycle run that waited on it finds the path gone and stops
        # instead of running beside a new lock (GAP-0112).
        lock="$lifecycle/lifecycle.lock"
        only_lock=1
        for entry in "$lifecycle"/* "$lifecycle"/.[!.]* "$lifecycle"/..?*; do
            [ -e "$entry" ] || [ -L "$entry" ] || continue
            [ "$entry" = "$lock" ] || only_lock=0
        done
        if [ "$only_lock" = 1 ] && [ -f "$lock" ] && [ ! -L "$lock" ] && command -v flock >/dev/null 2>&1; then
            flock -w 10 "$lock" rm -f "$lock" >/dev/null 2>&1 || true
        fi
        rmdir "$lifecycle" >/dev/null 2>&1 || true
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    case "${1:-}" in
        # A unit that failed before the removal stays listed "not-found
        # failed" until its state is reset.
        remove|purge|0) systemctl reset-failed 'defenseclaw-*' >/dev/null 2>&1 || true ;;
    esac
fi
exit 0
