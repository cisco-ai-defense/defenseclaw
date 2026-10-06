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

# A package downgrade replaces the binaries before the older package's own
# scripts can refuse it, and the older release cannot read the config_version
# 9 file this release writes, so its services would fail to start. dpkg runs
# the installed package's prerm with the version being installed ($2): refuse
# an older one here, before any file changes, unless the administrator asked
# for the rollback with the marker (used up by the downgrade it allows). rpm
# gives the old package's %preun no version and runs it after the new files
# are in place, so an rpm downgrade cannot be refused from here.
refuse_downgrade() {
    incoming=$1
    [ -n "$incoming" ] && command -v dpkg-query >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 || return 0
    installed=$(dpkg-query -W -f='${Version}' defenseclaw-enterprise 2>/dev/null) || return 0
    [ -n "$installed" ] || return 0
    # Snapshot builds share a release number; compare the release only.
    if ! dpkg --compare-versions "$(printf '%s' "$incoming" | sed 's/[-~+].*$//')" lt \
        "$(printf '%s' "$installed" | sed 's/[-~+].*$//')"; then
        return 0
    fi
    marker=$state/allow-downgrade
    if [ -f "$marker" ] && [ ! -L "$marker" ]; then
        rm -f "$marker"
        return 0
    fi
    echo "defenseclaw-enterprise: $installed is installed; refusing to downgrade to $incoming, because the older release cannot read this release's config_version 9 config." >&2
    echo "  For a deliberate rollback create the marker first: sudo touch $marker" >&2
    echo "  then install the older package and finish with: sudo $gateway enterprise linux ensure --from-package --allow-downgrade --config /etc/defenseclaw/config.yaml.v8.bak" >&2
    exit 1
}

case "${1:-}" in
    remove | 0) ;;
    upgrade)
        refuse_downgrade "${2:-}"
        exit 0
        ;;
    *) exit 0 ;; # deb deconfigure, rpm upgrade ($1 = 1)
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
