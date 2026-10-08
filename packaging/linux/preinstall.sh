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
# It fails the package transaction only for an administrator config this
# package cannot read (below); nothing else stops it.

set -u
case "${1:-}" in
    install | upgrade | [1-9]*) ;;
    *) exit 0 ;;
esac

# The highest config_version this package reads (MaxSupportedConfigVersion;
# a test keeps the two equal). A package older than the administrator
# config used to replace every file and then fail its ensure on the config,
# which left the new binaries next to the old deployment and services, with
# verify reporting them modified until a manual downgrade (GAP-0392). Refuse
# before any file is replaced instead.
max_config_version=8
config=/etc/defenseclaw/config.yaml
if [ -f "$config" ]; then
    found=$(sed -n "s/^config_version:[[:space:]]*\([0-9][0-9]*\).*/\1/p" "$config" 2>/dev/null | head -n 1)
    if [ -n "$found" ] && [ "$found" -gt "$max_config_version" ] 2>/dev/null; then
        echo "defenseclaw-enterprise: $config has config_version $found, and this package reads up to $max_config_version: it was written for a newer DefenseClaw. Nothing was changed. Install a DefenseClaw release that reads it, or push a config with config_version: $max_config_version first." >&2
        exit 1
    fi
fi

state=/var/lib/defenseclaw-enterprise
apply_path=defenseclaw-enterprise-apply.path
# The postinstall starts the trigger again when this marker is present.
held=/run/defenseclaw-enterprise-apply-path.held

[ -d /run/systemd/system ] || exit 0

if systemctl is-active --quiet "$apply_path" >/dev/null 2>&1; then
    systemctl stop "$apply_path" >/dev/null 2>&1 || true
    : >"$held" 2>/dev/null || true
fi

# A running lifecycle run (the apply unit, an MDM ensure) holds the lock for
# its whole transaction; wait for it, as the postinstall ensure would.
if [ -f "$state/lifecycle.lock" ] && command -v flock >/dev/null 2>&1; then
    if ! flock -w 600 "$state/lifecycle.lock" true >/dev/null 2>&1; then
        echo "defenseclaw-enterprise: another DefenseClaw lifecycle run held the lock for 10 minutes; the upgrade continues, and the postinstall waits for that run before it applies the package." >&2
    fi
fi
exit 0
