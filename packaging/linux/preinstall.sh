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
# package cannot read, or for a downgrade the administrator did not ask for
# (below); nothing else stops it.

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

# A package older than the deployed release replaced every binary, and then
# its postinstall ensure refused the downgrade: the older binaries sat next
# to the newer deployment, and status reported verify_failed and a failed
# apply unit until `ensure --from-package --allow-downgrade` (GAP-1115).
# Refuse before any file is replaced instead, unless the administrator
# created the root-owned rollback marker; the postinstall then applies the
# package with --allow-downgrade and deletes the marker. The release build
# stamps the package version below (.goreleaser.yaml); an unstamped copy
# leaves the refusal to the postinstall ensure.
package_version="@DC_PKG_VERSION@"
state=/var/lib/defenseclaw-enterprise
record="$state/deployment.json"
marker="$state/allow-downgrade"
root_owned() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1" 2>/dev/null)" = 0 ]
}
# not_older A B: A is not older than B, by the lifecycle's version order
# (enterpriseunix compareProductVersions: dotted numbers, a release above its
# prereleases, prerelease fields compared numerically where both are numbers).
not_older() {
    awk -v a="$1" -v b="$2" '
        function norm(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
        BEGIN {
            a = norm(a); b = norm(b); pa = ""; pb = ""
            if (index(a, "-")) { pa = substr(a, index(a, "-") + 1); a = substr(a, 1, index(a, "-") - 1) }
            if (index(b, "-")) { pb = substr(b, index(b, "-") + 1); b = substr(b, 1, index(b, "-") - 1) }
            na = split(a, x, "."); nb = split(b, y, "."); n = na > nb ? na : nb
            for (i = 1; i <= n; i++) {
                xi = (i <= na) ? x[i] + 0 : 0; yi = (i <= nb) ? y[i] + 0 : 0
                if (xi > yi) exit 0
                if (xi < yi) exit 1
            }
            if (pa == pb || pa == "") exit 0
            if (pb == "") exit 1
            np = split(pa, u, "."); nq = split(pb, w, "."); m = np > nq ? np : nq
            for (i = 1; i <= m; i++) {
                if (u[i] == w[i]) continue
                if (u[i] ~ /^[0-9]+$/ && w[i] ~ /^[0-9]+$/) exit (u[i] + 0 > w[i] + 0) ? 0 : 1
                exit (u[i] > w[i]) ? 0 : 1
            }
            exit 0
        }'
}
case "$package_version" in
    @*@) ;;
    *)
        if root_owned "$record" && ! root_owned "$marker"; then
            installed=$(sed -n 's/.*"product_version": *"\([^"]*\)".*/\1/p' "$record" 2>/dev/null | head -n 1)
            if [ -n "$installed" ] && ! not_older "$package_version" "$installed"; then
                echo "defenseclaw-enterprise: DefenseClaw $installed is deployed; refusing to downgrade to $package_version. Nothing was changed. For a deliberate rollback, create the rollback marker first (sudo touch $marker) and install this package again: it is then applied with 'enterprise linux ensure --from-package --allow-downgrade'." >&2
                exit 1
            fi
        fi
        ;;
esac

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
