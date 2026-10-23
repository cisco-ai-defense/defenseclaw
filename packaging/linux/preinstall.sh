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
# before any file is replaced instead. The version is read as YAML reads the
# top-level key: at the indentation of the document's first key (a document
# may be indented as a whole), with the key or value quoted or not; an
# indented config_version slipped past a match anchored at column 0
# (GAP-1065). A key nested under another one is not the config's version.
max_config_version=9
config=/etc/defenseclaw/config.yaml
if [ -f "$config" ]; then
    found=$(awk -v q="'" '
        /^[ \t]*(#|$)/ || /^(---|\.\.\.)[ \t]*$/ || /^%/ { next }
        {
            match($0, /^ */)
            if (top == "") top = RLENGTH
            if (RLENGTH != top) next
            line = substr($0, RLENGTH + 1)
            re = "^[\"" q "]?config_version[\"" q "]?[ \t]*:[ \t]*[\"" q "]?[0-9]+"
            if (match(line, re)) {
                v = substr(line, 1, RLENGTH)
                sub(/^.*[^0-9]/, "", v)
                print v
                exit
            }
        }' "$config" 2>/dev/null)
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
# owner_mode PATH: the owner's uid and the permission bits (octal) of PATH
# itself, not of a symlink's target.
owner_mode() { stat -c '%u %a' "$1" 2>/dev/null; }
root_owned() {
    [ -f "$1" ] && [ ! -L "$1" ] && ro_info=$(owner_mode "$1") && [ "${ro_info%% *}" = 0 ]
}
# root_only PATH: PATH itself, not a symlink's target, belongs to root, and
# no group or other account can write it (an ACL that lets another account
# write shows in the group bits, which are then its mask). An owner or mode
# that cannot be read is not root's.
root_only() {
    t_info=$(owner_mode "$1") || return 1
    case $t_info in
        "0 "[0-7]*) t_mode=${t_info#0 } ;;
        *) return 1 ;;
    esac
    case $t_mode in *[!0-7]*) return 1 ;; esac
    [ $((0$t_mode & 022)) -eq 0 ]
}
# trusted PATH: PATH is a regular file, not a symlink, and only root can
# change what it names. PATH is looked up one entry at a time, as the kernel
# looks it up, following every symlink on the way (its target from / or from
# the folder that holds it): every folder an entry is found in, and the
# file, are root_only, and every symlink belongs to root. A check
# of only the folders the path ends in missed the folder that holds a
# symlink and the folders a symlink's target passes through: an account
# that could write one could swap the symlink between the check and the
# run. t_real is then the file PATH names, reached through folders only, and
# the caller runs that file. A symlink that cannot be read, or more than 32
# of them, is not trusted.
trusted() {
    t_real=
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    case $1 in /*) ;; *) return 1 ;; esac
    root_only / || return 1
    t_dir=/
    t_rest=$1
    t_hops=0
    while :; do
        case $t_rest in
            /*) t_rest=${t_rest#/}; continue ;;
            "") return 1 ;;
            */*)
                t_name=${t_rest%%/*}
                t_rest=${t_rest#*/}
                t_more=/
                ;;
            *)
                t_name=$t_rest
                t_rest=
                t_more=
                ;;
        esac
        case $t_name in
            .) continue ;;
            ..)
                t_dir=${t_dir%/*}
                t_dir=${t_dir:-/}
                continue
                ;;
        esac
        t_path=${t_dir%/}/$t_name
        if [ -L "$t_path" ]; then
            t_hops=$((t_hops + 1))
            [ "$t_hops" -le 32 ] || return 1
            t_info=$(owner_mode "$t_path") || return 1
            [ "${t_info%% *}" = 0 ] || return 1
            t_link=$(readlink "$t_path") || return 1
            case $t_link in
                "") return 1 ;;
                /*) t_dir=/ ;;
            esac
            t_rest=$t_link$t_more$t_rest
            continue
        fi
        root_only "$t_path" || return 1
        if [ -z "$t_more" ] && [ -f "$t_path" ]; then
            t_real=$t_path
            return 0
        fi
        [ -d "$t_path" ] || return 1
        t_dir=$t_path
    done
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
# A device that takes signed policy bundles must not run a release below the
# one its confirmed bundle requires (min_product_version), even for a
# deliberate rollback: a bundle signed with a lower floor lifts it. A gateway
# from 1.0.4 on reads the floor, and its binary carries floor_check_marker:
# looking for it, without running the gateway, tells a gateway that cannot
# run from one before 1.0.4, which has no check and is not asked. When the
# installed gateway is gone or older (uninstall --keep-state and then the
# package removal, or an uninstall that failed after removing the binaries),
# the root-only copy that uninstall kept in the lifecycle folder answers.
# Only a gateway that was read and has no marker is an older one: a gateway
# that cannot be read, and a gateway with the marker or a kept copy that is
# not a root-owned file only root can change (trusted: another account
# cannot change it, a folder above it, or a symlink on the way to it), or
# whose owner or mode cannot be read, leave the floor unchecked unless the
# other one answers, and the install is refused. A trusted checker is run
# by the path it resolves to.
# Only exit 0 lets the install go on: exit 3 is the refusal, and any other
# result (application control denied the execution, the checker was killed
# or crashed) leaves the floor unchecked, so the install is refused too.
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
floor_check_marker=defenseclaw-package-floor-check/1
kept="$state/floor-check"
checker=
unchecked=
if [ -e "$gateway" ] || [ -L "$gateway" ]; then
    grep -qaF "$floor_check_marker" "$gateway" 2>/dev/null
    case $? in
    0)
        if trusted "$gateway"; then
            checker=$t_real
        else
            unchecked="$gateway has the floor check, but it is not a root-owned file that only root can change (another account can change it, a folder above it, or a symlink on the way to it), or its owner or mode could not be read"
        fi
        ;;
    1) ;; # a gateway before 1.0.4: it has no floor check
    *) unchecked="$gateway could not be read to tell whether it has the floor check" ;;
    esac
fi
if [ -z "$checker" ]; then
    if [ ! -L "$kept" ] && trusted "$kept/defenseclaw-gateway"; then
        checker=$t_real
        unchecked=
    elif [ -L "$kept" ] || [ -e "$kept/defenseclaw-gateway" ] || [ -L "$kept/defenseclaw-gateway" ]; then
        unchecked="$kept/defenseclaw-gateway, the gateway an uninstall kept for the floor check, is not a root-owned file that only root can change, in a folder that is not a symlink (another account can change it, a folder above it, or a symlink on the way to it), or its owner or mode could not be read"
    fi
fi
case "$package_version" in
    @*@) ;;
    *)
        if [ -n "$checker" ]; then
            floor_msg=$("$checker" enterprise bundle floor-check --product-version "$package_version" 2>&1 >/dev/null)
            floor_rc=$?
            if [ "$floor_rc" -ne 0 ]; then
                [ "$floor_rc" -eq 3 ] || floor_msg="the release floor of the confirmed signed policy bundle could not be checked: $checker exited $floor_rc${floor_msg:+ ($floor_msg)}. Let it run (for example, trust it in the application control policy) and install again."
                echo "defenseclaw-enterprise: refusing to install $package_version: ${floor_msg#Error: } Nothing was changed." >&2
                exit 1
            fi
        elif [ -n "$unchecked" ]; then
            echo "defenseclaw-enterprise: refusing to install $package_version: the release floor of the confirmed signed policy bundle could not be checked: $unchecked. Restore it as a readable, root-owned file that only root can write, in folders only root can write, and install again. Nothing was changed." >&2
            exit 1
        fi
        ;;
esac
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
    if ! flock -w 480 "$state/lifecycle.lock" true >/dev/null 2>&1; then
        echo "defenseclaw-enterprise: another DefenseClaw lifecycle run held the lock for 8 minutes; the upgrade continues, and the postinstall waits for that run before it applies the package." >&2
    fi
fi
exit 0
