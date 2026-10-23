#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise deb: apt Pre-Install-Pkgs hook that refuses to
# downgrade the package before dpkg runs, so the running deployment is left
# alone. The older release may not read the current config, so its services
# could fail to start. A package script cannot do
# this: dpkg runs the installed package's prerm with the incoming version,
# but when it fails dpkg falls back to the incoming package's own prerm and
# unpacks the older files anyway. rpm has no such hook, and a plain
# `dpkg -i` does not run apt hooks, so only an apt install is covered; there
# the incoming package's preinstall checks (a release before 1.0.4 checks
# neither the marker nor the bundle release floor).
#
# apt sends the "VERSION 2" protocol on stdin (see apt.conf(5)): the
# configuration, a blank line, then one line per package action:
#   name old-version direction new-version action
# The hook decides on the product versions, not on apt's direction: a deb
# version with a higher epoch (1:1.0.2) is an apt upgrade over 1.0.4 but an
# older DefenseClaw, and a package from before 1.0.4 has no floor check of
# its own. A deliberate rollback creates the root-owned marker first. The
# hook leaves it in place: the older package's preinstall checks it as well,
# and its postinstall applies the package with --allow-downgrade and deletes
# it.

set -u
state=/var/lib/defenseclaw-enterprise
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
config=/etc/defenseclaw/config.yaml
previous_config=/etc/defenseclaw/config.yaml.v8.bak

# Every action that unpacks or configures defenseclaw-enterprise, whatever
# its direction; a removal (new version "-") installs nothing.
changes=$(awk 'body && $1 == "defenseclaw-enterprise" && $4 != "-" { print $2, $4 } $0 == "" { body = 1 }')
[ -n "$changes" ] || exit 0

# The product version of a deb version: no epoch, and the prerelease back
# behind "-" (the deb writes 1.0.4-rc.1 as 1.0.4~rc.1). A prerelease is older
# than its release: dropping it let 1.0.4 go to 1.0.4~SNAPSHOT unrefused.
product() { printf '%s' "$1" | sed -e 's/^[0-9]*://' -e 's/~/-/'; }
# not_older A B: A is not older than B, by the lifecycle's version order (the
# package preinstall's not_older; enterpriseunix compareProductVersions).
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
# The installed gateway answers the floor check when its binary carries
# floor_check_marker (1.0.4 on; looked for without running it, so a gateway
# that cannot run is told apart from an older one, which is not asked).
# Without it (removed by hand, or an uninstall that failed after removing the
# binaries), the root-only copy an uninstall kept in the lifecycle folder
# does. Only a gateway that was read and has no marker is an older one: a
# gateway that cannot be read, and a gateway with the marker or a kept copy
# that is not a root-owned file only root can change (trusted: another
# account cannot change it, a folder above it, or a symlink on the way to
# it), or whose owner or mode cannot be read, leave the floor unchecked
# unless the other one answers, and every install is refused. A trusted
# checker is run by the path it resolves to.
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

# check INSTALLED INCOMING: refuse (exit 1) or return.
check() {
    installed=$1
    incoming=$2
    to=$(product "$incoming")
    # The rollback marker does not lift the release floor of a confirmed
    # signed policy bundle (min_product_version), and no apt direction does:
    # every incoming version is checked, as the package preinstall does.
    # Only exit 0 passes: exit 3 is the gateway's refusal, and any other
    # result (execution denied, killed, crashed) leaves the floor unchecked.
    if [ -n "$checker" ]; then
        floor_msg=$("$checker" enterprise bundle floor-check --product-version "$to" 2>&1 >/dev/null)
        floor_rc=$?
        if [ "$floor_rc" -ne 0 ]; then
            [ "$floor_rc" -eq 3 ] || floor_msg="the release floor of the confirmed signed policy bundle could not be checked: $checker exited $floor_rc${floor_msg:+ ($floor_msg)}. Let it run (for example, trust it in the application control policy) and install again."
            echo "defenseclaw-enterprise: refusing to install $incoming: ${floor_msg#Error: } Nothing was changed." >&2
            exit 1
        fi
    elif [ -n "$unchecked" ]; then
        echo "defenseclaw-enterprise: refusing to install $incoming: the release floor of the confirmed signed policy bundle could not be checked: $unchecked. Restore it as a readable, root-owned file that only root can write, in folders only root can write, and install again. Nothing was changed." >&2
        exit 1
    fi
    [ "$installed" != "-" ] || return 0
    not_older "$to" "$(product "$installed")" && return 0

    marker=$state/allow-downgrade
    if [ -f "$marker" ] && [ ! -L "$marker" ]; then
        # Leave the marker: the older package's preinstall checks it too, and
        # its postinstall applies the package with --allow-downgrade and
        # deletes it.
        return 0
    fi
    echo "defenseclaw-enterprise: $installed is installed; refusing to downgrade to $incoming. The older release may not read the current config. Nothing was changed." >&2
    echo "  For a deliberate rollback create the marker first: sudo touch $marker" >&2
    if [ -f "$previous_config" ]; then
        config=$previous_config
    fi
    echo "  Then install the older package; its postinstall applies it." >&2
    echo "  If it refuses the config, run: sudo $gateway enterprise linux ensure --from-package --allow-downgrade --config $config" >&2
    exit 1
}

# A here-document, not a pipe: the loop runs in this shell, so a refusal in
# check exits the hook.
while read -r installed incoming; do
    check "$installed" "$incoming"
done <<EOF
$changes
EOF
