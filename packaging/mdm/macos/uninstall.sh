#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# uninstall.sh - MDM removal of the standalone managed-enterprise deployment
# on Linux and macOS. Run as root.
#
# Runs `defenseclaw-gateway enterprise <linux|macos> uninstall --json`, which
# stops the services and removes DefenseClaw's hooks and machine-policy
# entries while preserving administrator-owned entries, then removes the
# package (dpkg / rpm; the macOS lifecycle forgets its pkg receipt itself).
# The uninstall also removes the administrator config, credentials, most
# state, logs and the service account. When an account keeps sandboxes, the
# gateway's sandbox registration store, key and root-owned setup record stay
# for the next ensure. --purge removes them and each enrolled account's
# ~/.defenseclaw and per-user binaries (the lifecycle purge runs before the
# package goes, so it can act as each user; an account's own personal install
# from before the enrollment is moved to a ~/.defenseclaw-backup-<UTC time>
# folder first), the staging folders that killed wrapper runs left (in the
# wrapper's state folder on Linux, in /var/tmp on macOS, and in the folder
# --staging-dir names when the wrapper runs used one) and the wrapper's empty
# state folder (/var/lib/defenseclaw-mdm, also its staging folder, on Linux;
# /var/db/defenseclaw-mdm on macOS).
# Without it each account keeps ~/.defenseclaw and its sandboxes. Every
# completed uninstall removes the wrapper's credential rotation journal
# (overwriting each earlier value it holds first), since the credentials go.
#
# Idempotent: on a host without the deployment it prints a no-op result and
# exits 0. Exit codes: 0 removed or nothing to do, 1 failure, 2 invalid
# arguments, 75 busy (retry later).
#
# Usage: uninstall.sh [--purge] [--keep-package] [--staging-dir DIR] [--log FILE]

set -eu

DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies
DC_LOG_NAME=uninstall.sh

# ---- MDM settings (flags override) -------------------------------------------
DC_PURGE=0          # 1: also remove each account's ~/.defenseclaw and per-user binaries
DC_KEEP_PACKAGE=0   # 1: leave the deb/rpm installed (Linux)
DC_STAGING_DIR=""   # the --staging-dir folder the wrapper runs used, if any (--purge sweeps it)
DC_LOG=""
# ---- end of settings ---------------------------------------------------------

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

readonly DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
readonly DC_LINUX_PACKAGE=defenseclaw-enterprise
# The wrapper's root-only state folder (on Linux also its staging folder,
# dc_stage_parent); it holds the credential rotation journal (rotation/).
DC_KIT_STATE=/var/lib/defenseclaw-mdm
DC_STAGE=""
DC_TRUST_ACL=""   # the ACL entry dc_trusted_path refused, for messages (set -u: read before any check ran)

dc_platform() {
    case "$(uname -s)" in
        Linux) echo linux ;;
        Darwin) echo darwin ;;
        *) echo unknown ;;
    esac
}

dc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

dc_json_escape() {
    printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\n\r\t' '   ' |
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

dc_log() {
    [ -n "$DC_LOG" ] || return 0
    if [ ! -e "$DC_LOG" ]; then
        ( umask 077; : >"$DC_LOG" ) 2>/dev/null || return 0
    fi
    [ -f "$DC_LOG" ] && [ ! -L "$DC_LOG" ] || return 0
    printf '%s %s[%s] %s\n' "$(dc_now)" "$DC_LOG_NAME" "$$" "$1" >>"$DC_LOG" 2>/dev/null || true
}

dc_stat_uid() {
    if [ "$DC_SCRIPT_OS" = darwin ]; then stat -f %u "$1"; else stat -c %u "$1"; fi
}

dc_stat_mode() { # octal permission bits including setuid/setgid/sticky, e.g. 1777
    if [ "$DC_SCRIPT_OS" = darwin ]; then stat -f %Mp%Lp "$1"; else stat -c %a "$1"; fi
}

# dc_acl_write_entry <path>: on macOS, print the first ACL entry of path (as
# ls -lde shows it) that lets an account other than root or the admin group
# change, delete or re-own it; return 1 when there is none. macOS grants such
# an entry without changing the owner or the mode bits, so a check of those
# alone trusts a path another account can change. An unreadable listing
# counts as such an entry.
dc_acl_write_entry() {
    [ "$DC_SCRIPT_OS" = darwin ] || return 1
    listing=$(ls -lde -- "$1" 2>/dev/null) || { printf 'unreadable ACL\n'; return 0; }
    entry=$(printf '%s\n' "$listing" | awk '
        /^ *[0-9]+: / {
            sub(/^ *[0-9]+: */, "")
            n = split(tolower($0), word, " ")
            kind = ""; rights = ""
            for (i = 2; i < n; i++) if (word[i] == "allow" || word[i] == "deny") { kind = word[i]; rights = word[i + 1] }
            if (kind != "allow" || word[1] == "user:root" || word[1] == "group:wheel" || word[1] == "group:admin") next
            split(rights, right, ",")
            for (r in right) if (right[r] ~ /^(write|add_file|append|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)$/) { print; exit }
        }')
    [ -n "$entry" ] || return 1
    printf '%s\n' "$entry"
}

# dc_trusted_path <path>: the file and every ancestor directory are owned by
# root, and none is writable by group or others unless it is a sticky
# directory (such as /tmp), whose root-owned entries other accounts cannot
# rename or delete, and (macOS) no ACL entry lets another account change
# one of them. So no other account can swap what root reads or runs.
# DC_TRUST_ACL names a refusing ACL entry for messages.
dc_trusted_path() {
    path=$1 child="" DC_TRUST_ACL=""
    case "$path" in /*) ;; *) return 1 ;; esac
    [ ! -L "$path" ] || return 1
    while :; do
        [ -e "$path" ] || return 1
        [ "$(dc_stat_uid "$path")" = 0 ] || return 1
        mode=$(dc_stat_mode "$path")
        # Last two octal digits: group and other. A write bit is accepted
        # only on a sticky ancestor directory, never on the target itself.
        group_other=$(printf '%s' "$mode" | sed 's/.*\(..\)$/\1/')
        case "$group_other" in
            [2367]? | ?[2367])
                [ -n "$child" ] && [ -d "$path" ] || return 1
                case "$mode" in 1??? | 3??? | 5??? | 7???) ;; *) return 1 ;; esac
                ;;
        esac
        if acl=$(dc_acl_write_entry "$path"); then
            DC_TRUST_ACL="; the macOS ACL entry '$acl' on $path lets another account change it (remove it with chmod -N $path)"
            return 1
        fi
        [ "$path" = / ] && return 0
        child=$path
        path=$(dirname "$path")
    done
}

# dc_result <ok> <noop> <exit> [<code> <message>]: print a schema-conformant
# result for an outcome the wrapper decided without the lifecycle.
dc_result() {
    ok=$1 noop=$2 exit_code=$3
    errors='[]'
    if [ "$#" -ge 5 ]; then
        errors=$(printf '[{"code":"%s","message":"%s"}]' "$4" "$(dc_json_escape "$5")")
    fi
    reason=''
    [ "$noop" = true ] && reason='"noop_reason":"not_installed",'
    document=$(printf '{"schema_version":2,"ok":%s,"action":"uninstall","noop":%s,%s"profile":"standalone","platform":"%s","product_version":"","installed":false,"transaction_pending":false,"services":[],"readiness":{"gateway":false,"guardian":false,"enumerator":false,"sensor_helper":false},"inspection":{"local":"unknown","ai_defense":"unknown"},"machine_policy":{},"enrollment":{"targets":0,"pending":0,"failed":0,"exempt":0},"coverage_complete":false,"security_complete":false,"errors":%s,"exit_code":%s}' \
        "$ok" "$noop" "$reason" "$DC_SCRIPT_OS" "$errors" "$exit_code")
    printf '%s\n' "$document"
    dc_log "result $document"
    exit "$exit_code"
}

dc_fail_result() { dc_result false false "$1" "$2" "$3"; }

dc_cleanup() {
    if [ -n "$DC_STAGE" ] && [ -d "$DC_STAGE" ]; then
        rm -rf "$DC_STAGE"
    fi
}

dc_busy_output() {
    printf '%s' "$1" | grep -Eqi 'could not get lock|dpkg frontend lock|lock-frontend|transaction lock|another install|is in use by another|waiting for cache lock'
}

# dc_linux_package_state: "deb", "rpm" or "" for the installed package.
dc_linux_package_state() {
    if command -v dpkg-query >/dev/null 2>&1 &&
        dpkg-query -W -f='${Status}' "$DC_LINUX_PACKAGE" 2>/dev/null | grep -q 'install ok installed'; then
        echo deb
    elif command -v rpm >/dev/null 2>&1 && rpm -q "$DC_LINUX_PACKAGE" >/dev/null 2>&1; then
        echo rpm
    fi
}

dc_remove_linux_package() {
    kind=$1
    case "$kind" in
        deb)
            flag=-r
            [ "$DC_PURGE" = 1 ] && flag=-P
            output=$(DEBIAN_FRONTEND=noninteractive dpkg "$flag" "$DC_LINUX_PACKAGE" 2>&1) || {
                dc_busy_output "$output" && dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                dc_fail_result "$DC_EXIT_FAILURE" mdm_package_remove_failed "dpkg failed: $output"
            }
            ;;
        rpm)
            output=$(rpm -e "$DC_LINUX_PACKAGE" 2>&1) || {
                dc_busy_output "$output" && dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                dc_fail_result "$DC_EXIT_FAILURE" mdm_package_remove_failed "rpm failed: $output"
            }
            ;;
    esac
    dc_log "removed package $DC_LINUX_PACKAGE ($kind)"
}

# dc_remove_rotation_journal: the uninstall removed the credentials, so the
# wrapper's credential rotation journal goes too; each earlier value it
# holds (<name>.value) is overwritten before it is removed. A journal that
# is a link or not root's own folder is left as it is and logged.
dc_remove_rotation_journal() {
    journal="$DC_KIT_STATE/rotation"
    [ -e "$journal" ] || [ -L "$journal" ] || return 0
    if [ -L "$journal" ] || [ ! -d "$journal" ] || [ "$(dc_stat_uid "$journal")" != 0 ]; then
        dc_log "left $journal as it is: it is not a root-owned folder"
        return 0
    fi
    for value in "$journal"/*.value; do
        if [ ! -f "$value" ] || [ -L "$value" ]; then continue; fi
        size=$(wc -c <"$value" | tr -d ' ')
        dd if=/dev/zero of="$value" bs=1 count="$size" conv=notrunc 2>/dev/null || true
    done
    rm -f "${journal:?}"/*.value "${journal:?}"/*.entry "${journal:?}"/*.entry.partial "${journal:?}"/.lock
    if rmdir "$journal" 2>/dev/null; then
        dc_log "removed the credential rotation journal $journal"
    else
        dc_log "could not remove the credential rotation journal $journal: it holds files the wrapper does not write"
    fi
}

# dc_sweep_stages <parent>: remove the staging folders of earlier runs that
# were killed before their cleanup ran: root-owned, and either their run is
# gone (the pid it recorded no longer runs) or, without a pid, a day old.
dc_sweep_stages() {
    for stale in "$1"/defenseclaw-mdm.*; do
        if [ ! -d "$stale" ] || [ -L "$stale" ]; then continue; fi
        [ "$(dc_stat_uid "$stale")" = 0 ] || continue
        owner=$(head -c 32 "$stale/pid" 2>/dev/null || true)
        case "$owner" in
            "" | *[!0-9]*)
                [ -n "$(find "$stale" -maxdepth 0 -mmin +1440 2>/dev/null)" ] || continue
                ;;
            *)
                ! kill -0 "$owner" 2>/dev/null || continue
                ;;
        esac
        rm -rf "$stale"
    done
}

# dc_remove_stage_parent: a purge removes the staging folders that wrapper
# runs killed before their cleanup left, with the wrapper's own rule
# (dc_sweep_stages, GAP-1733), and then the wrapper's root-only state folder
# once it is empty (#1298). On macOS the wrapper stages in /var/tmp, not in
# its state folder; a --staging-dir folder is the administrator's, so only
# its stale stages go. A folder that is not root's own directory, or that a
# wrapper run still stages in, stays.
dc_remove_stage_parent() {
    [ "$DC_PURGE" = 1 ] || return 0
    if [ "${DC_SCRIPT_OS:-}" = darwin ]; then
        dc_sweep_stages /var/tmp
    fi
    if [ -n "${DC_STAGING_DIR:-}" ]; then
        dc_sweep_stages "$DC_STAGING_DIR"
    fi
    [ -d "$DC_KIT_STATE" ] && [ ! -L "$DC_KIT_STATE" ] || return 0
    [ "$(dc_stat_uid "$DC_KIT_STATE")" = 0 ] || return 0
    dc_sweep_stages "$DC_KIT_STATE"
    if rmdir "$DC_KIT_STATE" 2>/dev/null; then
        dc_log "removed the empty folder $DC_KIT_STATE"
    fi
}

# Intune's Linux agent may repeat its /proc/self/fd/N script descriptor.
case "${1:-}" in
    /proc/self/fd/*)
        case "${1#/proc/self/fd/}" in '' | *[!0-9]*) ;; *) shift ;; esac
        ;;
esac
if [ "$DC_SCRIPT_OS" = darwin ]; then
    [ -n "$DC_LOG" ] || DC_LOG=/Library/Logs/Cisco/DefenseClaw/mdm-wrapper.log
else
    [ -n "$DC_LOG" ] || DC_LOG=/var/log/defenseclaw-enterprise-mdm.log
fi
dc_log "start action=uninstall"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge) DC_PURGE=1; shift ;;
        --keep-package) DC_KEEP_PACKAGE=1; shift ;;
        --staging-dir) DC_STAGING_DIR=${2:-}; shift 2 ;;
        --log) DC_LOG=${2:-}; shift 2 ;;
        -h | --help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "unknown argument: $1" ;;
    esac
done

[ "$(dc_platform)" = "$DC_SCRIPT_OS" ] ||
    dc_fail_result "$DC_EXIT_INVALID" mdm_wrong_platform "this copy of uninstall.sh is for $DC_SCRIPT_OS"
if [ "$DC_SCRIPT_OS" = darwin ]; then
    gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos DC_KIT_STATE=/var/db/defenseclaw-mdm
    [ -n "$DC_LOG" ] || DC_LOG=/Library/Logs/Cisco/DefenseClaw/mdm-wrapper.log
else
    gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux
    [ -n "$DC_LOG" ] || DC_LOG=/var/log/defenseclaw-enterprise-mdm.log
fi
[ -d "$(dirname "$DC_LOG")" ] || DC_LOG=""
[ "$(id -u)" = 0 ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_not_root "run as root (the MDM agent's system context)"
if [ -n "$DC_STAGING_DIR" ]; then
    case "$DC_STAGING_DIR" in
        /*) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--staging-dir must be an absolute path" ;;
    esac
    if [ ! -e "$DC_STAGING_DIR" ] && [ ! -L "$DC_STAGING_DIR" ]; then
        # GAP-2453: name a missing folder, as the wrapper does (GAP-0030).
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging folder $DC_STAGING_DIR does not exist; name the --staging-dir folder the wrapper runs used, or leave out --staging-dir"
    fi
    if [ ! -d "$DC_STAGING_DIR" ] || ! dc_trusted_path "$DC_STAGING_DIR"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging folder $DC_STAGING_DIR is not a root-owned directory that only root can write$DC_TRUST_ACL"
    fi
fi

DC_STAGE=$(mktemp -d /var/tmp/defenseclaw-mdm.XXXXXX)
trap dc_cleanup EXIT
trap 'exit 1' HUP INT TERM
dc_log "start action=uninstall purge=$DC_PURGE"

package=""
[ "$DC_SCRIPT_OS" = linux ] && package=$(dc_linux_package_state)

if [ -e "$gateway" ]; then
    dc_trusted_path "$gateway" ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "$gateway is not root-owned or is writable by other accounts; refusing to run it$DC_TRUST_ACL"
    set -- uninstall
    [ "$DC_PURGE" = 1 ] && set -- "$@" --purge
    set +e
    "$gateway" enterprise "$group" "$@" --json >"$DC_STAGE/result.json" 2>"$DC_STAGE/lifecycle.err" </dev/null
    status=$?
    set -e
    if [ ! -s "$DC_STAGE/result.json" ]; then
        detail=$(head -c 2048 "$DC_STAGE/lifecycle.err" 2>/dev/null || true)
        dc_fail_result "$DC_EXIT_FAILURE" mdm_lifecycle_no_result "the lifecycle printed no result: $detail"
    fi
    case "$status" in 0 | 1 | 2 | 75) ;; *) status=$DC_EXIT_FAILURE ;; esac
    if [ "$status" != 0 ]; then
        cat "$DC_STAGE/result.json"
        dc_log "result $(tr -d '\n' <"$DC_STAGE/result.json")"
        exit "$status"
    fi
    if [ -n "$package" ] && [ "$DC_KEEP_PACKAGE" = 0 ]; then
        dc_remove_linux_package "$package"
    fi
    dc_remove_rotation_journal
    dc_remove_stage_parent
    cat "$DC_STAGE/result.json"
    dc_log "result $(tr -d '\n' <"$DC_STAGE/result.json")"
    exit 0
fi

# No gateway: remove a half-removed package, otherwise nothing to do.
dc_remove_rotation_journal
dc_remove_stage_parent
if [ -n "$package" ] && [ "$DC_KEEP_PACKAGE" = 0 ]; then
    dc_remove_linux_package "$package"
    dc_result true false 0
fi
dc_result true true 0
