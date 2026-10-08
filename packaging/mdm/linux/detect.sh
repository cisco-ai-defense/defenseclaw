#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# detect.sh - MDM detection for the standalone managed-enterprise deployment
# on Linux and macOS. Read-only; run as root.
#
# Asks the installed, root-owned gateway for its lifecycle status (and, with
# --require-healthy, runs verify) instead of trusting marker files a user
# could create.
#
# Output formats:
#   exit (default)  exit 0 and print "DefenseClaw Enterprise <version>" when
#                   installed (and new enough / healthy); otherwise exit 1 and
#                   explain on stderr. For detection rules and compliance
#                   scripts that read the exit code.
#   value           always exit 0; print the installed version, or
#                   "not-installed" / "outdated" / "unhealthy". For Intune
#                   custom attributes and inventory scripts.
#   jamf            always exit 0; print <result>...</result> with the same
#                   values. For Jamf Pro extension attributes.
#
# Usage: detect.sh [--min-version X.Y.Z] [--require-healthy] [--format exit|value|jamf]

set -eu

DC_SCRIPT_OS=linux # linux | darwin - the only line that differs between the copies

# ---- MDM settings (flags override) -------------------------------------------
DC_MIN_VERSION=""       # detect only this version or newer
DC_REQUIRE_HEALTHY=0    # 1: also require `verify` to pass
DC_FORMAT="exit"        # exit | value | jamf
# ---- end of settings ---------------------------------------------------------

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

dc_platform() {
    case "$(uname -s)" in
        Linux) echo linux ;;
        Darwin) echo darwin ;;
        *) echo unknown ;;
    esac
}

dc_stat_uid() {
    if [ "$DC_SCRIPT_OS" = darwin ]; then stat -f %u "$1"; else stat -c %u "$1"; fi
}

dc_stat_mode() { # octal permission bits including setuid/setgid/sticky, e.g. 1777
    if [ "$DC_SCRIPT_OS" = darwin ]; then stat -f %Mp%Lp "$1"; else stat -c %a "$1"; fi
}

# dc_trusted_path <path>: the file and every ancestor directory are owned by
# root, and none is writable by group or others unless it is a sticky
# directory (such as /tmp), whose root-owned entries other accounts cannot
# rename or delete. So no other account can swap what root reads or runs.
dc_trusted_path() {
    path=$1 child=""
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
        [ "$path" = / ] && return 0
        child=$path
        path=$(dirname "$path")
    done
}

# dc_version_ge <a> <b>: a >= b for dotted release versions; a prerelease
# (1.2.0-rc1) sorts before its release, build metadata (+...) is ignored.
dc_version_ge() {
    awk -v a="$1" -v b="$2" '
        function norm(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
        BEGIN {
            a = norm(a); b = norm(b)
            pa = ""; pb = ""
            if (index(a, "-")) { pa = substr(a, index(a, "-") + 1); a = substr(a, 1, index(a, "-") - 1) }
            if (index(b, "-")) { pb = substr(b, index(b, "-") + 1); b = substr(b, 1, index(b, "-") - 1) }
            na = split(a, x, "."); nb = split(b, y, ".")
            n = na > nb ? na : nb
            for (i = 1; i <= n; i++) {
                xi = (i <= na) ? x[i] + 0 : 0; yi = (i <= nb) ? y[i] + 0 : 0
                if (xi > yi) exit 0
                if (xi < yi) exit 1
            }
            if (pa == pb) exit 0
            if (pa == "") exit 0
            if (pb == "") exit 1
            exit (pa > pb) ? 0 : 1
        }'
}

# dc_json_top <document> <field>: the scalar value of a top-level field of the
# lifecycle result (compact or indented JSON), without quotes. Nested objects
# and arrays are skipped, so a nested "ok" or "installed" never answers for the
# top-level one.
dc_json_top() {
    printf '%s' "$1" | awk -v want="$2" '
        BEGIN { RS = "\001" }
        {
            s = $0; n = length(s); depth = 0; key = ""; i = 1
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "\"") {
                    j = i + 1; str = ""
                    while (j <= n) {
                        d = substr(s, j, 1)
                        if (d == "\\") { str = str substr(s, j, 2); j += 2; continue }
                        if (d == "\"") break
                        str = str d; j++
                    }
                    i = j + 1
                    if (depth == 1) {
                        k = i
                        while (k <= n && substr(s, k, 1) ~ /[ \t\r\n]/) k++
                        if (substr(s, k, 1) == ":") { key = str; i = k + 1; continue }
                        if (key != "") { vals[key] = str; key = "" }
                    }
                    continue
                }
                if (c == "{" || c == "[") { depth++; if (depth == 2) key = ""; i++; continue }
                if (c == "}" || c == "]") { depth--; i++; continue }
                if (depth == 1 && key != "" && c ~ /[tfn0-9-]/) {
                    j = i
                    while (j <= n && substr(s, j, 1) ~ /[a-z0-9.eE+-]/) j++
                    vals[key] = substr(s, i, j - i); key = ""; i = j; continue
                }
                i++
            }
        }
        END { if (want in vals) print vals[want] }'
}

dc_json_field() { # <document> <field>: a top-level string field
    dc_json_top "$1" "$2"
}

dc_json_true() { # <document> <field>: a top-level field is the literal true
    [ "$(dc_json_top "$1" "$2")" = true ]
}

dc_report() { # <detected 0|1> <value> <reason>
    detected=$1 value=$2 reason=$3
    case "$DC_FORMAT" in
        value) printf '%s\n' "$value"; exit 0 ;;
        jamf) printf '<result>%s</result>\n' "$value"; exit 0 ;;
    esac
    if [ "$detected" = 1 ]; then
        printf 'DefenseClaw Enterprise %s\n' "$value"
        exit 0
    fi
    printf 'defenseclaw detect: %s\n' "$reason" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --min-version) DC_MIN_VERSION=${2:-}; shift 2 ;;
        --require-healthy) DC_REQUIRE_HEALTHY=1; shift ;;
        --format) DC_FORMAT=${2:-}; shift 2 ;;
        -h | --help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'defenseclaw detect: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
case "$DC_FORMAT" in exit | value | jamf) ;; *) printf 'defenseclaw detect: --format must be exit, value or jamf\n' >&2; exit 2 ;; esac

[ "$(dc_platform)" = "$DC_SCRIPT_OS" ] || dc_report 0 not-installed "this copy of detect.sh is for $DC_SCRIPT_OS"
[ "$(id -u)" = 0 ] || dc_report 0 not-installed "run as root"

if [ "$DC_SCRIPT_OS" = darwin ]; then
    gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos
else
    gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux
fi
dc_trusted_path "$gateway" || dc_report 0 not-installed "$gateway is missing or not root-owned"
# An empty binary (a power loss during a package upgrade) runs as an empty
# script that prints nothing and exits 0 (GAP-0467).
[ -s "$gateway" ] || dc_report 0 not-installed "$gateway is empty, likely from a power loss during a package upgrade; reinstall the package"

status=$("$gateway" enterprise "$group" status --json 2>/dev/null </dev/null || true)
dc_json_true "$status" installed || dc_report 0 not-installed "the managed deployment is not installed"
version=$(dc_json_field "$status" installed_version)
[ -n "$version" ] || version=$(dc_json_field "$status" product_version)
[ -n "$version" ] || dc_report 0 not-installed "the lifecycle status reports no installed version"
if [ -n "$DC_MIN_VERSION" ] && ! dc_version_ge "$version" "$DC_MIN_VERSION"; then
    dc_report 0 outdated "installed version $version is older than $DC_MIN_VERSION"
fi
if [ "$DC_REQUIRE_HEALTHY" = 1 ]; then
    verify=$("$gateway" enterprise "$group" verify --json 2>/dev/null </dev/null || true)
    dc_json_true "$verify" ok || dc_report 0 unhealthy "verify reported problems; run: $gateway enterprise $group verify"
fi
dc_report 1 "$version" ""
