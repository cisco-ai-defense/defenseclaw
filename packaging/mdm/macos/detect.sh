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
#   value           exit 0 (except sessions failure); print the installed version, or
#                   "not-installed" / "outdated" / "unhealthy". For Intune
#                   custom attributes and inventory scripts.
#   jamf            exit 0 (except sessions failure); print <result>...</result> with the same
#                   values. For Jamf Pro extension attributes.
#
# --require-tetragon MODE (Linux only; consume, observe or enforce) also
# requires `enterprise linux tetragon verify --ready-for MODE` to pass; a host
# that is not ready reports "tetragon-not-ready:<first failing check>".
#
# --require-bundle <bundle id | version> also requires a signed policy bundle
# --require-sessions-protected fails while running agents need a restart to
# load newly installed managed hooks.
# (`enterprise bundle status`): a bundle id (b-<ULID>) must be the current
# confirmed bundle, a version number must be at most the current version,
# and the running gateway must enforce the bundle's effective policy digest.
# Otherwise: bundle-missing, bundle-mismatch, bundle-outdated or
# bundle-not-enforced.
#
# --bundle-status prints "<bundle id> <version> <state>" of the enforcing
# receipt and always exits 0; with --format jamf inside <result>.
# For a Jamf extension attribute or a compliance script. state is a receipt
# state (received, verified, staged, applied, confirmed), failed:<error
# code>, not-enforced (confirmed, but the gateway does not report its
# digest), none (no bundle received yet), or not-installed / unknown with
# "none 0" when there is nothing to read.
#
# Usage: detect.sh [--min-version X.Y.Z] [--require-healthy]
#                  [--require-tetragon consume|observe|enforce]
#                  [--require-bundle ID|VERSION] [--require-sessions-protected]
#                  [--format exit|value|jamf]
#        detect.sh --bundle-status [--format exit|value|jamf]

set -eu

DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies

# ---- MDM settings (flags override) -------------------------------------------
DC_MIN_VERSION=""       # detect only this version or newer
DC_MIN_VERSION_SET=0
DC_REQUIRE_HEALTHY=0    # 1: also require `verify` to pass
DC_REQUIRE_TETRAGON=""  # consume | observe | enforce: also require Tetragon readiness (Linux)
DC_REQUIRE_BUNDLE=""    # bundle id (b-<ULID>) or minimum version: also require that signed policy bundle
DC_REQUIRE_SESSIONS_PROTECTED=0 # 1: no preexisting agent sessions without managed hooks
DC_BUNDLE_STATUS=0      # 1: print "<bundle id> <version> <state>" of the enforcing receipt instead
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
    [ "${DC_BUNDLE_STATUS:-0}" = 0 ] || dc_bundle_line "none 0 $value"
    case "$DC_FORMAT" in
        value) printf '%s\n' "$value"; [ "${DC_SESSIONS_REQUIRED_FAILURE:-0}" = 0 ] && exit 0 || exit 1 ;;
        jamf) printf '<result>%s</result>\n' "$value"; [ "${DC_SESSIONS_REQUIRED_FAILURE:-0}" = 0 ] && exit 0 || exit 1 ;;
    esac
    if [ "$value" = busy ]; then
        printf 'defenseclaw detect: lifecycle is busy; retry later\n' >&2
        exit 75
    fi
    if [ "$detected" = 1 ]; then
        printf 'DefenseClaw Enterprise %s%s\n' "$value" "${DC_BUNDLE_TEXT:-}"
        exit 0
    fi
    printf 'defenseclaw detect: %s\n' "$reason" >&2
    exit 1
}

# dc_json_object <document> <field>: the text of a top-level object field,
# for dc_json_top and dc_json_field; nothing when the field is not an object.
dc_json_object() {
    printf '%s' "$1" | awk -v want="$2" '
        BEGIN { RS = "\001" }
        {
            s = $0; n = length(s); depth = 0; key = ""; start = 0; i = 1
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "\"") {
                    j = i + 1
                    while (j <= n) {
                        d = substr(s, j, 1)
                        if (d == "\\") { j += 2; continue }
                        if (d == "\"") break
                        j++
                    }
                    str = substr(s, i + 1, j - i - 1)
                    i = j + 1
                    if (depth == 1) {
                        k = i
                        while (k <= n && substr(s, k, 1) ~ /[ \t\r\n]/) k++
                        if (substr(s, k, 1) == ":") { key = str; i = k + 1 } else key = ""
                    }
                    continue
                }
                if (c == "{" || c == "[") {
                    depth++
                    if (depth == 2 && c == "{" && key == want) start = i
                    if (depth == 2) key = ""
                    i++; continue
                }
                if (c == "}" || c == "]") {
                    if (depth == 2 && start) { print substr(s, start, i - start + 1); exit }
                    depth--; i++; continue
                }
                if (depth == 1 && c !~ /[ \t\r\n]/) key = ""
                i++
            }
        }'
}

# dc_bundle_line <line>: print the --bundle-status line in the format asked
# for and exit 0.
dc_bundle_line() {
    case "$DC_FORMAT" in
        jamf) printf '<result>%s</result>\n' "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
    exit 0
}

# dc_bundle_status <gateway>: --bundle-status from `enterprise bundle status`.
dc_bundle_status() {
    doc=$("$1" enterprise bundle status --json 2>/dev/null </dev/null || true)
    dc_json_true "$doc" ok || dc_bundle_line "none 0 unknown"
    bundle=$(dc_json_object "$doc" bundle)
    current=$(dc_json_object "$doc" current)
    receipt=$(dc_json_object "$doc" last_receipt)
    if [ "$(dc_json_field "$receipt" state)" = confirmed ] &&
       [ "$(dc_json_field "$receipt" bundle_id)" = "$(dc_json_field "$current" bundle_id)" ]; then
        bundle=$receipt
    fi
    id=$(dc_json_field "$bundle" bundle_id)
    [ -n "$id" ] || dc_bundle_line "none 0 none"
    version=$(dc_json_field "$bundle" version)
    state=$(dc_json_field "$bundle" state)
    case "$state" in
        failed)
            code=$(dc_json_field "$bundle" error_code)
            state="failed:${code:-unknown}"
            ;;
        confirmed) dc_json_true "$doc" applied || state=not-enforced ;;
        "") state=unknown ;;
    esac
    dc_bundle_line "$id ${version:-0} $state"
}

# dc_require_bundle <gateway> <bundle id | version>: report not detected
# unless that bundle (or a newer version) is current and the gateway
# enforces it.
dc_require_bundle() {
    doc=$("$1" enterprise bundle status --json 2>/dev/null </dev/null || true)
    current=$(dc_json_object "$doc" current)
    bundle_id=$(dc_json_field "$current" bundle_id)
    bundle_version=$(dc_json_field "$current" version)
    case "$bundle_id:$bundle_version" in
        b-*:[0-9]*) ;;
        *) dc_report 0 bundle-missing "no signed policy bundle is confirmed on this computer; run: sudo $1 enterprise bundle status" ;;
    esac
    case "$2" in
        b-*) [ "$bundle_id" = "$2" ] || dc_report 0 bundle-mismatch "the confirmed policy bundle is $bundle_id, not $2" ;;
        *) [ "$bundle_version" -ge "$2" ] || dc_report 0 bundle-outdated "the confirmed policy bundle is version $bundle_version, older than $2" ;;
    esac
    dc_json_true "$doc" applied ||
        dc_report 0 bundle-not-enforced "the running gateway does not enforce policy bundle $bundle_id; run: sudo $1 enterprise bundle status"
    DC_BUNDLE_TEXT=", policy bundle $bundle_id version $bundle_version"
}

# dc_require_sessions_protected <gateway>: a bundle can be confirmed while
# agents already running still have the hooks they read before installation.
dc_require_sessions_protected() {
    doc=$("$1" enterprise bundle status --json 2>/dev/null </dev/null || true)
    sessions=$(dc_json_object "$doc" sessions_restart_required)
    state=$(dc_json_top "$sessions" state)
    count=$(dc_json_top "$sessions" count)
    DC_SESSIONS_REQUIRED_FAILURE=1
    [ "$(dc_json_top "$doc" ok)" = true ] && [ "$state" = known ] ||
        dc_report 0 unknown "running agent sessions could not be checked; run: sudo $1 enterprise bundle status"
    case "$count" in
        '' | *[!0-9]*) dc_report 0 unknown "bundle status reported no session count" ;;
    esac
    [ "$count" -eq 0 ] ||
        dc_report 0 sessions-need-restart "sessions-need-restart: $count running agent session(s) need restart to load managed hooks"
    DC_SESSIONS_REQUIRED_FAILURE=0
}

# dc_first_failing_check <tetragon verify --json document>: the id of its
# first failing check.
dc_first_failing_check() {
    printf '%s' "$1" | tr -d '\n' | awk '
        BEGIN { RS = "\001" }
        {
            s = $0; id = ""
            while (match(s, /"(id|status)"[ \t]*:[ \t]*"[^"]*"/)) {
                n = split(substr(s, RSTART, RLENGTH), part, "\"")
                s = substr(s, RSTART + RLENGTH)
                if (part[2] == "id") id = part[4]
                else if (part[4] == "fail" && id != "") { print id; exit }
            }
        }'
}

# dc_require_tetragon <gateway> <mode>: report the host not ready unless
# `tetragon verify --ready-for <mode>` passes.
dc_require_tetragon() {
    readiness=$("$1" enterprise linux tetragon verify --ready-for "$2" --json 2>/dev/null </dev/null || true)
    dc_json_true "$readiness" ready && return 0
    check=$(dc_first_failing_check "$readiness")
    dc_report 0 "tetragon-not-ready:${check:-unknown}" "not ready for Tetragon mode $2 (${check:-no readiness report}); run: sudo $1 enterprise linux tetragon verify --ready-for $2"
}

# dc_package_interrupted prints why the package manager still holds the
# DefenseClaw package mid-transaction, or nothing: dpkg left it half-configured
# or half-installed (a power loss in its postinst), or rpm lists two versions
# (an interrupted upgrade). apt refuses every other install until it is
# finished, so detection must not report it healthy (GAP-0930).
dc_package_interrupted() {
    [ "$DC_SCRIPT_OS" = linux ] || return 0
    if command -v dpkg-query >/dev/null 2>&1; then
        state=$(dpkg-query -W -f='${Status}' defenseclaw-enterprise 2>/dev/null || true)
        case "$state" in
            "" | *" installed" | *" not-installed" | *" config-files") ;;
            *)
                printf 'dpkg reports the defenseclaw-enterprise package %s, so an install or upgrade was interrupted; run the deployment again (or dpkg --configure -a)' "${state##* }"
                return 0
                ;;
        esac
    fi
    if command -v rpm >/dev/null 2>&1; then
        count=$(rpm -q defenseclaw-enterprise 2>/dev/null | grep -c '^defenseclaw-enterprise-' || true)
        if [ "${count:-0}" -gt 1 ]; then
            printf 'rpm lists %s versions of defenseclaw-enterprise, so an upgrade was interrupted; run the deployment again' "$count"
        fi
    fi
}

# Intune's Linux agent may repeat its /proc/self/fd/N script descriptor.
case "${1:-}" in
    /proc/self/fd/*)
        case "${1#/proc/self/fd/}" in '' | *[!0-9]*) ;; *) shift ;; esac
        ;;
esac
while [ "$#" -gt 0 ]; do
    case "$1" in
        --min-version) DC_MIN_VERSION=${2:-}; DC_MIN_VERSION_SET=1; shift 2 ;;
        --require-healthy) DC_REQUIRE_HEALTHY=1; shift ;;
        --require-tetragon) DC_REQUIRE_TETRAGON=${2:-}; shift 2 ;;
        --require-bundle) DC_REQUIRE_BUNDLE=${2:-}; [ -n "$DC_REQUIRE_BUNDLE" ] || DC_REQUIRE_BUNDLE=-; shift 2 ;;
        --require-sessions-protected) DC_REQUIRE_SESSIONS_PROTECTED=1; shift ;;
        --bundle-status) DC_BUNDLE_STATUS=1; shift ;;
        --format) DC_FORMAT=${2:-}; shift 2 ;;
        -h | --help) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
        *) printf 'defenseclaw detect: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if { [ "$DC_MIN_VERSION_SET" = 1 ] || [ -n "$DC_MIN_VERSION" ]; } &&
    ! printf '%s' "$DC_MIN_VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?(\+[A-Za-z0-9][A-Za-z0-9.-]*)?$'; then
    printf 'defenseclaw detect: --min-version must be a dotted release version\n' >&2
    exit 2
fi
case "$DC_FORMAT" in exit | value | jamf) ;; *) printf 'defenseclaw detect: --format must be exit, value or jamf\n' >&2; exit 2 ;; esac
case "$DC_REQUIRE_TETRAGON" in
    "" | consume | observe | enforce) ;;
    *) printf 'defenseclaw detect: --require-tetragon must be consume, observe or enforce\n' >&2; exit 2 ;;
esac
if [ -n "$DC_REQUIRE_BUNDLE" ] &&
    ! printf '%s' "$DC_REQUIRE_BUNDLE" | grep -Eq '^(b-[0-7][0-9A-HJKMNP-TV-Z]{25}|[0-9]{1,16})$'; then
    printf 'defenseclaw detect: --require-bundle must be a bundle id (b-<ULID>) or a version number\n' >&2
    exit 2
fi
if [ "$DC_BUNDLE_STATUS" = 1 ] &&
    { [ -n "$DC_MIN_VERSION$DC_REQUIRE_TETRAGON$DC_REQUIRE_BUNDLE" ] || [ "$DC_REQUIRE_HEALTHY" = 1 ] || [ "$DC_REQUIRE_SESSIONS_PROTECTED" = 1 ]; }; then
    printf 'defenseclaw detect: --bundle-status takes no --min-version or --require-* option\n' >&2
    exit 2
fi
if [ -n "$DC_REQUIRE_TETRAGON" ] && [ "$DC_SCRIPT_OS" != linux ]; then
    printf 'defenseclaw detect: --require-tetragon is Linux only (Tetragon runs on Linux)\n' >&2
    exit 2
fi

[ "$(dc_platform)" = "$DC_SCRIPT_OS" ] || dc_report 0 not-installed "this copy of detect.sh is for $DC_SCRIPT_OS"
[ "$(id -u)" = 0 ] || dc_report 0 unknown "run as root"

if [ "$DC_SCRIPT_OS" = darwin ]; then
    gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos
else
    gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux
fi
dc_trusted_path "$gateway" || dc_report 0 not-installed "$gateway is missing or not root-owned$DC_TRUST_ACL"
# An empty binary (a power loss during a package upgrade) runs as an empty
# script that prints nothing and exits 0 (GAP-0467).
[ -s "$gateway" ] || dc_report 0 not-installed "$gateway is empty, likely from a power loss during a package upgrade; reinstall the package"
[ "$DC_BUNDLE_STATUS" = 0 ] || dc_bundle_status "$gateway"

if status=$("$gateway" enterprise "$group" status --json 2>/dev/null </dev/null); then
    status_code=0
else
    status_code=$?
fi
[ "$status_code" != 75 ] && ! printf '%s' "$status" | grep -Eq '"code"[[:space:]]*:[[:space:]]*"lifecycle_busy"' || dc_report 0 busy "lifecycle is busy"
dc_json_true "$status" installed || dc_report 0 not-installed "the managed deployment is not installed"
version=$(dc_json_field "$status" installed_version)
[ -n "$version" ] || version=$(dc_json_field "$status" product_version)
[ -n "$version" ] || dc_report 0 not-installed "the lifecycle status reports no installed version"
if [ "$DC_REQUIRE_HEALTHY" = 1 ] || [ "$DC_FORMAT" = exit ]; then
    if verify=$("$gateway" enterprise "$group" verify --json 2>/dev/null </dev/null); then
        verify_status=0
    else
        verify_status=$?
    fi
    [ "$verify_status" != 75 ] && [ "$(printf '%s' "$verify" | grep -c '"code": "lifecycle_busy"' || true)" = 0 ] || dc_report 0 busy "lifecycle is busy"
fi
if [ -n "$DC_MIN_VERSION" ] && ! dc_version_ge "$version" "$DC_MIN_VERSION"; then
    dc_report 0 outdated "installed version $version is older than $DC_MIN_VERSION"
fi
if [ "$DC_REQUIRE_HEALTHY" = 1 ]; then
    package_problem=$(dc_package_interrupted)
    [ -z "$package_problem" ] || dc_report 0 unhealthy "$package_problem"
    dc_json_true "$verify" ok || dc_report 0 unhealthy "verify reported problems; run: $gateway enterprise $group verify"
    dc_json_true "$verify" security_complete || dc_report 0 unhealthy "verify reported incomplete security; run: $gateway enterprise $group verify"
fi
[ -z "$DC_REQUIRE_TETRAGON" ] || dc_require_tetragon "$gateway" "$DC_REQUIRE_TETRAGON"
[ -z "$DC_REQUIRE_BUNDLE" ] || dc_require_bundle "$gateway" "$DC_REQUIRE_BUNDLE"
[ "$DC_REQUIRE_SESSIONS_PROTECTED" = 0 ] || dc_require_sessions_protected "$gateway"
dc_report 1 "$version" ""
