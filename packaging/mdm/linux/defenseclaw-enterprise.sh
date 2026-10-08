#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise.sh - generic MDM wrapper for the standalone
# managed-enterprise deployment on Linux and macOS.
#
# Any MDM, configuration-management tool or administrator shell that can run
# a root script uses this one entry point. It:
#   1. refuses unless it runs as root, and never depends on the caller's
#      environment (PATH, HOME, locale, proxies) or on a TTY;
#   2. copies the staged package or payload into a root-only staging
#      directory and verifies it there (SHA-256 pin and/or vendor signature)
#      before anything is installed;
#   3. installs the package (deb, rpm or pkg) or the extracted payload, then
#      runs `defenseclaw-gateway enterprise <linux|macos> ensure --json`,
#      which is a true no-op when nothing changed;
#   4. takes the administrator config and the optional AI Defense credential
#      from a file or standard input, never from the command line;
#   5. prints the lifecycle result (packaging/mdm/contract/
#      lifecycle-result.schema.json) on stdout, appends it to a root-only log
#      and exits with the lifecycle exit code: 0 success or no-op, 1 failure
#      (already rolled back), 2 invalid arguments, 75 busy (retry later).
#      When the package step installed or upgraded the package (its
#      postinstall applies the deployment, so the ensure that follows is
#      usually a no-op), the result says so: action install or upgrade and a
#      package_installed or package_upgraded warning with the versions.
#
# The Linux and macOS copies are identical except DC_SCRIPT_OS; each refuses
# to run on the other platform.
#
# Usage (every flag overrides the settings block below):
#   defenseclaw-enterprise.sh [--action ensure|status|verify]
#       [--source FILE | --source-url https://...] [--sha256 HEX]
#       [--trust-mode hash_pinned|signed]
#       [--allowed-team-id TEAMID]... (macOS signed)
#       [--gpg-keyring FILE] [--signature FILE | --signature-url URL] (Linux signed)
#       [--config-file FILE | --config-stdin]
#       [--secret-name NAME (--secret-file FILE | --secret-stdin)]
#       [--product-version X.Y.Z] [--https-proxy URL] [--log FILE]
#
# Sources: a defenseclaw-enterprise .deb or .rpm (Linux), a .pkg (macOS) or
# the defenseclaw-enterprise-<version>-<os>-<arch>.tar.gz payload (both).
# Without a source the wrapper re-applies the installed deployment (for
# example after a config change).

set -eu

DC_SCRIPT_OS=linux # linux | darwin - the only line that differs between the copies

# ---- MDM settings ------------------------------------------------------------
# Script-only MDMs (Intune platform scripts, Jamf policies, ...) upload this
# file without arguments: set the values here. Command-line flags override.
DC_ACTION=ensure
DC_SOURCE=""                # absolute path of a staged package or payload archive
DC_SOURCE_URL=""            # or an https:// URL to download it from
DC_SOURCE_SHA256=""         # SHA-256 of the source (required for hash_pinned)
DC_TRUST_MODE=hash_pinned   # hash_pinned | signed
DC_ALLOWED_TEAM_IDS=""      # macOS signed: space-separated Developer ID team IDs
DC_GPG_KEYRING=""           # Linux signed: root-owned keyring holding the release key
DC_SIGNATURE=""             # Linux signed: detached signature (default: <source>.asc)
DC_SIGNATURE_URL=""         # Linux signed: or an https:// URL for it
DC_PRODUCT_VERSION=""       # refuse unless the source is exactly this version
DC_CONFIG_FILE=""           # absolute path of the administrator config
DC_SECRET_NAME=""           # e.g. ai-defense-api-key (value only via file or stdin)
DC_SECRET_FILE=""
DC_HTTPS_PROXY=""           # proxy for the download only
DC_LOG=""                   # default: the platform log path below

# Inline administrator config for script-only MDMs: put the YAML between the
# markers. Never put credentials here - MDM script bodies are not secret
# storage; deliver credentials with --secret-file or --secret-stdin.
dc_inline_config() {
    cat <<'DEFENSECLAW_CONFIG'
DEFENSECLAW_CONFIG
}
# ---- end of settings ---------------------------------------------------------

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset IFS || true
umask 077

readonly DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
readonly DC_MAX_CONFIG_BYTES=1048576 DC_MAX_SECRET_BYTES=16384
readonly DC_LINUX_PACKAGE=defenseclaw-enterprise
readonly DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise

DC_CONFIG_STDIN=0
DC_SECRET_STDIN=0
DC_STAGE=""
DC_CHILD=""
DC_RESULT=""
DC_PACKAGE_ACTION=""   # install | upgrade when the package manager ran
DC_PACKAGE_PREVIOUS="" # the version it replaced
DC_PACKAGE_VERSION=""  # the version it installed

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

# dc_fail_result <exit> <code> <message>: print a schema-conformant result for
# a failure the wrapper detected before the lifecycle ran, log it and exit.
# installed=false here means "not evaluated"; run --action status to inspect.
dc_fail_result() {
    exit_code=$1 code=$2 message=$(dc_json_escape "$3")
    case "$DC_ACTION" in
        install | upgrade | repair | ensure | reconcile | status | verify | uninstall) action=$DC_ACTION ;;
        *) action=ensure ;;
    esac
    document=$(printf '{"schema_version":2,"ok":false,"action":"%s","noop":false,"profile":"standalone","platform":"%s","product_version":"","installed":false,"transaction_pending":false,"services":[],"readiness":{"gateway":false,"guardian":false,"enumerator":false,"sensor_helper":false},"inspection":{"local":"unknown","ai_defense":"unknown"},"machine_policy":{},"enrollment":{"targets":0,"pending":0,"failed":0,"exempt":0},"coverage_complete":false,"security_complete":false,"errors":[{"code":"%s","message":"%s"}],"exit_code":%s}' \
        "$action" "$DC_SCRIPT_OS" "$code" "$message" "$exit_code")
    printf '%s\n' "$document"
    dc_log "result $document"
    exit "$exit_code"
}

dc_log() {
    [ -n "$DC_LOG" ] || return 0
    if [ ! -e "$DC_LOG" ]; then
        ( umask 077; : >"$DC_LOG" ) 2>/dev/null || return 0
    fi
    [ -f "$DC_LOG" ] && [ ! -L "$DC_LOG" ] || return 0
    printf '%s %s[%s] %s\n' "$(dc_now)" "${0##*/}" "$$" "$1" >>"$DC_LOG" 2>/dev/null || true
}

dc_cleanup() {
    if [ -n "$DC_STAGE" ] && [ -d "$DC_STAGE" ]; then
        rm -rf "$DC_STAGE"
    fi
}

# dc_stop_child: an interrupted run stops the lifecycle command it waits for,
# so the command does not finish (or store a credential) after the run was
# reported failed.
dc_stop_child() {
    [ -z "$DC_CHILD" ] || kill "$DC_CHILD" 2>/dev/null || true
}

# dc_sweep_stages <parent>: remove the staging folders of earlier runs that
# were killed before their cleanup ran: root-owned, and either their run is
# gone (the pid it recorded no longer runs) or, without a pid, a day old.
dc_sweep_stages() {
    for stale in "$1"/defenseclaw-mdm.*; do
        [ -d "$stale" ] && [ ! -L "$stale" ] || continue
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

dc_is_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

dc_sha256() {
    if [ "$DC_SCRIPT_OS" = darwin ]; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

dc_lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }

dc_download() {
    url=$1 dest=$2
    case "$url" in https://*) ;; *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "download URLs must use https://" ;; esac
    if command -v curl >/dev/null 2>&1; then
        set -- curl -fsS --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 5 \
            --connect-timeout 30 --max-time 1800 -o "$dest"
        [ -z "$DC_HTTPS_PROXY" ] || set -- "$@" --proxy "$DC_HTTPS_PROXY"
        "$@" "$url"
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$DC_HTTPS_PROXY" ]; then
            https_proxy=$DC_HTTPS_PROXY wget -q --https-only --tries=3 --timeout=60 -O "$dest" "$url"
        else
            wget -q --https-only --tries=3 --timeout=60 -O "$dest" "$url"
        fi
    else
        dc_fail_result "$DC_EXIT_FAILURE" mdm_download_unavailable "neither curl nor wget is installed"
    fi
}

# dc_read_bounded <dest> <max-bytes> <label>: copy standard input into the
# staging directory, refusing oversized input.
dc_read_bounded() {
    dest=$1 limit=$2 label=$3
    head -c "$((limit + 1))" >"$dest"
    size=$(wc -c <"$dest" | tr -d ' ')
    if [ "$size" -gt "$limit" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_input_too_large "$label exceeds $limit bytes"
    fi
}

# dc_stage_file <src> <dest> <max-bytes> <label> [trusted]: copy a file into
# the staging directory. Inputs that are verified after the copy (sources,
# signatures) may live anywhere; inputs that are not (config, credentials)
# must be "trusted": root-owned with no group/other write on the whole path,
# so another account cannot swap them before the copy.
dc_stage_file() {
    src=$1 dest=$2 limit=$3 label=$4 require=${5:-}
    case "$src" in /*) ;; *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "$label must be an absolute path" ;; esac
    if [ ! -f "$src" ] || [ -L "$src" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "$label is not a regular file: $src"
    fi
    if [ "$require" = trusted ] && ! dc_trusted_path "$src"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "$label or one of its directories is not root-owned or is writable by other accounts: $src"
    fi
    dc_read_bounded "$dest" "$limit" "$label" <"$src"
}

dc_usage() {
    sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
}

dc_parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --action)
                DC_ACTION=${2:-}
                case "$DC_ACTION" in
                    ensure | status | verify) ;;
                    *) DC_ACTION=ensure; dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--action must be ensure, status or verify (use uninstall.sh to remove)" ;;
                esac
                shift 2
                ;;
            --source) DC_SOURCE=${2:-}; shift 2 ;;
            --source-url) DC_SOURCE_URL=${2:-}; shift 2 ;;
            --sha256) DC_SOURCE_SHA256=${2:-}; shift 2 ;;
            --trust-mode) DC_TRUST_MODE=${2:-}; shift 2 ;;
            --allowed-team-id) DC_ALLOWED_TEAM_IDS="$DC_ALLOWED_TEAM_IDS ${2:-}"; shift 2 ;;
            --gpg-keyring) DC_GPG_KEYRING=${2:-}; shift 2 ;;
            --signature) DC_SIGNATURE=${2:-}; shift 2 ;;
            --signature-url) DC_SIGNATURE_URL=${2:-}; shift 2 ;;
            --product-version) DC_PRODUCT_VERSION=${2:-}; shift 2 ;;
            --config-file) DC_CONFIG_FILE=${2:-}; shift 2 ;;
            --config-stdin) DC_CONFIG_STDIN=1; shift ;;
            --secret-name) DC_SECRET_NAME=${2:-}; shift 2 ;;
            --secret-file) DC_SECRET_FILE=${2:-}; shift 2 ;;
            --secret-stdin) DC_SECRET_STDIN=1; shift ;;
            --https-proxy) DC_HTTPS_PROXY=${2:-}; shift 2 ;;
            --log) DC_LOG=${2:-}; shift 2 ;;
            -h | --help) dc_usage; exit 0 ;;
            *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "unknown argument: $1" ;;
        esac
    done
}

dc_validate_args() {
    case "$DC_ACTION" in
        ensure | status | verify) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--action must be ensure, status or verify (use uninstall.sh to remove)" ;;
    esac
    case "$DC_TRUST_MODE" in
        hash_pinned | signed) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--trust-mode must be hash_pinned or signed" ;;
    esac
    if [ -n "$DC_SOURCE" ] && [ -n "$DC_SOURCE_URL" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--source and --source-url are exclusive"
    fi
    DC_SOURCE_SHA256=$(dc_lower "$DC_SOURCE_SHA256")
    if [ -n "$DC_SOURCE_SHA256" ] && ! dc_is_sha256 "$DC_SOURCE_SHA256"; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--sha256 must be 64 hexadecimal characters"
    fi
    if [ -n "$DC_SOURCE$DC_SOURCE_URL" ] && [ "$DC_TRUST_MODE" = hash_pinned ] && [ -z "$DC_SOURCE_SHA256" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "hash_pinned trust requires --sha256 for the source"
    fi
    if [ "$DC_CONFIG_STDIN" = 1 ] && [ "$DC_SECRET_STDIN" = 1 ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "only one of --config-stdin and --secret-stdin can read standard input"
    fi
    if [ "$DC_CONFIG_STDIN" = 1 ] && [ -n "$DC_CONFIG_FILE" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--config-file and --config-stdin are exclusive"
    fi
    if [ -n "$DC_SECRET_NAME" ]; then
        case "$DC_SECRET_NAME" in
            [a-z0-9]*) ;;
            *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--secret-name must be lowercase letters, digits and dashes" ;;
        esac
        case "$DC_SECRET_NAME" in
            *[!a-z0-9-]*) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--secret-name must be lowercase letters, digits and dashes" ;;
        esac
        if [ "$DC_SECRET_STDIN" = 1 ] && [ -n "$DC_SECRET_FILE" ]; then
            dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--secret-file and --secret-stdin are exclusive"
        fi
        if [ "$DC_SECRET_STDIN" = 0 ] && [ -z "$DC_SECRET_FILE" ]; then
            dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--secret-name needs --secret-file or --secret-stdin"
        fi
    elif [ "$DC_SECRET_STDIN" = 1 ] || [ -n "$DC_SECRET_FILE" ]; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "a secret value needs --secret-name"
    fi
    if [ "$DC_ACTION" != ensure ] &&
        { [ -n "$DC_SOURCE$DC_SOURCE_URL$DC_CONFIG_FILE$DC_SECRET_NAME$DC_SECRET_FILE" ] ||
            [ "$DC_CONFIG_STDIN$DC_SECRET_STDIN" != 00 ]; }; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--action $DC_ACTION is read-only and takes no source, config or secret"
    fi
}

# dc_binaries_damaged: the installed gateway or hook binary is empty, which
# a power loss during a package upgrade leaves behind (GAP-0467). The same
# package version then counts as not installed, so it is installed again.
dc_binaries_damaged() {
    bin_dir=$(dirname "$DC_GATEWAY")
    for name in defenseclaw-gateway defenseclaw-hook; do
        if [ -e "$bin_dir/$name" ] && [ ! -s "$bin_dir/$name" ]; then
            return 0
        fi
    done
    return 1
}

dc_layout() {
    if [ "$DC_SCRIPT_OS" = darwin ]; then
        DC_GATEWAY=/opt/cisco/defenseclaw/bin/defenseclaw-gateway
        DC_OS_GROUP=macos
        [ -n "$DC_LOG" ] || DC_LOG=/Library/Logs/Cisco/DefenseClaw/mdm-wrapper.log
    else
        DC_GATEWAY=/opt/defenseclaw/bin/defenseclaw-gateway
        DC_OS_GROUP=linux
        [ -n "$DC_LOG" ] || DC_LOG=/var/log/defenseclaw-enterprise-mdm.log
    fi
    log_dir=$(dirname "$DC_LOG")
    if [ ! -d "$log_dir" ]; then
        # The wrapper runs under umask 077, but the log directory's parents
        # are shared: the gateway's own log lives under /Library/Logs/Cisco
        # and its service account must traverse it. The log stays private.
        ( umask 022; mkdir -p "$log_dir" ) 2>/dev/null || DC_LOG=""
    fi
}

# dc_verify_signature <file>: the vendor signature check of signed trust.
dc_verify_signature() {
    file=$1
    if [ "$DC_SCRIPT_OS" = darwin ]; then
        case "$file" in *.pkg) ;; *) dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_unsupported "signed trust on macOS verifies .pkg installers; use hash_pinned for a payload archive" ;; esac
        [ -n "$(printf '%s' "$DC_ALLOWED_TEAM_IDS" | tr -d ' ')" ] ||
            dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "signed trust on macOS needs --allowed-team-id"
        if ! check=$(pkgutil --check-signature "$file" 2>&1); then
            dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_invalid "pkgutil rejected the package signature"
        fi
        printf '%s\n' "$check" | grep -q 'Status: signed by a developer certificate issued by Apple for distribution' ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_invalid "the package is not signed with a Developer ID Installer certificate"
        team=$(printf '%s\n' "$check" | sed -n 's/^ *1\. Developer ID Installer: .*(\([A-Z0-9]\{10\}\))$/\1/p' | head -n 1)
        allowed=0
        for candidate in $DC_ALLOWED_TEAM_IDS; do
            [ "$candidate" = "$team" ] && allowed=1
        done
        [ "$allowed" = 1 ] ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_signer_not_allowed "package signer team '$team' is not in --allowed-team-id"
        spctl --assess --type install "$file" >/dev/null 2>&1 ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_invalid "Gatekeeper rejected the package (not notarized or revoked)"
        return 0
    fi
    command -v gpgv >/dev/null 2>&1 || dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_unsupported "signed trust needs gpgv"
    [ -n "$DC_GPG_KEYRING" ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "signed trust on Linux needs --gpg-keyring"
    dc_trusted_path "$DC_GPG_KEYRING" ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "the GPG keyring is not root-owned or is writable by other accounts"
    signature="$DC_STAGE/source.sig"
    if [ -n "$DC_SIGNATURE_URL" ]; then
        dc_download "$DC_SIGNATURE_URL" "$signature" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_download_failed "could not download the signature"
    else
        if [ -z "$DC_SIGNATURE" ]; then
            [ -n "$DC_SOURCE" ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "a downloaded source needs --signature-url or --signature"
            DC_SIGNATURE="$DC_SOURCE.asc"
        fi
        dc_stage_file "$DC_SIGNATURE" "$signature" 65536 "signature"
    fi
    gpgv --keyring "$DC_GPG_KEYRING" "$signature" "$file" >/dev/null 2>&1 ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_signature_invalid "the detached signature does not verify against the pinned keyring"
}

# dc_stage_source: copy the source into staging and verify it there, so a
# change to the original after verification cannot reach the installer.
dc_stage_source() {
    name=${DC_SOURCE_URL:-$DC_SOURCE}
    name=${name%%\?*}
    name=$(basename "$name")
    case "$name" in
        *.deb | *.rpm | *.pkg | *.tar.gz | *.tgz) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "unsupported source type: $name (expected .deb, .rpm, .pkg or .tar.gz)" ;;
    esac
    case "$name" in *[!A-Za-z0-9._+-]*) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "unexpected characters in the source name: $name" ;; esac
    DC_STAGED_SOURCE="$DC_STAGE/$name"
    if [ -n "$DC_SOURCE_URL" ]; then
        dc_download "$DC_SOURCE_URL" "$DC_STAGED_SOURCE" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_download_failed "could not download the source"
    else
        dc_stage_file "$DC_SOURCE" "$DC_STAGED_SOURCE" 1073741824 "source"
    fi
    if [ -n "$DC_SOURCE_SHA256" ]; then
        actual=$(dc_sha256 "$DC_STAGED_SOURCE")
        [ "$actual" = "$DC_SOURCE_SHA256" ] ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_hash_mismatch "source SHA-256 $actual does not match the pinned $DC_SOURCE_SHA256"
    fi
    if [ "$DC_TRUST_MODE" = signed ]; then
        dc_verify_signature "$DC_STAGED_SOURCE"
    fi
    dc_log "verified source $name (trust=$DC_TRUST_MODE sha256=${DC_SOURCE_SHA256:-unpinned})"
}

dc_busy_output() {
    printf '%s' "$1" | grep -Eqi 'could not get lock|dpkg frontend lock|lock-frontend|transaction lock|another install|is in use by another|waiting for cache lock'
}

# dc_require_product_version <release version>: refuse a source that is not
# the --product-version pin. Runs before the package manager: the package's
# own maintainer scripts apply the deployment as soon as it is installed.
dc_require_product_version() {
    [ -n "$DC_PRODUCT_VERSION" ] || return 0
    [ "$1" = "${DC_PRODUCT_VERSION#v}" ] ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_version_mismatch "the source is version $1, not $DC_PRODUCT_VERSION; nothing was installed"
}

# dc_package_release_version <package version>: the release version a deb or
# rpm version names. The epoch and the Debian revision are dropped and the
# "~" packages use for a prerelease reads as "-", so 1:1.4.0~rc1-1 is 1.4.0-rc1.
dc_package_release_version() {
    printf '%s' "$1" | sed -e 's/^[0-9][0-9]*://' -e 's/-[^-]*$//' -e 's/~/-/'
}

# dc_install_package: install the staged package when its version differs
# from the installed one; sets DC_CHANNEL_FLAG for the lifecycle.
dc_install_package() {
    file=$DC_STAGED_SOURCE
    DC_CHANNEL_FLAG=--from-package
    case "$file" in
        *.deb)
            [ "$DC_SCRIPT_OS" = linux ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments ".deb sources are Linux packages"
            command -v dpkg >/dev/null 2>&1 || dc_fail_result "$DC_EXIT_FAILURE" mdm_package_manager_missing "dpkg is not installed; use the .rpm or the payload archive"
            package=$(dpkg-deb -f "$file" Package 2>/dev/null || true)
            version=$(dpkg-deb -f "$file" Version 2>/dev/null || true)
            arch=$(dpkg-deb -f "$file" Architecture 2>/dev/null || true)
            [ "$package" = "$DC_LINUX_PACKAGE" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_package "the .deb is '$package', not $DC_LINUX_PACKAGE"
            [ "$arch" = "$(dpkg --print-architecture)" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_architecture "the .deb is for $arch"
            dc_require_product_version "$(dc_package_release_version "$version")"
            installed=$(dpkg-query -W -f='${Status} ${Version}' "$DC_LINUX_PACKAGE" 2>/dev/null || true)
            if [ "$installed" = "install ok installed $version" ] && ! dc_binaries_damaged; then
                dc_log "package $version already installed"
            else
                if ! output=$(DEBIAN_FRONTEND=noninteractive dpkg -i "$file" 2>&1); then
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                    fi
                    dc_fail_result "$DC_EXIT_FAILURE" mdm_package_install_failed "dpkg failed: $output"
                fi
                case "$installed" in
                    "install ok installed "*) dc_package_step "$(dc_package_release_version "${installed#install ok installed }")" "$(dc_package_release_version "$version")" ;;
                    *) dc_package_step "" "$(dc_package_release_version "$version")" ;;
                esac
            fi
            ;;
        *.rpm)
            [ "$DC_SCRIPT_OS" = linux ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments ".rpm sources are Linux packages"
            command -v rpm >/dev/null 2>&1 || dc_fail_result "$DC_EXIT_FAILURE" mdm_package_manager_missing "rpm is not installed; use the .deb or the payload archive"
            package=$(rpm -qp --qf '%{NAME}' "$file" 2>/dev/null || true)
            version=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$file" 2>/dev/null || true)
            [ "$package" = "$DC_LINUX_PACKAGE" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_package "the .rpm is '$package', not $DC_LINUX_PACKAGE"
            dc_require_product_version "$(dc_package_release_version "$version")"
            installed=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$DC_LINUX_PACKAGE" 2>/dev/null || true)
            if [ "$installed" = "$version" ] && ! dc_binaries_damaged; then
                dc_log "package $version already installed"
            else
                previous=""
                replace=""
                [ "$installed" != "$version" ] || replace=--replacepkgs
                if rpm -q "$DC_LINUX_PACKAGE" >/dev/null 2>&1; then
                    previous=$(dc_package_release_version "$installed")
                fi
                # rpm -U refuses a downgrade, which keeps an older package
                # from silently replacing a newer deployment.
                if ! output=$(rpm -U --quiet $replace "$file" 2>&1); then
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                    fi
                    dc_fail_result "$DC_EXIT_FAILURE" mdm_package_install_failed "rpm failed: $output"
                fi
                dc_package_step "$previous" "$(dc_package_release_version "$version")"
            fi
            ;;
        *.pkg)
            [ "$DC_SCRIPT_OS" = darwin ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments ".pkg sources are macOS installers"
            expanded="$DC_STAGE/expanded"
            pkgutil --expand "$file" "$expanded" >/dev/null 2>&1 ||
                dc_fail_result "$DC_EXIT_FAILURE" mdm_package_invalid "pkgutil could not expand the package"
            version=$(sed -n "s/.*<pkg-ref id=\"$DC_MACOS_PACKAGE_ID\" version=\"\([^\"]*\)\".*/\1/p" "$expanded/Distribution" 2>/dev/null | head -n 1)
            [ -n "$version" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_package "the package does not contain $DC_MACOS_PACKAGE_ID"
            dc_require_product_version "$version"
            installed=$(pkgutil --pkg-info "$DC_MACOS_PACKAGE_ID" 2>/dev/null | sed -n 's/^version: //p')
            if [ "$installed" = "$version" ] && ! dc_binaries_damaged; then
                dc_log "package $version already installed"
            else
                if ! output=$(installer -pkg "$file" -target / 2>&1); then
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "another installation is running; retry later"
                    fi
                    dc_fail_result "$DC_EXIT_FAILURE" mdm_package_install_failed "installer failed: $output"
                fi
                dc_package_step "$installed" "$version"
            fi
            ;;
        *)
            dc_extract_payload
            return 0
            ;;
    esac
}

# dc_package_step <previous version> <installed version>: record that the
# package manager installed (no previous version) or upgraded the package.
dc_package_step() {
    DC_PACKAGE_PREVIOUS=$1
    DC_PACKAGE_VERSION=$2
    if [ -n "$1" ]; then DC_PACKAGE_ACTION=upgrade; else DC_PACKAGE_ACTION=install; fi
    dc_log "package $DC_PACKAGE_ACTION ${1:+$1 -> }$2"
}

# dc_annotate_package_step: after a successful ensure, make the result
# document report the package step. The package's postinstall applied the
# deployment, so the ensure that followed is usually a no-op, and an MDM
# reading "action ensure, noop true" would conclude nothing changed. The
# lifecycle prints the document with two-space indentation, one top-level
# field per line.
dc_annotate_package_step() {
    [ -n "$DC_PACKAGE_ACTION" ] && [ -n "$DC_RESULT" ] || return 0
    if [ "$DC_PACKAGE_ACTION" = upgrade ]; then
        code=package_upgraded
        note="the package step upgraded the DefenseClaw enterprise package from $DC_PACKAGE_PREVIOUS to $DC_PACKAGE_VERSION; its postinstall applied the deployment"
    else
        code=package_installed
        note="the package step installed the DefenseClaw enterprise package $DC_PACKAGE_VERSION; its postinstall applied the deployment"
    fi
    annotated="$DC_STAGE/result.annotated.json"
    # The values go through the environment: awk -v would interpret the
    # backslashes of the JSON escapes.
    if DC_AWK_ACTION=$DC_PACKAGE_ACTION \
        DC_AWK_WARNING="{\"code\": \"$code\", \"message\": \"$(dc_json_escape "$note")\"}" \
        awk '
            BEGIN { action = ENVIRON["DC_AWK_ACTION"]; warning = ENVIRON["DC_AWK_WARNING"] }
            /^  "action": "ensure",$/ { print "  \"action\": \"" action "\","; next }
            /^  "noop": true,$/ { print "  \"noop\": false,"; next }
            /^  "noop_reason": / { next }
            /^  "warnings": \[$/ { print; print "    " warning ","; warned = 1; next }
            /^  "exit_code": / && !warned { print "  \"warnings\": [" warning "],"; warned = 1 }
            { print }
        ' "$DC_RESULT" >"$annotated"; then
        DC_RESULT=$annotated
    fi
}

# dc_extract_payload: unpack the payload archive into staging without
# trusting its member names, owners or modes.
dc_extract_payload() {
    file=$DC_STAGED_SOURCE
    listing=$(tar -tzf "$file" 2>/dev/null) || dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive cannot be read"
    if printf '%s\n' "$listing" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive has absolute or parent-relative members"
    fi
    payload="$DC_STAGE/payload"
    mkdir "$payload"
    tar -xzf "$file" -C "$payload" --no-same-owner --no-same-permissions 2>/dev/null ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive did not extract"
    if [ -n "$(find "$payload" \( ! -type f ! -type d \) -o \( -type f -links +1 \) | head -n 1)" ]; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive contains links or special files"
    fi
    gateway=$(find "$payload" -maxdepth 2 -type f -name defenseclaw-gateway -print | head -n 1)
    [ -n "$gateway" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive has no defenseclaw-gateway"
    chown -R 0:0 "$payload"
    chmod -R go-w "$payload"
    DC_CHANNEL_FLAG="--payload=$(dirname "$gateway")"
    DC_PAYLOAD_GATEWAY=$gateway
}

# dc_emit_result: print the lifecycle's result document, the one document
# this wrapper writes to stdout on success or on a lifecycle failure.
dc_emit_result() {
    [ -n "$DC_RESULT" ] || return 0
    cat "$DC_RESULT"
    dc_log "result $(tr -d '\n' <"$DC_RESULT")"
}

# dc_run_lifecycle <gateway> <args...>: run the lifecycle, keep its result
# for dc_emit_result and return its exit code.
dc_run_lifecycle() {
    gateway=$1
    shift
    result="$DC_STAGE/result.json"
    set +e
    "$gateway" enterprise "$DC_OS_GROUP" "$@" --json >"$result" 2>"$DC_STAGE/lifecycle.err" </dev/null
    status=$?
    set -e
    if [ -s "$result" ]; then
        DC_RESULT=$result
    else
        detail=$(head -c 2048 "$DC_STAGE/lifecycle.err" 2>/dev/null || true)
        case "$status" in 0 | 1 | 2 | 75) ;; *) status=$DC_EXIT_FAILURE ;; esac
        [ "$status" != 0 ] || status=$DC_EXIT_FAILURE
        dc_fail_result "$status" mdm_lifecycle_no_result "the lifecycle printed no result: $detail"
    fi
    case "$status" in 0 | 1 | 2 | 75) ;; *) status=$DC_EXIT_FAILURE ;; esac
    return "$status"
}

dc_main() {
    dc_parse_args "$@"
    platform=$(dc_platform)
    [ "$platform" = "$DC_SCRIPT_OS" ] ||
        dc_fail_result "$DC_EXIT_INVALID" mdm_wrong_platform "this copy of the wrapper is for $DC_SCRIPT_OS, not $platform"
    dc_layout
    dc_validate_args
    [ "$(id -u)" = 0 ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_not_root "run as root (the MDM agent's system context)"

    stage_parent=/var/tmp
    dc_sweep_stages "$stage_parent"
    DC_STAGE=$(mktemp -d "$stage_parent/defenseclaw-mdm.XXXXXX")
    trap dc_cleanup EXIT
    trap 'dc_stop_child; exit 1' HUP INT TERM
    chmod 0700 "$DC_STAGE"
    [ "$(dc_stat_uid "$DC_STAGE")" = 0 ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging directory is not root-owned"
    printf '%s\n' "$$" >"$DC_STAGE/pid"
    dc_log "start action=$DC_ACTION"

    if [ "$DC_ACTION" != ensure ]; then
        dc_trusted_path "$DC_GATEWAY" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "the managed deployment is not installed ($DC_GATEWAY is missing or not root-owned)"
        status=0
        dc_run_lifecycle "$DC_GATEWAY" "$DC_ACTION" || status=$?
        dc_emit_result
        return "$status"
    fi

    config=""
    if [ "$DC_CONFIG_STDIN" = 1 ]; then
        config="$DC_STAGE/config.yaml"
        dc_read_bounded "$config" "$DC_MAX_CONFIG_BYTES" "config"
    elif [ -n "$DC_CONFIG_FILE" ]; then
        config="$DC_STAGE/config.yaml"
        dc_stage_file "$DC_CONFIG_FILE" "$config" "$DC_MAX_CONFIG_BYTES" "config" trusted
    else
        inline="$DC_STAGE/inline-config.yaml"
        dc_inline_config >"$inline"
        if grep -q '[^[:space:]]' "$inline"; then
            config=$inline
        fi
    fi
    # The credential stays in memory and reaches the lifecycle through a
    # pipe: a staged copy outlived a run killed before its cleanup.
    secret_data=""
    if [ -n "$DC_SECRET_NAME" ]; then
        if [ "$DC_SECRET_STDIN" = 1 ]; then
            secret_data=$(head -c "$((DC_MAX_SECRET_BYTES + 1))")
        else
            case "$DC_SECRET_FILE" in /*) ;; *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "secret must be an absolute path" ;; esac
            if [ ! -f "$DC_SECRET_FILE" ] || [ -L "$DC_SECRET_FILE" ]; then
                dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "secret is not a regular file: $DC_SECRET_FILE"
            fi
            dc_trusted_path "$DC_SECRET_FILE" ||
                dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "secret or one of its directories is not root-owned or is writable by other accounts: $DC_SECRET_FILE"
            secret_data=$(head -c "$((DC_MAX_SECRET_BYTES + 1))" <"$DC_SECRET_FILE")
        fi
        [ "$(printf '%s' "$secret_data" | wc -c | tr -d ' ')" -le "$DC_MAX_SECRET_BYTES" ] ||
            dc_fail_result "$DC_EXIT_INVALID" mdm_input_too_large "secret exceeds $DC_MAX_SECRET_BYTES bytes"
        [ -n "$secret_data" ] || dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "the secret value is empty"
    fi

    DC_CHANNEL_FLAG=""
    DC_PAYLOAD_GATEWAY=""
    if [ -n "$DC_SOURCE$DC_SOURCE_URL" ]; then
        dc_stage_source
        dc_install_package
    fi

    # The payload channel runs the verified staged binary; every other run
    # uses the installed, root-owned gateway.
    gateway=$DC_GATEWAY
    if [ -n "$DC_PAYLOAD_GATEWAY" ]; then
        gateway=$DC_PAYLOAD_GATEWAY
    elif ! dc_trusted_path "$gateway"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "no source was given and $gateway is missing or not root-owned"
    elif dc_binaries_damaged; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_binaries_damaged "the installed DefenseClaw binaries are empty, likely from a power loss during a package upgrade; run this script with the package as --source, or reinstall the package"
    fi

    # The credential is stored first: a config that references it (the AI
    # Defense key, an observability header) only applies once it exists.
    # Before the first payload install the staged gateway stores it, and
    # the install gives the gateway access. Both steps wait for an apply
    # that the package's postinstall or the change itself started (the
    # apply path unit) instead of failing busy.
    if [ -n "$DC_SECRET_NAME" ]; then
        set +e
        printf '%s' "$secret_data" |
            "$gateway" enterprise secret set --name "$DC_SECRET_NAME" --from-stdin --lock-wait 10m --json >"$DC_STAGE/secret.json" 2>"$DC_STAGE/secret.err" &
        DC_CHILD=$!
        wait "$DC_CHILD"
        secret_status=$?
        DC_CHILD=""
        set -e
        secret_data=""
        if [ "$secret_status" != 0 ]; then
            detail=$(head -c 1024 "$DC_STAGE/secret.err" 2>/dev/null || true)
            case "$secret_status" in 1 | 2 | 75) ;; *) secret_status=$DC_EXIT_FAILURE ;; esac
            dc_fail_result "$secret_status" mdm_secret_failed "storing credential '$DC_SECRET_NAME' failed, so the config was not applied: $detail"
        fi
        dc_log "stored credential $DC_SECRET_NAME"
    fi

    set -- ensure --reason mdm --lock-wait 10m
    [ -z "$DC_CHANNEL_FLAG" ] || set -- "$@" "$DC_CHANNEL_FLAG"
    [ -z "$config" ] || set -- "$@" "--config=$config"
    [ -z "$DC_PRODUCT_VERSION" ] || set -- "$@" "--product-version=$DC_PRODUCT_VERSION"
    status=0
    dc_run_lifecycle "$gateway" "$@" || status=$?
    [ "$status" != 0 ] || dc_annotate_package_step
    dc_emit_result
    return "$status"
}

dc_main "$@"
