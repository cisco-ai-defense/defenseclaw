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
#       [--bundle-file FILE.dcbundle] [--trust-anchor-file FILE]
#       [--format json|jamf]
#       [--product-version X.Y.Z] [--https-proxy URL] [--log FILE] [--staging-dir DIR]
#
# Sources: a defenseclaw-enterprise .deb or .rpm (Linux), a .pkg (macOS) or
# the defenseclaw-enterprise-<version>-<os>-<arch>.tar.gz payload (both).
# Without a source the wrapper re-applies the installed deployment (for
# example after a config change).
#
# Signed policy bundles: --trust-anchor-file installs the trust anchor file
# (root-only writable) and turns on bundle mode; --bundle-file applies a
# signed bundle with `enterprise bundle apply` after the package step and the
# credential. When the installed gateway has `enterprise bundle anchors
# install` (management_contract 1 in --version-json), the wrapper installs the
# anchor file with it, under the lifecycle lock; with an older gateway it
# writes the file itself. When the apply fails, the bundle in force keeps
# enforcing and the trust anchor file this run replaced is put back. Script-only MDMs can
# paste the anchor file and the base64 of the bundle into the settings below.
# A bundle carries its own config. A config given with it (--config-file,
# --config-stdin or the inline config) is the base config. Its guardrail:
# block must be the bundle's, apart from custom_packs.<pack>.path, which
# names the pack's folder installed before this run. Its claude_code:,
# codex:, connector_hooks: and application_protection: blocks must be the
# bundle's, or absent from both: their hook modes override the guardrail
# mode. Otherwise nothing is installed (mdm_base_config_mismatch, exit 2).
# The check reads the bundle with tar; without tar nothing is installed
# (mdm_tar_missing, exit 1). No other config key is compared. On a device
# that is not yet in bundle mode the base config is applied before the trust
# anchors and the bundle, so while the bundle is pending, or after it fails
# to apply, the agents run under a base config whose guardrail block and hook
# modes are the bundle's (GAP-0090).
# Bundle config should omit data_dir: the gateway uses its managed data
# directory; enterprise lifecycle state stays separate and root-only.

set -eu

DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies
DC_LOG_NAME=defenseclaw-enterprise.sh

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
DC_REFUSE_CAPABILITY_LOSS=0 # opt in: refuse a bundle that disables an enforced capability
DC_BUNDLE_FILE=""           # absolute path of a signed policy bundle (.dcbundle)
DC_TRUST_ANCHOR_FILE=""     # absolute path of the bundle trust anchor file (bundle-anchors.json)
DC_FORMAT=json              # json | jamf; Jamf wraps the result document in <result>
DC_HTTPS_PROXY=""           # proxy for the download only
DC_LOG=""                   # default: the platform log path below
DC_STAGING_DIR=""           # root-only folder for the staged copy (default: /var/lib/defenseclaw-mdm on Linux, /var/tmp on macOS)

# Inline administrator config for script-only MDMs without a signed bundle.
# Leave this block empty when using an inline bundle, which carries its own
# config. Never put credentials here - MDM script bodies are not secret storage;
# deliver credentials with --secret-file or --secret-stdin.
dc_inline_config() {
    cat <<'DEFENSECLAW_CONFIG'
DEFENSECLAW_CONFIG
}

# Inline trust anchor file (the JSON of bundle-anchors.json) and inline
# policy bundle (the base64 of the .dcbundle file, line breaks allowed) for
# script-only MDMs. Both are public: the anchor file holds public keys only and
# a bundle holds no secret values. MDM script bodies have size limits, so
# deliver a large bundle as a file (--bundle-file) instead.
dc_inline_trust_anchors() {
    cat <<'DC_TRUST_ANCHORS_JSON'
DC_TRUST_ANCHORS_JSON
}
dc_inline_bundle() {
    cat <<'DC_BUNDLE_BASE64'
DC_BUNDLE_BASE64
}
# ---- end of settings ---------------------------------------------------------

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset IFS || true
umask 077

readonly DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
readonly DC_MAX_CONFIG_BYTES=1048576 DC_MAX_SECRET_BYTES=16384
readonly DC_MAX_BUNDLE_BYTES=4194304 DC_MAX_ANCHORS_BYTES=65536
readonly DC_LINUX_PACKAGE=defenseclaw-enterprise
readonly DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise

DC_CONFIG_STDIN=0
DC_SECRET_STDIN=0
DC_STAGE=""
DC_CHILD=""
DC_RESULT=""
DC_CONFIG_STAGED=""
DC_CONFIG_ORIGIN=""
DC_PACKAGE_ACTION=""   # install | upgrade when the package manager ran
DC_PACKAGE_PREVIOUS="" # the version it replaced
DC_PACKAGE_VERSION=""  # the version it installed
DC_INSTALL_ROOT=""     # the install tree whose volume the package fills
DC_ANCHORS_PREVIOUS="" # staged copy of the trust anchor file this run replaced
DC_ANCHORS_CHANGED=0   # 1 when this run installed a different trust anchor file
DC_ANCHORS_COMMITTED=0 # 1 when that file stays after a successful run (dc_annotate_anchors_step)
DC_ANCHORS_VERB=0      # 1 when the installed gateway installs it (enterprise bundle anchors install)
DC_ANCHORS_SOURCE=""   # the private copy of the anchor file that command reads
DC_ANCHORS_RESULT=""   # its result: installed, replaced or unchanged
DC_DEPLOYMENT_RECORD="" # committed binary digests for same-version repair
DC_PACKAGE_RESULT=""   # the result the package's own install scripts write
DC_TRUST_ACL=""        # the ACL entry dc_trusted_path refused, for messages (set -u: read before any check ran)
DC_SECRETS_DIR=""      # the deployment's credential store (dc_layout)
DC_SECRET_ROTATED=0    # 1 while a credential stored with --bundle waits for that bundle to apply
DC_SECRET_PREVIOUS_SET=0 # 1 when a value was stored before it, 0 when none was
DC_SECRET_GATEWAY=""   # the gateway that stored it, which puts the old value back
DC_SECRET_CONFIRMED="" # manifest SHA-256 of the bundle confirmed before the rotation, or none
DC_GATEWAY_BEFORE=0    # 1 when a gateway was installed before this run delivered anything
DC_ROTATION_LOCK_PID="" # the process that holds the rotation journal lock for this run
DC_JOURNAL_DIR=""      # root-only credential rotation journal (dc_layout)
DC_INSTALLED_CONFIG="" # the deployment's installed config.yaml (dc_layout)

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

dc_print_result() {
    if [ "$DC_FORMAT" = jamf ]; then
        printf '<result>'
        tr -d '\n' | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
        printf '</result>\n'
    else
        cat
    fi
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
    printf '%s\n' "$document" | dc_print_result
    dc_log "result $document"
    exit "$exit_code"
}

dc_log() {
    [ -n "$DC_LOG" ] || return 0
    if [ ! -e "$DC_LOG" ]; then
        ( umask 077; : >"$DC_LOG" ) 2>/dev/null || return 0
    fi
    [ -f "$DC_LOG" ] && [ ! -L "$DC_LOG" ] || return 0
    printf '%s %s[%s] %s\n' "$(dc_now)" "$DC_LOG_NAME" "$$" "$1" >>"$DC_LOG" 2>/dev/null || true
}

dc_cleanup() {
    # A failed or interrupted run puts back the credential it rotated, with
    # the gateway that stored it, before the stage (which may hold that
    # gateway) goes.
    dc_restore_secret || true
    dc_rotation_unlock
    [ -z "$DC_ANCHORS_SOURCE" ] || rm -f "$DC_ANCHORS_SOURCE"
    # A failed or interrupted apply must leave the as-found trust anchors.
    if ! dc_restore_anchors; then
        # Keep the root-only backup for an administrator if restoration failed.
        dc_log "kept $DC_STAGE because the previous trust anchor could not be restored"
        return 0
    fi
    if [ -n "$DC_STAGE" ] && [ -d "$DC_STAGE" ]; then
        rm -rf "$DC_STAGE"
    fi
}

# dc_stop_child: an interrupted run stops the lifecycle command it waits for,
# so the command does not finish (or store a credential) after the run was
# reported failed.
dc_stop_child() {
    [ -n "$DC_CHILD" ] || return 0
    kill "$DC_CHILD" 2>/dev/null || true
    wait "$DC_CHILD" 2>/dev/null || true
    DC_CHILD=""
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

# dc_stage_parent: set DC_STAGE_PARENT to the root-only folder this run
# stages in. CIS hosts mount the shared /tmp and /var/tmp noexec, where the
# payload's gateway cannot run, so on Linux the default is a root-only folder
# of its own (GAP-0752); --staging-dir names another one.
dc_stage_parent() {
    DC_STAGE_PARENT=$DC_STAGING_DIR DC_TRUST_ACL=""
    if [ -z "$DC_STAGE_PARENT" ]; then
        if [ "$DC_SCRIPT_OS" = darwin ]; then
            DC_STAGE_PARENT=/var/tmp
            return 0
        fi
        DC_STAGE_PARENT=/var/lib/defenseclaw-mdm
        [ -d "$DC_STAGE_PARENT" ] || mkdir -m 0700 "$DC_STAGE_PARENT" 2>/dev/null ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "cannot create the staging folder $DC_STAGE_PARENT"
    fi
    case "$DC_STAGE_PARENT" in
        /*) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--staging-dir must be an absolute path" ;;
    esac
    if [ ! -e "$DC_STAGE_PARENT" ] && [ ! -L "$DC_STAGE_PARENT" ]; then
        # The wrapper creates only its Linux default; a --staging-dir folder
        # is the administrator's (GAP-0030: this read as a shell error).
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging folder $DC_STAGE_PARENT does not exist; create it as a root-owned directory that only root can write (mkdir -m 0700), or leave out --staging-dir"
    fi
    if [ ! -d "$DC_STAGE_PARENT" ] || ! dc_trusted_path "$DC_STAGE_PARENT"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging folder $DC_STAGE_PARENT is not a root-owned directory that only root can write$DC_TRUST_ACL"
    fi
}

# dc_noexec_mount <path>: print the mount point of path when that mount is
# noexec (Linux).
dc_noexec_mount() {
    [ "$DC_SCRIPT_OS" = linux ] || return 1
    line=$(findmnt -n -o TARGET,OPTIONS --target "$1" 2>/dev/null) || return 1
    case ",${line##* }," in
        *,noexec,*) printf '%s\n' "${line%% *}" ;;
        *) return 1 ;;
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
    DC_DOWNLOAD_ERROR="download failed"
    case "$url" in https://*) ;; *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "download URLs must use https://" ;; esac
    if command -v curl >/dev/null 2>&1; then
        set -- curl -fsS --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 5 \
            --connect-timeout 30 --max-time 1800 -D "$DC_STAGE/download.headers" -o "$dest"
        [ -z "$DC_HTTPS_PROXY" ] || set -- "$@" --proxy "$DC_HTTPS_PROXY"
        if "$@" "$url" 2>"$DC_STAGE/download.err"; then result=0; else result=$?; fi
        http_status=$(awk '/^HTTP\// {code=$2} END {print code}' "$DC_STAGE/download.headers" 2>/dev/null)
        case "$http_status" in
            3??) DC_DOWNLOAD_ERROR="download redirected (HTTP $http_status); use a URL that serves the file directly"; return 1 ;;
        esac
        [ "$result" = 0 ] && return 0
        case "$http_status" in 4?? | 5??) DC_DOWNLOAD_ERROR="download failed: HTTP $http_status"; return 1 ;; esac
        case "$result" in
            5) reason="proxy lookup failed" ;; 6) reason="DNS lookup failed" ;;
            7) reason="connection failed" ;; 18) reason="transfer ended early" ;;
            28) reason="timed out" ;; 35) reason="TLS handshake failed" ;;
            52) reason="server sent no response" ;; 56) reason="connection closed during transfer" ;;
            60) reason="TLS certificate verification failed" ;;
            *) reason="network error" ;;
        esac
        DC_DOWNLOAD_ERROR="download failed: $reason (curl exit $result)"
        return 1
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$DC_HTTPS_PROXY" ]; then
            https_proxy=$DC_HTTPS_PROXY wget -q --server-response --max-redirect=0 --https-only --tries=3 --timeout=60 -O "$dest" "$url" 2>"$DC_STAGE/download.err" && return 0
        else
            wget -q --server-response --max-redirect=0 --https-only --tries=3 --timeout=60 -O "$dest" "$url" 2>"$DC_STAGE/download.err" && return 0
        fi
        result=$?
        http_status=$(awk '/^[[:space:]]*HTTP\// {code=$2} END {print code}' "$DC_STAGE/download.err")
        case "$http_status" in
            3??) DC_DOWNLOAD_ERROR="download redirected (HTTP $http_status); use a URL that serves the file directly" ;;
            4?? | 5??) DC_DOWNLOAD_ERROR="download failed: HTTP $http_status" ;;
            *) DC_DOWNLOAD_ERROR="download failed: wget exit $result" ;;
        esac
        return 1
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
        dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "$label or one of its directories is not root-owned or is writable by other accounts: $src$DC_TRUST_ACL"
    fi
    dc_read_bounded "$dest" "$limit" "$label" <"$src"
}

# Read the raw credential before putting it in a shell variable, since command
# substitution discards NUL bytes. The temporary copy is removed immediately.
dc_read_secret() {
    secret_input="$DC_STAGE/secret-input"
    if [ "$DC_SECRET_STDIN" = 1 ]; then
        (umask 077; head -c "$((DC_MAX_SECRET_BYTES + 1))" >"$secret_input")
    else
        case "$DC_SECRET_FILE" in /*) ;; *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "secret must be an absolute path" ;; esac
        if [ ! -f "$DC_SECRET_FILE" ] || [ -L "$DC_SECRET_FILE" ]; then
            dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "secret is not a regular file: $DC_SECRET_FILE"
        fi
        dc_trusted_path "$DC_SECRET_FILE" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_untrusted_input "secret or one of its directories is not root-owned or is writable by other accounts: $DC_SECRET_FILE$DC_TRUST_ACL"
        (umask 077; head -c "$((DC_MAX_SECRET_BYTES + 1))" <"$DC_SECRET_FILE" >"$secret_input")
    fi
    secret_bytes=$(wc -c <"$secret_input" | tr -d ' ')
    if [ "$secret_bytes" -gt "$DC_MAX_SECRET_BYTES" ]; then
        rm -f "$secret_input"
        dc_fail_result "$DC_EXIT_INVALID" mdm_input_too_large "secret exceeds $DC_MAX_SECRET_BYTES bytes"
    fi
    without_nul=$(tr -d '\000' <"$secret_input" | wc -c | tr -d ' ')
    if [ "$secret_bytes" != "$without_nul" ]; then
        rm -f "$secret_input"
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "the secret contains a NUL byte"
    fi
    [ "$secret_bytes" != 0 ] || { rm -f "$secret_input"; dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "the secret value is empty"; }
    secret_data=$(cat "$secret_input"; printf x)
    secret_data=${secret_data%x}
    rm -f "$secret_input"
}

dc_usage() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

dc_parse_args() {
    # Intune's Linux agent invokes sh /proc/self/fd/N /proc/self/fd/N.
    # The second descriptor is its script argument, not an operator flag.
    case "${1:-}" in
        /proc/self/fd/*)
            case "${1#/proc/self/fd/}" in '' | *[!0-9]*) ;; *) shift ;; esac
            ;;
    esac
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
            --bundle-file) DC_BUNDLE_FILE=${2:-}; shift 2 ;;
            --refuse-capability-loss) DC_REFUSE_CAPABILITY_LOSS=1; shift ;;
            --trust-anchor-file) DC_TRUST_ANCHOR_FILE=${2:-}; shift 2 ;;
            --format) DC_FORMAT=${2:-}; shift 2 ;;
            --https-proxy) DC_HTTPS_PROXY=${2:-}; shift 2 ;;
            --log) DC_LOG=${2:-}; shift 2 ;;
            --staging-dir) DC_STAGING_DIR=${2:-}; shift 2 ;;
            -h | --help) dc_usage; exit 0 ;;
            *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "unknown argument: $1" ;;
        esac
    done
}

dc_validate_args() {
    case "$DC_FORMAT" in
        json | jamf) ;;
        *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--format must be json or jamf" ;;
    esac
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
        { [ -n "$DC_SOURCE$DC_SOURCE_URL$DC_CONFIG_FILE$DC_SECRET_NAME$DC_SECRET_FILE$DC_BUNDLE_FILE$DC_TRUST_ANCHOR_FILE" ] ||
            [ "$DC_CONFIG_STDIN$DC_SECRET_STDIN" != 00 ] || [ "$DC_REFUSE_CAPABILITY_LOSS" = 1 ]; }; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--action $DC_ACTION is read-only and takes no source, config, secret, bundle or trust anchor file"
    fi
    if [ "$DC_REFUSE_CAPABILITY_LOSS" = 1 ] && [ -z "$DC_BUNDLE_FILE" ] && ! dc_inline_bundle | grep -q '[^[:space:]]'; then
        dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--refuse-capability-loss requires a bundle"
    fi
    for path in "$DC_BUNDLE_FILE" "$DC_TRUST_ANCHOR_FILE"; do
        case "$path" in
            "" | /*) ;;
            *) dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "--bundle-file and --trust-anchor-file take absolute paths: $path" ;;
        esac
    done
}

# The lifecycle record pins the installed bytes. A missing or unreadable
# digest is not proof that a same-version package is healthy.
dc_recorded_binary_sha256() {
    [ -f "$DC_DEPLOYMENT_RECORD" ] && [ ! -L "$DC_DEPLOYMENT_RECORD" ] || return 1
    recorded_digest=$(awk -v key="\"$1\":" '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (index(line, key) != 1) next
            line = substr(line, length(key) + 1)
            sub(/^[[:space:]]*"/, "", line)
            sub(/"[,]?[[:space:]]*$/, "", line)
            print line
            exit
        }
    ' "$DC_DEPLOYMENT_RECORD") || return 1
    dc_is_sha256 "$recorded_digest" || return 1
    printf '%s\n' "$recorded_digest"
}

# Reinstall a same-version package when a required binary is absent, cannot
# execute, or differs from the committed deployment.
dc_binaries_damaged() {
    bin_dir=$(dirname "$DC_GATEWAY")
    for name in defenseclaw-gateway defenseclaw-hook defenseclaw-sensor-helper; do
        binary="$bin_dir/$name"
        [ -s "$binary" ] && [ -x "$binary" ] || return 0
        expected=$(dc_recorded_binary_sha256 "$binary") || return 0
        actual=$(dc_sha256 "$binary" 2>/dev/null) || return 0
        [ "$actual" = "$expected" ] || return 0
    done
    return 1
}

dc_layout() {
    if [ "$DC_SCRIPT_OS" = darwin ]; then
        DC_GATEWAY=/opt/cisco/defenseclaw/bin/defenseclaw-gateway
        DC_INSTALL_ROOT=/opt/cisco/defenseclaw
        DC_DEPLOYMENT_RECORD=/opt/cisco/defenseclaw/lifecycle/deployment.json
        DC_ANCHORS=/opt/cisco/defenseclaw/etc/trust/bundle-anchors.json
        DC_SECRETS_DIR=/opt/cisco/defenseclaw/etc/secrets
        DC_INSTALLED_CONFIG=/opt/cisco/defenseclaw/etc/config.yaml
        DC_JOURNAL_DIR=/var/db/defenseclaw-mdm/rotation
        DC_PACKAGE_RESULT=/opt/cisco/defenseclaw/lifecycle/last-package-result.json
        DC_OS_GROUP=macos
        [ -n "$DC_LOG" ] || DC_LOG=/Library/Logs/Cisco/DefenseClaw/mdm-wrapper.log
    else
        DC_GATEWAY=/opt/defenseclaw/bin/defenseclaw-gateway
        DC_INSTALL_ROOT=/opt/defenseclaw
        DC_DEPLOYMENT_RECORD=/var/lib/defenseclaw-enterprise/deployment.json
        DC_ANCHORS=/etc/defenseclaw/trust/bundle-anchors.json
        DC_SECRETS_DIR=/etc/defenseclaw/secrets
        DC_INSTALLED_CONFIG=/etc/defenseclaw/config.yaml
        DC_JOURNAL_DIR=/var/lib/defenseclaw-mdm/rotation
        DC_PACKAGE_RESULT=/var/lib/defenseclaw-enterprise/last-package-result.json
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
            dc_fail_result "$DC_EXIT_FAILURE" mdm_download_failed "$DC_DOWNLOAD_ERROR (signature)"
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
            dc_fail_result "$DC_EXIT_FAILURE" mdm_download_failed "$DC_DOWNLOAD_ERROR (source)"
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
    printf '%s' "$1" | sed -e 's/^[0-9][0-9]*://' -e 's/-[0-9][0-9]*$//' -e 's/~/-/'
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
            case "$installed" in
                "install ok installed "*)
                    installed_version=${installed#install ok installed }
                    if dpkg --compare-versions "$version" lt "$installed_version"; then
                        dc_fail_result "$DC_EXIT_FAILURE" downgrade_refused "package version $version is older than the installed $installed_version; nothing was installed"
                    fi
                    ;;
            esac
            if [ "$installed" = "install ok installed $version" ] && ! dc_binaries_damaged; then
                dc_log "package $version already installed"
            else
                : >"$DC_STAGE/package.started"
                attempt=1
                while ! output=$(DEBIAN_FRONTEND=noninteractive dpkg -i "$file" 2>&1); do
                    if dc_busy_output "$output" && [ "$attempt" -lt 3 ]; then
                        dc_log "package manager busy; retry $attempt of 2"
                        attempt=$((attempt + 1))
                        sleep 10
                        continue
                    fi
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                    fi
                    dc_fail_result "$DC_EXIT_FAILURE" mdm_package_install_failed "dpkg failed: $output"
                done
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
            arch=$(rpm -qp --qf '%{ARCH}' "$file" 2>/dev/null || true)
            host_arch=$(rpm --eval '%{_arch}' 2>/dev/null || true)
            [ "$package" = "$DC_LINUX_PACKAGE" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_package "the .rpm is '$package', not $DC_LINUX_PACKAGE"
            [ -n "$host_arch" ] && [ "$arch" = "$host_arch" ] ||
                dc_fail_result "$DC_EXIT_FAILURE" mdm_wrong_architecture "the .rpm is for $arch; this host needs $host_arch"
            dc_require_product_version "$(dc_package_release_version "$version")"
            # An interrupted upgrade can leave multiple installed versions.
            # Use the newest one for the repair decision and result metadata.
            installed=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$DC_LINUX_PACKAGE" 2>/dev/null | sort -V | tail -n 1 || true)
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
                : >"$DC_STAGE/package.started"
                attempt=1
                while ! output=$(rpm -U --quiet $replace "$file" 2>&1); do
                    if dc_busy_output "$output" && [ "$attempt" -lt 3 ]; then
                        dc_log "package manager busy; retry $attempt of 2"
                        attempt=$((attempt + 1))
                        sleep 10
                        continue
                    fi
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "the package manager is busy; retry later"
                    fi
                    dc_fail_result "$DC_EXIT_FAILURE" mdm_package_install_failed "rpm failed: $output"
                done
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
                dc_require_free_space "$(sed -n 's/.*installKBytes="\([0-9][0-9]*\)".*/\1/p' "$expanded"/*/PackageInfo 2>/dev/null | head -n 1)"
                started="$DC_STAGE/installer.started"
                : >"$started"
                if ! output=$(installer -pkg "$file" -target / 2>&1); then
                    if dc_busy_output "$output"; then
                        dc_fail_result "$DC_EXIT_BUSY" mdm_package_manager_busy "another installation is running; retry later"
                    fi
                    case "$output" in
                        *"No space left"* | *"not enough space"* | *"not enough disk space"*)
                            dc_fail_result "$DC_EXIT_FAILURE" mdm_disk_full "the installer ran out of disk space; free some space, then rerun: $output" ;;
                    esac
                    dc_package_script_result "$started" "$output"
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

# dc_require_free_space <KB the package installs>: refuse before the package
# manager runs when the volume of the install tree lacks room for the
# package plus the lifecycle snapshot and logs. A full data volume failed the
# Installer with its generic "The upgrade failed" text and left no lifecycle
# result (GAP-0539).
dc_require_free_space() {
    case "$1" in '' | *[!0-9]*) return 0 ;; esac
    [ -n "$DC_INSTALL_ROOT" ] || return 0
    dir=$DC_INSTALL_ROOT
    while [ ! -d "$dir" ]; do dir=$(dirname "$dir"); done
    free=$(df -Pk "$dir" 2>/dev/null | awk 'NR == 2 { print $4 }')
    case "$free" in '' | *[!0-9]*) return 0 ;; esac
    need=$(($1 + 102400))
    [ "$free" -ge "$need" ] ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_disk_full "not enough free disk space on the volume of $DC_INSTALL_ROOT: the package needs about $((need / 1024)) MB and $((free / 1024)) MB is free; nothing was installed. Free some space, then rerun"
}

# dc_lifecycle_lock_held <lock>: whether a lifecycle run holds the lifecycle
# lock now. The gateway takes it with flock(2) (internal/enterpriseunix/
# lock.go) and macOS has no flock command, so perl tries a non-blocking
# flock on a read-only descriptor. A missing lock file or a probe that
# cannot run counts as not held.
dc_lifecycle_lock_held() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    perl -e 'use Fcntl qw(:flock O_RDONLY O_NOFOLLOW);
        sysopen(my $fh, $ARGV[0], O_RDONLY | O_NOFOLLOW) or exit 1;
        exit(flock($fh, LOCK_EX | LOCK_NB) ? 1 : ($!{EWOULDBLOCK} ? 0 : 1))' "$1" 2>/dev/null
}

# dc_package_script_result <marker> <installer output>: after a failed installer run, print the
# result the package's preinstall or postinstall wrote during it and exit
# with its exit code. The Installer only says "an error occurred while
# running scripts", while that result names the cause: a refused downgrade
# with both versions, or a rejected config (GAP-0538). A postinstall that
# timed out waiting for another lifecycle run reports 75, which an MDM
# retries; exiting 1 instead turned it into a failure (GAP-1413). A result
# not older than the marker is this run's: the file system can stamp both
# in one clock tick, and a strict "newer" test dropped a preinstall that
# refused at once. <installer output> goes into the failure that names a
# result the package script left empty.
dc_package_script_result() {
    result=$DC_PACKAGE_RESULT
    [ -n "$result" ] && [ -f "$result" ] && [ ! -L "$result" ] && [ -f "$1" ] || return 0
    [ -z "$(find "$1" -newer "$result" 2>/dev/null)" ] || return 0
    # The postinstall empties the result when it starts the lifecycle. The
    # Installer stops a script at 10 minutes and returns at once, while the
    # lifecycle it started still writes its result a moment later: wait for
    # that, and when none comes, say whether the lock is still held
    # (GAP-1413). An empty result read at once gave exit 1 and no output.
    waited=0
    while [ ! -s "$result" ] && [ "$waited" -lt 30 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if [ ! -s "$result" ] || [ -L "$result" ]; then
        if dc_lifecycle_lock_held "$(dirname "$result")/lifecycle.lock"; then
            dc_fail_result "$DC_EXIT_BUSY" lifecycle_busy "another lifecycle run still holds the lock after the package script timed out; retry later"
        fi
        dc_fail_result "$DC_EXIT_FAILURE" mdm_package_result_empty "the package script left no result in $result; its log is $(dirname "$result")/last-package-result.log. installer: $2"
    fi
    cp "$result" "$DC_STAGE/package-result.json" 2>/dev/null || return 0
    DC_RESULT="$DC_STAGE/package-result.json"
    dc_emit_result
    # The top-level exit_code is the document's last field.
    status=$(grep -o '"exit_code"[[:space:]]*:[[:space:]]*[0-9]*' "$DC_RESULT" | tail -n 1 | sed 's/.*://; s/[[:space:]]//g')
    case "$status" in 2 | 75) exit "$status" ;; esac
    exit "$DC_EXIT_FAILURE"
}

# dc_package_apply_failed: after this run installed the deb or rpm, report
# the result its postinstall wrote when that run did not activate the
# deployment. The postinstall never fails the package transaction, and with
# no deployment record every binary reads as damaged: the wrapper reported
# mdm_binaries_damaged while the postinstall had named the cause, unit files
# the package shipped group-writable (GAP-0108).
dc_package_apply_failed() {
    [ -n "$DC_PACKAGE_ACTION" ] && [ -f "$DC_STAGE/package.started" ] || return 0
    [ -n "$DC_PACKAGE_RESULT" ] && [ -f "$DC_PACKAGE_RESULT" ] && [ ! -L "$DC_PACKAGE_RESULT" ] || return 0
    grep -m 1 '"ok"' "$DC_PACKAGE_RESULT" 2>/dev/null | grep -q false || return 0
    dc_package_script_result "$DC_STAGE/package.started" "the package installed, but its postinstall wrote no result"
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

# dc_annotate_anchors_step: after a successful run, make the result document
# report the trust anchor file this run installed. The lifecycle result is
# the ensure that ran before the anchors, or the bundle apply that found the
# confirmed bundle again: its "noop": true ("compliant", "already_applied")
# would tell the MDM nothing changed although the anchors did (GAP-0034). The
# lifecycle prints the document with two-space indentation, one top-level
# field per line.
dc_annotate_anchors_step() {
    { [ "$DC_ANCHORS_CHANGED" = 1 ] || [ "$DC_ANCHORS_COMMITTED" = 1 ]; } && [ -n "$DC_RESULT" ] || return 0
    if [ -n "$DC_ANCHORS_PREVIOUS" ]; then
        change="replaced the trust anchors in $DC_ANCHORS"
    else
        change="installed trust anchors in $DC_ANCHORS"
    fi
    annotated="$DC_STAGE/result.anchors.json"
    if DC_AWK_CHANGE="\"$(dc_json_escape "$change")\"" \
        awk '
            BEGIN { change = ENVIRON["DC_AWK_CHANGE"] }
            /^  "noop": true,$/ { print "  \"noop\": false,"; next }
            /^  "noop_reason": / { next }
            /^  "changes": \[$/ { print; print "    " change ","; noted = 1; next }
            /^  "exit_code": / && !noted { print "  \"changes\": [" change "],"; noted = 1 }
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
    if ! mkdir_err=$(mkdir "$payload" 2>&1 >/dev/null); then
        available=$(df -Pk "$DC_STAGE" 2>/dev/null | awk 'END { print $4 }')
        if printf '%s\n' "$mkdir_err" | grep -Eiq 'No space left|ENOSPC|Disk quota exceeded' || [ "$available" = 0 ]; then
            dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_full "the staging filesystem is full at $DC_STAGE; choose a staging folder with more space"
        fi
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "cannot create the payload staging folder $payload: $mkdir_err"
    fi
    if ! tar_err=$(tar -xzf "$file" -C "$payload" --no-same-owner --no-same-permissions 2>&1 >/dev/null); then
        available=$(df -Pk "$DC_STAGE" 2>/dev/null | awk 'END { print $4 }')
        if printf '%s\n' "$tar_err" | grep -Eiq 'No space left|ENOSPC|Disk quota exceeded' || [ "$available" = 0 ]; then
            dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_full "the staging filesystem is full at $DC_STAGE; choose a staging folder with more space"
        fi
        dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive did not extract"
    fi
    if [ -n "$(find "$payload" \( ! -type f ! -type d \) -o \( -type f -links +1 \) | head -n 1)" ]; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive contains links or special files"
    fi
    gateway=$(find "$payload" -maxdepth 2 -type f -name defenseclaw-gateway -print | head -n 1)
    [ -n "$gateway" ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_payload_invalid "the payload archive has no defenseclaw-gateway"
    chown -R 0:0 "$payload"
    chmod -R go-w "$payload"
    # A staging folder on a noexec mount cannot run the payload's gateway;
    # the lifecycle step then failed with the shell's "Permission denied"
    # and mdm_lifecycle_no_result (GAP-0752).
    set +e
    "$gateway" --version-json >/dev/null 2>&1
    probe=$?
    set -e
    if [ "$probe" = 126 ] && mount=$(dc_noexec_mount "$DC_STAGE"); then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_noexec "cannot run defenseclaw-gateway from the staging folder $DC_STAGE: $mount is mounted noexec. Pass --staging-dir with a root-only folder on a filesystem that allows execution, or use the deb or rpm package as --source"
    fi
    DC_CHANNEL_FLAG="--payload=$(dirname "$gateway")"
    DC_PAYLOAD_GATEWAY=$gateway
}

# dc_guardrail_block <config>: the config's top-level guardrail: block with
# LF line ends and without full-line comments or trailing blank lines. A
# comment, even at column 0, does not end the block: in YAML the keys after
# it are still guardrail keys. Fails unless the file has exactly one plain
# guardrail: line.
dc_guardrail_block() {
    awk '
        { sub(/\r$/, "") }
        $0 == "guardrail:" { count++; inside = (count == 1); if (inside) { n = 1; block[1] = $0 }; next }
        inside && /^[ \t]*#/ { next }
        inside && ($0 == "" || substr($0, 1, 1) == " ") { block[++n] = $0; next }
        { inside = 0 }
        END {
            if (count != 1) exit 1
            while (n > 1 && block[n] == "") n--
            for (i = 1; i <= n; i++) print block[i]
        }
    ' "$1"
}

# dc_custom_pack_path <block> <pack>: "<line> <path>" of
# guardrail.custom_packs.<pack>.path in a dc_guardrail_block file, the path
# without quotes; nothing when the block names none.
dc_custom_pack_path() {
    awk -v pack="$2" -v quotes="\"'" '
        $0 == "  custom_packs:" { packs = 1; inpack = 0; next }
        packs && substr($0, 1, 4) ~ /[^ ]/ { packs = 0 }
        !packs { next }
        /^    [^ \t:]+:[ \t]*$/ { name = $0; sub(/^    /, "", name); sub(/:[ \t]*$/, "", name); inpack = (name == pack); next }
        inpack && /^      path:[ \t]*[^ \t]/ {
            value = $0
            sub(/^      path:[ \t]*/, "", value)
            sub(/[ \t]*$/, "", value)
            while (value != "" && index(quotes, substr(value, 1, 1))) value = substr(value, 2)
            while (value != "" && index(quotes, substr(value, length(value), 1))) value = substr(value, 1, length(value) - 1)
            print NR " " value
            exit
        }
    ' "$1"
}

# dc_top_block <config> <key>: every top-level <key>: block of the config
# (the key plain or quoted), with LF line ends and without blank or
# full-line comment lines; nothing when the config has none.
dc_top_block() {
    awk -v key="$2" -v bom="$(printf '\357\273\277')" '
        { sub(/\r$/, "") }
        NR == 1 && index($0, bom) == 1 { $0 = substr($0, length(bom) + 1) }
        /^[ \t]*#/ || /^[ \t]*$/ { next }
        substr($0, 1, 1) != " " {
            inside = ($0 ~ ("^(" key "|\"" key "\"|\047" key "\047)[ \t]*:([ \t]|$)"))
        }
        inside { print }
    ' "$1"
}

# dc_plain_bytes <config>: fails, printing why, unless every byte of the
# base config is printable ASCII or LF, a CR comes only right before an LF
# and a UTF-8 byte order mark only first (GAP-0090 verify r3). The product's
# loader also starts a new line at a lone CR, NEL, LS and PS, so a key after
# one was hidden from the text checks, which split lines only at LF. od reads
# the bytes, so the check does not depend on the awk or the locale; a file
# od does not read in full is refused.
dc_plain_bytes() {
    size=$(wc -c <"$1" | tr -d ' ')
    LC_ALL=C od -An -v -tu1 "$1" 2>/dev/null | LC_ALL=C awk -v size="$size" '
        function refuse(why) {
            msg = "the base config line " line " " why "; write the base config in plain ASCII with LF or CRLF line ends"
            bad = 1
        }
        function high(   name) {
            name = sprintf("a non-ASCII byte (0x%02X)", seq1)
            if (seq1 == 194 && seq2 == 133) name = "a NEL (U+0085) line break"
            if (seq1 == 226 && seq2 == 128 && seq3 == 168) name = "an LS (U+2028) line break"
            if (seq1 == 226 && seq2 == 128 && seq3 == 169) name = "a PS (U+2029) line break"
            if (seq1 == 239 && seq2 == 187 && seq3 == 191) {
                if (start == 1) return
                name = "a byte order mark that is not at the start of the file"
            }
            refuse("has " name)
        }
        BEGIN { line = 1 }
        {
            for (f = 1; f <= NF; f++) {
                b = $f + 0
                at++
                if (want) {
                    if (++got == 2) seq2 = b; else seq3 = b
                    if (--want == 0) { high(); if (bad) exit }
                    continue
                }
                if (cr) { cr = 0; if (b != 10) { refuse("has a carriage return (CR) that is not followed by a line feed (LF)"); exit } }
                if (b == 10) { line++; continue }
                if (b >= 32 && b <= 126) continue
                if (b == 13) { cr = 1; continue }
                if (b >= 128) {
                    seq1 = b; seq2 = seq3 = -1; got = 1; start = at
                    want = (b == 194) ? 1 : ((b == 226 || b == 239) ? 2 : 0)
                    if (!want) { high(); exit }
                    continue
                }
                if (b == 0) refuse("has a NUL byte")
                else if (b == 9) refuse("has a tab")
                else if (b == 11) refuse("has a vertical tab")
                else if (b == 12) refuse("has a form feed")
                else refuse(sprintf("has a control character (0x%02X)", b))
                exit
            }
        }
        END {
            if (!bad && want) high()
            if (!bad && cr) refuse("has a carriage return (CR) that is not followed by a line feed (LF)")
            if (!bad && at != size + 0) { msg = "the base config could not be read byte by byte"; bad = 1 }
            if (bad) { print msg; exit 1 }
        }
    '
}

# dc_plain_yaml <config>: fails, printing why, unless the base config is
# written plainly enough for dc_guardrail_block and dc_top_block, which find
# a key by its text (GAP-0090 verify r2). The product's loader also reads
# "claude\u005fcode":, !!str claude_code: and ? claude_code as claude_code,
# and takes a line that continues a quoted value or a {...} or [...] as part
# of that value even when the line starts in column 1, so a config written
# that way passed the compare and still set a hook mode or hid its guardrail
# block. Every top-level key must be lowercase letters, digits and
# underscores, plain or in quotes (the document may start with ---), and
# every quoted value and {...} or [...] must end on the line it starts on.
# Block scalar (| and >) lines are not read. A single-quoted '' is read as
# the end of one quoted value and the start of the next, which ends on the
# same line either way. The config must pass dc_plain_bytes first, so it has
# no tab.
dc_plain_yaml() {
    LC_ALL=C awk -v bom="$(printf '\357\273\277')" '
        function refuse(why) { print "the base config line " NR " " why; bad = 1; exit }
        BEGIN { block = -1 }
        { sub(/\r$/, "") }
        NR == 1 && index($0, bom) == 1 { $0 = substr($0, length(bom) + 1) }
        { line = $0; n = length(line); match(line, /^ */); indent = RLENGTH }
        block >= 0 && (line ~ /^ *$/ || indent > block) { next }
        { block = -1 }
        line ~ /^ *#/ || line ~ /^ *$/ { next }
        indent == 0 {
            if (line == "---" && !top) { top = 1; next }
            top = 1
            if (line !~ /^([a-z0-9_]+|"[a-z0-9_]+"|\047[a-z0-9_]+\047) *:( |$)/) {
                key = line
                sub(/ *:.*/, "", key)
                gsub(/^["\047]+|["\047]+$/, "", key)
                lower = tolower(key)
                if (key != lower && (lower == "guardrail" || lower == "claude_code" || lower == "codex" || lower == "connector_hooks" || lower == "application_protection"))
                    refuse("writes the top-level key " lower " in other letters; write it in lowercase")
                refuse("is not a plain top-level key; write each top-level key in lowercase letters, digits and underscores, plain or in quotes, without an escape, tag, anchor, alias, merge key, complex key or {...} or [...]")
            }
        }
        {
            i = indent + 1; depth = 0; owner = indent; start = indent
            while (i <= n) {
                c = substr(line, i, 1)
                spaced = (i == n || substr(line, i + 1, 1) == " ")
                if (c == " ") { i++; continue }
                if (c == "#") break
                if (c == "\"" || c == "\047") {
                    for (j = i + 1; j <= n && substr(line, j, 1) != c; j++)
                        if (c == "\"" && substr(line, j, 1) == "\\") j++
                    if (j > n) refuse("leaves a quoted value open; end each quoted value on the line it starts on")
                    start = i - 1; i = j + 1; continue
                }
                if (c == "{" || c == "[") { depth++; i++; continue }
                if ((c == "}" || c == "]") && depth > 0) { depth--; i++; continue }
                if (c == "," && depth > 0) { i++; continue }
                if (c == ":" && (spaced || depth > 0)) { owner = start; i++; continue }
                if ((c == "-" || c == "?") && spaced) { owner = i - 1; i++; continue }
                if ((c == "|" || c == ">") && depth == 0) { block = owner; next }
                if (c == "!" || c == "&" || c == "*") {
                    while (i <= n && !index(" ,{}[]", substr(line, i, 1))) i++
                    continue
                }
                start = i - 1
                for (; i <= n; i++) {
                    c = substr(line, i, 1)
                    if (c == ":" && (depth > 0 || i == n || substr(line, i + 1, 1) == " ")) break
                    if (depth > 0 && index(",{}[]", c)) break
                    if (c == "#" && substr(line, i - 1, 1) == " ") break
                }
            }
            if (depth > 0) refuse("leaves a {...} or [...] open; end each one on the line it starts on")
        }
        END { exit bad }
    ' "$1"
}

# dc_check_base_config <config> <bundle>: a base config delivered with a
# signed bundle is the config the agents run under until the bundle applies,
# and after a bundle that does not apply (GAP-0090; the Intune Windows
# packager checks the same, GAP-0105). The two guardrail: blocks must be
# identical apart from where each custom rule pack the bundle ships is
# installed: the bundle names policies/guardrail/<pack> inside itself, the
# base config an absolute folder the administrator installed before this
# run. The claude_code:, codex:, connector_hooks: and application_protection:
# blocks must be identical too, or absent from both: the hooks take
# claude_code.mode, codex.mode and connector_hooks.<connector>.mode before
# the guardrail mode, and application_protection sets the guardrail policy
# of automatically protected agents. No other key is compared. The config
# must pass dc_plain_bytes and dc_plain_yaml first. Prints why and fails
# when they differ.
# Needs tar (dc_main checks for it). The bundle
# apply verifies the signature later; the config compared here must match
# the manifest's files[] pin.
dc_check_base_config() {
    dc_plain_bytes "$1" || return 1
    dc_plain_yaml "$1" || return 1
    parity="$DC_STAGE/parity"
    rm -rf "$parity"
    mkdir "$parity"
    for member in manifest.json config.yaml; do
        tar -xzOf "$2" "$member" 2>/dev/null | head -c 262145 >"$parity/$member" || true
        size=$(wc -c <"$parity/$member" | tr -d ' ')
        if [ "$size" = 0 ]; then
            echo "the bundle has no readable $member"
            return 1
        fi
        if [ "$size" -gt 262144 ]; then
            echo "the bundle $member is larger than 262144 bytes"
            return 1
        fi
    done
    manifest=$(tr -d ' \t\r\n' <"$parity/manifest.json")
    pin=$(printf '%s\n' "$manifest" | sed -n 's/.*"path":"config\.yaml","sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
    if [ -z "$pin" ] || [ "$pin" != "$(dc_sha256 "$parity/config.yaml")" ]; then
        echo "the bundle config.yaml does not match the signed manifest files[] pin"
        return 1
    fi
    if ! dc_guardrail_block "$1" >"$parity/base" || ! dc_guardrail_block "$parity/config.yaml" >"$parity/bundle"; then
        echo "the base config and the bundle config must each have one plain guardrail: block"
        return 1
    fi
    selected=$(grep '^  rule_pack: ' "$parity/bundle" || true)
    if [ -n "$selected" ] && [ "$(printf '%s\n' "$selected" | wc -l | tr -d ' ')" = 1 ] && ! grep -qxF "$selected" "$parity/base"; then
        echo "the base config must select the bundle rule pack ${selected#  rule_pack: }"
        return 1
    fi
    packs=$(printf '%s\n' "$manifest" | grep -o '"path":"policies/guardrail/[^/"]*/' | sed -e 's|.*/guardrail/||' -e 's|/$||' | sort -u)
    case "$(printf '%s' "$packs" | tr '\n' '.')" in
        *[!A-Za-z0-9._-]*) echo "the bundle names a rule pack folder that is not a plain name"; return 1 ;;
    esac
    for pack in $packs; do
        in_bundle=$(dc_custom_pack_path "$parity/bundle" "$pack")
        in_base=$(dc_custom_pack_path "$parity/base" "$pack")
        if [ -z "$in_bundle" ] || [ "${in_bundle#* }" != "policies/guardrail/$pack" ]; then
            echo "the bundle config.yaml must name policies/guardrail/$pack as custom_packs.$pack.path"
            return 1
        fi
        if [ -z "$in_base" ]; then
            echo "the base config must define custom_packs.$pack"
            return 1
        fi
        case "${in_base#* }" in
            /*) ;;
            *) echo "the base config must name an absolute, preinstalled path for bundle rule pack $pack"; return 1 ;;
        esac
        awk -v at="${in_base%% *}" -v from="${in_bundle%% *}" '
            NR == FNR { if (FNR == from + 0) line = $0; next }
            FNR == at + 0 { print line; next }
            { print }
        ' "$parity/bundle" "$parity/base" >"$parity/base.next"
        mv -f "$parity/base.next" "$parity/base"
    done
    if ! cmp -s "$parity/base" "$parity/bundle"; then
        echo "the base config guardrail: block differs from the signed bundle's; use the same policy source and change only custom_packs.<pack>.path"
        return 1
    fi
    for key in claude_code codex connector_hooks application_protection; do
        dc_top_block "$1" "$key" >"$parity/base.$key"
        dc_top_block "$parity/config.yaml" "$key" >"$parity/bundle.$key"
        cmp -s "$parity/base.$key" "$parity/bundle.$key" && continue
        case "$key" in
            claude_code) why="claude_code.mode overrides the guardrail mode for Claude Code" ;;
            codex) why="codex.mode overrides the guardrail mode for Codex" ;;
            connector_hooks) why="connector_hooks.<connector>.mode overrides the guardrail mode for that connector" ;;
            *) why="it sets the guardrail policy of automatically protected agents" ;;
        esac
        echo "the base config $key: block differs from the signed bundle's ($why); use the bundle's $key: block, or leave it out of both"
        return 1
    done
}

# Replace the private staging path in the version-8 warning with the source
# the administrator actually supplied.
dc_relabel_config_source() {
    [ -n "$DC_CONFIG_STAGED" ] && [ -n "$DC_CONFIG_ORIGIN" ] || return 0
    grep -q '"code": "config_version_8"' "$DC_RESULT" || return 0
    DC_AWK_OLD=$(dc_json_escape "$DC_CONFIG_STAGED")
    DC_AWK_NEW=$(dc_json_escape "$DC_CONFIG_ORIGIN")
    export DC_AWK_OLD DC_AWK_NEW
    awk '
        BEGIN { old = ENVIRON["DC_AWK_OLD"]; source = ENVIRON["DC_AWK_NEW"]; warning = 0 }
        /"code"[[:space:]]*:[[:space:]]*"config_version_8"/ { warning = 1 }
        {
            if (warning && (at = index($0, old)) > 0) {
                $0 = substr($0, 1, at - 1) source substr($0, at + length(old))
                warning = 0
            }
            print
        }
    ' "$DC_RESULT" >"$DC_STAGE/result-source.json"
    DC_RESULT="$DC_STAGE/result-source.json"
}

# dc_anchors_dir: create the root-owned 0755 trust folder next to the config
# and set dir to it.
dc_anchors_dir() {
    dir=$(dirname "$DC_ANCHORS")
    [ -d "$(dirname "$dir")" ] ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "$(dirname "$dir") is missing; install the deployment before the trust anchor file"
    if [ ! -d "$dir" ]; then
        ( umask 022; mkdir "$dir" ) ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "cannot create $dir"
    fi
    if [ -L "$dir" ] || ! chown 0:0 "$dir" || ! chmod 0755 "$dir"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "cannot make $dir a root-only folder"
    fi
}

# dc_anchors_verb: succeed when the installed gateway has `enterprise bundle
# anchors install`. The probe is the management agent contract's (section
# 3): --version-json reports management_contract 1 or later. Builds before
# the contract (1.0.2 and earlier) print no such member. A --help probe
# would not do: those builds answer `enterprise bundle anchors install
# --help` with the enterprise help and exit 0.
dc_anchors_verb() {
    [ -x "$DC_GATEWAY" ] && dc_trusted_path "$DC_GATEWAY" || return 1
    probe=$("$DC_GATEWAY" --version-json </dev/null 2>/dev/null) || return 1
    contract=$(printf '%s\n' "$probe" |
        sed -n 's/^{.*"management_contract":[[:space:]]*\([1-9][0-9]\{0,3\}\)[[:space:]]*[,}].*$/\1/p' | head -n 1)
    [ -n "$contract" ]
}

# dc_run_anchors_verb <src>: install src with the installed gateway's
# `enterprise bundle anchors install`, which takes the lifecycle lock, checks
# the file and puts the previous one back when the installed file fails its
# check; set DC_ANCHORS_RESULT. The command reads only a file that no account
# but root can change, with no link on its path; the macOS staging folder
# under /var/tmp (sticky, behind the /var link) is not one, so it reads a
# private copy in the trust folder. A refusal is mdm_anchor_install_failed
# with the command's exit code: 1 refused, 2 invalid arguments, 75 busy
# after the lock wait.
dc_run_anchors_verb() {
    dc_anchors_dir
    DC_ANCHORS_SOURCE="$dir/.bundle-anchors.json.mdm-source-$$"
    if ! cp "$1" "$DC_ANCHORS_SOURCE" || ! chown 0:0 "$DC_ANCHORS_SOURCE" || ! chmod 0600 "$DC_ANCHORS_SOURCE"; then
        rm -f "$DC_ANCHORS_SOURCE"
        DC_ANCHORS_SOURCE=""
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "cannot write a copy of the trust anchor file in $dir"
    fi
    set +e
    "$DC_GATEWAY" enterprise bundle anchors install --file "$DC_ANCHORS_SOURCE" --lock-wait 10m --json \
        >"$DC_STAGE/anchors.json" 2>"$DC_STAGE/anchors.err" </dev/null &
    DC_CHILD=$!
    wait "$DC_CHILD"
    status=$?
    DC_CHILD=""
    set -e
    rm -f "$DC_ANCHORS_SOURCE"
    DC_ANCHORS_SOURCE=""
    document=$(tr -d '\n' <"$DC_STAGE/anchors.json")
    [ -z "$document" ] || dc_log "anchors install $document"
    DC_ANCHORS_RESULT=$(printf '%s\n' "$document" | sed -n 's/^[^[]*"result":[[:space:]]*"\([a-z]*\)".*$/\1/p')
    [ "$status" != 0 ] || return 0
    errors=""
    case "$document" in *'"errors"'*) errors=${document##*'"errors"'} ;; esac
    code=$(printf '%s\n' "$errors" | sed -n 's/^[^}]*"code":[[:space:]]*"\([a-z_]*\)".*$/\1/p')
    message=$(printf '%s\n' "$errors" | sed -n 's/^[^}]*"message":[[:space:]]*"\([^"]*\)".*$/\1/p')
    [ -n "$code$message" ] || message=$(head -c 1024 "$DC_STAGE/anchors.err" 2>/dev/null || true)
    case "$status" in 1 | 2 | 75) ;; *) status=$DC_EXIT_FAILURE ;; esac
    dc_fail_result "$status" mdm_anchor_install_failed "enterprise bundle anchors install did not install the trust anchor file${code:+ ($code)}: $message"
}

# dc_put_anchors <src>: atomically replace the trust anchor file with src
# (root-owned, 0644, in a root-owned 0755 trust folder next to the config).
# The writer for an installed gateway without `enterprise bundle anchors
# install`; it stays while releases before the management contract (1.0.2
# and earlier) are supported, since MDMs upload the kit apart from the
# package and can run it against them.
dc_put_anchors() {
    dc_anchors_dir
    next="$dir/.bundle-anchors.json.mdm-$$"
    if ! cp "$1" "$next" || ! chown 0:0 "$next" || ! chmod 0644 "$next" || ! mv -f "$next" "$DC_ANCHORS"; then
        rm -f "$next"
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "cannot write $DC_ANCHORS"
    fi
    dc_trusted_path "$DC_ANCHORS" ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "$DC_ANCHORS or one of its folders is not root-owned or is writable by other accounts$DC_TRUST_ACL"
}

# dc_install_anchors <staged>: install the staged trust anchor file and keep
# the file it replaces for dc_restore_anchors. The installed gateway's
# command (dc_anchors_verb) reports whether the file changed; without it the
# wrapper writes the file itself and skips an identical one.
dc_install_anchors() {
    DC_ANCHORS_VERB=0
    if dc_anchors_verb; then
        DC_ANCHORS_VERB=1
    elif [ -f "$DC_ANCHORS" ] && [ ! -L "$DC_ANCHORS" ] &&
        [ "$(dc_sha256 "$1")" = "$(dc_sha256 "$DC_ANCHORS" 2>/dev/null || true)" ]; then
        dc_log "trust anchor file unchanged"
        return 0
    fi
    if [ -L "$DC_ANCHORS" ] || { [ -e "$DC_ANCHORS" ] && [ ! -f "$DC_ANCHORS" ]; }; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "$DC_ANCHORS is not a regular file"
    fi
    if [ -f "$DC_ANCHORS" ]; then
        DC_ANCHORS_PREVIOUS="$DC_STAGE/bundle-anchors.previous.json"
        cp "$DC_ANCHORS" "$DC_ANCHORS_PREVIOUS" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_anchor_install_failed "cannot keep a copy of $DC_ANCHORS"
    fi
    if [ "$DC_ANCHORS_VERB" = 1 ]; then
        dc_run_anchors_verb "$1"
        if [ "$DC_ANCHORS_RESULT" = unchanged ]; then
            DC_ANCHORS_PREVIOUS=""
            dc_log "trust anchor file unchanged"
            return 0
        fi
        DC_ANCHORS_CHANGED=1
        dc_log "installed trust anchor file $DC_ANCHORS with enterprise bundle anchors install"
        return 0
    fi
    DC_ANCHORS_CHANGED=1
    dc_put_anchors "$1"
    dc_log "installed trust anchor file $DC_ANCHORS"
}

# dc_restore_anchors: after a failed bundle apply, put back the trust anchor
# file this run replaced (or remove the one it added), so a bad anchor file
# never replaces the one that verified the bundle in force. It uses the
# writer that installed the file.
dc_restore_anchors() {
    [ "$DC_ANCHORS_CHANGED" = 1 ] || return 0
    # A subshell: a restore that fails is logged, and the apply result stays
    # the document this run prints.
    if [ -n "$DC_ANCHORS_PREVIOUS" ]; then
        writer=dc_put_anchors
        [ "$DC_ANCHORS_VERB" = 0 ] || writer=dc_run_anchors_verb
        ( "$writer" "$DC_ANCHORS_PREVIOUS" ) >/dev/null || {
            dc_log "could not restore the previous trust anchor file $DC_ANCHORS"
            # The final trust check can fail after the previous file was put
            # back. Otherwise invalidate the new file without removing the
            # path: its presence keeps bundle mode on and refuses the file.
            if [ ! -L "$DC_ANCHORS" ] &&
                ! cmp -s "$DC_ANCHORS_PREVIOUS" "$DC_ANCHORS"; then
                ( : >"$DC_ANCHORS" ) 2>/dev/null ||
                    dc_log "could not invalidate the trust anchor file $DC_ANCHORS"
            fi
            return 1
        }
    else
        rm -f "$DC_ANCHORS" || {
            dc_log "could not remove the newly installed trust anchor file $DC_ANCHORS"
            return 1
        }
    fi
    DC_ANCHORS_CHANGED=0
    dc_log "restored the previous trust anchor file after the failed bundle apply"
}

# dc_emit_result: print the lifecycle's result document, the one document
# this wrapper writes to stdout on success or on a lifecycle failure.
dc_emit_result() {
    [ -n "$DC_RESULT" ] || return 0
    dc_relabel_config_source
    dc_print_result <"$DC_RESULT"
    dc_log "result $(tr -d '\n' <"$DC_RESULT")"
}

# dc_run_lifecycle <gateway> <group> <args...>: run `enterprise <group>
# <args...>` (group linux, macos or bundle), keep its result for
# dc_emit_result and return its exit code.
dc_run_lifecycle() {
    gateway=$1
    shift
    result="$DC_STAGE/result.json"
    set +e
    "$gateway" enterprise "$@" --json >"$result" 2>"$DC_STAGE/lifecycle.err" </dev/null &
    DC_CHILD=$!
    wait "$DC_CHILD"
    status=$?
    DC_CHILD=""
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

dc_run_lifecycle_retry() {
    attempt=1
    while :; do
        status=0
        dc_run_lifecycle "$@" || status=$?
        if [ "$status" != 75 ] || [ "$attempt" -ge 3 ]; then break; fi
        dc_log "lifecycle busy; retry $attempt of 2"
        attempt=$((attempt + 1))
        sleep 10
    done
    return "$status"
}

# Read the first error message from the gateway's lifecycle JSON. The CLI
# writes a refused --json secret set only to stdout, with no stderr text.
dc_secret_json_error() {
    head -c 65536 "$1" 2>/dev/null | awk '
        { document = document $0 }
        END {
            if (!match(document, /"errors"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{/)) exit
            document = substr(document, RSTART + RLENGTH)
            if (!match(document, /"message"[[:space:]]*:[[:space:]]*"/)) exit
            document = substr(document, RSTART + RLENGTH)
            message = ""
            for (i = 1; i <= length(document); i++) {
                c = substr(document, i, 1)
                if (c == "\"") { print message; exit }
                if (c == "\\") {
                    i++
                    c = substr(document, i, 1)
                    if (c == "n" || c == "r" || c == "t") c = " "
                    else if (c == "b" || c == "f") c = ""
                    else if (c == "u") {
                        hex = substr(document, i + 1, 4)
                        if (length(hex) != 4 || hex ~ /[^[:xdigit:]]/) exit
                        value = 0
                        for (j = 1; j <= 4; j++) value = value * 16 + index("0123456789abcdef", tolower(substr(hex, j, 1))) - 1
                        c = value >= 32 && value <= 126 ? sprintf("%c", value) : "\\u" hex
                        i += 4
                    }
                    else if (c != "\"" && c != "\\" && c != "/") exit
                }
                message = message c
            }
        }
    '
}

# dc_secret_set_bundle <gateway>: succeed when the gateway's `enterprise
# secret set` takes --bundle: --version-json reports secret_set_bundle (from
# 1.0.4). An older build binds no credential value and refuses the flag.
dc_secret_set_bundle() {
    probe=$("$1" --version-json </dev/null 2>/dev/null) || return 1
    printf '%s\n' "$probe" | grep -q '"secret_set_bundle":[[:space:]]*true'
}

# dc_read_stored_secret: print credential DC_SECRET_NAME as the deployment
# stores it. Returns 1 when none is stored and 2 when the path is a link,
# not a regular file, or cannot be read.
dc_read_stored_secret() {
    dc_stored="$DC_SECRETS_DIR/$DC_SECRET_NAME"
    if [ ! -e "$dc_stored" ] && [ ! -L "$dc_stored" ]; then return 1; fi
    if [ -L "$dc_stored" ] || [ ! -f "$dc_stored" ]; then return 2; fi
    head -c "$DC_MAX_SECRET_BYTES" "$dc_stored" 2>/dev/null || return 2
}

# dc_save_secret_previous <gateway>: before a credential is stored with the
# bundle it came with (secret set --bundle), journal the value it replaces, or
# that none was stored, on disk (dc_journal_rotation). The rotation and that bundle's
# apply are one transaction: until the apply succeeds the confirmed bundle
# signs only the old value, so a failed or interrupted run puts it back
# (dc_restore_secret). A stored credential that is not a regular file is
# not rotated.
dc_save_secret_previous() {
    dc_saved_status=0
    dc_read_stored_secret >/dev/null || dc_saved_status=$?
    case "$dc_saved_status" in
        0) DC_SECRET_PREVIOUS_SET=1 ;;
        1) DC_SECRET_PREVIOUS_SET=0 ;;
        *)
            dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "the stored credential $DC_SECRETS_DIR/$DC_SECRET_NAME is a link, not a regular file, or cannot be read, so it was not rotated and the config was not applied"
            ;;
    esac
    # ParseSecretValue in the CLI strips one trailing LF and then one CR.
    # Hash those exact bytes now; the put-back compares the stored file
    # under the lifecycle lock, so a later administrator save is retained.
    dc_rotated_value=$secret_data
    dc_lf='
'
    case "$dc_rotated_value" in *"$dc_lf") dc_rotated_value=${dc_rotated_value%"$dc_lf"} ;; esac
    dc_cr=$(printf '\r')
    case "$dc_rotated_value" in *"$dc_cr") dc_rotated_value=${dc_rotated_value%"$dc_cr"} ;; esac
    printf '%s' "$dc_rotated_value" >"$DC_STAGE/rotation-value"
    DC_SECRET_ROTATED_DIGEST=$(dc_sha256 "$DC_STAGE/rotation-value") ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "cannot record the value the credential rotation will store; nothing was rotated"
    rm -f "$DC_STAGE/rotation-value"
    dc_rotated_value=""
    dc_journal_rotation "$1"
    DC_SECRET_GATEWAY=$1
    DC_SECRET_ROTATED=1
}

# The credential rotation journal (GAP-1173, GAP-1188). The rotation and
# its bundle apply are one transaction, so what it replaces is kept on disk,
# not only in memory: <name>.entry names the bundle confirmed before the
# rotation, the SHA-256 of the value it stores, whether a value was stored
# before and the SHA-256 of the installed config then; <name>.value holds
# that earlier value. A failed run puts the credential back from it, and a
# run that stopped before it settled (killed) is put back at the start of
# the next ensure. The put-back (secret set|remove --undo-rotation) runs only
# while the bundle confirmed before the rotation still is and does not sign
# the value stored now; a credential the rotation added is removed although
# the installed config references it only while that very config is
# installed (--undo-config). Only the refusal rotation_confirmed proves the
# rotation committed, so only then does the new value stay; any other
# refusal (credential_in_use, credential_changed, secret_ref_mismatch)
# proves nothing: the entry stays and is logged, and no other rotation runs
# while it does.

# dc_journal_ready: the journal folder exists and only root can change it.
dc_journal_ready() {
    dc_journal_parent=$(dirname "$DC_JOURNAL_DIR")
    [ -d "$dc_journal_parent" ] || mkdir -m 0700 "$dc_journal_parent" 2>/dev/null || return 1
    [ -d "$DC_JOURNAL_DIR" ] || mkdir -m 0700 "$DC_JOURNAL_DIR" 2>/dev/null || return 1
    [ ! -L "$DC_JOURNAL_DIR" ] && dc_trusted_path "$DC_JOURNAL_DIR" || return 1
    case "$(dc_stat_mode "$DC_JOURNAL_DIR")" in *00) return 0 ;; esac
    return 1
}

# dc_rotation_lock: hold the rotation journal lock ($DC_JOURNAL_DIR/.lock)
# until this run ends, as the Windows wrapper holds rotation.lock: a second
# run's settle must not put back the credential a running one just rotated,
# before that run's bundle apply (GAP-1575). macOS has no flock command, so
# a perl process takes flock(2) and keeps it while this shell runs; it waits
# up to 10 minutes for a run that holds it.
dc_rotation_lock() {
    [ -z "${DC_ROTATION_LOCK_PID:-}" ] || return 0
    dc_lock_out="$DC_STAGE/rotation-lock"
    : >"$dc_lock_out"
    perl -e 'use Fcntl qw(:flock O_RDWR O_CREAT O_NOFOLLOW);
        sysopen(my $fh, $ARGV[0], O_RDWR | O_CREAT | O_NOFOLLOW, 0600) or exit 2;
        flock($fh, LOCK_EX) or exit 3;
        open(my $out, ">", $ARGV[2]) or exit 4; print $out "locked\n"; close $out;
        sleep 1 while kill(0, $ARGV[1]);' "$DC_JOURNAL_DIR/.lock" "$$" "$dc_lock_out" </dev/null >/dev/null 2>&1 &
    DC_ROTATION_LOCK_PID=$!
    dc_waited=0
    while ! grep -q locked "$dc_lock_out" 2>/dev/null; do
        if ! kill -0 "$DC_ROTATION_LOCK_PID" 2>/dev/null || [ "$dc_waited" -ge 600 ]; then
            dc_rotation_unlock
            dc_fail_result "$DC_EXIT_BUSY" mdm_secret_failed "another wrapper run holds the credential rotation journal lock $DC_JOURNAL_DIR/.lock; nothing was rotated or put back: run ensure again"
        fi
        sleep 1
        dc_waited=$((dc_waited + 1))
    done
}

# dc_rotation_unlock: release the rotation journal lock this run holds.
dc_rotation_unlock() {
    [ -n "${DC_ROTATION_LOCK_PID:-}" ] || return 0
    kill "$DC_ROTATION_LOCK_PID" 2>/dev/null || true
    wait "$DC_ROTATION_LOCK_PID" 2>/dev/null || true
    DC_ROTATION_LOCK_PID=""
}

# dc_confirmed_bundle <gateway>: print the manifest SHA-256 of the
# confirmed policy bundle (bundle status --json), or none when no bundle is
# confirmed or the device is not managed yet; return 1 with the reason
# printed when status cannot tell.
dc_confirmed_bundle() {
    set +e
    "$1" enterprise bundle status --json </dev/null >"$DC_STAGE/bundle-status.json" 2>/dev/null
    dc_bundle_status=$?
    set -e
    dc_doc=$(head -c 1048576 "$DC_STAGE/bundle-status.json" 2>/dev/null | tr -d '\r\n')
    if [ "$dc_bundle_status" != 0 ]; then
        if printf '%s' "$dc_doc" | grep -Eq '"code"[[:space:]]*:[[:space:]]*"not_managed"'; then
            echo none
            return 0
        fi
        echo "bundle status failed (exit $dc_bundle_status)"
        return 1
    fi
    case "$dc_doc" in *'"current"'*) ;; *) echo "bundle status did not report the confirmed bundle"; return 1 ;; esac
    dc_after=${dc_doc#*\"current\"}
    if printf '%s' "$dc_after" | grep -Eq '^[[:space:]]*:[[:space:]]*null'; then
        echo none
        return 0
    fi
    dc_sha=$(printf '%s' "${dc_after%%\}*}" | sed -n 's/.*"manifest_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p')
    if [ "${#dc_sha}" != 64 ]; then
        echo "bundle status reported no valid manifest digest for the confirmed bundle"
        return 1
    fi
    echo "$dc_sha"
}

# dc_journal_rotation <gateway>: journal the credential DC_SECRET_NAME
# before secret set --bundle replaces it. Refused while an earlier rotation
# is not settled.
dc_journal_rotation() {
    dc_journal_ready ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "the credential journal $DC_JOURNAL_DIR is not a folder only root can change, so nothing was rotated and the config was not applied"
    dc_rotation_lock
    for dc_left in "$DC_JOURNAL_DIR"/*.entry; do
        [ -e "$dc_left" ] || [ -L "$dc_left" ] || continue
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "an earlier credential rotation is not settled ($dc_left): each ensure tries to settle it first and logs why it could not; no credential is rotated until it is"
    done
    DC_SECRET_CONFIRMED=$(dc_confirmed_bundle "$1") ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "the confirmed policy bundle is unknown ($DC_SECRET_CONFIRMED), so nothing was rotated and the config was not applied"
    dc_config_before=none
    if [ -f "$DC_INSTALLED_CONFIG" ] && [ ! -L "$DC_INSTALLED_CONFIG" ]; then
        dc_config_before=$(dc_sha256 "$DC_INSTALLED_CONFIG") ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "cannot read the installed config before the rotation; nothing was rotated"
    fi
    dc_retire_rotation "$DC_SECRET_NAME"
    dc_entry="$DC_JOURNAL_DIR/$DC_SECRET_NAME.entry"
    dc_value="$DC_JOURNAL_DIR/$DC_SECRET_NAME.value"
    dc_previous="absent"
    if [ "$DC_SECRET_PREVIOUS_SET" = 1 ]; then
        dc_previous="set"
        (umask 077; head -c "$DC_MAX_SECRET_BYTES" "$DC_SECRETS_DIR/$DC_SECRET_NAME" >"$dc_value") ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "cannot journal credential $DC_SECRET_NAME before its rotation; nothing was rotated"
    fi
    (umask 077; printf 'confirmed=%s\nrotated=%s\nprevious=%s\nconfig=%s\n' "$DC_SECRET_CONFIRMED" "$DC_SECRET_ROTATED_DIGEST" "$dc_previous" "$dc_config_before" >"$dc_entry.partial") &&
        mv -f "$dc_entry.partial" "$dc_entry" ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "cannot journal credential $DC_SECRET_NAME before its rotation; nothing was rotated"
}

# dc_retire_rotation <name>: the rotation of credential name is settled.
dc_retire_rotation() {
    rm -f "${DC_JOURNAL_DIR:?}/${1:?}.entry" "${DC_JOURNAL_DIR:?}/${1:?}.value" "${DC_JOURNAL_DIR:?}/${1:?}.entry.partial"
}

# dc_journal_field <entry> <key>: print one field of a journal entry.
dc_journal_field() {
    sed -n "s/^$2=//p" "$1" | head -n 1
}

# dc_secret_json_code <file>: the first errors[].code of a gateway result.
dc_secret_json_code() {
    dc_doc=$(head -c 65536 "$1" 2>/dev/null | tr -d '\r\n')
    case "$dc_doc" in *'"errors"'*) ;; *) return 0 ;; esac
    dc_after=${dc_doc#*\"errors\"}
    printf '%s' "${dc_after%%\}*}" | sed -n 's/.*"code"[[:space:]]*:[[:space:]]*"\([a-z0-9_]*\)".*/\1/p'
}

# dc_settle_rotation <gateway> <name>: put credential name back as its
# journal entry says, unless the rotation committed; return 1 when the entry
# could not be settled and stays.
dc_settle_rotation() {
    dc_entry="$DC_JOURNAL_DIR/$2.entry"
    dc_value="$DC_JOURNAL_DIR/$2.value"
    [ -e "$dc_entry" ] || [ -L "$dc_entry" ] || return 0
    dc_valid=1
    [ -f "$dc_entry" ] && [ ! -L "$dc_entry" ] || dc_valid=0
    dc_confirmed="" dc_rotated="" dc_previous="" dc_config_before=""
    if [ "$dc_valid" = 1 ]; then
        dc_confirmed=$(dc_journal_field "$dc_entry" confirmed)
        dc_rotated=$(dc_journal_field "$dc_entry" rotated)
        dc_previous=$(dc_journal_field "$dc_entry" previous)
        dc_config_before=$(dc_journal_field "$dc_entry" config)
    fi
    for dc_digest in "$dc_confirmed" "$dc_config_before"; do
        case "$dc_digest" in none) ;; *[!0-9a-f]* | "") dc_valid=0 ;; *) [ "${#dc_digest}" = 64 ] || dc_valid=0 ;; esac
    done
    case "$dc_rotated" in *[!0-9a-f]* | "") dc_valid=0 ;; *) [ "${#dc_rotated}" = 64 ] || dc_valid=0 ;; esac
    case "$dc_previous" in absent) ;; set) [ -f "$dc_value" ] && [ ! -L "$dc_value" ] || dc_valid=0 ;; *) dc_valid=0 ;; esac
    if [ "$dc_valid" != 1 ]; then
        dc_log "the credential journal entry $dc_entry is not one this wrapper writes, so it was not used and was left as it is; check credential $2, then delete it"
        return 1
    fi
    dc_stored="$DC_SECRETS_DIR/$2"
    # The state from before the rotation is already on disk.
    if [ "$dc_previous" = set ] && [ -f "$dc_stored" ] && [ ! -L "$dc_stored" ] && cmp -s "$dc_value" "$dc_stored"; then
        dc_retire_rotation "$2"
        return 0
    fi
    if [ "$dc_previous" = absent ] && [ ! -e "$dc_stored" ] && [ ! -L "$dc_stored" ]; then
        dc_retire_rotation "$2"
        return 0
    fi
    set +e
    if [ "$dc_previous" = set ]; then
        "$1" enterprise secret set --name "$2" --from-stdin --lock-wait 10m --json --undo-rotation "$dc_confirmed" --if-stored "$dc_rotated" <"$dc_value" >"$DC_STAGE/secret-restore.json" 2>"$DC_STAGE/secret-restore.err"
    else
        "$1" enterprise secret remove --name "$2" --lock-wait 10m --json --undo-rotation "$dc_confirmed" --undo-config "$dc_config_before" --if-stored "$dc_rotated" </dev/null >"$DC_STAGE/secret-restore.json" 2>"$DC_STAGE/secret-restore.err"
    fi
    dc_restore_status=$?
    set -e
    if [ "$dc_restore_status" = 0 ]; then
        dc_log "put back credential $2: the bundle that signs its new value did not apply"
        dc_retire_rotation "$2"
        return 0
    fi
    dc_restore_code=$(dc_secret_json_code "$DC_STAGE/secret-restore.json" || true)
    if [ "$dc_restore_code" = rotation_confirmed ]; then
        dc_log "kept credential $2: the bundle that signs its new value is confirmed (rotation_confirmed)"
        dc_retire_rotation "$2"
        return 0
    fi
    dc_restore_detail=$(dc_secret_json_error "$DC_STAGE/secret-restore.json" || true)
    [ -n "$dc_restore_detail" ] || dc_restore_detail=$(head -c 1024 "$DC_STAGE/secret-restore.err" 2>/dev/null || true)
    dc_log "did not put back credential $2: the gateway refused the undo (exit $dc_restore_status ${dc_restore_code:-no code}): $dc_restore_detail; the stored value was left unchanged and the journal entry $dc_entry stays for the next ensure"
    return 1
}

# dc_resume_rotation: before an ensure stores a credential or applies a
# config, settle the rotations an earlier run left in the journal, with the
# newest gateway this run has: the payload's when it delivers one, else the
# installed one (a delivered package is already installed). A gateway
# before 1.0.5 cannot remove a credential its installed config references
# (--undo-config), so a package delivered with the ensure settles what it
# could not. Nothing installed (no root-owned gateway) has nothing to put
# back: an entry is retired only when no gateway was installed before this
# run delivered one (the deployment and its credentials were removed). An
# installed gateway that is not root-owned keeps the journal, which holds
# the only copy of the earlier credential, and stops the ensure
# (GAP-1614). An entry that cannot be settled stops this ensure before it
# can install a config that adopts the unsettled credential.
dc_resume_rotation() {
    [ -e "$DC_JOURNAL_DIR" ] || [ -L "$DC_JOURNAL_DIR" ] || return 0
    dc_journal_ready ||
        dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "the credential journal $DC_JOURNAL_DIR is not a folder only root can change; nothing in it was used and nothing was changed"
    dc_rotation_lock
    for dc_left in "$DC_JOURNAL_DIR"/*.entry; do
        [ -e "$dc_left" ] || [ -L "$dc_left" ] || continue
        dc_name=$(basename "$dc_left" .entry)
        case "$dc_name" in "" | *[!a-z0-9-]*)
            dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "the credential journal entry $dc_left is not one this wrapper writes; nothing was changed" ;;
        esac
        if [ "$DC_GATEWAY_BEFORE" != 1 ]; then
            dc_log "retired the credential journal entry of $dc_name: no deployment was installed to put it back into"
            dc_retire_rotation "$dc_name"
            continue
        fi
        dc_trusted_path "$DC_GATEWAY" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "$DC_GATEWAY is not root-owned$DC_TRUST_ACL, so the earlier credential rotation of $dc_name was not settled and its journal entry was kept; nothing was changed"
        dc_settle_rotation "${DC_PAYLOAD_GATEWAY:-$DC_GATEWAY}" "$dc_name" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_secret_failed "an earlier credential rotation of $dc_name is not settled (the wrapper log says why); no credential was stored and no config applied: resolve it and run ensure again. A gateway before 1.0.5 cannot put back a credential its installed config references: deliver the package with --source and the gateway it installs settles it"
    done
}

# dc_restore_secret: after a failed or interrupted run that stored a
# credential with --bundle, settle its journal entry with the gateway that
# stored it (dc_settle_rotation): the value it replaced goes back, or the one
# it added goes, unless the gateway proves the rotation committed
# (rotation_confirmed). An entry it cannot settle stays for the next ensure.
dc_restore_secret() {
    [ "$DC_SECRET_ROTATED" = 1 ] || return 0
    DC_SECRET_ROTATED=0
    dc_settle_rotation "$DC_SECRET_GATEWAY" "$DC_SECRET_NAME"
}

dc_store_secret() {
    gateway=$1
    # A credential delivered with a bundle goes with it: a value the
    # confirmed bundle does not sign is stored only when this bundle signs it
    # (secret set --bundle), and the value it replaces goes back unless that
    # bundle applies (dc_save_secret_previous). A gateway before 1.0.4 takes
    # no --bundle and stores the credential as before.
    set --
    if [ -n "${bundle:-}" ] && dc_secret_set_bundle "$gateway"; then
        dc_save_secret_previous "$gateway"
        # Only while the bundle the journal names is still confirmed.
        set -- --bundle "$bundle" --if-confirmed "$DC_SECRET_CONFIRMED"
    fi
    set +e
    printf '%s' "$secret_data" |
        "$gateway" enterprise secret set --name "$DC_SECRET_NAME" --from-stdin --lock-wait 10m --json "$@" >"$DC_STAGE/secret.json" 2>"$DC_STAGE/secret.err" &
    DC_CHILD=$!
    wait "$DC_CHILD"
    secret_status=$?
    DC_CHILD=""
    set -e
    secret_data=""
    if [ "$secret_status" != 0 ]; then
        detail=$(head -c 1024 "$DC_STAGE/secret.err" 2>/dev/null || true)
        if [ -z "$detail" ]; then
            detail=$(dc_secret_json_error "$DC_STAGE/secret.json" || true)
        fi
        [ -n "$detail" ] || detail="the gateway returned no error message"
        case "$secret_status" in 1 | 2 | 75) ;; *) secret_status=$DC_EXIT_FAILURE ;; esac
        dc_fail_result "$secret_status" mdm_secret_failed "storing credential '$DC_SECRET_NAME' failed, so the config was not applied: $detail"
    fi
    dc_log "stored credential $DC_SECRET_NAME"
}

dc_main() {
    dc_layout
    dc_log "start action=$DC_ACTION"
    dc_parse_args "$@"
    dc_layout
    platform=$(dc_platform)
    [ "$platform" = "$DC_SCRIPT_OS" ] ||
        dc_fail_result "$DC_EXIT_INVALID" mdm_wrong_platform "this copy of the wrapper is for $DC_SCRIPT_OS, not $platform"
    dc_validate_args
    [ "$(id -u)" = 0 ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_not_root "run as root (the MDM agent's system context)"

    dc_stage_parent
    dc_sweep_stages "$DC_STAGE_PARENT"
    DC_STAGE=$(mktemp -d "$DC_STAGE_PARENT/defenseclaw-mdm.XXXXXX")
    trap dc_cleanup EXIT
    trap 'dc_stop_child; dc_fail_result "$DC_EXIT_FAILURE" mdm_cancelled "the MDM run was cancelled; the lifecycle was stopped"' HUP INT TERM
    chmod 0700 "$DC_STAGE"
    [ "$(dc_stat_uid "$DC_STAGE")" = 0 ] || dc_fail_result "$DC_EXIT_FAILURE" mdm_staging_untrusted "the staging directory is not root-owned"
    printf '%s\n' "$$" >"$DC_STAGE/pid"
    dc_log "validated action=$DC_ACTION"

    if [ "$DC_ACTION" != ensure ]; then
        dc_trusted_path "$DC_GATEWAY" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "the managed deployment is not installed ($DC_GATEWAY is missing or not root-owned)$DC_TRUST_ACL"
        status=0
        dc_run_lifecycle "$DC_GATEWAY" "$DC_OS_GROUP" "$DC_ACTION" || status=$?
        dc_emit_result
        return "$status"
    fi

    config=""
    if [ "$DC_CONFIG_STDIN" = 1 ]; then
        config="$DC_STAGE/config.yaml"
        DC_CONFIG_ORIGIN="MDM standard input"
        dc_read_bounded "$config" "$DC_MAX_CONFIG_BYTES" "config"
    elif [ -n "$DC_CONFIG_FILE" ]; then
        config="$DC_STAGE/config.yaml"
        DC_CONFIG_ORIGIN=$DC_CONFIG_FILE
        dc_stage_file "$DC_CONFIG_FILE" "$config" "$DC_MAX_CONFIG_BYTES" "config" trusted
    else
        inline="$DC_STAGE/inline-config.yaml"
        dc_inline_config >"$inline"
        if grep -q '[^[:space:]]' "$inline"; then
            config=$inline
            DC_CONFIG_ORIGIN="MDM inline config"
        fi
    fi
    DC_CONFIG_STAGED=$config
    bundle=""
    if [ -n "$DC_BUNDLE_FILE" ]; then
        bundle="$DC_STAGE/policy.dcbundle"
        # Verified after the copy: the signature and file hashes.
        dc_stage_file "$DC_BUNDLE_FILE" "$bundle" "$DC_MAX_BUNDLE_BYTES" "bundle"
    elif dc_inline_bundle | grep -q '[^[:space:]]'; then
        bundle="$DC_STAGE/policy.dcbundle"
        dc_inline_bundle | tr -d ' \t\r\n' | { base64 -d 2>/dev/null || base64 -D; } >"$DC_STAGE/inline.dcbundle" 2>/dev/null ||
            dc_fail_result "$DC_EXIT_INVALID" mdm_invalid_arguments "the inline bundle is not valid base64"
        dc_read_bounded "$bundle" "$DC_MAX_BUNDLE_BYTES" "bundle" <"$DC_STAGE/inline.dcbundle"
    fi
    # A config delivered with a bundle is the base config; it is checked
    # against the bundle before anything is installed. The check reads the
    # bundle with tar, which minimal Linux images may lack.
    if [ -n "$bundle" ] && [ -n "$config" ]; then
        command -v tar >/dev/null 2>&1 ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_tar_missing "tar is not installed; the wrapper needs it to compare the base config with the signed bundle, so nothing was installed (install tar, or deliver the bundle without a base config)"
        reason=$(dc_check_base_config "$config" "$bundle") ||
            dc_fail_result "$DC_EXIT_INVALID" mdm_base_config_mismatch "the base config does not match the signed bundle's guardrail block and hook modes, so nothing was installed: $reason"
    fi
    anchors=""
    if [ -n "$DC_TRUST_ANCHOR_FILE" ]; then
        anchors="$DC_STAGE/bundle-anchors.json"
        # Not verified after the copy: it is the root of bundle trust.
        dc_stage_file "$DC_TRUST_ANCHOR_FILE" "$anchors" "$DC_MAX_ANCHORS_BYTES" "trust anchor file" trusted
    elif dc_inline_trust_anchors | grep -q '[^[:space:]]'; then
        anchors="$DC_STAGE/bundle-anchors.json"
        dc_inline_trust_anchors | dc_read_bounded "$anchors" "$DC_MAX_ANCHORS_BYTES" "trust anchor file"
    fi
    # After a raw-byte check, the credential stays in memory and reaches the
    # lifecycle through a pipe. No staged copy remains during the lifecycle.
    secret_data=""
    if [ -n "$DC_SECRET_NAME" ]; then
        dc_read_secret
    fi

    DC_CHANNEL_FLAG=""
    DC_PAYLOAD_GATEWAY=""
    # Whether a deployment existed before this run delivered one (the
    # journal settle below retires entries only without one).
    if [ -e "$DC_GATEWAY" ] || [ -L "$DC_GATEWAY" ]; then DC_GATEWAY_BEFORE=1; fi
    if [ -n "$DC_SOURCE$DC_SOURCE_URL" ]; then
        dc_stage_source
        dc_install_package
    fi
    # Settled after the delivered package or payload, so the gateway it
    # brings settles a rotation the installed one could not put back.
    dc_resume_rotation

    # The payload channel runs the verified staged binary; every other run
    # uses the installed, root-owned gateway.
    gateway=$DC_GATEWAY
    if [ -n "$DC_PAYLOAD_GATEWAY" ]; then
        gateway=$DC_PAYLOAD_GATEWAY
    elif ! dc_trusted_path "$gateway"; then
        dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "no source was given and $gateway is missing or not root-owned$DC_TRUST_ACL"
    elif dc_binaries_damaged; then
        dc_package_apply_failed
        dc_fail_result "$DC_EXIT_FAILURE" mdm_binaries_damaged "a required installed DefenseClaw binary is missing, not executable, or differs from its deployment record; run this script with the package as --source, or reinstall the package"
    fi

    # The credential is stored first: a config that references it (the AI
    # Defense key, an observability header) only applies once it exists.
    # Before the first payload install the staged gateway stores it, and
    # the install gives the gateway access. Both steps wait for an apply
    # that the package's postinstall or the change itself started (the
    # apply path unit) instead of failing busy.
    if [ -n "$DC_SECRET_NAME" ]; then
        dc_store_secret "$gateway"
    fi

    # A bundle apply runs the ensure transaction itself, so with a bundle
    # ensure runs first only to install the payload channel (the package
    # channel's postinstall already applied the deployment) or to apply the
    # base config. The base config goes in before the trust anchors, so
    # until the bundle applies the hooks answer under the base config that
    # dc_check_base_config compared with the bundle (GAP-0090).
    # In bundle mode (trust anchors installed) only the current bundle's
    # config applies, so the base config is not used.
    ensure_config=$config
    if [ -n "$bundle" ] && { [ -e "$DC_ANCHORS" ] || [ -L "$DC_ANCHORS" ]; }; then
        ensure_config=""
    fi
    if [ -z "$bundle" ] || [ -n "$DC_PAYLOAD_GATEWAY" ] || [ -n "$ensure_config" ]; then
        set -- "$DC_OS_GROUP" ensure --reason mdm --lock-wait 10m
        [ -z "$DC_CHANNEL_FLAG" ] || set -- "$@" "$DC_CHANNEL_FLAG"
        [ -z "$ensure_config" ] || set -- "$@" "--config=$ensure_config"
        [ -z "$DC_PRODUCT_VERSION" ] || set -- "$@" "--product-version=$DC_PRODUCT_VERSION"
        status=0
        dc_run_lifecycle_retry "$gateway" "$@" || status=$?
        if [ "$status" != 0 ] || [ -z "$bundle$anchors" ]; then
            [ "$status" != 0 ] || dc_annotate_package_step
            dc_emit_result
            return "$status"
        fi
        gateway=$DC_GATEWAY
        dc_trusted_path "$gateway" ||
            dc_fail_result "$DC_EXIT_FAILURE" mdm_not_installed "the payload install left no root-owned $gateway$DC_TRUST_ACL"
    fi
    [ -z "$anchors" ] || dc_install_anchors "$anchors"
    if [ -z "$bundle" ]; then
        DC_ANCHORS_COMMITTED=$DC_ANCHORS_CHANGED
        DC_ANCHORS_CHANGED=0
        dc_annotate_package_step
        dc_annotate_anchors_step
        dc_emit_result
        return 0
    fi
    status=0
    if [ "$DC_REFUSE_CAPABILITY_LOSS" = 1 ]; then
        dc_run_lifecycle_retry "$gateway" bundle apply --bundle "$bundle" --reason mdm --refuse-capability-loss --lock-wait 10m || status=$?
    else
        dc_run_lifecycle_retry "$gateway" bundle apply --bundle "$bundle" --reason mdm --lock-wait 10m || status=$?
    fi
    if [ "$status" = 0 ]; then
        # The applied bundle signs the credential this run stored.
        [ "$DC_SECRET_ROTATED" != 1 ] || dc_retire_rotation "$DC_SECRET_NAME"
        DC_SECRET_ROTATED=0
        DC_ANCHORS_COMMITTED=$DC_ANCHORS_CHANGED
        DC_ANCHORS_CHANGED=0
        dc_annotate_package_step
        dc_annotate_anchors_step
    else
        dc_restore_anchors || true
        dc_restore_secret || true
    fi
    dc_emit_result
    return "$status"
}

dc_main "$@"
