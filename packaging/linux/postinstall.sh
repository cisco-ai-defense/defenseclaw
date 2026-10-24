#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: apply the standalone managed deployment
# after an install or upgrade (deb configure, rpm %post).
#
# This script never fails the package transaction. The lifecycle validates
# the administrator config, activates the services and rolls back on its
# own; its JSON result is kept in the lifecycle directory and
# `defenseclaw-gateway enterprise linux verify` reports any problem.

set -u
# dpkg runs "postinst abort-remove" after preremove refused a removal because
# another lifecycle run kept the lock or the hook-removal precheck refused.
# Nothing was removed, so there is nothing to apply, and a second wait on
# the same busy lock would only stall apt. "abort-upgrade" is the same after
# a failed upgrade step: the previous files are back, so there is nothing to
# apply.
case "${1:-}" in
    abort-remove) exit 0 ;;
    abort-upgrade | abort-install | abort-deconfigure)
        # Restart the apply trigger the preinstall held for this upgrade.
        if [ -e /run/defenseclaw-enterprise-apply-path.held ]; then
            if systemctl start defenseclaw-enterprise-apply.path >/dev/null 2>&1; then
                rm -f /run/defenseclaw-enterprise-apply-path.held
                systemctl stop defenseclaw-enterprise-apply-recovery.timer >/dev/null 2>&1 || true
            fi
        fi
        exit 0
        ;;
esac

gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise
# The preinstall leaves this marker when it held the apply trigger for the
# transaction (GAP-0268).
held=/run/defenseclaw-enterprise-apply-path.held

if [ ! -d /run/systemd/system ]; then
    echo "defenseclaw-enterprise: systemd is not running; run '$gateway enterprise linux ensure --from-package' on a systemd host." >&2
    exit 0
fi

# The config-apply path unit watches /etc/defenseclaw, so the tmpfiles and
# daemon-reload below would start an apply run that races this scriptlet's
# ensure for the lifecycle lock (every upgrade then reported busy). Hold the
# trigger while the scriptlet applies, and put it back afterwards.
apply_path=defenseclaw-enterprise-apply.path
apply_path_was_active=0
if systemctl is-active --quiet "$apply_path" >/dev/null 2>&1; then
    apply_path_was_active=1
    systemctl stop "$apply_path" >/dev/null 2>&1 || true
fi
if [ -e "$held" ]; then
    apply_path_was_active=1
fi

# Flush the payload the package manager just unpacked before anything uses
# it: a power loss after the rename but before the data reached the disk
# left zero-length binaries and units, and an empty hook binary runs as an
# empty script that exits 0, so every agent's hook allowed everything
# (GAP-0467).
sync >/dev/null 2>&1 || true
systemd-sysusers /usr/lib/sysusers.d/defenseclaw.conf >/dev/null 2>&1 || true
systemd-tmpfiles --create /usr/lib/tmpfiles.d/defenseclaw.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true

umask 077
mkdir -p "$state" && chmod 0700 "$state"
# The preinstall let an older package through only for the root-owned
# rollback marker; apply it as the deliberate rollback it is, and delete the
# marker, so each rollback needs a new one (GAP-1115).
marker="$state/allow-downgrade"
downgrade=""
if [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(stat -c %u "$marker" 2>/dev/null)" = 0 ]; then
    downgrade=" --allow-downgrade"
fi
# An apply run that started before the trigger was held may hold the lock
# for a whole transaction; wait for it like the apply trigger does. When it
# already applied this package, ensure is a no-op and reports success. Every
# package script waits 8 minutes, as the macOS pkg must (GAP-1413).
# Allocate fresh files before running ensure. Opening stdout over the last
# result used to erase it before a full disk refused the stderr open.
result=""
status=1
lifecycle_started=0
output_saved=0
result_tmp=""
log_tmp=""
if result_tmp=$(mktemp "$state/.last-package-result.json.XXXXXX") && \
    log_tmp=$(mktemp "$state/.last-package-result.log.XXXXXX"); then
    lifecycle_started=1
    # Capture JSON in memory so a partial disk write cannot replace the last
    # complete result. The subshell also contains a file-size-limit signal.
    # shellcheck disable=SC2086 # $downgrade is empty or one flag
    result=$("$gateway" enterprise linux ensure --from-package$downgrade --reason package --json --lock-wait 8m 2>"$log_tmp")
    status=$?
    if [ -n "$result" ] && (printf '%s\n' "$result" >"$result_tmp") && \
        mv -fT "$result_tmp" "$state/last-package-result.json"; then
        output_saved=1
    fi
    mv -fT "$log_tmp" "$state/last-package-result.log" 2>/dev/null || true
    rm -f "$marker"
fi
[ -z "$result_tmp" ] || rm -f "$result_tmp"
[ -z "$log_tmp" ] || rm -f "$log_tmp"
if [ "$apply_path_was_active" = 1 ]; then
    if systemctl start "$apply_path" >/dev/null 2>&1; then
        rm -f "$held"
        systemctl stop defenseclaw-enterprise-apply-recovery.timer >/dev/null 2>&1 || true
    fi
fi

# ensure --json writes indented JSON, so join the lines first and allow
# whitespace between the tokens.
result=$(printf '%s' "$result" | tr '\n' ' ')
if [ "$status" = 0 ] && [ -z "$result" ]; then
    status=1
fi
if [ "$output_saved" != 1 ]; then
    echo "defenseclaw-enterprise: the current package result could not be saved (disk full or storage write failure); last-package-result.json was not replaced." >&2
    echo "  Free disk space or correct the storage problem, then run: sudo $gateway enterprise linux ensure --from-package$downgrade" >&2
fi
unescape() {
    sed 's/\\"/"/g; s/\\u003c/</g; s/\\u003e/>/g; s/\\u0026/\&/g'
}
# message_of CODE prints the message of the errors[] or warnings[] entry
# with that code, on one line ("" when there is none).
message_of() {
    printf '%s\n' "$result" |
        sed -n 's/.*"code":[[:space:]]*"'"$1"'",[[:space:]]*"message":[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1/p' |
        head -n 1 | unescape
}

# Keep the errors and warnings arrays separate. A message can contain a ']'
# inside its JSON string, so a plain sed character class would truncate it.
message_codes() {
    printf '%s\n' "$result" | awk -v name="$1" '
        BEGIN { RS = "\001" }
        {
            start = index($0, "\"" name "\"")
            if (!start) exit
            s = substr($0, start)
            start = index(s, "[")
            if (!start) exit
            quoted = 0; escaped = 0
            for (i = start + 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (escaped) { escaped = 0; continue }
                if (c == "\\" && quoted) { escaped = 1; continue }
                if (c == "\"") { quoted = !quoted; continue }
                if (c == "]" && !quoted) {
                    print substr(s, start + 1, i - start - 1)
                    exit
                }
            }
        }' |
        grep -oE '"code":[[:space:]]*"[^" ]+"' |
        sed 's/^"code":[[:space:]]*"//; s/"$//'
}

case "$status" in
    0)
        echo "defenseclaw-enterprise: the managed deployment is active."
        # A config.yaml the lifecycle rejected stays out: the deployment runs
        # the last applied config, which a successful package run hid.
        rejected=$(message_of config_rejected)
        if [ -n "$rejected" ]; then
            echo "  But config.yaml was not applied: $rejected" >&2
        fi
        ;;
    75)
        echo "defenseclaw-enterprise: installed, but another DefenseClaw lifecycle run held the lock for 8 minutes." >&2
        echo "  Apply this package with: sudo $gateway enterprise linux ensure --from-package$downgrade" >&2
        ;;
    *)
        rollback_warning=$(message_codes warnings | grep -E '^(rolled_back|rollback_failed)$')
        # Name the cause (the first error of the JSON result, one line) so
        # the administrator does not have to open the file (GAP-1744).
        cause=$(printf '%s\n' "$result" |
            sed -n 's/.*"errors":[[:space:]]*\[[[:space:]]*{[[:space:]]*"code":[[:space:]]*"\([^"]*\)",[[:space:]]*"message":[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1: \2/p' |
            head -n 1 | unescape)
        # A refused config or successful rollback names the previous version
        # (GAP-0176). A missing version is not proof that no service is active.
        running=$(printf '%s\n' "$result" | sed -n 's/.*"installed_version":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        if [ "$lifecycle_started" = 0 ]; then
            echo "defenseclaw-enterprise: the package is installed but not applied; the lifecycle did not run, so the previous deployment was not changed." >&2
            finish="apply this package with"
        elif [ -z "$result" ]; then
            echo "defenseclaw-enterprise: the package is installed but its deployment state could not be confirmed." >&2
            finish="check and apply this package with"
        elif [ -n "$running" ] && ! printf '%s\n' "$rollback_warning" | grep -Fxq rollback_failed; then
            echo "defenseclaw-enterprise: the package is installed but not applied; the previous deployment ($running) keeps running unchanged." >&2
            finish="apply this package with"
        else
            echo "defenseclaw-enterprise: installed, but the lifecycle reported a problem; deployment state could not be confirmed." >&2
            finish="finish the install with"
        fi
        if [ -n "$cause" ]; then
            echo "  $cause" >&2
        fi
        # A full disk follows the failed step's error; name it too (GAP-0662).
        disk=$(message_of disk_full)
        if [ -n "$disk" ]; then
            echo "  disk_full: $disk" >&2
        fi
        echo "  Fix that, then $finish: sudo $gateway enterprise linux ensure --from-package$downgrade" >&2
        if [ "$output_saved" = 1 ]; then
            echo "  The full result is in $state/last-package-result.json." >&2
        fi
        ;;
esac
exit 0
