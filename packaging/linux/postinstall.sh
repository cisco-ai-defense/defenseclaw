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
# another lifecycle run kept the lock: nothing was removed, so there is
# nothing to apply, and a second 10-minute wait on the same busy lock would
# only stall apt.
case "${1:-}" in
    abort-remove) exit 0 ;;
    abort-upgrade|abort-install|abort-deconfigure)
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

systemd-sysusers /usr/lib/sysusers.d/defenseclaw.conf >/dev/null 2>&1 || true
systemd-tmpfiles --create /usr/lib/tmpfiles.d/defenseclaw.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true

umask 077
mkdir -p "$state" && chmod 0700 "$state"
# An apply run that started before the trigger was held may hold the lock
# for a whole transaction; wait for it like the apply trigger does. When it
# already applied this package, ensure is a no-op and reports success.
"$gateway" enterprise linux ensure --from-package --reason package --json --lock-wait 10m \
    >"$state/last-package-result.json" 2>"$state/last-package-result.log"
status=$?
if [ "$apply_path_was_active" = 1 ]; then
    if systemctl start "$apply_path" >/dev/null 2>&1; then
        rm -f "$held"
        systemctl stop defenseclaw-enterprise-apply-recovery.timer >/dev/null 2>&1 || true
    fi
fi

# ensure --json writes indented JSON, so join the lines first and allow
# whitespace between the tokens.
result=$(tr '\n' ' ' 2>/dev/null <"$state/last-package-result.json")
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
        echo "defenseclaw-enterprise: installed, but another DefenseClaw lifecycle run held the lock for 10 minutes." >&2
        echo "  Apply this package with: sudo $gateway enterprise linux ensure --from-package" >&2
        ;;
    *)
        # Name the cause (the first error of the JSON result, one line) so
        # the administrator does not have to open the file (GAP-1744).
        cause=$(printf '%s\n' "$result" |
            sed -n 's/.*"errors":[[:space:]]*\[[[:space:]]*{[[:space:]]*"code":[[:space:]]*"\([^"]*\)",[[:space:]]*"message":[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1: \2/p' |
            head -n 1 | unescape)
        # A run that refused the config, or rolled its change back, leaves the
        # previous deployment running; only a first install, or a failed
        # rollback, leaves none (GAP-0176).
        running=$(printf '%s\n' "$result" | sed -n 's/.*"installed_version":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -n "$running" ] && [ -z "$(message_of rollback_failed)" ]; then
            echo "defenseclaw-enterprise: the package is installed but not applied; the previous deployment ($running) keeps running unchanged." >&2
            finish="apply this package with"
        else
            echo "defenseclaw-enterprise: installed, but the lifecycle reported a problem, so no deployment is active." >&2
            finish="finish the install with"
        fi
        if [ -n "$cause" ]; then
            echo "  $cause" >&2
        fi
        echo "  Fix that, then $finish: sudo $gateway enterprise linux ensure --from-package" >&2
        echo "  The full result is in $state/last-package-result.json." >&2
        ;;
esac
exit 0
