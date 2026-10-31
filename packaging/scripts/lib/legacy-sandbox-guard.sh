# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# The legacy sandbox guard of the defenseclaw-enterprise package (POSIX sh).
# scripts/stamp-package-script.sh puts it in place of the marker line of the
# Linux preinstall and of the macOS pkg preinstall, which run it as root
# before the package replaces any file.
#
# A sandbox daemon of DefenseClaw 1.0.3 or older notices that a package
# replaced its program and then, as soon as none of its user's sandboxes is
# provisioning, starting or ready, stops the user's OpenShell gateway and
# exits. It does not count a MicroVM whose workload completed or failed,
# which keeps running until it is deleted, so that stop ends the VM with what
# it has not written to its disk (GAP-0903). DefenseClaw stops no sandbox
# itself, so the package refuses instead, before it changes anything, while
# such a daemon has a sandbox that may hold compute: the refusal names each
# one, with the command its user runs to end it. A daemon it cannot ask
# refuses the package too: what it cannot see may be running. An older
# daemon with nothing running is ended first (SIGKILL, so its exit runs
# nothing, and on Linux its units are stopped so systemd does not start it
# again), so no older sandbox code runs while the files change. A daemon of
# DefenseClaw 1.0.4 or later (its status reports "live") counts every
# sandbox that holds compute itself and is left alone.

# dc_guard_json MODE reads a sandbox daemon's JSON answer on stdin. MODE
# status prints "live" when the top-level object has that key (DefenseClaw
# 1.0.4 or later). MODE list prints "list" once it has read the "sandboxes"
# array of `sandbox list --output json`, and one line per sandbox in it:
# "sandbox", its name, phase, compute driver and phase reason, separated by
# "|" (the reason last: it may hold one). Nested objects are skipped,
# whatever keys they hold.
dc_guard_json() {
    awk -v mode="$1" '
        function item() { return depth == 3 && kind[1] == "{" && kind[2] == "[" && kind[3] == "{" && under[2] == "sandboxes" }
        { text = text $0 "\n" }
        END {
            n = length(text); depth = 0; ins = 0; esc = 0; pend = 0; key = ""; s = ""
            for (i = 1; i <= n; i++) {
                c = substr(text, i, 1)
                if (ins) {
                    if (esc) { esc = 0; s = s c; continue }
                    if (c == "\\") { esc = 1; continue }
                    if (c == "\"") { ins = 0; pend = 1; continue }
                    s = s c
                    continue
                }
                if (c == " " || c == "\t" || c == "\n" || c == "\r") continue
                if (pend) {
                    pend = 0
                    if (c == ":") {
                        key = s
                        if (depth == 1 && mode == "status" && key == "live") live = 1
                        continue
                    }
                    if (item() && key != "") f[key] = s
                    key = ""
                }
                if (c == "\"") { ins = 1; s = ""; continue }
                if (c == "{" || c == "[") {
                    depth++; kind[depth] = c; under[depth] = key; key = ""
                    if (mode == "list" && depth == 2 && kind[1] == "{" && c == "[" && under[2] == "sandboxes") listed = 1
                    if (item()) split("", f)
                    continue
                }
                if (c == "}" || c == "]") {
                    if (item() && mode == "list") printf "sandbox|%s|%s|%s|%s\n", f["name"], f["phase"], f["driver"], f["phase_reason"]
                    depth--; key = ""
                    continue
                }
                if (c == ",") key = ""
            }
            if (mode == "status" && live) print "live"
            if (mode == "list" && listed) print "list"
        }'
}

# dc_guard_as UID NAME HOME COMMAND... runs COMMAND as the account, with its
# home and (Linux) its user manager, with no input, and ends it after 30
# seconds. Its output is on stdout.
dc_guard_as() {
    dc_as_uid=$1 dc_as_name=$2 dc_as_home=$3
    shift 3
    if [ "$dc_guard_os" = darwin ]; then
        set -- sudo -n -u "#$dc_as_uid" -H /usr/bin/env HOME="$dc_as_home" "$@"
    else
        set -- runuser -u "$dc_as_name" -- /usr/bin/env HOME="$dc_as_home" XDG_RUNTIME_DIR="/run/user/$dc_as_uid" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$dc_as_uid/bus" "$@"
    fi
    "$@" </dev/null 2>/dev/null &
    dc_as_pid=$!
    # runuser and sudo wait for the command (env, which becomes the
    # launcher): end both.
    (sleep 30 && pkill -KILL -P "$dc_as_pid"; kill -KILL "$dc_as_pid") >/dev/null 2>&1 </dev/null &
    dc_as_watch=$!
    wait "$dc_as_pid"
    dc_as_rc=$?
    kill "$dc_as_watch" >/dev/null 2>&1
    return "$dc_as_rc"
}

# dc_guard_account UID sets dc_acct_name and dc_acct_home for the account.
dc_guard_account() {
    dc_acct_name= dc_acct_home=
    if [ "$dc_guard_os" = darwin ]; then
        dc_acct_name=$(id -nu "$1" 2>/dev/null)
        dc_acct_home=$(dscacheutil -q user -a uid "$1" 2>/dev/null | sed -n 's/^dir: *//p' | head -n 1)
    else
        dc_acct_line=$(getent passwd "$1" 2>/dev/null | head -n 1)
        dc_acct_name=$(printf '%s\n' "$dc_acct_line" | cut -d: -f1)
        dc_acct_home=$(printf '%s\n' "$dc_acct_line" | cut -d: -f6)
    fi
    [ -n "$dc_acct_name" ] && [ -n "$dc_acct_home" ]
}

# dc_guard_holds PHASE DRIVER REASON reports a sandbox that may hold compute
# (manager.HoldsCompute): every phase but stopped, deleting, deleted and
# missing, except a docker sandbox whose workload ended and a MicroVM in
# OpenShell's error state whose VM exited (ProcessExited). A record without
# a driver is a docker one, as for the daemon.
dc_guard_holds() {
    case "$1" in
        stopped | deleting | deleted | missing) return 1 ;;
        completed) [ "${2:-docker}" != docker ] ;;
        error)
            [ "${2:-docker}" != docker ] || return 1
            case "$3" in ProcessExited*) return 1 ;; esac
            return 0
            ;;
        *) return 0 ;;
    esac
}

# dc_legacy_sandbox_guard OS GATEWAY LAUNCHER returns 0 when the package may
# replace the files (no sandbox daemon of an earlier DefenseClaw has a
# sandbox that may hold compute; any such daemon with nothing running was
# ended), and 1 when it must not: dc_guard_message is then the refusal for
# stderr, one line per sandbox, and dc_guard_reason the same on one line,
# for a result document. OS is linux or darwin, GATEWAY the installed
# defenseclaw-gateway the daemons run, and LAUNCHER the installed
# `defenseclaw` launcher.
dc_legacy_sandbox_guard() {
    dc_guard_os=$1 dc_guard_gateway=$2 dc_guard_launcher=$3
    dc_guard_reason= dc_guard_message=
    dc_nl='
'
    # The daemon runs GATEWAY, or on macOS the package's content-addressed
    # copy of it that the LaunchAgent executes (DefenseClaw 1.0.3:
    # bin/launch-agents/<sha256>/defenseclaw-gateway beside GATEWAY).
    dc_daemons=$(ps -A -o uid= -o pid= -o args= 2>/dev/null | awk -v gw="$dc_guard_gateway" '
        BEGIN {
            base = gw; sub(/.*\//, "", base)
            pre = substr(gw, 1, length(gw) - length(base)) "launch-agents/"
            suf = "/" base " sandbox-daemon"
        }
        {
            uid = $1; pid = $2; $1 = ""; $2 = ""; sub(/^ +/, "")
            if ($0 == gw " sandbox-daemon") { print uid, pid; next }
            mid = substr($0, length(pre) + 1, length($0) - length(pre) - length(suf))
            if (index($0, pre) == 1 && substr($0, length($0) - length(suf) + 1) == suf && mid ~ /^[0-9a-f]+$/) print uid, pid
        }')
    [ -n "$dc_daemons" ] || return 0
    dc_held= dc_quiet=
    while read -r dc_uid dc_pid; do
        [ -n "$dc_uid" ] || continue
        if ! dc_guard_account "$dc_uid"; then
            dc_held="$dc_held$dc_nl  uid $dc_uid: its account could not be read, so its sandbox daemon could not be asked which sandboxes run"
            continue
        fi
        dc_who=$dc_acct_name
        # After an uninstall that kept the package (enterprise uninstall
        # without purge) the launcher is gone: the installed gateway, which
        # the launcher runs, asks the daemon instead (GAP-0181).
        dc_ask=$dc_guard_launcher
        [ -x "$dc_ask" ] || dc_ask=$dc_guard_gateway
        if ! dc_status=$(dc_guard_as "$dc_uid" "$dc_who" "$dc_acct_home" "$dc_ask" sandbox status --output json); then
            if [ "$dc_guard_os" = darwin ]; then
                dc_held="$dc_held$dc_nl  $dc_who: the sandbox daemon did not answer; \`defenseclaw sandbox list\`, run as $dc_who, names the sandboxes that run"
            else
                # A way out that needs no DefenseClaw command: the daemon's own
                # units, which an uninstall that kept the package can leave
                # running with nothing to answer for (GAP-0181).
                dc_held="$dc_held$dc_nl  $dc_who: the sandbox daemon did not answer (pid $dc_pid); \`defenseclaw sandbox list\`, run as $dc_who, names the sandboxes that run; if that command is not there or does not answer either, run as $dc_who \`systemctl --user stop defenseclaw-sandbox.socket defenseclaw-sandbox.service\` (it stops that user's sandboxes first, if any run), or sign $dc_who out"
            fi
            continue
        fi
        if printf '%s\n' "$dc_status" | dc_guard_json status | grep -qx live; then
            continue # DefenseClaw 1.0.4 or later: it waits for its sandboxes itself
        fi
        if ! dc_list=$(dc_guard_as "$dc_uid" "$dc_who" "$dc_acct_home" "$dc_ask" sandbox list --output json) ||
            ! dc_rows=$(printf '%s\n' "$dc_list" | dc_guard_json list) ||
            ! printf '%s\n' "$dc_rows" | grep -qx list; then
            dc_held="$dc_held$dc_nl  $dc_who: the sandbox daemon of an earlier DefenseClaw did not list its sandboxes; \`defenseclaw sandbox list\`, run as $dc_who, names the sandboxes that run"
            continue
        fi
        dc_account_held=
        while IFS='|' read -r dc_tag dc_name dc_phase dc_driver dc_why; do
            [ "$dc_tag" = sandbox ] || continue
            dc_guard_holds "$dc_phase" "$dc_driver" "$dc_why" || continue
            dc_account_held=1
            case "$dc_phase" in
                completed | error)
                    dc_held="$dc_held$dc_nl  $dc_who: $dc_name ($dc_phase MicroVM, which OpenShell does not stop): \`defenseclaw sandbox delete $dc_name\` (it deletes the sandbox with its work)"
                    ;;
                *)
                    dc_held="$dc_held$dc_nl  $dc_who: $dc_name (${dc_phase:-unknown}): save the work you need, then \`defenseclaw sandbox stop $dc_name\`"
                    ;;
            esac
        done <<EOF
$dc_rows
EOF
        [ -n "$dc_account_held" ] || dc_quiet="$dc_quiet$dc_uid:$dc_pid:$dc_who:$dc_acct_home$dc_nl"
    done <<EOF
$dc_daemons
EOF
    if [ -n "$dc_held" ]; then
        dc_guard_reason="nothing was changed: sandboxes run under the sandbox daemon of an earlier DefenseClaw, which stops their OpenShell gateway once this package replaces its program, and that ends a MicroVM with what it has not written to its disk. DefenseClaw stops no sandbox for you: each user ends these, as that user, then install this package again:$(printf '%s' "$dc_held" | tr '\n' ';')"
        dc_guard_message="defenseclaw-enterprise: this install was refused, and nothing was changed: sandboxes run under the sandbox daemon of an earlier DefenseClaw, which stops their OpenShell gateway once this package replaces its program, and that ends a MicroVM with what it has not written to its disk. DefenseClaw stops no sandbox for you. Each user ends these, as that user, then install this package again:$dc_held"
        return 1
    fi
    # Nothing runs: end each earlier daemon before its program changes.
    while IFS=: read -r dc_q_uid dc_q_pid dc_q_name dc_q_home; do
        [ -n "$dc_q_pid" ] || continue
        kill -KILL "$dc_q_pid" 2>/dev/null
        if [ "$dc_guard_os" != darwin ]; then
            dc_guard_as "$dc_q_uid" "$dc_q_name" "$dc_q_home" systemctl --user stop defenseclaw-sandbox.socket defenseclaw-sandbox.service >/dev/null
        fi
    done <<EOF
$dc_quiet
EOF
    return 0
}
