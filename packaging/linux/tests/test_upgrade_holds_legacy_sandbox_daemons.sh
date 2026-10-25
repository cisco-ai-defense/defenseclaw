#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# GAP-0868: a sandbox daemon of DefenseClaw before 1.0.4 stops its account's
# OpenShell gateway once the package replaced its program, also under a
# failed MicroVM that still runs. The preinstall holds it (SIGSTOP) before
# any file is replaced, and the postinstall ends it with SIGKILL before its
# ensure; an upgrade from 1.0.4 holds nothing, and an aborted upgrade lets
# the held daemon go on.
set -eu
work=$(mktemp -d)
daemon=""
cleanup() {
    [ -z "$daemon" ] || kill -KILL "$daemon" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/systemd" "$work/state"
export TEST_WORK="$work"
cat >"$work/bin/systemctl" <<'MOCK'
#!/bin/sh
printf '%s %s\n' "$1" "${2:-}" >>"$TEST_WORK/systemctl.log"
[ "$1" != is-active ]
MOCK
cat >"$work/bin/systemd-run" <<'MOCK'
#!/bin/sh
for argument do command=$argument; done
printf '%s\n' "$command" >"$TEST_WORK/recovery.sh"
MOCK
cat >"$work/bin/defenseclaw-gateway" <<'MOCK'
#!/bin/sh
printf '{"ok":true,"installed":true,"action":"ensure","errors":[],"warnings":[]}\n'
MOCK
for command in systemd-sysusers systemd-tmpfiles sync; do
    printf '#!/bin/sh\nexit 0\n' >"$work/bin/$command"
done
chmod +x "$work/bin/"*
# The stand-in daemon: its command line is what the scripts look for.
cp "$(command -v sleep)" "$work/sandbox-daemon"
fake_cmd="$work/sandbox-daemon 3000"
# The record check is root_owned in the package; here the file is the test's.
# shellcheck disable=SC2016
scripts() {
    sed -e "s#/run/systemd/system#$work/systemd#g" \
        -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
        -e "s#/run/defenseclaw-enterprise-apply-path.held#$work/held#g" \
        -e "s#/run/defenseclaw-sandbox-daemons.held#$work/sandbox.held#g" \
        -e "s#^sandbox_daemon_cmd=.*#sandbox_daemon_cmd=\"$fake_cmd\"#" \
        -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/bin/defenseclaw-gateway#g" \
        -e 's#root_owned "$record" || return 1#[ -f "$record" ] || return 1#' \
        packaging/linux/preinstall.sh >"$work/preinstall.sh"
    sed -e "s#/run/systemd/system#$work/systemd#g" \
        -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
        -e "s#/run/defenseclaw-enterprise-apply-path.held#$work/held#g" \
        -e "s#/run/defenseclaw-sandbox-daemons.held#$work/sandbox.held#g" \
        -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/bin/defenseclaw-gateway#g" \
        packaging/linux/postinstall.sh >"$work/postinstall.sh"
}
state_of() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1; }
deployed() { printf '{"product_version": "%s"}\n' "$1" >"$work/state/deployment.json"; }
start_daemon() {
    "$work/sandbox-daemon" 3000 &
    daemon=$!
    i=0
    while [ "$(tr '\0' ' ' <"/proc/$daemon/cmdline" 2>/dev/null)" != "$fake_cmd " ] && [ "$i" -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
}
scripts

# From 1.0.3: held before the file swap, killed before the ensure.
deployed 1.0.3
start_daemon
PATH="$work/bin:$PATH" sh "$work/preinstall.sh" upgrade
test "$(state_of "$daemon")" = T || { echo "the 1.0.3 sandbox daemon was not held: $(state_of "$daemon")" >&2; exit 1; }
grep -q "^$daemon " "$work/sandbox.held"
test -s "$work/recovery.sh"
PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >/dev/null 2>&1
wait "$daemon" 2>/dev/null || true
if [ -e "/proc/$daemon" ] && [ "$(state_of "$daemon")" != Z ]; then
    echo "the held sandbox daemon survived the postinstall" >&2
    exit 1
fi
daemon=""
test ! -e "$work/sandbox.held"

# An aborted upgrade lets the held daemon go on.
start_daemon
PATH="$work/bin:$PATH" sh "$work/preinstall.sh" upgrade
test "$(state_of "$daemon")" = T
PATH="$work/bin:$PATH" sh "$work/postinstall.sh" abort-upgrade
sleep 0.2
test "$(state_of "$daemon")" = S || { echo "the aborted upgrade left the daemon $(state_of "$daemon")" >&2; exit 1; }
test ! -e "$work/sandbox.held"

# The recovery after a failed unpack does the same.
PATH="$work/bin:$PATH" sh "$work/preinstall.sh" upgrade
test "$(state_of "$daemon")" = T
sh "$work/recovery.sh"
sleep 0.2
test "$(state_of "$daemon")" = S
test ! -e "$work/sandbox.held"

# From 1.0.4 the daemon counts those MicroVMs: nothing is held.
deployed 1.0.4
PATH="$work/bin:$PATH" sh "$work/preinstall.sh" upgrade
test "$(state_of "$daemon")" = S
test ! -e "$work/sandbox.held"
echo "ok"
