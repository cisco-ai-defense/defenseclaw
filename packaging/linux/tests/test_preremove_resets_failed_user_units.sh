#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# GAP-0137: after `enterprise linux uninstall --purge`, an account's sandbox
# daemon that restarted without the deployment exits 78 (or its ExecStop is
# refused), so its user unit is failed when the package goes. The prerm's
# stop_user_units stops the units and then resets their failed state, so they
# end inactive. This runs the script's own functions against a fake user
# service manager.
set -eu
source_script=${1:-packaging/linux/preremove.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
uid=$(id -u)
mkdir -p "$work/run/$uid/systemd"
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$work/run/$uid/systemd/private"
# The functions only: everything from user_systemctl() up to the case that runs them.
sed -n '/^user_systemctl() {/,/^recorded_policies() {/p' "$source_script" | sed '$d' >"$work/functions.sh"
cat >"$work/run.sh" <<EOS
user_runtime=$work/run
user_units="defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service"
. $work/functions.sh
# The fake manager: every unit stopped, the daemon failed (exit 78).
user_systemctl() {
    shift 4
    echo "\$*" >>$work/calls
    case "\$1" in
        is-active) printf 'inactive\nfailed\ninactive\n'; return 3 ;;
    esac
    return 0
}
systemctl() { return 0; }
stop_user_units
EOS
sh "$work/run.sh"
grep -q '^stop defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service$' "$work/calls" || { echo "no stop: $(cat "$work/calls")"; exit 1; }
grep -q '^reset-failed defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service$' "$work/calls" || { echo "failed units are not reset: $(cat "$work/calls")"; exit 1; }
echo "ok: stop_user_units stops and resets the failed user units"
