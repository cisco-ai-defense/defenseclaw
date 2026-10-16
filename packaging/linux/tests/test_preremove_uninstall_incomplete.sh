#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# GAP-1519: an uninstall that stopped before removing the binaries
# (uninstall_incomplete) keeps the package files; any other uninstall
# failure (uninstall_failed) lets the removal go on.
set -eu
source_script=${1:-packaging/linux/preremove.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/systemd"
run() {
    printf '#!/bin/sh\nprintf "%%s\\n" %s\nexit 1\n' "'$1'" >"$work/gateway"
    chmod +x "$work/gateway"
    rm -rf "$work/state"
    sed -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/gateway#g" \
        -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
        -e "s#/run/systemd/system#$work/systemd#g" \
        "$source_script" >"$work/preremove.sh"
    TMPDIR="$work" sh "$work/preremove.sh" remove >"$work/stdout" 2>"$work/stderr"
}
if run '{"ok":false,"errors":[{"code":"uninstall_failed","message":"policy"},{"code":"uninstall_incomplete","message":"stopped before removing the DefenseClaw binaries"}]}'; then
    echo "preremove allowed package removal after the uninstall kept the binaries" >&2
    exit 1
fi
grep -q 'uninstall_incomplete' "$work/state/last-package-result.json"
grep -q 'package files were kept' "$work/stderr"
if ! run '{"ok":false,"errors":[{"code":"uninstall_failed","message":"not uninstall_incomplete"}]}'; then
    echo "preremove refused package removal after an ordinary uninstall failure" >&2
    exit 1
fi
grep -q 'uninstall reported a problem' "$work/stderr"
