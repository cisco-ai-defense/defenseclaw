#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu
source_script=${1:-packaging/linux/preremove.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/systemd"
cat >"$work/gateway" <<'MOCK'
#!/bin/sh
printf '%s\n' '{"ok":false,"errors":[{"code":"uninstall_precheck_refused","message":"hook removal refused"}]}'
exit 1
MOCK
chmod +x "$work/gateway"
sed -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/gateway#g" \
    -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
    -e "s#/run/systemd/system#$work/systemd#g" \
    "$source_script" >"$work/preremove.sh"
if TMPDIR="$work" sh "$work/preremove.sh" remove >"$work/stdout" 2>"$work/stderr"; then
    echo "preremove allowed package removal after the uninstall precheck refused" >&2
    exit 1
fi
grep -q 'uninstall_precheck_refused' "$work/state/last-package-result.json"
grep -q 'hook-removal precheck refused' "$work/stderr"
