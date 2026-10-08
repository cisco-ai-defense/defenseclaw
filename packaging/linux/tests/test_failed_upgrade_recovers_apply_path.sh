#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/systemd"
export TEST_WORK="$work"
cat >"$work/bin/systemctl" <<'MOCK'
#!/bin/sh
printf '%s %s\n' "$1" "${2:-}" >>"$TEST_WORK/systemctl.log"
[ "$1" != is-active ] || exit 0
MOCK
cat >"$work/bin/systemd-run" <<'MOCK'
#!/bin/sh
for argument do command=$argument; done
printf '%s\n' "$command" >"$TEST_WORK/recovery.sh"
MOCK
chmod +x "$work/bin/systemctl" "$work/bin/systemd-run"
sed "s#/run/systemd/system#$work/systemd#g; s#/run/defenseclaw-enterprise-apply-path.held#$work/held#g" \
    packaging/linux/preinstall.sh >"$work/preinstall.sh"
PATH="$work/bin:$PATH" sh "$work/preinstall.sh" upgrade
test -e "$work/held"
test -s "$work/recovery.sh"
grep -q '^stop defenseclaw-enterprise-apply.path$' "$work/systemctl.log"
# Simulate a failed unpack: postinstall never ran. The scheduled recovery
# must put the trigger back and consume only its own hold marker.
PATH="$work/bin:$PATH" sh "$work/recovery.sh"
grep -q '^start defenseclaw-enterprise-apply.path$' "$work/systemctl.log"
test ! -e "$work/held"
