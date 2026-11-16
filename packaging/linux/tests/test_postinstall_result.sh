#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/systemd"
cat >"$work/bin/systemctl" <<'MOCK'
#!/bin/sh
[ "$1" != is-active ]
MOCK
cat >"$work/bin/defenseclaw-gateway" <<'MOCK'
#!/bin/sh
cat "$DC_TEST_RESULT"
exit 1
MOCK
for command in systemd-sysusers systemd-tmpfiles sync; do
    printf '#!/bin/sh\nexit 0\n' >"$work/bin/$command"
done
chmod +x "$work/bin/"*
sed -e "s#/run/systemd/system#$work/systemd#g" \
    -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/bin/defenseclaw-gateway#g" \
    -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
    -e "s#/run/defenseclaw-enterprise-apply-path.held#$work/held#g" \
    packaging/linux/postinstall.sh >"$work/postinstall.sh"
# Any lifecycle error is a failed apply, including a legacy namespace error.
cat >"$work/failed.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.4","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"kernel fact unavailable"}],"warnings":[]}
JSON
DC_TEST_RESULT="$work/failed.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
grep -q 'package is installed but not applied' "$work/stderr"
grep -q 'unprivileged_user_namespaces: kernel fact unavailable' "$work/stderr"
if grep -q 'until this host reboots' "$work/stderr"; then
    echo 'postinstall still treats an error as a successful pending reboot' >&2
    exit 1
fi
test -s "$work/state/last-package-result.json"

cat >"$work/rolled-back.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.3","action":"ensure","errors":[{"code":"lifecycle_test_fault","message":"apply failed after starting services"}],"warnings":[{"code":"rolled_back","message":"restored the previous deployment"}]}
JSON
DC_TEST_RESULT="$work/rolled-back.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
grep -q 'package is installed but not applied; the previous deployment (1.0.3) keeps running unchanged' "$work/stderr"
grep -q 'lifecycle_test_fault: apply failed after starting services' "$work/stderr"
