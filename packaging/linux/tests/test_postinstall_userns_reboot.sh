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
cat >"$work/reboot.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.4","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"reboot this host"}],"warnings":[{"code":"security_incomplete","message":"reboot pending"}]}
JSON
DC_TEST_RESULT="$work/reboot.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
if ! grep -q 'until this host reboots' "$work/stderr"; then
    cat "$work/stderr" >&2
    exit 1
fi
if grep -q 'not applied\|no deployment is active' "$work/stderr"; then
    echo 'postinstall claimed an applied deployment was not applied' >&2
    exit 1
fi
test -s "$work/state/last-package-result.json"

cat >"$work/rolled-back.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.3","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"restriction marker missing"},{"code":"lifecycle_test_fault","message":"apply failed after starting services"}],"warnings":[{"code":"rolled_back","message":"restored the previous deployment"}]}
JSON
DC_TEST_RESULT="$work/rolled-back.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
grep -q 'package is installed but not applied; the previous deployment (1.0.3) keeps running unchanged' "$work/stderr"
grep -q 'lifecycle_test_fault: apply failed after starting services' "$work/stderr"
if grep -q 'until this host reboots' "$work/stderr"; then
    echo 'postinstall mislabeled a rolled-back upgrade as reboot-only' >&2
    exit 1
fi

cat >"$work/rolled-back-userns.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.3","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"restriction marker missing"}],"warnings":[{"code":"rolled_back","message":"restored the previous deployment"}]}
JSON
DC_TEST_RESULT="$work/rolled-back-userns.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
if grep -q 'until this host reboots' "$work/stderr"; then
    echo 'postinstall ignored the rollback warning' >&2
    exit 1
fi

cat >"$work/rollback-failed-userns.json" <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.3","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"restriction marker missing"}],"warnings":[{"code":"rollback_failed","message":""}]}
JSON
DC_TEST_RESULT="$work/rollback-failed-userns.json" PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
if grep -q 'until this host reboots' "$work/stderr"; then
    echo 'postinstall ignored a failed rollback' >&2
    exit 1
fi
grep -q 'deployment state could not be confirmed' "$work/stderr"
