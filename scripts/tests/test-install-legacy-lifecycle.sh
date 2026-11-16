#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT
LEGACY_VERSION=0.8.10
with_cosign() { "$@"; }
source "$(dirname "${BASH_SOURCE[0]}")/../lib/install-legacy-lifecycle.sh"

cat >"${ROOT}/install-${LEGACY_VERSION}.sh" <<'INSTALLER'
#!/usr/bin/env bash
count=0
[[ -f "${ROOT}/attempts" ]] && count="$(cat "${ROOT}/attempts")"
count=$((count + 1))
printf '%s\n' "${count}" >"${ROOT}/attempts"
case "${INSTALLER_MODE}" in
    transient) [[ "${count}" -eq 1 ]] || exit 0 ;;
    persistent) ;;
    checksum) echo 'checksum mismatch' >&2; exit 1 ;;
esac
echo 'curl: (22) The requested URL returned error: 500' >&2
exit 22
INSTALLER
export ROOT

INSTALLER_MODE=transient
export INSTALLER_MODE
install_legacy >"${ROOT}/transient.log" 2>&1
[[ "$(cat "${ROOT}/attempts")" -eq 2 ]]

rm "${ROOT}/attempts"
INSTALLER_MODE=checksum
if install_legacy >"${ROOT}/checksum.log" 2>&1; then
    echo 'checksum error unexpectedly passed' >&2
    exit 1
fi
[[ "$(cat "${ROOT}/attempts")" -eq 1 ]]

rm "${ROOT}/attempts"
INSTALLER_MODE=persistent
if install_legacy >"${ROOT}/persistent.log" 2>&1; then
    echo 'persistent release failure unexpectedly passed' >&2
    exit 1
fi
[[ "$(cat "${ROOT}/attempts")" -eq 3 ]]
echo 'legacy install retry: passed'
