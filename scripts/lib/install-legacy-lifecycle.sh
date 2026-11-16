#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# install_legacy installs LEGACY_VERSION with its own installer. Releases
# before 0.8.5 published it only in the source tree. The caller provides
# ROOT and with_cosign.
install_legacy() {
    local installer="${ROOT}/install-${LEGACY_VERSION}.sh"
    [[ -f "${installer}" ]] || curl -fsSL -o "${installer}" \
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/${LEGACY_VERSION}/install.sh" \
        || curl -fsSL -o "${installer}" \
        "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${LEGACY_VERSION}/scripts/install.sh"
    # The 0.8.4 installer refuses to run without cosign on PATH. Retry only
    # an upstream HTTP 5xx response while fetching release assets; a failed
    # checksum or an installer error must still fail this lane immediately.
    local output attempt rc
    output="$(mktemp "${ROOT}/legacy-install.XXXXXX")" || return 1
    for attempt in 1 2 3; do
        if VERSION="${LEGACY_VERSION}" with_cosign bash "${installer}" --yes --no-openclaw >"${output}" 2>&1; then
            cat "${output}"
            rm -f "${output}"
            return 0
        else
            rc=$?
        fi
        cat "${output}"
        if ! grep -Eq 'curl: \(22\).*error: 5[0-9][0-9]' "${output}" || [[ "${attempt}" -eq 3 ]]; then
            rm -f "${output}"
            return "${rc}"
        fi
        echo "[lifecycle] legacy release service returned 5xx; retrying install (${attempt}/2)" >&2
    done
}
