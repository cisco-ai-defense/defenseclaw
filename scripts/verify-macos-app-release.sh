#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Verify the macOS release artifacts from build-macos-app-release.sh. STATUS is
# the verification status the build reported; when omitted it is read from the
# app signature. Notarized artifacts must carry the Developer ID Team ID,
# stapled tickets, and pass Gatekeeper.

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 VERSION OUTPUT_DIR [notarized|unverified]" >&2
    exit 64
fi

VERSION="$1"
OUT_DIR="$2"
EXPECTED_STATUS="${3:-}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "version must be X.Y.Z (got: ${VERSION})" >&2
    exit 64
}
case "${EXPECTED_STATUS}" in
    ""|notarized|unverified) ;;
    *)
        echo "status must be notarized or unverified (got: ${EXPECTED_STATUS})" >&2
        exit 64
        ;;
esac
[[ "$(uname -s)" == "Darwin" ]] || {
    echo "macOS release artifacts must be verified on macOS" >&2
    exit 1
}

for command in codesign ditto hdiutil spctl xcrun; do
    command -v "${command}" >/dev/null || {
        echo "required command not found: ${command}" >&2
        exit 1
    }
done

DMG="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
ZIP="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.zip"
[[ -f "${DMG}" ]] || { echo "DMG not found: ${DMG}" >&2; exit 1; }
[[ -f "${ZIP}" ]] || { echo "ZIP not found: ${ZIP}" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-macos-verify.XXXXXX")"
MOUNT="${WORK}/mounted"
UNZIP="${WORK}/zip"
MOUNTED=0
cleanup() {
    if [[ "${MOUNTED}" == "1" ]]; then
        hdiutil detach "${MOUNT}" -quiet >/dev/null 2>&1 || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT
mkdir -p "${MOUNT}" "${UNZIP}"

hdiutil attach "${DMG}" -readonly -nobrowse -mountpoint "${MOUNT}" -quiet
MOUNTED=1

DMG_APP="${MOUNT}/DefenseClawMac.app"
[[ -d "${DMG_APP}" ]] || { echo "DMG does not contain DefenseClawMac.app" >&2; exit 1; }
[[ -L "${MOUNT}/Applications" && "$(readlink "${MOUNT}/Applications")" == "/Applications" ]] || {
    echo "DMG Applications link is missing or incorrect" >&2
    exit 1
}

# install.sh unpacks the ZIP with `ditto -xk` and expects the app at its root.
ditto -x -k "${ZIP}" "${UNZIP}"
ZIP_APP="${UNZIP}/DefenseClawMac.app"
[[ "$(ls -A "${UNZIP}")" == "DefenseClawMac.app" && -d "${ZIP_APP}" ]] || {
    echo "ZIP must contain only DefenseClawMac.app at its root" >&2
    exit 1
}

for app in "${DMG_APP}" "${ZIP_APP}"; do
    info="${app}/Contents/Info.plist"
    bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${info}")"
    bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${info}")"
    [[ "${bundle_id}" == "com.cisco.defenseclaw.macos" ]] || { echo "unexpected bundle ID: ${bundle_id}" >&2; exit 1; }
    [[ "${bundle_version}" == "${VERSION}" ]] || { echo "unexpected app version: ${bundle_version}" >&2; exit 1; }
    [[ ! -e "${app}/Contents/Resources/RuntimePayload" ]] || {
        echo "the app must not embed a runtime payload; install.sh installs the runtime" >&2
        exit 1
    }
    codesign --verify --deep --strict --verbose=2 "${app}"
done

DMG_SIGNATURE="$(codesign -d --verbose=4 "${DMG_APP}" 2>&1)"
ZIP_SIGNATURE="$(codesign -d --verbose=4 "${ZIP_APP}" 2>&1)"
[[ "$(sed -n 's/^CDHash=//p' <<<"${DMG_SIGNATURE}")" == "$(sed -n 's/^CDHash=//p' <<<"${ZIP_SIGNATURE}")" ]] || {
    echo "DMG and ZIP contain different app builds" >&2
    exit 1
}
SIGNED_STATUS="notarized"
if grep -qx 'Signature=adhoc' <<<"${DMG_SIGNATURE}"; then
    SIGNED_STATUS="unverified"
fi
[[ -z "${EXPECTED_STATUS}" || "${EXPECTED_STATUS}" == "${SIGNED_STATUS}" ]] || {
    echo "expected ${EXPECTED_STATUS} artifacts, but the app signature is ${SIGNED_STATUS}" >&2
    exit 1
}

if [[ "${SIGNED_STATUS}" == "notarized" ]]; then
    EXPECTED_TEAM_ID="$(sed -n 's/^TeamIdentifier=//p' <<<"${DMG_SIGNATURE}")"
    [[ "${EXPECTED_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]] || {
        echo "verified macOS app has no valid 10-character Team ID" >&2
        exit 1
    }
    APP_REQUIREMENT="=identifier \"com.cisco.defenseclaw.macos\" and anchor apple generic and certificate leaf[subject.OU] = \"${EXPECTED_TEAM_ID}\""
    for app in "${DMG_APP}" "${ZIP_APP}"; do
        codesign --verify --strict -R "${APP_REQUIREMENT}" --verbose=2 "${app}"
        xcrun stapler validate "${app}"
        spctl --assess --type execute --verbose=2 "${app}"
    done
    xcrun stapler validate "${DMG}"
    spctl --assess --type open --context context:primary-signature --verbose=2 "${DMG}"
fi

echo "macOS release artifacts verified (${SIGNED_STATUS}):"
echo "  DMG: ${DMG}"
echo "  ZIP: ${ZIP}"
