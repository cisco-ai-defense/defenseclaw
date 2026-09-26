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

# Build both macOS release artifacts from one app bundle: the zip that the
# release's install.sh unpacks when it updates the app, and a
# drag-to-Applications DMG. The app embeds no runtime; install.sh installs it.
# Artifacts are ad-hoc signed by default. If release-environment Developer ID
# and notary credentials are supplied, this same script imports them into a
# temporary keychain, signs, notarizes, and staples. The asset names are the
# same either way; the verification status (notarized or unverified) is
# printed and, when GITHUB_OUTPUT is set, written as verification_status.

set -euo pipefail

readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"

macos_hardware_machine() {
    local machine="$1"
    if [[ "${machine}" == "x86_64" || "${machine}" == "amd64" ]] \
        && [[ -x "${MACOS_SYSCTL_BIN}" && ! -L "${MACOS_SYSCTL_BIN}" ]] \
        && [[ "$("${MACOS_SYSCTL_BIN}" -in sysctl.proc_translated 2>/dev/null || true)" == "1" ]]; then
        printf '%s\n' "arm64"
        return 0
    fi
    printf '%s\n' "${machine}"
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 VERSION [OUTPUT_DIR]" >&2
    exit 64
fi

VERSION="$1"
OUT_DIR="${2:-dist}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "version must be X.Y.Z (got: ${VERSION})" >&2
    exit 64
}
[[ "$(uname -s)" == "Darwin" ]] || {
    echo "macOS app releases must be built on macOS" >&2
    exit 1
}
[[ "$(macos_hardware_machine "$(uname -m)")" == "arm64" ]] || {
    echo "Intel macOS is unsupported; macOS app releases require Apple Silicon (arm64)" >&2
    exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${ROOT}/macos/DefenseClawMac"
PROJECT="${APP_ROOT}/DefenseClawMac.xcodeproj"
WORK="${RUNNER_TEMP:-${ROOT}/build}/defenseclaw-macos-app-${VERSION}"
DERIVED_DATA="${WORK}/DerivedData"
STAGE="${WORK}/stage"
APP="${STAGE}/DefenseClawMac.app"
KEYCHAIN_PATH=""
KEYCHAIN_PASSWORD=""
NOTARY_KEY_PATH=""
P12_PATH=""
ORIGINAL_KEYCHAINS=()

cleanup() {
    if [[ -n "${KEYCHAIN_PATH}" ]]; then
        if (( ${#ORIGINAL_KEYCHAINS[@]} > 0 )); then
            security list-keychains -d user -s "${ORIGINAL_KEYCHAINS[@]}" >/dev/null 2>&1 || true
        fi
        security delete-keychain "${KEYCHAIN_PATH}" >/dev/null 2>&1 || true
    fi
    [[ -z "${P12_PATH}" ]] || rm -f "${P12_PATH}"
    [[ -z "${NOTARY_KEY_PATH}" ]] || rm -f "${NOTARY_KEY_PATH}"
}
trap cleanup EXIT

for command in xcodebuild xcrun codesign ditto hdiutil python3 shasum spctl; do
    command -v "${command}" >/dev/null || {
        echo "required command not found: ${command}" >&2
        exit 1
    }
done
[[ -d "${PROJECT}" ]] || { echo "Xcode project not found: ${PROJECT}" >&2; exit 1; }

rm -rf "${WORK}"
mkdir -p "${WORK}" "${STAGE}" "${OUT_DIR}"

SIGNING_IDENTITY="-"
VERIFICATION_STATUS="unverified"

APPLE_CREDENTIAL_VALUES=(
    "${MACOS_DEVELOPER_ID_P12_BASE64:-}"
    "${MACOS_DEVELOPER_ID_P12_PASSWORD:-}"
    "${MACOS_NOTARY_KEY_BASE64:-}"
    "${MACOS_NOTARY_KEY_ID:-}"
    "${MACOS_NOTARY_ISSUER_ID:-}"
)
APPLE_CREDENTIAL_COUNT=0
for value in "${APPLE_CREDENTIAL_VALUES[@]}"; do
    [[ -z "${value}" ]] || APPLE_CREDENTIAL_COUNT=$((APPLE_CREDENTIAL_COUNT + 1))
done
if (( APPLE_CREDENTIAL_COUNT != 0 && APPLE_CREDENTIAL_COUNT != ${#APPLE_CREDENTIAL_VALUES[@]} )); then
    echo "Apple signing/notarization credentials are partially configured; provide all required values or none" >&2
    exit 1
fi

if [[ -n "${MACOS_DEVELOPER_ID_P12_BASE64:-}" ]]; then
    command -v openssl >/dev/null || { echo "required command not found: openssl" >&2; exit 1; }
    : "${MACOS_DEVELOPER_ID_P12_PASSWORD:?MACOS_DEVELOPER_ID_P12_PASSWORD is required}"
    while IFS= read -r keychain; do
        keychain="${keychain#"${keychain%%[![:space:]]*}"}"
        keychain="${keychain#\"}"
        keychain="${keychain%\"}"
        [[ -z "${keychain}" ]] || ORIGINAL_KEYCHAINS+=("${keychain}")
    done < <(security list-keychains -d user)
    KEYCHAIN_PATH="${WORK}/release-signing.keychain-db"
    KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
    P12_PATH="${WORK}/developer-id.p12"
    (umask 077; printf '%s' "${MACOS_DEVELOPER_ID_P12_BASE64}" | /usr/bin/base64 -D > "${P12_PATH}")
    chmod 600 "${P12_PATH}"
    security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
    security set-keychain-settings -lut 21600 "${KEYCHAIN_PATH}"
    security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
    security import "${P12_PATH}" -k "${KEYCHAIN_PATH}" \
        -P "${MACOS_DEVELOPER_ID_P12_PASSWORD}" -T /usr/bin/codesign -T /usr/bin/security
    security set-key-partition-list -S apple-tool:,apple:,codesign: \
        -s -k "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}" >/dev/null
    security list-keychains -d user -s "${KEYCHAIN_PATH}" "${ORIGINAL_KEYCHAINS[@]}"
    rm -f "${P12_PATH}"
    P12_PATH=""
    SIGNING_IDENTITY="${MACOS_SIGNING_IDENTITY:-$(security find-identity -v -p codesigning "${KEYCHAIN_PATH}" | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
    [[ -n "${SIGNING_IDENTITY}" ]] || { echo "Developer ID Application identity not found" >&2; exit 1; }
    VERIFICATION_STATUS="signed-unnotarized"
fi

echo "Building DefenseClawMac.app"
xcodebuild \
    -project "${PROJECT}" \
    -scheme DefenseClawMac \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -derivedDataPath "${DERIVED_DATA}" \
    ARCHS=arm64 \
    ONLY_ACTIVE_ARCH=YES \
    MARKETING_VERSION="${VERSION}" \
    CURRENT_PROJECT_VERSION="${GITHUB_RUN_NUMBER:-1}" \
    CODE_SIGNING_ALLOWED=NO \
    build

BUILT_APP="${DERIVED_DATA}/Build/Products/Release/DefenseClawMac.app"
[[ -d "${BUILT_APP}" ]] || { echo "app build not found: ${BUILT_APP}" >&2; exit 1; }
ditto "${BUILT_APP}" "${APP}"
# The staged app is now independent of Xcode's intermediates. Reclaim them
# before the disk image needs working space.
rm -rf "${DERIVED_DATA}"

sign_args=(--force --options runtime --sign "${SIGNING_IDENTITY}")
if [[ "${SIGNING_IDENTITY}" != "-" ]]; then
    sign_args+=(--timestamp)
fi
# The Xcode build phase compiles the on-demand administrator helper ad hoc.
# Sign it with the app's identity first: notarization requires every nested
# executable to carry the Developer ID signature, and the helper and app each
# require their peer to be signed by their own team.
GATEWAY_ADMIN_HELPER="${APP}/Contents/Library/LaunchServices/DefenseClawGatewayHelper"
[[ -f "${GATEWAY_ADMIN_HELPER}" && ! -L "${GATEWAY_ADMIN_HELPER}" ]] || {
    echo "administrator helper missing from the app build: ${GATEWAY_ADMIN_HELPER}" >&2
    exit 1
}
codesign "${sign_args[@]}" --identifier com.cisco.defenseclaw.macos.GatewayAdmin "${GATEWAY_ADMIN_HELPER}"
codesign "${sign_args[@]}" "${APP}"
codesign --verify --deep --strict --verbose=2 "${APP}"

NOTARY_READY=0
if [[ "${SIGNING_IDENTITY}" != "-" && -n "${MACOS_NOTARY_KEY_BASE64:-}" ]]; then
    : "${MACOS_NOTARY_KEY_ID:?MACOS_NOTARY_KEY_ID is required}"
    : "${MACOS_NOTARY_ISSUER_ID:?MACOS_NOTARY_ISSUER_ID is required}"
    NOTARY_KEY_PATH="${WORK}/AuthKey_${MACOS_NOTARY_KEY_ID}.p8"
    (umask 077; printf '%s' "${MACOS_NOTARY_KEY_BASE64}" | /usr/bin/base64 -D > "${NOTARY_KEY_PATH}")
    chmod 600 "${NOTARY_KEY_PATH}"
    NOTARY_READY=1
fi

notarize() {
    local artifact="$1"
    local label="$2"
    local result="${WORK}/notary-${label}.json"
    echo "Submitting ${label} to Apple notary service"
    xcrun notarytool submit "${artifact}" \
        --key "${NOTARY_KEY_PATH}" \
        --key-id "${MACOS_NOTARY_KEY_ID}" \
        --issuer "${MACOS_NOTARY_ISSUER_ID}" \
        --wait --output-format json > "${result}"
    python3 - "${result}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
if result.get("status") != "Accepted":
    raise SystemExit(f"notarization failed: {result}")
PY
}

# Staple the app itself: the zip cannot carry a ticket, and install.sh
# unpacks the app from it.
if [[ "${NOTARY_READY}" == "1" ]]; then
    APP_NOTARY_ZIP="${WORK}/DefenseClawMac-${VERSION}-app-notary.zip"
    ditto -c -k --keepParent "${APP}" "${APP_NOTARY_ZIP}"
    notarize "${APP_NOTARY_ZIP}" "app"
    xcrun stapler staple "${APP}"
    xcrun stapler validate "${APP}"
fi

echo "Creating drag-to-Applications DMG"
[[ ! -e "${STAGE}/Applications" && ! -L "${STAGE}/Applications" ]] || {
    echo "DMG staging link already exists" >&2
    exit 1
}
ln -s /Applications "${STAGE}/Applications"
TEMP_DMG="${WORK}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
# hdiutil's automatic -srcfolder sizing can leave too little filesystem
# headroom for the final copy. Size the image from the staged bytes with 20%
# growth room plus 64 MiB for filesystem metadata and copy variance.
DMG_SOURCE_KIB="$(du -sk "${STAGE}" | awk '{print $1}')"
[[ "${DMG_SOURCE_KIB}" =~ ^[0-9]+$ ]] || {
    echo "could not determine DMG staging size" >&2
    exit 1
}
DMG_SIZE_KIB=$((DMG_SOURCE_KIB + DMG_SOURCE_KIB / 5 + 65536))
echo "DMG source: ${DMG_SOURCE_KIB} KiB; capacity: ${DMG_SIZE_KIB} KiB"
hdiutil create \
    -volname DefenseClawMac \
    -srcfolder "${STAGE}" \
    -size "${DMG_SIZE_KIB}k" \
    -ov -format UDZO \
    "${TEMP_DMG}"

dmg_sign_args=(--force --sign "${SIGNING_IDENTITY}")
if [[ "${SIGNING_IDENTITY}" != "-" ]]; then
    dmg_sign_args+=(--timestamp)
fi
codesign "${dmg_sign_args[@]}" "${TEMP_DMG}"
codesign --verify --verbose=2 "${TEMP_DMG}"

if [[ "${NOTARY_READY}" == "1" ]]; then
    notarize "${TEMP_DMG}" "dmg"
    xcrun stapler staple "${TEMP_DMG}"
    xcrun stapler validate "${TEMP_DMG}"
    spctl -a -t open --context context:primary-signature -vv "${TEMP_DMG}"
    VERIFICATION_STATUS="notarized"
fi

if (( APPLE_CREDENTIAL_COUNT == ${#APPLE_CREDENTIAL_VALUES[@]} )) \
    && [[ "${VERIFICATION_STATUS}" != "notarized" ]]; then
    echo "complete Apple credentials were configured, but signing and notarization did not complete" >&2
    exit 1
fi
if (( APPLE_CREDENTIAL_COUNT == 0 )) \
    && [[ "${VERIFICATION_STATUS}" != "unverified" ]]; then
    echo "credential-free macOS builds must remain explicitly unverified" >&2
    exit 1
fi
if [[ "${MACOS_REQUIRE_NOTARIZATION:-false}" == "true" && "${VERIFICATION_STATUS}" != "notarized" ]]; then
    echo "MACOS_REQUIRE_NOTARIZATION=true but the app was not notarized" >&2
    exit 1
fi

ZIP_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.zip"
DMG_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
rm -f "${ZIP_ARTIFACT}" "${DMG_ARTIFACT}"
# --keepParent puts DefenseClawMac.app at the archive root for `ditto -xk`.
ditto -c -k --keepParent "${APP}" "${ZIP_ARTIFACT}"
cp "${TEMP_DMG}" "${DMG_ARTIFACT}"
shasum -a 256 "${DMG_ARTIFACT}" "${ZIP_ARTIFACT}"
"${ROOT}/scripts/verify-macos-app-release.sh" "${VERSION}" "${OUT_DIR}" "${VERIFICATION_STATUS}"
echo "macOS app verification status: ${VERIFICATION_STATUS}"
echo "DMG artifact: ${DMG_ARTIFACT}"
echo "app zip artifact: ${ZIP_ARTIFACT}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        printf 'artifact=%s\n' "${DMG_ARTIFACT}"
        printf 'dmg=%s\n' "${DMG_ARTIFACT}"
        printf 'zip=%s\n' "${ZIP_ARTIFACT}"
        printf 'verification_status=%s\n' "${VERIFICATION_STATUS}"
    } >> "${GITHUB_OUTPUT}"
fi
