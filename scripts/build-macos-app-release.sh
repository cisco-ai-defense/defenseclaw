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

# Build both macOS release artifacts: an app-only zip for self-updates and a
# drag-to-Applications DMG whose app embeds the matching DefenseClaw gateway
# and wheel in Contents/Resources/RuntimePayload. Artifacts are ad-hoc signed
# and explicitly named "unverified" by default. If release-environment
# Developer ID and notary credentials are supplied, this same script imports
# them into a temporary keychain, signs, notarizes, staples, and emits verified
# artifact names.

set -euo pipefail

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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${ROOT}/macos/DefenseClawMac"
PROJECT="${APP_ROOT}/DefenseClawMac.xcodeproj"
WORK="${RUNNER_TEMP:-${ROOT}/build}/defenseclaw-macos-app-${VERSION}"
DERIVED_DATA="${WORK}/DerivedData"
PLAIN_STAGE="${WORK}/app-only"
PLAIN_APP="${PLAIN_STAGE}/DefenseClawMac.app"
UNIFIED_STAGE="${WORK}/unified"
APP="${UNIFIED_STAGE}/DefenseClawMac.app"
PAYLOAD="${APP}/Contents/Resources/RuntimePayload"
DMG_STAGE="${WORK}/dmg-stage"
WHEEL="${ROOT}/dist/defenseclaw-${VERSION}-py3-none-any.whl"
GATEWAY="${WORK}/defenseclaw-gateway"
OVERRIDES="${WORK}/overrides.txt"
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

for command in xcodebuild xcrun codesign ditto file go hdiutil python3 shasum spctl; do
    command -v "${command}" >/dev/null || {
        echo "required command not found: ${command}" >&2
        exit 1
    }
done
[[ -d "${PROJECT}" ]] || { echo "Xcode project not found: ${PROJECT}" >&2; exit 1; }
[[ -f "${WHEEL}" ]] || {
    echo "matching wheel not found: ${WHEEL}" >&2
    echo "run scripts/stamp-version.sh ${VERSION} && make dist-cli first" >&2
    exit 1
}

rm -rf "${WORK}"
mkdir -p "${WORK}" "${PLAIN_STAGE}" "${UNIFIED_STAGE}" "${OUT_DIR}"

SIGNING_IDENTITY="-"
VERIFICATION_STATUS="adhoc"

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
    printf '%s' "${MACOS_DEVELOPER_ID_P12_BASE64}" | /usr/bin/base64 -D > "${P12_PATH}"
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

echo "Building DefenseClaw gateway ${VERSION} (darwin/arm64)"
COMMIT="$(git -C "${ROOT}" rev-parse --short=12 HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
(
    cd "${ROOT}"
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
        -o "${GATEWAY}" ./cmd/defenseclaw
)
file "${GATEWAY}" | grep -q 'Mach-O 64-bit executable arm64' || {
    echo "gateway is not a darwin/arm64 Mach-O" >&2
    exit 1
}

python3 "${ROOT}/scripts/export-uv-overrides.py" "${ROOT}/pyproject.toml" > "${OVERRIDES}"
grep -q '^textual' "${OVERRIDES}" || { echo "dependency overrides are incomplete" >&2; exit 1; }

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
ditto "${BUILT_APP}" "${PLAIN_APP}"

sign_args=(--force --options runtime --sign "${SIGNING_IDENTITY}")
if [[ "${SIGNING_IDENTITY}" != "-" ]]; then
    sign_args+=(--timestamp)
fi
codesign "${sign_args[@]}" "${PLAIN_APP}"
codesign --verify --deep --strict --verbose=2 "${PLAIN_APP}"

# The zip is intentionally app-only so in-app self-updates stay small and do
# not replace or reinstall a separately updating DefenseClaw runtime. The DMG
# below receives a copy with RuntimePayload injected.
ditto "${PLAIN_APP}" "${APP}"
mkdir -p "${PAYLOAD}"
cp "${GATEWAY}" "${PAYLOAD}/defenseclaw-gateway"
cp "${WHEEL}" "${PAYLOAD}/$(basename "${WHEEL}")"
cp "${OVERRIDES}" "${PAYLOAD}/overrides.txt"

codesign "${sign_args[@]}" "${PAYLOAD}/defenseclaw-gateway"

GATEWAY_SHA="$(shasum -a 256 "${PAYLOAD}/defenseclaw-gateway" | awk '{print $1}')"
WHEEL_SHA="$(shasum -a 256 "${PAYLOAD}/$(basename "${WHEEL}")" | awk '{print $1}')"
OVERRIDES_SHA="$(shasum -a 256 "${PAYLOAD}/overrides.txt" | awk '{print $1}')"

python3 - "${PAYLOAD}/payload-manifest.json" "${VERSION}" "${GATEWAY_SHA}" \
    "$(basename "${WHEEL}")" "${WHEEL_SHA}" "${OVERRIDES_SHA}" "${BUILD_DATE}" <<'PY'
import json
from pathlib import Path
import sys

path, version, gateway_sha, wheel_name, wheel_sha, overrides_sha, built_at = sys.argv[1:]
payload = {
    "runtime_version": version,
    "runtime_tag": version,
    "arch": "arm64",
    "gateway": {"file": "defenseclaw-gateway", "sha256": gateway_sha},
    "wheel": {"file": wheel_name, "sha256": wheel_sha},
    "overrides": {"file": "overrides.txt", "sha256": overrides_sha},
    "built_at": built_at,
}
Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

codesign "${sign_args[@]}" "${APP}"
codesign --verify --deep --strict --verbose=2 "${APP}"

NOTARY_READY=0
if [[ "${SIGNING_IDENTITY}" != "-" && -n "${MACOS_NOTARY_KEY_BASE64:-}" ]]; then
    : "${MACOS_NOTARY_KEY_ID:?MACOS_NOTARY_KEY_ID is required}"
    : "${MACOS_NOTARY_ISSUER_ID:?MACOS_NOTARY_ISSUER_ID is required}"
    NOTARY_KEY_PATH="${WORK}/AuthKey_${MACOS_NOTARY_KEY_ID}.p8"
    printf '%s' "${MACOS_NOTARY_KEY_BASE64}" | /usr/bin/base64 -D > "${NOTARY_KEY_PATH}"
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

if [[ "${NOTARY_READY}" == "1" ]]; then
    PLAIN_NOTARY_ZIP="${WORK}/DefenseClawMac-${VERSION}-app-only-notary.zip"
    ditto -c -k --keepParent "${PLAIN_APP}" "${PLAIN_NOTARY_ZIP}"
    notarize "${PLAIN_NOTARY_ZIP}" "app-only"
    xcrun stapler staple "${PLAIN_APP}"
    xcrun stapler validate "${PLAIN_APP}"

    UNIFIED_NOTARY_ZIP="${WORK}/DefenseClawMac-${VERSION}-unified-notary.zip"
    ditto -c -k --keepParent "${APP}" "${UNIFIED_NOTARY_ZIP}"
    notarize "${UNIFIED_NOTARY_ZIP}" "unified-app"
    xcrun stapler staple "${APP}"
    xcrun stapler validate "${APP}"
fi

echo "Creating unified drag-to-Applications DMG"
rm -rf "${DMG_STAGE}"
mkdir -p "${DMG_STAGE}"
ditto "${APP}" "${DMG_STAGE}/DefenseClawMac.app"
ln -s /Applications "${DMG_STAGE}/Applications"
TEMP_DMG="${WORK}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
hdiutil create \
    -volname DefenseClawMac \
    -srcfolder "${DMG_STAGE}" \
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

if [[ "${VERIFICATION_STATUS}" == "notarized" ]]; then
    ZIP_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.zip"
    DMG_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
else
    ZIP_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64-unverified.zip"
    DMG_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64-unverified.dmg"
fi
rm -f "${ZIP_ARTIFACT}" "${DMG_ARTIFACT}"
ditto -c -k --keepParent "${PLAIN_APP}" "${ZIP_ARTIFACT}"
cp "${TEMP_DMG}" "${DMG_ARTIFACT}"
shasum -a 256 "${DMG_ARTIFACT}" "${ZIP_ARTIFACT}"
echo "macOS app verification status: ${VERIFICATION_STATUS}"
echo "unified DMG artifact: ${DMG_ARTIFACT}"
echo "app-only update artifact: ${ZIP_ARTIFACT}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'artifact=%s\n' "${DMG_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'dmg=%s\n' "${DMG_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'zip=%s\n' "${ZIP_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'verification_status=%s\n' "${VERIFICATION_STATUS}" >> "${GITHUB_OUTPUT}"
fi
