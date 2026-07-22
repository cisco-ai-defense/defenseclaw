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
UPGRADE_MANIFEST="${ROOT}/dist/upgrade-manifest.json"
RUNTIME_ATTESTATION="${ROOT}/dist/runtime-candidate-checksums.txt"
WHEEL=""
GATEWAY="${WORK}/defenseclaw-gateway"
GATEWAY_INPUT="${MACOS_GATEWAY_INPUT:-}"
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

for command in xcodebuild xcrun codesign ditto file hdiutil python3 shasum spctl cmp; do
    command -v "${command}" >/dev/null || {
        echo "required command not found: ${command}" >&2
        exit 1
    }
done
if [[ -z "${GATEWAY_INPUT}" ]]; then
    command -v go >/dev/null || { echo "required command not found: go" >&2; exit 1; }
fi
[[ -d "${PROJECT}" ]] || { echo "Xcode project not found: ${PROJECT}" >&2; exit 1; }
[[ -f "${UPGRADE_MANIFEST}" && -f "${RUNTIME_ATTESTATION}" ]] || {
    echo "signed runtime policy inputs are missing from dist/" >&2
    exit 1
}
EXPECTED_WHEEL_PATH="${ROOT}/dist/defenseclaw-${VERSION}-2-py3-none-any.dcwheel"
[[ -f "${EXPECTED_WHEEL_PATH}" ]] || {
    echo "matching wheel not found: ${EXPECTED_WHEEL_PATH}" >&2
    echo "run scripts/stamp-version.sh ${VERSION} && make dist-cli first" >&2
    exit 1
}
WHEEL_ATTESTATION=""
if ! WHEEL_ATTESTATION="$(python3 - "${UPGRADE_MANIFEST}" "${RUNTIME_ATTESTATION}" "${VERSION}" <<'PY'
import io
import json
from pathlib import Path
import re
import sys
import zipfile

manifest_path = Path(sys.argv[1])
checksums_path = Path(sys.argv[2])
version = sys.argv[3]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
expected_gateways = {}
for os_name in ("darwin", "linux", "windows"):
    expected_gateways[os_name] = {
        arch: f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway"
        for arch in ("amd64", "arm64")
    }
expected_wheel = f"defenseclaw-{version}-2-py3-none-any.dcwheel"
if (
    manifest.get("schema_version") != 2
    or manifest.get("release_version") != version
    or manifest.get("release_artifacts")
    != {"wheel": expected_wheel, "gateways": expected_gateways}
):
    raise SystemExit("upgrade manifest does not bind the protected macOS runtime wheel")
checksums = {}
for raw in checksums_path.read_text(encoding="utf-8").splitlines():
    parts = raw.split()
    if len(parts) == 2 and re.fullmatch(r"[0-9A-Fa-f]{64}", parts[0]):
        checksums[parts[1].removeprefix("./")] = parts[0].lower()
digest = checksums.get(expected_wheel)
if digest is None:
    raise SystemExit("runtime candidate attestation does not authenticate the protected runtime wheel")
outer = (manifest_path.parent / expected_wheel).read_bytes()
magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
if not outer.startswith(magic) or len(outer) == len(magic):
    raise SystemExit("protected runtime wheel envelope is invalid")
inner = bytes(value ^ 0xA5 for value in outer[len(magic):])
if zipfile.is_zipfile(manifest_path.parent / expected_wheel):
    raise SystemExit("protected runtime wheel is directly package-installable")
if not zipfile.is_zipfile(io.BytesIO(inner)):
    raise SystemExit("protected runtime wheel payload is invalid")
print(expected_wheel, digest)
PY
)"; then
    echo "protected runtime wheel attestation failed" >&2
    exit 1
fi
read -r WHEEL_NAME EXPECTED_WHEEL_SHA <<<"${WHEEL_ATTESTATION}"
[[ -n "${WHEEL_NAME}" && -n "${EXPECTED_WHEEL_SHA}" ]] || {
    echo "protected runtime wheel attestation returned no authenticated wheel" >&2
    exit 1
}
unset WHEEL_ATTESTATION
WHEEL="${ROOT}/dist/${WHEEL_NAME}"
[[ "$(shasum -a 256 "${WHEEL}" | awk '{print $1}')" == "${EXPECTED_WHEEL_SHA}" ]] || {
    echo "protected runtime wheel checksum mismatch: ${WHEEL_NAME}" >&2
    exit 1
}

rm -rf "${WORK}"
mkdir -p "${WORK}" "${PLAIN_STAGE}" "${UNIFIED_STAGE}" "${OUT_DIR}"

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

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ -n "${GATEWAY_INPUT}" ]]; then
    [[ -f "${GATEWAY_INPUT}" && ! -L "${GATEWAY_INPUT}" ]] || {
        echo "MACOS_GATEWAY_INPUT must name a regular non-symlink candidate binary" >&2
        exit 1
    }
    echo "Using sealed DefenseClaw gateway candidate ${GATEWAY_INPUT}"
    cp "${GATEWAY_INPUT}" "${GATEWAY}"
    chmod 755 "${GATEWAY}"
    cmp -s "${GATEWAY_INPUT}" "${GATEWAY}" || {
        echo "copied gateway bytes differ from MACOS_GATEWAY_INPUT" >&2
        exit 1
    }
else
    echo "Building DefenseClaw gateway ${VERSION} (darwin/arm64)"
    COMMIT="$(git -C "${ROOT}" rev-parse --short=12 HEAD)"
    (
        cd "${ROOT}"
        CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
            -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
            -o "${GATEWAY}" ./cmd/defenseclaw
    )
fi
file "${GATEWAY}" | grep -q 'Mach-O 64-bit executable arm64' || {
    echo "gateway is not a darwin/arm64 Mach-O" >&2
    exit 1
}
GATEWAY_VERSION_OUTPUT="$("${GATEWAY}" --version 2>&1)" || {
    echo "gateway candidate did not execute for version verification" >&2
    exit 1
}
printf '%s' "${GATEWAY_VERSION_OUTPUT}" | grep -Fq "${VERSION}" || {
    echo "gateway candidate version mismatch: expected ${VERSION}" >&2
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
# The staged app is now independent of Xcode's intermediates. Reclaim them
# before the unified payload and disk image need simultaneous working space.
rm -rf "${DERIVED_DATA}"

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
cp "${UPGRADE_MANIFEST}" "${PAYLOAD}/upgrade-manifest.json"
cp "${RUNTIME_ATTESTATION}" "${PAYLOAD}/runtime-candidate-checksums.txt"

codesign "${sign_args[@]}" --identifier com.cisco.defenseclaw.gateway \
    "${PAYLOAD}/defenseclaw-gateway"
GATEWAY_REQUIREMENT='=identifier "com.cisco.defenseclaw.gateway"'
if [[ "${SIGNING_IDENTITY}" != "-" ]]; then
    EXPECTED_TEAM_ID="$(
        codesign -d --verbose=4 "${PLAIN_APP}" 2>&1 \
            | sed -n 's/^TeamIdentifier=//p'
    )"
    [[ "${EXPECTED_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]] || {
        echo "signed macOS app has no valid 10-character Team ID" >&2
        exit 1
    }
    GATEWAY_REQUIREMENT+=" and anchor apple generic and certificate leaf[subject.OU] = \"${EXPECTED_TEAM_ID}\""
fi
codesign --verify --strict -R "${GATEWAY_REQUIREMENT}" --verbose=2 \
    "${PAYLOAD}/defenseclaw-gateway"
unset GATEWAY_REQUIREMENT

GATEWAY_SHA="$(shasum -a 256 "${PAYLOAD}/defenseclaw-gateway" | awk '{print $1}')"
WHEEL_SHA="$(shasum -a 256 "${PAYLOAD}/$(basename "${WHEEL}")" | awk '{print $1}')"
OVERRIDES_SHA="$(shasum -a 256 "${PAYLOAD}/overrides.txt" | awk '{print $1}')"
UPGRADE_MANIFEST_SHA="$(shasum -a 256 "${PAYLOAD}/upgrade-manifest.json" | awk '{print $1}')"
RUNTIME_ATTESTATION_SHA="$(shasum -a 256 "${PAYLOAD}/runtime-candidate-checksums.txt" | awk '{print $1}')"

python3 - "${PAYLOAD}/payload-manifest.json" "${VERSION}" "${GATEWAY_SHA}" \
    "$(basename "${WHEEL}")" "${WHEEL_SHA}" "${OVERRIDES_SHA}" \
    "${UPGRADE_MANIFEST_SHA}" "${RUNTIME_ATTESTATION_SHA}" "${BUILD_DATE}" <<'PY'
import json
from pathlib import Path
import sys

(
    path,
    version,
    gateway_sha,
    wheel_name,
    wheel_sha,
    overrides_sha,
    upgrade_manifest_sha,
    runtime_attestation_sha,
    built_at,
) = sys.argv[1:]
payload = {
    "runtime_version": version,
    "runtime_tag": version,
    "arch": "arm64",
    "gateway": {"file": "defenseclaw-gateway", "sha256": gateway_sha},
    "wheel": {"file": wheel_name, "sha256": wheel_sha},
    "overrides": {"file": "overrides.txt", "sha256": overrides_sha},
    "upgrade_manifest": {"file": "upgrade-manifest.json", "sha256": upgrade_manifest_sha},
    "runtime_attestation": {
        "file": "runtime-candidate-checksums.txt",
        "sha256": runtime_attestation_sha,
    },
    "built_at": built_at,
}
Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

codesign "${sign_args[@]}" "${APP}"
codesign --verify --deep --strict --verbose=2 "${APP}"
[[ "$(shasum -a 256 "${PAYLOAD}/defenseclaw-gateway" | awk '{print $1}')" == "${GATEWAY_SHA}" ]] || {
    echo "outer app signing changed the release-attested gateway bytes" >&2
    exit 1
}

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
[[ ! -e "${UNIFIED_STAGE}/Applications" && ! -L "${UNIFIED_STAGE}/Applications" ]] || {
    echo "unified DMG staging link already exists" >&2
    exit 1
}
ln -s /Applications "${UNIFIED_STAGE}/Applications"
TEMP_DMG="${WORK}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
# hdiutil's automatic -srcfolder sizing can leave too little filesystem
# headroom for the final copy. Size the image from the staged bytes with 20%
# growth room plus 64 MiB for filesystem metadata and copy variance.
DMG_SOURCE_KIB="$(du -sk "${UNIFIED_STAGE}" | awk '{print $1}')"
[[ "${DMG_SOURCE_KIB}" =~ ^[0-9]+$ ]] || {
    echo "could not determine unified DMG staging size" >&2
    exit 1
}
DMG_SIZE_KIB=$((DMG_SOURCE_KIB + DMG_SOURCE_KIB / 5 + 65536))
echo "Unified DMG source: ${DMG_SOURCE_KIB} KiB; capacity: ${DMG_SIZE_KIB} KiB"
hdiutil create \
    -volname DefenseClawMac \
    -srcfolder "${UNIFIED_STAGE}" \
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

if [[ "${VERIFICATION_STATUS}" == "notarized" ]]; then
    ZIP_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.zip"
    DMG_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64.dmg"
else
    ZIP_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64-unverified.zip"
    DMG_ARTIFACT="${OUT_DIR}/DefenseClawMac-${VERSION}-macos-arm64-unverified.dmg"
fi

if [[ "${MACOS_REQUIRE_NOTARIZATION:-false}" == "true" && "${VERIFICATION_STATUS}" != "notarized" ]]; then
    echo "MACOS_REQUIRE_NOTARIZATION=true but the app was not notarized" >&2
    exit 1
fi
rm -f "${ZIP_ARTIFACT}" "${DMG_ARTIFACT}"
ditto -c -k --keepParent "${PLAIN_APP}" "${ZIP_ARTIFACT}"
cp "${TEMP_DMG}" "${DMG_ARTIFACT}"
shasum -a 256 "${DMG_ARTIFACT}" "${ZIP_ARTIFACT}"
"${ROOT}/scripts/verify-macos-app-release.sh" "${VERSION}" "${OUT_DIR}"
echo "macOS app verification status: ${VERIFICATION_STATUS}"
echo "unified DMG artifact: ${DMG_ARTIFACT}"
echo "app-only update artifact: ${ZIP_ARTIFACT}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'artifact=%s\n' "${DMG_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'dmg=%s\n' "${DMG_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'zip=%s\n' "${ZIP_ARTIFACT}" >> "${GITHUB_OUTPUT}"
    printf 'verification_status=%s\n' "${VERIFICATION_STATUS}" >> "${GITHUB_OUTPUT}"
fi
