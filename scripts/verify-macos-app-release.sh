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

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 VERSION OUTPUT_DIR" >&2
    exit 64
fi

VERSION="$1"
OUT_DIR="$2"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "version must be X.Y.Z (got: ${VERSION})" >&2
    exit 64
}
[[ "$(uname -s)" == "Darwin" ]] || {
    echo "macOS release artifacts must be verified on macOS" >&2
    exit 1
}

for command in codesign ditto hdiutil python3 shasum; do
    command -v "${command}" >/dev/null || {
        echo "required command not found: ${command}" >&2
        exit 1
    }
done

shopt -s nullglob
dmgs=("${OUT_DIR}"/DefenseClawMac-"${VERSION}"-macos-arm64*.dmg)
zips=("${OUT_DIR}"/DefenseClawMac-"${VERSION}"-macos-arm64*.zip)
(( ${#dmgs[@]} == 1 )) || { echo "expected exactly one DMG for ${VERSION}" >&2; exit 1; }
(( ${#zips[@]} == 1 )) || { echo "expected exactly one ZIP for ${VERSION}" >&2; exit 1; }
DMG="${dmgs[0]}"
ZIP="${zips[0]}"

DMG_UNVERIFIED=0
ZIP_UNVERIFIED=0
[[ "${DMG}" != *-unverified.dmg ]] || DMG_UNVERIFIED=1
[[ "${ZIP}" != *-unverified.zip ]] || ZIP_UNVERIFIED=1
[[ "${DMG_UNVERIFIED}" == "${ZIP_UNVERIFIED}" ]] || {
    echo "DMG and ZIP verification status mismatch" >&2
    exit 1
}

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
PAYLOAD="${DMG_APP}/Contents/Resources/RuntimePayload"
[[ -d "${DMG_APP}" ]] || { echo "DMG does not contain DefenseClawMac.app" >&2; exit 1; }
[[ -L "${MOUNT}/Applications" && "$(readlink "${MOUNT}/Applications")" == "/Applications" ]] || {
    echo "DMG Applications link is missing or incorrect" >&2
    exit 1
}
for relative in defenseclaw-gateway overrides.txt payload-manifest.json upgrade-manifest.json runtime-candidate-checksums.txt; do
    [[ -f "${PAYLOAD}/${relative}" ]] || { echo "runtime payload missing ${relative}" >&2; exit 1; }
done

INFO="${DMG_APP}/Contents/Info.plist"
BUNDLE_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${INFO}")"
BUNDLE_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${INFO}")"
[[ "${BUNDLE_ID}" == "com.cisco.defenseclaw.macos" ]] || { echo "unexpected bundle ID: ${BUNDLE_ID}" >&2; exit 1; }
[[ "${BUNDLE_VERSION}" == "${VERSION}" ]] || { echo "unexpected app version: ${BUNDLE_VERSION}" >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "${DMG_APP}"
GATEWAY_REQUIREMENT='=identifier "com.cisco.defenseclaw.gateway"'
if [[ "${DMG_UNVERIFIED}" == "0" ]]; then
    EXPECTED_TEAM_ID="$(
        codesign -d --verbose=4 "${DMG_APP}" 2>&1 \
            | sed -n 's/^TeamIdentifier=//p'
    )"
    [[ "${EXPECTED_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]] || {
        echo "verified macOS app has no valid 10-character Team ID" >&2
        exit 1
    }
    APP_REQUIREMENT="=identifier \"com.cisco.defenseclaw.macos\" and anchor apple generic and certificate leaf[subject.OU] = \"${EXPECTED_TEAM_ID}\""
    codesign --verify --strict -R "${APP_REQUIREMENT}" --verbose=2 "${DMG_APP}"
    GATEWAY_REQUIREMENT+=" and anchor apple generic and certificate leaf[subject.OU] = \"${EXPECTED_TEAM_ID}\""
fi
codesign --verify --strict -R "${GATEWAY_REQUIREMENT}" --verbose=2 \
    "${PAYLOAD}/defenseclaw-gateway"
unset GATEWAY_REQUIREMENT

python3 - "${PAYLOAD}" "${VERSION}" <<'PY'
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

payload = Path(sys.argv[1])
version = sys.argv[2]
manifest = json.loads((payload / "payload-manifest.json").read_text(encoding="utf-8"))
if manifest.get("runtime_version") != version or manifest.get("arch") != "arm64":
    raise SystemExit("payload manifest version or architecture mismatch")
for key in ("gateway", "wheel", "overrides", "upgrade_manifest", "runtime_attestation"):
    item = manifest.get(key) or {}
    path = payload / str(item.get("file", ""))
    if not path.is_file():
        raise SystemExit(f"payload manifest references missing {key} file")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item.get("sha256"):
        raise SystemExit(f"payload manifest hash mismatch for {key}")

release = json.loads((payload / "upgrade-manifest.json").read_text(encoding="utf-8"))
expected_gateways = {}
for os_name in ("darwin", "linux", "windows"):
    expected_gateways[os_name] = {
        arch: f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway"
        for arch in ("amd64", "arm64")
    }
expected_wheel = f"defenseclaw-{version}-2-py3-none-any.dcwheel"
if (
    release.get("schema_version") != 2
    or release.get("release_version") != version
    or release.get("release_artifacts")
    != {"wheel": expected_wheel, "gateways": expected_gateways}
):
    raise SystemExit("embedded release manifest does not bind the protected runtime wheel")
if manifest.get("wheel", {}).get("file") != expected_wheel:
    raise SystemExit("RuntimePayload wheel is not the manifest-bound protected artifact")
if (payload / f"defenseclaw-{version}-py3-none-any.whl").exists():
    raise SystemExit("RuntimePayload contains the canonical refusal wheel")
checksums = {}
for raw in (payload / "runtime-candidate-checksums.txt").read_text(encoding="utf-8").splitlines():
    parts = raw.split()
    if len(parts) == 2:
        checksums[parts[1].removeprefix("./")] = parts[0].lower()
wheel_digest = hashlib.sha256((payload / expected_wheel).read_bytes()).hexdigest()
if checksums.get(expected_wheel) != wheel_digest:
    raise SystemExit("embedded runtime attestation does not authenticate the protected RuntimePayload wheel")
outer = (payload / expected_wheel).read_bytes()
magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
if not outer.startswith(magic) or len(outer) == len(magic):
    raise SystemExit("embedded protected wheel envelope is invalid")
inner = bytes(value ^ 0xA5 for value in outer[len(magic):])
if zipfile.is_zipfile(payload / expected_wheel):
    raise SystemExit("embedded protected wheel is directly package-installable")
if not zipfile.is_zipfile(io.BytesIO(inner)):
    raise SystemExit("embedded protected wheel payload is invalid")
PY

ditto -x -k "${ZIP}" "${UNZIP}"
ZIP_APP="${UNZIP}/DefenseClawMac.app"
[[ -d "${ZIP_APP}" ]] || { echo "ZIP does not contain DefenseClawMac.app" >&2; exit 1; }
[[ ! -e "${ZIP_APP}/Contents/Resources/RuntimePayload" ]] || {
    echo "app-only ZIP unexpectedly contains RuntimePayload" >&2
    exit 1
}
ZIP_INFO="${ZIP_APP}/Contents/Info.plist"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${ZIP_INFO}")" == "${BUNDLE_ID}" ]] || {
    echo "ZIP bundle ID does not match DMG" >&2
    exit 1
}
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${ZIP_INFO}")" == "${VERSION}" ]] || {
    echo "ZIP app version does not match ${VERSION}" >&2
    exit 1
}
codesign --verify --deep --strict --verbose=2 "${ZIP_APP}"

if [[ "${DMG_UNVERIFIED}" == "0" ]]; then
    codesign --verify --strict -R "${APP_REQUIREMENT}" --verbose=2 "${ZIP_APP}"
    xcrun stapler validate "${DMG}"
    xcrun stapler validate "${DMG_APP}"
    xcrun stapler validate "${ZIP_APP}"
    spctl --assess --type open --context context:primary-signature --verbose=2 "${DMG}"
    spctl --assess --type execute --verbose=2 "${DMG_APP}"
    spctl --assess --type execute --verbose=2 "${ZIP_APP}"
fi

echo "macOS release artifacts verified:"
echo "  DMG: ${DMG}"
echo "  ZIP: ${ZIP}"
