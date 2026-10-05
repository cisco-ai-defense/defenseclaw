#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# build-macos-release.sh <version> <out-dir> - build the standalone macOS
# enterprise package for a release, and when Apple credentials are
# configured sign it (Developer ID Application for the binaries, Developer
# ID Installer for the pkg), notarize and staple it.
#
# Called by the release workflow's enterprise-macos job. Credentials come
# from the environment only:
#   signing:       MACOS_INSTALLER_SIGNING_IDENTITY ("Developer ID Installer: ...")
#                  turns it on and needs MACOS_DEVELOPER_ID_P12_BASE64,
#                  MACOS_DEVELOPER_ID_P12_PASSWORD and MACOS_SIGNING_IDENTITY
#                  ("Developer ID Application: ..."), and MACOS_INSTALLER_P12_BASE64
#                  / _PASSWORD when the installer identity is in a separate PKCS#12
#   notarization:  MACOS_NOTARY_KEY_BASE64, MACOS_NOTARY_KEY_ID, MACOS_NOTARY_ISSUER_ID
#                  (all or none), used only when the pkg is signed
# The Developer ID P12 and the notary key are also the macOS app's signing
# secrets, which a release sets for the app. Without the installer identity
# the pkg is unsigned (hash-pinned trust), whatever else is set.

set -euo pipefail

version=${1:?usage: build-macos-release.sh <version> <out-dir>}
out=${2:?usage: build-macos-release.sh <version> <out-dir>}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

signing=0
if [ -n "${MACOS_INSTALLER_SIGNING_IDENTITY:-}" ]; then
    if [ -z "${MACOS_DEVELOPER_ID_P12_BASE64:-}" ] || [ -z "${MACOS_SIGNING_IDENTITY:-}" ]; then
        echo "::error::MACOS_INSTALLER_SIGNING_IDENTITY needs MACOS_DEVELOPER_ID_P12_BASE64 and MACOS_SIGNING_IDENTITY to sign the pkg" >&2
        exit 1
    fi
    signing=1
elif [ -n "${MACOS_INSTALLER_P12_BASE64:-}" ]; then
    echo "::error::MACOS_INSTALLER_P12_BASE64 is set without MACOS_INSTALLER_SIGNING_IDENTITY" >&2
    exit 1
fi
notary=0
for value in "${MACOS_NOTARY_KEY_BASE64:-}" "${MACOS_NOTARY_KEY_ID:-}" "${MACOS_NOTARY_ISSUER_ID:-}"; do
    [ -z "$value" ] || notary=$((notary + 1))
done
if [ "$notary" -ne 0 ] && [ "$notary" -ne 3 ]; then
    echo "::error::Set all three MACOS_NOTARY_* secrets or none of them" >&2
    exit 1
fi

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dc-macos-enterprise.XXXXXX")
keychain=""
cleanup() {
    if [ -n "$keychain" ]; then security delete-keychain "$keychain" >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
chmod 0700 "$work"

if [ "$signing" -eq 1 ]; then
    keychain="$work/signing.keychain-db"
    keychain_password=$(openssl rand -hex 24)
    security create-keychain -p "$keychain_password" "$keychain"
    security set-keychain-settings -lut 3600 "$keychain"
    security unlock-keychain -p "$keychain_password" "$keychain"
    import_p12() {
        local base64_value=$1 password=$2 file="$work/identity-$RANDOM.p12"
        (umask 077 && printf '%s' "$base64_value" | base64 --decode >"$file")
        security import "$file" -k "$keychain" -P "$password" -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/productbuild >/dev/null
        rm -f "$file"
    }
    import_p12 "$MACOS_DEVELOPER_ID_P12_BASE64" "${MACOS_DEVELOPER_ID_P12_PASSWORD:-}"
    if [ -n "${MACOS_INSTALLER_P12_BASE64:-}" ]; then
        import_p12 "$MACOS_INSTALLER_P12_BASE64" "${MACOS_INSTALLER_P12_PASSWORD:-}"
    fi
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" >/dev/null
    existing=()
    while IFS= read -r line; do
        line=${line//\"/}
        line=${line#"${line%%[![:space:]]*}"}
        [ -z "$line" ] || existing+=("$line")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "$keychain" ${existing[@]+"${existing[@]}"}
    export MACOS_APP_SIGN_IDENTITY="$MACOS_SIGNING_IDENTITY"
    export MACOS_INSTALLER_SIGN_IDENTITY="$MACOS_INSTALLER_SIGNING_IDENTITY"
    export MACOS_SIGN_KEYCHAIN="$keychain"
else
    echo "::notice title=Unsigned macOS enterprise package::MACOS_INSTALLER_SIGNING_IDENTITY is not set; the pkg ships unsigned (hash-pinned trust through checksums.txt)."
fi

"$root/scripts/build-macos-enterprise-pkg.sh" --version "$version" --dist-dir "$out"
pkg="$out/defenseclaw-enterprise-${version}-darwin-arm64.pkg"
[ -f "$pkg" ] || { echo "::error::the build did not produce $pkg" >&2; exit 1; }
rm -f "$pkg.sha256" # checksums.txt covers every release asset

if [ "$signing" -eq 1 ]; then
    pkgutil --check-signature "$pkg" | grep -q 'signed by a developer certificate issued by Apple for distribution' || {
        echo "::error::the pkg is not signed with a Developer ID Installer certificate" >&2
        exit 1
    }
fi
if [ "$signing" -eq 1 ] && [ "$notary" -eq 3 ]; then
    key="$work/notary.p8"
    (umask 077 && printf '%s' "$MACOS_NOTARY_KEY_BASE64" | base64 --decode >"$key")
    xcrun notarytool submit "$pkg" --key "$key" --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER_ID" --wait --timeout 30m
    xcrun stapler staple "$pkg"
    spctl --assess --type install --verbose=2 "$pkg"
elif [ "$signing" -eq 1 ]; then
    echo "::warning title=Unnotarized macOS enterprise package::MACOS_NOTARY_* secrets are not set; Gatekeeper-based (signed) trust will reject the pkg."
fi
echo "built $pkg"
