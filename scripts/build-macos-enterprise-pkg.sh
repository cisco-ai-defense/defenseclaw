#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Build the macOS standalone managed-enterprise installer package
# (defenseclaw-enterprise-<version>-darwin-arm64.pkg).
#
# The package installs the gateway, hook runtime and sensor helper under
# /opt/cisco/defenseclaw/bin; its postinstall runs
#   defenseclaw-gateway enterprise macos ensure --from-package
# which validates the administrator config, creates the _defenseclaw service
# account and LaunchDaemons, activates them in order and rolls back on any
# failure. Deploy it with any MDM that installs flat packages. Remove it with
#   sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos uninstall [--purge]
#
# Called by the `packaging-macos-enterprise` Make target.
#
# Usage:
#   scripts/build-macos-enterprise-pkg.sh --version 1.2.3 [--dist-dir dist]
#       [--payload DIR]
#
#   --payload DIR   use prebuilt darwin/arm64 binaries (defenseclaw-gateway,
#                   defenseclaw-hook, defenseclaw-sensor-helper and optionally
#                   defenseclaw-acp) instead of building them.
#
# Signing is optional and off by default:
#   MACOS_APP_SIGN_IDENTITY        "Developer ID Application: ..." codesigns
#                                  the binaries with the hardened runtime.
#   MACOS_INSTALLER_SIGN_IDENTITY  "Developer ID Installer: ..." signs the
#                                  product archive.
#   MACOS_SIGN_KEYCHAIN            keychain holding both identities.
# Notarize the signed package separately (xcrun notarytool submit ...).

set -euo pipefail

readonly PKG_ID="com.cisco.defenseclaw.enterprise"
readonly INSTALL_BIN="opt/cisco/defenseclaw/bin"

VERSION=""
DIST_DIR="dist"
PAYLOAD=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --dist-dir) DIST_DIR="${2:?--dist-dir needs a value}"; shift 2 ;;
        --payload) PAYLOAD="${2:?--payload needs a value}"; shift 2 ;;
        -h | --help) sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
VERSION="${VERSION#v}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$ ]]; then
    echo "--version must be a release version such as 1.2.3 (got '${VERSION}')" >&2
    exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "pkgbuild and productbuild run on macOS only" >&2
    exit 1
fi
for command in pkgbuild productbuild; do
    command -v "$command" >/dev/null || { echo "missing $command (install the Xcode command line tools)" >&2; exit 1; }
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIST_DIR"
DIST_DIR="$(cd "$DIST_DIR" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-enterprise-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
SCRIPTS="$WORK/scripts"
mkdir -p "$ROOT/$INSTALL_BIN" "$SCRIPTS"

binaries=(defenseclaw-gateway defenseclaw-hook defenseclaw-sensor-helper)
if [ -n "$PAYLOAD" ]; then
    for name in "${binaries[@]}" defenseclaw-acp; do
        if [ -f "$PAYLOAD/$name" ]; then
            install -m 0755 "$PAYLOAD/$name" "$ROOT/$INSTALL_BIN/$name"
        elif [ "$name" != defenseclaw-acp ]; then
            echo "payload $PAYLOAD lacks $name" >&2
            exit 1
        fi
    done
else
    build() { # build <output> <package> <ldflags>
        (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
            go build -trimpath -buildvcs=false -ldflags "$3" -o "$ROOT/$INSTALL_BIN/$1" "$2")
    }
    COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=8 HEAD 2>/dev/null || echo unknown)"
    version_flags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}"
    build defenseclaw-gateway ./cmd/defenseclaw "$version_flags"
    build defenseclaw-hook ./cmd/defenseclaw-hook "$version_flags"
    build defenseclaw-sensor-helper ./cmd/defenseclaw-sensor-helper "$version_flags"
    build defenseclaw-acp ./cmd/defenseclaw-acp "$version_flags"
fi

if [ -n "${MACOS_APP_SIGN_IDENTITY:-}" ]; then
    sign_args=(--force --timestamp --options runtime --sign "$MACOS_APP_SIGN_IDENTITY")
    [ -n "${MACOS_SIGN_KEYCHAIN:-}" ] && sign_args+=(--keychain "$MACOS_SIGN_KEYCHAIN")
    for binary in "$ROOT/$INSTALL_BIN"/*; do
        codesign "${sign_args[@]}" --identifier "com.cisco.defenseclaw.$(basename "$binary")" "$binary"
    done
fi

# preinstall refuses before any file lands on a Secure Client host: the two
# deployments share the gateway port and the lifecycle would refuse anyway.
# It also refuses a downgrade before the older binaries replace the installed
# ones, unless the administrator created the root-owned rollback marker
# /opt/cisco/defenseclaw/lifecycle/allow-downgrade (postinstall consumes it).
cat >"$SCRIPTS/preinstall" <<'EOF'
#!/bin/sh
if [ -e /opt/cisco/secureclient/defenseclaw ] ||
    ls /Library/LaunchDaemons/com.cisco.secureclient.defenseclaw*.plist >/dev/null 2>&1; then
    echo "DefenseClaw is already managed by Cisco Secure Client on this Mac; the standalone package cannot be installed beside it." >&2
    exit 1
fi
state=/opt/cisco/defenseclaw/lifecycle
package_version="@DC_PKG_VERSION@"
record="$state/deployment.json"
if [ -f "$record" ] && [ ! -L "$record" ] && [ "$(stat -f %u "$record")" = 0 ]; then
    installed=$(sed -n 's/.*"product_version": *"\([^"]*\)".*/\1/p' "$record" | head -n 1)
    marker="$state/allow-downgrade"
    if [ -n "$installed" ] && ! [ -f "$marker" ] && ! awk -v a="$package_version" -v b="$installed" '
        function norm(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
        BEGIN {
            a = norm(a); b = norm(b); pa = ""; pb = ""
            if (index(a, "-")) { pa = substr(a, index(a, "-") + 1); a = substr(a, 1, index(a, "-") - 1) }
            if (index(b, "-")) { pb = substr(b, index(b, "-") + 1); b = substr(b, 1, index(b, "-") - 1) }
            na = split(a, x, "."); nb = split(b, y, "."); n = na > nb ? na : nb
            for (i = 1; i <= n; i++) {
                xi = (i <= na) ? x[i] + 0 : 0; yi = (i <= nb) ? y[i] + 0 : 0
                if (xi > yi) exit 0
                if (xi < yi) exit 1
            }
            if (pa == pb || pa == "") exit 0
            if (pb == "") exit 1
            np = split(pa, u, "."); nq = split(pb, w, "."); m = np > nq ? np : nq
            for (i = 1; i <= m; i++) {
                if (u[i] == w[i]) continue
                if (u[i] ~ /^[0-9]+$/ && w[i] ~ /^[0-9]+$/) exit (u[i] + 0 > w[i] + 0) ? 0 : 1
                exit (u[i] > w[i]) ? 0 : 1
            }
            exit 0
        }'; then
        echo "DefenseClaw $installed is installed; refusing to downgrade to $package_version. For a deliberate rollback, create $marker as root first." >&2
        exit 1
    fi
fi
exit 0
EOF
sed -i.bak "s/@DC_PKG_VERSION@/${VERSION}/" "$SCRIPTS/preinstall" && rm -f "$SCRIPTS/preinstall.bak"

# postinstall applies the deployment. A failure has already been rolled back
# by the lifecycle; it fails the install so the MDM reports it. It waits for
# a config-apply run that holds the lifecycle lock, as that trigger does,
# instead of failing the install as busy after the default 5 seconds.
cat >"$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway
state=/opt/cisco/defenseclaw/lifecycle
umask 077
mkdir -p "$state" && chmod 0700 "$state"
downgrade=""
if [ -f "$state/allow-downgrade" ] && [ ! -L "$state/allow-downgrade" ] && [ "$(stat -f %u "$state/allow-downgrade")" = 0 ]; then
    downgrade=--allow-downgrade
fi
"$gateway" enterprise macos ensure --from-package $downgrade --reason package --json --lock-wait 10m \
    >"$state/last-package-result.json" 2>"$state/last-package-result.log"
status=$?
rm -f "$state/allow-downgrade"
if [ "$status" -ne 0 ]; then
    echo "DefenseClaw: the managed deployment did not apply (exit $status); see $state/last-package-result.json" >&2
fi
exit "$status"
EOF
chmod 0755 "$SCRIPTS/preinstall" "$SCRIPTS/postinstall"

COMPONENT="$WORK/defenseclaw-enterprise-component.pkg"
pkgbuild --root "$ROOT" --identifier "$PKG_ID" --version "$VERSION" \
    --scripts "$SCRIPTS" --install-location / --ownership recommended "$COMPONENT"

cat >"$WORK/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>DefenseClaw Managed Enterprise</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <choices-outline><line choice="default"/></choices-outline>
    <choice id="default" visible="false">
        <pkg-ref id="${PKG_ID}"/>
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION}" onConclusion="none">defenseclaw-enterprise-component.pkg</pkg-ref>
</installer-gui-script>
EOF

OUTPUT="$DIST_DIR/defenseclaw-enterprise-${VERSION}-darwin-arm64.pkg"
product_args=(--distribution "$WORK/distribution.xml" --package-path "$WORK")
if [ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]; then
    product_args+=(--sign "$MACOS_INSTALLER_SIGN_IDENTITY" --timestamp)
    [ -n "${MACOS_SIGN_KEYCHAIN:-}" ] && product_args+=(--keychain "$MACOS_SIGN_KEYCHAIN")
fi
productbuild "${product_args[@]}" "$OUTPUT"
(cd "$DIST_DIR" && shasum -a 256 "$(basename "$OUTPUT")" >"$(basename "$OUTPUT").sha256")
echo "built $OUTPUT"
