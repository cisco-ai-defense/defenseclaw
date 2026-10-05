#!/bin/bash
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

# Build only. Registering the service always requires an explicit app action.
set -euo pipefail

ROOT="${SRCROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
if [[ $# -gt 0 ]]; then
    APP="$1"
else
    APP="${TARGET_BUILD_DIR:?}/${WRAPPER_NAME:?}"
fi
HELPER_ID="com.cisco.defenseclaw.macos.GatewayAdmin"
APP_ID="com.cisco.defenseclaw.macos"
HELPER_NAME="DefenseClawGatewayHelper"
CONFIG="${CONFIGURATION:-Debug}"
IDENTITY="${EXPANDED_CODE_SIGN_IDENTITY:--}"
TEAM="${DEVELOPMENT_TEAM:-}"
DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
# Xcode permits transient compiler files under TARGET_TEMP_DIR. Declared output
# directories use literal sandbox rules, so DERIVED_FILE_DIR cannot host a
# dynamically named compiler/module-cache tree in a clean archive.
BUILD_ROOT="${TARGET_TEMP_DIR:-${TMPDIR:-/tmp}}/GatewayAdminHelper"
mkdir -p "$BUILD_ROOT"
BUILD_DIR="$(mktemp -d "$BUILD_ROOT/build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

fail() { printf 'Gateway helper build: %s\n' "$*" >&2; exit 1; }
[[ "$APP" == *.app && ! -L "$APP" ]] || fail "expected a regular .app output directory"
[[ "$DEPLOYMENT_TARGET" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fail "invalid deployment target"
[[ -n "$IDENTITY" ]] || IDENTITY=-
[[ "${CODE_SIGNING_ALLOWED:-YES}" != NO ]] || IDENTITY=-
if [[ "$IDENTITY" != - && -z "$TEAM" ]]; then
    fail "a Developer ID helper build requires DEVELOPMENT_TEAM"
fi

LIBRARY="$APP/Contents/Library"
TOOLS="$LIBRARY/LaunchServices"
DAEMONS="$LIBRARY/LaunchDaemons"
for directory in "$APP/Contents" "$LIBRARY" "$TOOLS" "$DAEMONS"; do
    [[ ! -L "$directory" ]] || fail "refusing symlinked bundle directory: $directory"
    mkdir -p "$directory"
done

cat > "$BUILD_DIR/HelperInfo.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$HELPER_ID</string>
<key>CFBundleName</key><string>$HELPER_NAME</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundlePackageType</key><string>TOOL</string>
</dict></plist>
PLIST

SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
read -r -a helper_archs <<< "${ARCHS:-$(/usr/bin/uname -m)}"
[[ ${#helper_archs[@]} -gt 0 ]] || fail "no target architecture selected"
helper_slices=()
for helper_arch in "${helper_archs[@]}"; do
    case "$helper_arch" in arm64|x86_64) ;; *) fail "unsupported architecture: $helper_arch" ;; esac
    slice="$BUILD_DIR/$HELPER_NAME-$helper_arch"
    /usr/bin/xcrun --sdk macosx swiftc -parse-as-library -swift-version 5 \
        -sdk "$SDK" -target "$helper_arch-apple-macosx$DEPLOYMENT_TARGET" \
        -module-cache-path "$BUILD_DIR/ModuleCache" -O \
        -framework Foundation -framework Security \
        -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist \
        -Xlinker "$BUILD_DIR/HelperInfo.plist" \
        "$ROOT/DefenseClawMac/DataLayer/GatewayAdminProtocol.swift" \
        "$ROOT/GatewayAdminHelper/main.swift" -o "$slice"
    helper_slices+=("$slice")
done
/usr/bin/lipo -create "${helper_slices[@]}" -output "$BUILD_DIR/$HELPER_NAME"
/bin/chmod 755 "$BUILD_DIR/$HELPER_NAME"
# Local builds do not contact the timestamp service. Release packaging uses it.
helper_timestamp=--timestamp=none
if [[ "$CONFIG" == Release && "$IDENTITY" != - ]]; then
    helper_timestamp=--timestamp
fi
/usr/bin/codesign --force --options runtime "$helper_timestamp" \
    --identifier "$HELPER_ID" --sign "$IDENTITY" "$BUILD_DIR/$HELPER_NAME"
/bin/rm -f "$TOOLS/$HELPER_NAME"
/bin/cp "$BUILD_DIR/$HELPER_NAME" "$TOOLS/$HELPER_NAME"

# SMAppService resolves BundleProgram against the sealed application bundle.
# No RunAtLoad/KeepAlive: registration happens only on explicit user action.
cat > "$BUILD_DIR/$HELPER_ID.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$HELPER_ID</string>
<key>BundleProgram</key><string>Contents/Library/LaunchServices/$HELPER_NAME</string>
<key>ProgramArguments</key><array><string>$HELPER_NAME</string></array>
<key>MachServices</key><dict><key>$HELPER_ID</key><true/></dict>
<key>AssociatedBundleIdentifiers</key><array><string>$APP_ID</string></array>
<key>UserName</key><string>root</string>
</dict></plist>
PLIST
/bin/rm -f "$DAEMONS/$HELPER_ID.plist"
/bin/cp "$BUILD_DIR/$HELPER_ID.plist" "$DAEMONS/$HELPER_ID.plist"
/bin/chmod 644 "$DAEMONS/$HELPER_ID.plist"
/usr/bin/plutil -lint "$DAEMONS/$HELPER_ID.plist"

# Remove a stale runtime from earlier build outputs. Administrator operations
# use the existing installed runtime only after fresh native authorization;
# an app update must never substitute its own gateway executable.
/bin/rm -f "$TOOLS/defenseclaw-gateway"
if [[ "$IDENTITY" == - ]]; then
    printf 'Gateway helper compiled ad-hoc; privileged authorization remains unavailable.\n'
fi
