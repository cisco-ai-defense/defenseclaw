#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# stamp-package-script.sh VERSION IN OUT writes the package script IN to OUT
# as a release ships it: @DC_PKG_VERSION@ becomes VERSION, and the line
# "# @LEGACY_SANDBOX_GUARD@" becomes the legacy sandbox guard
# (packaging/scripts/lib/legacy-sandbox-guard.sh). The Linux preinstall
# (.goreleaser.yaml) and the macOS pkg preinstall
# (scripts/build-macos-enterprise-pkg.sh) are stamped with it.
set -eu
version=$1 in=$2 out=$3
guard="$(cd "$(dirname "$0")/.." && pwd)/packaging/scripts/lib/legacy-sandbox-guard.sh"
[ -f "$guard" ] || {
    echo "stamp-package-script.sh: $guard is missing" >&2
    exit 1
}
grep -qx '# @LEGACY_SANDBOX_GUARD@' "$in" || {
    echo "stamp-package-script.sh: $in has no # @LEGACY_SANDBOX_GUARD@ line" >&2
    exit 1
}
tmp="$out.stamp.$$"
awk -v version="$version" -v guard="$guard" '
    $0 == "# @LEGACY_SANDBOX_GUARD@" {
        while ((getline line < guard) > 0) print line
        close(guard)
        next
    }
    { gsub(/@DC_PKG_VERSION@/, version); print }' "$in" >"$tmp"
mv -f "$tmp" "$out"
