#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the optional Fleet compiler source in a built enterprise package
# without installing the package or changing a Fleet-off host. The managed
# lifecycle tests separately cover Fleet-on materialization and rollback.

set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: $0 <enterprise.deb|enterprise.rpm>" >&2
    exit 2
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
package=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-fleet-package.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/extracted" "$work/output"
case "$package" in
    *.deb)
        command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 2; }
        dpkg-deb --extract "$package" "$work/extracted"
        ;;
    *.rpm)
        command -v rpm2cpio >/dev/null || { echo "rpm2cpio is required" >&2; exit 2; }
        command -v cpio >/dev/null || { echo "cpio is required" >&2; exit 2; }
        (cd "$work/extracted" && rpm2cpio "$package" | cpio -idm --quiet --no-absolute-filenames)
        ;;
    *)
        echo "expected a .deb or .rpm enterprise package" >&2
        exit 2
        ;;
esac

compiler="$work/extracted/opt/defenseclaw/share/fleet/policy_compiler.py"
active="$work/extracted/opt/defenseclaw/lib/defenseclaw/policy_compiler.py"
[ -f "$compiler" ] && [ ! -L "$compiler" ] || {
    echo "optional Fleet compiler source is missing or not regular: $compiler" >&2
    exit 1
}
[ ! -e "$active" ] || {
    echo "Fleet-off package unexpectedly contains an active compiler: $active" >&2
    exit 1
}
cmp "$repo/edge-connector/tools/policy_compiler.py" "$compiler" || {
    echo "packaged Fleet compiler differs from release source" >&2
    exit 1
}

python=$(command -v python3)
"$python" -I -c 'import yaml; assert callable(yaml.safe_load)' || {
    echo "Fleet compiler smoke needs Python 3 and PyYAML in its isolated interpreter" >&2
    exit 2
}
(
    cd "$work/output"
    "$python" -I "$compiler" \
        --input "$repo/edge-connector/policies/strict.yaml" \
        --profile standard --version 1 \
        --output-header policy_tables.h \
        --output-binary policy.bin
)
[ -s "$work/output/policy_tables.h" ] && [ -s "$work/output/policy.bin" ] || {
    echo "packaged Fleet compiler produced no policy outputs" >&2
    exit 1
}
echo "Fleet compiler package smoke passed: $(basename "$package")"
