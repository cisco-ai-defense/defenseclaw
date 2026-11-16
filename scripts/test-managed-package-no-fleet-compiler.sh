#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# Check extracted managed payload bytes, not only recipe declarations.
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <managed package>..." >&2
    exit 2
fi
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-managed-package.XXXXXX")
trap 'rm -rf "$work"' EXIT
for package in "$@"; do
    [ -f "$package" ] || { echo "missing package: $package" >&2; exit 2; }
    package=$(cd "$(dirname "$package")" && pwd)/$(basename "$package")
    rm -rf "$work/extracted"
    mkdir -p "$work/extracted"
    case "$package" in
        *.deb) dpkg-deb --extract "$package" "$work/extracted" ;;
        *.rpm)
            if command -v rpm >/dev/null; then
                rpm -qpl "$package" > "$work/rpm-files"
                if grep -E '(^|/)policy_compiler\.py$' "$work/rpm-files"; then
                    echo "managed package contains Fleet compiler: $package" >&2
                    exit 1
                fi
                echo "managed package has no Fleet compiler: $(basename "$package")"
                continue
            elif command -v bsdtar >/dev/null; then
                bsdtar -xf "$package" -C "$work/extracted"
            else
                echo "rpm or bsdtar is required to inspect RPM packages" >&2
                exit 2
            fi
            ;;
        *.pkg)
            rmdir "$work/extracted"
            pkgutil --expand-full "$package" "$work/extracted"
            ;;
        *.tar.gz) tar -xzf "$package" -C "$work/extracted" ;;
        *.zip) unzip -q "$package" -d "$work/extracted" ;;
        *.exe)
            (cd "$repo" && go run ./scripts/check-managed-setup-payload.go "$package")
            continue
            ;;
        *) echo "unsupported managed package: $package" >&2; exit 2 ;;
    esac
    if find "$work/extracted" -type f -name policy_compiler.py -print -quit | grep -q .; then
        echo "managed package contains Fleet compiler: $package" >&2
        exit 1
    fi
    echo "managed package has no Fleet compiler: $(basename "$package")"
done
