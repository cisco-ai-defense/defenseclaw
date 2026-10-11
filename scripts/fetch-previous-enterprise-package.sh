#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# fetch-previous-enterprise-package.sh - download one standalone enterprise
# package of a published release for the enterprise upgrade lanes, and verify
# it: checksums.txt against the Release workflow's cosign identity, then the
# package against its SHA-256 in checksums.txt.
#
# Usage:
#   fetch-previous-enterprise-package.sh --asset ASSET --dir DIR
#       [--version VERSION] [--require] [--github-output FILE]
#
#   --asset ASSET   linux-amd64.deb, linux-amd64.rpm, darwin-arm64.pkg or setup
#                   (the Windows DefenseClawSetup-Enterprise-Standalone-x64.exe)
#   --dir DIR       where to download it
#   --version V     the release to fetch (default: the latest release)
#   --require       fail when there is no such release or package; without it
#                   a missing one is a notice and an empty version output
#   --github-output FILE
#                   append version=<V> and package=<path> (both empty when
#                   skipped) to this file
#
# Needs gh (GH_TOKEN), cosign and sha256sum or shasum.

set -euo pipefail

asset=""
dir=""
version=""
require=false
github_output=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --asset) asset=${2:?--asset needs a value}; shift 2 ;;
        --dir) dir=${2:?--dir needs a value}; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --require) require=true; shift ;;
        --github-output) github_output=${2:?--github-output needs a value}; shift 2 ;;
        -h | --help) sed -n '4,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$asset" ] && [ -n "$dir" ] || { echo "usage: $0 --asset ASSET --dir DIR [--version V] [--require] [--github-output FILE]" >&2; exit 2; }
repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must name the repository}
identity="https://github.com/$repository/.github/workflows/release.yaml@refs/heads/main"

output() {
    if [ -n "$github_output" ]; then
        printf 'version=%s\npackage=%s\n' "$1" "$2" >>"$github_output"
    fi
}
skip() {
    if [ "$require" = true ]; then
        echo "::error::$1" >&2
        exit 1
    fi
    echo "::notice title=Enterprise upgrade lane skipped::$1"
    output "" ""
    exit 0
}

if [ -z "$version" ]; then
    if ! version=$(gh release list --repo "$repository" --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName // empty'); then
        echo "::error::could not look up the latest published release" >&2
        exit 1
    fi
    [ -n "$version" ] || skip "no published release to upgrade from"
fi
case "$asset" in
    setup) name=DefenseClawSetup-Enterprise-Standalone-x64.exe ;;
    linux-amd64.deb | linux-amd64.rpm | darwin-arm64.pkg) name="defenseclaw-enterprise-$version-$asset" ;;
    *) echo "unknown --asset $asset" >&2; exit 2 ;;
esac

mkdir -p "$dir"
if ! gh release download "$version" --repo "$repository" --dir "$dir" --clobber \
    --pattern "$name" --pattern checksums.txt --pattern checksums.txt.bundle; then
    skip "release $version has no $name, checksums.txt or checksums.txt.bundle"
fi
[ -f "$dir/$name" ] || skip "release $version has no $name"

cosign verify-blob --bundle "$dir/checksums.txt.bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$dir/checksums.txt"
want=$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1 }' "$dir/checksums.txt")
[ -n "$want" ] || { echo "checksums.txt of $version does not list $name" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$dir/$name" | cut -d' ' -f1)
else
    got=$(shasum -a 256 "$dir/$name" | cut -d' ' -f1)
fi
[ "$got" = "$want" ] || { echo "$name of $version does not match checksums.txt" >&2; exit 1; }

package=$(cd "$dir" && pwd)/$name
if command -v cygpath >/dev/null 2>&1; then
    package=$(cygpath -w "$package") # Git Bash on Windows: a path PowerShell reads
fi
echo "verified $name of $version: $got"
output "$version" "$package"
