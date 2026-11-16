#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${script_dir}/../install.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

mkdir -p "${scratch}/.staging/bin"
printf 'the downloaded archive was altered\n' > "${scratch}/.staging/release.tar.gz"
printf '%s  release.tar.gz\n' "$(printf 'the expected archive\n' | shasum -a 256 | cut -d' ' -f1)" > "${scratch}/.staging/checksums.txt"
printf 'installed version stays here\n' > "${scratch}/installed"

functions="$(sed -n '/^checksum_ok() {/,/^}/p; /^verify() {/,/^}/p' "${installer}")"
if STAGING="${scratch}/.staging" ARCHIVE="${scratch}/.staging/release.tar.gz" FUNCTIONS="${functions}" \
    bash -c 'set -euo pipefail; sha256_of() { shasum -a 256 "$1" | cut -d" " -f1; }; die() { echo "$*" >&2; exit 1; }; eval "$FUNCTIONS"; verify "$ARCHIVE"' \
    > "${scratch}/out" 2>&1; then
    echo 'checksum mismatch was accepted' >&2
    exit 1
fi

grep -q 'release.tar.gz does not match checksums.txt' "${scratch}/out"
test ! -e "${scratch}/.staging"
test "$(cat "${scratch}/installed")" = 'installed version stays here'
