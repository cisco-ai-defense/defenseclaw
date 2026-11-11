#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Put the tools a CI step needs on a GitHub-hosted Ubuntu runner without
# making the step depend on one apt round trip (rel-1-0-6 GAP-1070).
#
#   runner-apt-install.sh "COMMAND..." PACKAGE...
#
# COMMAND... lists the programs the step runs, separated by spaces; an item
# "a|b" is met by either program. Then:
#   1. When every COMMAND is already on PATH (the runner image ships cmake,
#      gcc, g++, make and rpm), apt is not used at all.
#   2. Otherwise apt-get update and the download of PACKAGE... run up to
#      three times, 15 s and 30 s apart, each with Acquire::Retries and each
#      network phase cut at 30 s (a resolver that times out makes one apt
#      attempt take about 9 minutes otherwise); the packages then install from
#      the local cache with --no-download, which needs no network.
#   3. When apt stays unreachable, each PACKAGE pinned in runner-apt-pins.txt
#      for this Ubuntu release is downloaded from an Ubuntu mirror, checked
#      against its pinned SHA-256 and installed with dpkg.
# The step fails unless every COMMAND is on PATH at the end.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 \"COMMAND...\" PACKAGE..." >&2
    exit 2
fi
read -ra commands <<< "$1"
shift
packages=("$@")
pins="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runner-apt-pins.txt"

missing() {
    local item alt found
    local -a alts out=()
    for item in "${commands[@]}"; do
        found=0
        IFS="|" read -ra alts <<< "$item"
        for alt in "${alts[@]}"; do
            if command -v "$alt" >/dev/null 2>&1; then
                found=1
                break
            fi
        done
        [ "$found" -eq 1 ] || out+=("$item")
    done
    echo "${out[*]}"
}

if [ -z "$(missing)" ]; then
    echo "runner-apt-install: ${commands[*]} already on the runner image; apt not used"
    exit 0
fi

apt_opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
delays=(15 30)
network_seconds=30
installed=0
for attempt in 1 2 3; do
    if ! timeout "$network_seconds" sudo apt-get "${apt_opts[@]}" update -q; then
        echo "::warning title=apt-get update failed::attempt $attempt of 3"
    fi
    if timeout "$network_seconds" sudo apt-get "${apt_opts[@]}" install -y -q --download-only "${packages[@]}"; then
        sudo apt-get install -y -q --no-download "${packages[@]}"
        installed=1
        break
    fi
    if [ "$attempt" -lt 3 ]; then
        sleep "${delays[attempt - 1]}"
    fi
done

if [ "$installed" -eq 0 ]; then
    # shellcheck source=/dev/null
    codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
    for package in "${packages[@]}"; do
        pool_path=""
        while read -r pin_package pin_codename pin_path pin_sha256; do
            if [ "$pin_package" = "$package" ] && [ "$pin_codename" = "$codename" ]; then
                pool_path=$pin_path
                sha256=$pin_sha256
            fi
        done < <(grep -v "^#" "$pins")
        if [ -z "$pool_path" ]; then
            echo "::error title=apt unreachable::apt-get install $package failed 3 times and runner-apt-pins.txt pins no $package for ${codename:-this release}"
            exit 1
        fi
        echo "::warning title=apt unreachable::installing the pinned $(basename "$pool_path") for $codename"
        deb="${RUNNER_TEMP:-/tmp}/$(basename "$pool_path")"
        fetched=0
        for mirror in https://mirrors.edge.kernel.org/ubuntu https://archive.ubuntu.com/ubuntu; do
            if curl -fsSL --retry 2 --retry-all-errors --connect-timeout 20 --max-time 60 -o "$deb" "$mirror/$pool_path"; then
                fetched=1
                break
            fi
        done
        if [ "$fetched" -eq 0 ]; then
            echo "::error title=apt unreachable::no mirror served $pool_path"
            exit 1
        fi
        if ! echo "$sha256  $deb" | sha256sum --check --quiet -; then
            rm -f "$deb"
            echo "::error title=pinned package mismatch::$pool_path does not have its pinned SHA-256"
            exit 1
        fi
        sudo dpkg -i "$deb"
        rm -f "$deb"
    done
fi

still=$(missing)
if [ -n "$still" ]; then
    echo "::error title=tools missing::$still not on PATH after installing ${packages[*]}"
    exit 1
fi
