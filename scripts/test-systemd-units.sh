#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# test-systemd-units.sh - run `systemd-analyze verify` over the standalone
# Linux units exactly as the package installs them (/usr/lib/systemd/system,
# executables under /opt/defenseclaw/bin), inside a scratch --root, and fail
# on any diagnostic. systemd-analyze exits 0 for unknown keys and invalid
# values and only prints them, so any output counts as a failure.
#
# Usage: test-systemd-units.sh [units-dir]   (default: packaging/systemd)
# Needs systemd-analyze with --root support (systemd 250 or later). Runs
# unprivileged and installs nothing.

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
units_dir=${1:-"$repo/packaging/systemd"}

command -v systemd-analyze >/dev/null 2>&1 || {
    echo "systemd-analyze is not installed" >&2
    exit 2
}

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/usr/lib/systemd" "$root/opt/defenseclaw/bin"
# The host's own units resolve the dependencies (sysinit.target, sockets.target...).
cp -a /usr/lib/systemd/system "$root/usr/lib/systemd/"

units=()
for unit in "$units_dir"/*.service "$units_dir"/*.socket "$units_dir"/*.path "$units_dir"/*.timer; do
    [ -f "$unit" ] || continue
    cp "$unit" "$root/usr/lib/systemd/system/"
    units+=("$(basename "$unit")")
done
[ "${#units[@]}" -gt 0 ] || {
    echo "no units found in $units_dir" >&2
    exit 1
}

# verify checks that every Exec* program exists; stand in for the binaries.
while IFS= read -r binary; do
    [ -n "$binary" ] || continue
    printf '#!/bin/sh\nexit 0\n' >"$root$binary"
    chmod 0755 "$root$binary"
done < <(sed -n 's|^Exec[A-Za-z]*=[-+!@:]*\(/opt/defenseclaw/bin/[^ ]*\).*|\1|p' "$units_dir"/*.service | sort -u)

cd "$root/usr/lib/systemd/system"
status=0
output=$(systemd-analyze verify --root="$root" "${units[@]}" 2>&1) || status=$?
output=${output//"$root"/}
if [ "$status" -ne 0 ] || [ -n "$output" ]; then
    printf 'systemd-analyze verify reported problems (exit %s):\n%s\n' "$status" "$output" >&2
    exit 1
fi
echo "systemd-analyze verify: ${#units[@]} units clean"
