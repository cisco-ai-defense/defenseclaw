#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Build the Claude Cowork VM sensor package for one VM architecture:
#   defenseclaw-cowork-<amd64|arm64>.tar.gz
# A gzip tar of regular files and folders only, install.sh at the top level,
# owner 0, sorted entries and a fixed mtime, so the same inputs give the same
# bytes. check-package.py then enforces Anthropic's package rules (EDR guide
# v1.7: 512 MiB packed, 1 GiB unpacked). Signing is a separate step (sign.sh).
#
#   build.sh --arch amd64 --version 1.0.8 --gateway PATH --helper PATH \
#            [--policies DIR] [--collector-ca FILE] [--out-dir DIR]
#
# --policies: the gateway's rule packs, needed until the gateway starts
# without them when guardrails are off (R108-COWORK-4). Tests, Go sources and
# the kernel, sandbox and scanner policies are left out.
# --collector-ca: a CA for a collector without a publicly trusted
# certificate; a generic package ships without one.
# SOURCE_DATE_EPOCH (default: the HEAD commit time) sets every entry's mtime.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
arch="" version="" gateway="" helper="" policies="" ca="" out="$root/dist/cowork-vm"
die() { echo "build.sh: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch=${2:?}; shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --gateway) gateway=${2:?}; shift 2 ;;
    --helper) helper=${2:?}; shift 2 ;;
    --policies) policies=${2:?}; shift 2 ;;
    --collector-ca) ca=${2:?}; shift 2 ;;
    --out-dir) out=${2:?}; shift 2 ;;
    -h | --help) sed -n '4,21p' "$0"; exit 0 ;;
    *) die "unknown argument $1" ;;
  esac
done
case "$arch" in amd64) machine=3e00 ;; arm64) machine=b700 ;; *) die "--arch must be amd64 or arm64" ;; esac
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$ ]] || die "--version must be a plain version string"
for b in "$gateway" "$helper"; do
  [ -f "$b" ] || die "missing binary: ${b:-(not given)}"
  # ELF, little endian, e_machine x86-64 (0x3e) or AArch64 (0xb7).
  [ "$(od -An -tx1 -N4 "$b" | tr -d ' \n')" = 7f454c46 ] || die "$b is not an ELF executable"
  [ "$(od -An -tx1 -j18 -N2 "$b" | tr -d ' \n')" = "$machine" ] || die "$b is not a linux/$arch binary"
done
[ -z "$policies" ] || [ -d "$policies" ] || die "--policies $policies is not a folder"
[ -z "$ca" ] || [ -f "$ca" ] || die "--collector-ca $ca is not a file"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2> /dev/null || echo 0)"
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be seconds since the epoch"

stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
umask 022
mkdir -p "$stage/bin" "$stage/licenses"
sed -e "s/@ARCH@/$arch/" -e "s/@VERSION@/$version/" "$here/install.sh" > "$stage/install.sh"
cp "$here/config.yaml.tmpl" "$stage/config.yaml.tmpl"
cp "$gateway" "$stage/bin/defenseclaw-gateway"
cp "$helper" "$stage/bin/defenseclaw-sensor-helper"
printf '%s\n' "$version" > "$stage/VERSION"
for f in LICENSE NOTICE THIRD_PARTY_LICENSES.txt; do cp "$root/$f" "$stage/licenses/$f"; done
[ -z "$ca" ] || cp "$ca" "$stage/collector-ca.pem"
if [ -n "$policies" ]; then
  mkdir -p "$stage/policies"
  tar -C "$policies" --exclude='*.go' --exclude='*_test.rego' --exclude=./kernel --exclude=./sandbox \
    --exclude=./scanners -cf - . | tar -C "$stage/policies" -xf -
fi
# Regular files and folders only, with fixed modes.
if [ -n "$(find "$stage" ! -type f ! -type d -print -quit)" ]; then
  find "$stage" ! -type f ! -type d >&2; die "the package tree holds something other than files and folders"
fi
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/install.sh" "$stage/bin/defenseclaw-gateway" "$stage/bin/defenseclaw-sensor-helper"

mkdir -p "$out"
pkg="$out/defenseclaw-cowork-$arch.tar.gz"
# Top-level entries in byte order; tar sorts inside each folder.
mapfile -t entries < <(cd "$stage" && find . -mindepth 1 -maxdepth 1 | sed 's#^\./##' | LC_ALL=C sort)
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
  --no-acls --no-xattrs --no-selinux -C "$stage" -cf - "${entries[@]}" | gzip -9 -n > "$pkg.tmp"
mv -f "$pkg.tmp" "$pkg"
python3 "$here/check-package.py" --arch "$arch" --version "$version" "$pkg"
