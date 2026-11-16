#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Sign Claude Cowork VM sensor packages the way Claude Desktop accepts them
# (EDR guide v1.7, section 3.4): a detached binary OpenPGP signature over the
# package file, <package>.sig next to it, no notation, policy URL or key server,
# expiring at most 730 days after it is made. The key must be the Cowork-only
# signing key; it is used for nothing else.
#
#   COWORK_GPG_PRIVATE_KEY=<armored secret key> [COWORK_GPG_PASSPHRASE=...] \
#     COWORK_GPG_FINGERPRINT=<pinned fingerprint> \
#     sign.sh [--expire 180d] [--public-key-out FILE] [--published-key FILE] PACKAGE...
#   sign.sh --key-file KEY.asc [--passphrase-file FILE] --fingerprint FPR ...
#
# The key must have the pinned primary fingerprint (--fingerprint, or
# COWORK_GPG_FINGERPRINT); any other key is refused before anything is signed.
# --published-key names the public key a release already carries: a re-sign
# with a different key is refused, so it cannot replace those signatures.
# Each signature is checked with verify-signature.py against the exported
# public key before this exits 0.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
expire=180d key_file="" pass_file="" pub_out="" published_key="" want="${COWORK_GPG_FINGERPRINT:-}"
die() { echo "sign.sh: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --expire) expire=${2:?}; shift 2 ;;
    --key-file) key_file=${2:?}; shift 2 ;;
    --passphrase-file) pass_file=${2:?}; shift 2 ;;
    --public-key-out) pub_out=${2:?}; shift 2 ;;
    --published-key) published_key=${2:?}; shift 2 ;;
    --fingerprint) want=${2:?}; shift 2 ;;
    -h | --help) sed -n '4,22p' "$0"; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option $1" ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || die "name at least one package"
[[ "$expire" =~ ^([1-9][0-9]{0,2})d$ ]] && [ "${BASH_REMATCH[1]}" -le 730 ] ||
  die "--expire must be 1d to 730d (got $expire); gpg's 2y is 730d"
want="$(printf '%s' "$want" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
[ -n "$want" ] || die "no pinned Cowork key fingerprint: pass --fingerprint or set COWORK_GPG_FINGERPRINT"
[[ "$want" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]] || die "the pinned fingerprint is not 40 or 64 hex digits: $want"
[ -z "$published_key" ] || [ -f "$published_key" ] || die "no such published key: $published_key"

GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; chmod 0700 "$GNUPGHOME"
trap 'gpgconf --kill all > /dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
# An empty gpg.conf: no default notation, policy URL or key server can creep in.
: > "$GNUPGHOME/gpg.conf"
if [ -n "$key_file" ]; then
  gpg --batch --quiet --import "$key_file" || die "cannot import $key_file"
elif [ -n "${COWORK_GPG_PRIVATE_KEY:-}" ]; then
  printf '%s' "$COWORK_GPG_PRIVATE_KEY" | gpg --batch --quiet --import || die "cannot import COWORK_GPG_PRIVATE_KEY"
else
  die "no signing key: set COWORK_GPG_PRIVATE_KEY or pass --key-file"
fi
# Exactly one primary secret key: the Cowork-only key, nothing else.
mapfile -t fprs < <(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "sec" {want = 1; next} want && $1 == "fpr" {print $10; want = 0}')
[ "${#fprs[@]}" -gt 0 ] || die "the key file holds no secret key"
[ "${#fprs[@]}" = 1 ] || die "the key file holds ${#fprs[@]} secret keys; give it only the Cowork signing key"
fpr=${fprs[0]}
[ "$fpr" = "$want" ] || die "the key is $fpr, not the pinned Cowork key $want; refusing to sign"
if [ -n "$published_key" ]; then
  mapfile -t pubs < <(gpg --batch --with-colons --show-keys "$published_key" 2> /dev/null | awk -F: '$1 == "pub" {want = 1; next} want && $1 == "fpr" {print $10; want = 0}')
  [ "${#pubs[@]}" = 1 ] || die "$published_key does not hold exactly one public key"
  [ "${pubs[0]}" = "$fpr" ] || die "the release is signed by ${pubs[0]}; refusing to replace its signatures with key $fpr"
fi
passphrase="$GNUPGHOME/passphrase"
if [ -n "$pass_file" ]; then cp "$pass_file" "$passphrase"; else printf '%s' "${COWORK_GPG_PASSPHRASE:-}" > "$passphrase"; fi
public="$GNUPGHOME/public.asc"
gpg --batch --armor --export "$fpr" > "$public"
[ -z "$pub_out" ] || cp "$public" "$pub_out"

for pkg in "$@"; do
  [ -f "$pkg" ] || die "no such package: $pkg"
  rm -f "$pkg.sig"
  gpg --batch --yes --no-options --pinentry-mode loopback --passphrase-file "$passphrase" \
    --local-user "$fpr" --digest-algo SHA256 --default-sig-expire "$expire" \
    --detach-sign --output "$pkg.sig" "$pkg"
  python3 "$here/verify-signature.py" "$pkg.sig" --package "$pkg" --public-key "$public" --fingerprint "$fpr"
done
