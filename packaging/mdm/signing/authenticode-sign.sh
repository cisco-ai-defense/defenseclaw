#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# authenticode-sign.sh <file> - Authenticode-sign one Windows file in place
# with osslsigncode, then verify it and print the signer certificate's
# SHA-256 thumbprint (the value administrators pin in allowedsigners= /
# -AllowedSigners / enterprise.trust.allowed_signers).
#
# authenticode-sign.sh --thumbprint - print only that thumbprint of
# AUTHENTICODE_PFX, signing nothing (the value build-setup.sh takes as
# --expected-signer-sha256).
#
# Used as the --sign-command of packaging/windows/standalone/build-setup.sh
# by the release workflow and for customer re-signing. Signs PE files and
# PowerShell scripts (.ps1, .psm1; osslsigncode 2.5 or later).
#
# Environment (never pass secrets on the command line):
#   AUTHENTICODE_PFX            path of the PKCS#12 code-signing certificate
#   AUTHENTICODE_PFX_PASSWORD   its password (may be empty)
#   AUTHENTICODE_TIMESTAMP_URL  RFC 3161 timestamp server
#                               (default http://timestamp.digicert.com;
#                               "none" signs without a timestamp, for
#                               throwaway test certificates only)
#   AUTHENTICODE_CA_BUNDLE      optional CA bundle for the post-sign verify
#   AUTHENTICODE_EXPECTED_SHA256
#                               optional: refuse unless the signer
#                               certificate has exactly this thumbprint

set -euo pipefail

file=${1:?usage: authenticode-sign.sh <file> | --thumbprint}
thumbprint_only=0
if [ "$file" = --thumbprint ]; then
    thumbprint_only=1
else
    [ -f "$file" ] || { echo "authenticode-sign: no such file: $file" >&2; exit 1; }
fi
: "${AUTHENTICODE_PFX:?AUTHENTICODE_PFX must name the PKCS#12 signing certificate}"
[ -f "$AUTHENTICODE_PFX" ] || { echo "authenticode-sign: AUTHENTICODE_PFX does not exist" >&2; exit 1; }
[ "$thumbprint_only" -eq 1 ] || command -v osslsigncode >/dev/null 2>&1 || { echo "authenticode-sign: osslsigncode is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "authenticode-sign: openssl is required" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/dc-authenticode.XXXXXX")
trap 'rm -rf "$work"' EXIT
chmod 0700 "$work"

# The password never goes on argv: osslsigncode reads it from a 0600 file,
# openssl from the environment. Neither reads an empty password file, so a
# PFX without a password is opened without one.
export AUTHENTICODE_PFX_PASSWORD="${AUTHENTICODE_PFX_PASSWORD:-}"
password_args=()
if [ -n "$AUTHENTICODE_PFX_PASSWORD" ]; then
    password_file="$work/password"
    printf '%s' "$AUTHENTICODE_PFX_PASSWORD" >"$password_file"
    password_args=(-readpass "$password_file")
fi

# Signer certificate thumbprint = SHA-256 over the DER certificate, the same
# value Windows-side checks compute from SignerCertificate.RawData.
signer_thumbprint() {
    openssl pkcs12 -in "$AUTHENTICODE_PFX" -passin env:AUTHENTICODE_PFX_PASSWORD -clcerts -nokeys -out "$work/signer.pem" 2>/dev/null
    openssl x509 -in "$work/signer.pem" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
}

if [ "$thumbprint_only" -eq 1 ]; then
    signer_thumbprint
    exit 0
fi

# osslsigncode picks PE or script handling from the file extension, so the
# signed copy keeps the original name.
signed="$work/$(basename "$file")"
timestamp=(-ts "${AUTHENTICODE_TIMESTAMP_URL:-http://timestamp.digicert.com}")
[ "${AUTHENTICODE_TIMESTAMP_URL:-}" != none ] || timestamp=()
osslsigncode sign \
    -pkcs12 "$AUTHENTICODE_PFX" ${password_args[@]+"${password_args[@]}"} \
    -h sha256 \
    ${timestamp[@]+"${timestamp[@]}"} \
    -n "Cisco DefenseClaw" -i "https://github.com/cisco-ai-defense/defenseclaw" \
    -in "$file" -out "$signed" >/dev/null

verify_args=(verify)
[ -z "${AUTHENTICODE_CA_BUNDLE:-}" ] || verify_args+=(-CAfile "$AUTHENTICODE_CA_BUNDLE")
if ! osslsigncode "${verify_args[@]}" -in "$signed" >"$work/verify.log" 2>&1; then
    cat "$work/verify.log" >&2
    echo "authenticode-sign: the signed file does not verify" >&2
    exit 1
fi

thumbprint=$(signer_thumbprint)
if [ -n "${AUTHENTICODE_EXPECTED_SHA256:-}" ] &&
    [ "$thumbprint" != "$(printf '%s' "$AUTHENTICODE_EXPECTED_SHA256" | tr 'A-F' 'a-f')" ]; then
    echo "authenticode-sign: signer $thumbprint is not AUTHENTICODE_EXPECTED_SHA256" >&2
    exit 1
fi

mv -f "$signed" "$file"
echo "signed $(basename "$file") signer_sha256=$thumbprint"
