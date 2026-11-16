#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# packaging/windows/standalone/prove-signing-path.sh - prove the Authenticode
# path of the standalone Setup build with a throwaway self-signed certificate.
#
# It creates a code-signing certificate for this run only, builds
# DefenseClawSetup-Enterprise-Standalone-x64.exe with build-setup.sh
# --sign-command packaging/mdm/signing/authenticode-sign.sh --signing-type DEV
# and that certificate's thumbprint (so windows-avc-assembler verifies every
# signed inner file with osslsigncode), then checks that the outer Setup
# verifies against that certificate and carries the signed "standalone"
# payload. The certificate and its key are deleted on exit.
#
# The Setup it builds is a test artifact signed by an untrusted certificate:
# never ship it. The release dry run runs this script; a release signs only
# with the release environment's certificate.
#
# Usage:
#   packaging/windows/standalone/prove-signing-path.sh --version 1.4.0 --out-dir <dir>
#
# Prereqs: those of build-setup.sh, plus openssl and osslsigncode 2.5 or later.

set -euo pipefail

die() {
    printf 'prove-signing-path: %s\n' "$*" >&2
    exit 1
}

VERSION=""
OUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
        -h|--help) sed -n '5,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "${VERSION}" ] || die "--version is required"
[ -n "${OUT_DIR}" ] || die "--out-dir is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v osslsigncode >/dev/null 2>&1 || die "osslsigncode 2.5 or later is required"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SIGN="${REPO_ROOT}/packaging/mdm/signing/authenticode-sign.sh"

work=$(mktemp -d "${TMPDIR:-/tmp}/dc-signing-proof.XXXXXX")
trap 'rm -rf "$work"' EXIT
chmod 0700 "$work"

echo "==> creating a throwaway self-signed code-signing certificate"
openssl req -x509 -newkey rsa:3072 -sha256 -days 2 -nodes \
    -subj "/CN=DefenseClaw signing-path test certificate (not for release)" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" \
    -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
# A random password, so the proof opens the PFX the way the release does.
AUTHENTICODE_PFX_PASSWORD="$(openssl rand -hex 16)"
export AUTHENTICODE_PFX_PASSWORD
openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" \
    -out "$work/test.pfx" -passout env:AUTHENTICODE_PFX_PASSWORD 2>/dev/null

export AUTHENTICODE_PFX="$work/test.pfx"
# A throwaway certificate gets no timestamp; the post-sign verify of each
# file trusts that certificate alone.
export AUTHENTICODE_TIMESTAMP_URL=none
export AUTHENTICODE_CA_BUNDLE="$work/cert.pem"
SIGNER="$("${SIGN}" --thumbprint)"
[[ "${SIGNER}" =~ ^[0-9a-f]{64}$ ]] || die "cannot read the test certificate thumbprint"
export AUTHENTICODE_EXPECTED_SHA256="${SIGNER}"
echo "    test signer_sha256=${SIGNER}"

"${REPO_ROOT}/packaging/windows/standalone/build-setup.sh" \
    --version "${VERSION}" --out-dir "${OUT_DIR}" \
    --sign-command "${SIGN}" \
    --signing-type DEV --expected-signer-sha256 "${SIGNER}"

SETUP="${OUT_DIR}/DefenseClawSetup-Enterprise-Standalone-x64.exe"
echo "==> verifying the signed outer Setup"
osslsigncode verify -in "${SETUP}" -CAfile "$work/cert.pem" \
    -require-leaf-hash "sha256:${SIGNER}" >"$work/verify.log" 2>&1 || {
    cat "$work/verify.log" >&2
    die "the signed Setup does not verify against the test certificate"
}
python3 - "${OUT_DIR}/payload-manifest.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
if manifest.get("distribution_flavor") != "standalone" or manifest.get("unsigned"):
    sys.exit(f"prove-signing-path: payload flavor {manifest.get('distribution_flavor')!r}, unsigned={manifest.get('unsigned')!r}; want the signed standalone payload")
PY
echo "==> signing path proven: ${SETUP##*/} (test certificate, not for release)"
