#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assert-cisco-signature.sh — bash port of Assert-CiscoSignature.
#
# Source (dot-include) this file from bash — it defines
# `defenseclaw_assert_cisco_signature` and no side effects. Uses bash
# arrays and here-docs, so it requires bash 4+; it is not POSIX sh
# (an earlier version claimed POSIX portability, which was wrong).
#
# Used by packaging/scripts/lib/assemble.sh during the AVC-driven
# Windows managed-enterprise Setup assembly step when the runner is
# Linux (see docs/specs/002-windows-avc-packaging/tasks.md task 2).
#
# Contract:
#   - The file at $1 MUST carry a valid Authenticode signature
#     (osslsigncode verify exit 0, no chain error).
#   - The signer certificate's Subject Common Name MUST be exactly
#     "Cisco Systems, Inc." — same string the pwsh helper's
#     GetNameInfo(SimpleName) returns.
#   - Any deviation calls `die <code> <msg>` (a function the caller —
#     assemble.sh — must define). Signature/verify failures pass code 4;
#     missing tools (osslsigncode/openssl) pass code 6. The caller
#     controls how those codes map onto its exit-code table
#     (design.md § Interfaces: 4=signature, 6=io).
#
# Dependencies (all installed on the ubuntu-latest CI runner via the
# workflow's setup step): osslsigncode, openssl.
#
# For a PowerShell/pwsh runner, use packaging/scripts/lib/assert-cisco-signature.ps1
# instead — the two are contract-equivalent, differ only in the
# underlying signature-verification tooling.

# Guard idempotent double-source: repeated `.` of this file must not
# redefine constants or leak state.
if [ "${_DEFENSECLAW_ASSERT_CISCO_SIGNATURE_SOURCED:-0}" = "1" ]; then
    return 0
fi
_DEFENSECLAW_ASSERT_CISCO_SIGNATURE_SOURCED=1

readonly _DEFENSECLAW_CISCO_PUBLISHER_CN='Cisco Systems, Inc.'

# defenseclaw_assert_cisco_signature <path>
#
# Verifies an Authenticode signature and asserts the signer CN. Exits
# via the caller's `die` on any failure so the caller controls the
# exit code shape. The extracted signer cert lives in a mktemp'd file
# that is cleaned up on function return (bash trap can't handle a
# per-function cleanup, so this uses a subshell for the extraction).
defenseclaw_assert_cisco_signature() {
    local path="${1:?}"

    if [ ! -f "${path}" ]; then
        die 4 "assert-cisco-signature: file not found: ${path}"
    fi

    if ! command -v osslsigncode >/dev/null 2>&1; then
        die 6 "assert-cisco-signature: osslsigncode is required but not on PATH"
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        die 6 "assert-cisco-signature: openssl is required but not on PATH"
    fi

    # osslsigncode verify exits 0 on a valid signature with a trusted
    # chain. --require-leaf-hash pins the leaf certificate hash if the
    # caller wants to enforce a specific cert, but we do CN matching
    # instead to mirror the pwsh helper's contract. --CAfile is passed
    # by the caller via the DEFENSECLAW_CISCO_CA_BUNDLE env if a
    # non-system trust store is required (the CI round-trip test with
    # a disposable cert sets this to the disposable CA).
    local verify_args=(verify)
    if [ -n "${DEFENSECLAW_CISCO_CA_BUNDLE:-}" ]; then
        verify_args+=(-CAfile "${DEFENSECLAW_CISCO_CA_BUNDLE}")
    fi
    verify_args+=("${path}")

    local verify_output
    if ! verify_output=$(osslsigncode "${verify_args[@]}" 2>&1); then
        die 4 "assert-cisco-signature: ${path} failed osslsigncode verify:
${verify_output}"
    fi

    # osslsigncode extract-signature -pem emits a PEM-encoded PKCS#7
    # container (SignedData), NOT a bare X.509 certificate. `openssl
    # x509 -in <pkcs7>` fails on every valid signature. Use `openssl
    # pkcs7 -inform PEM -print_certs -in <pkcs7>` to get all certs in
    # the chain, then select the signer explicitly. The signer is the
    # cert whose Subject matches the SignerInfo's serial/issuer, but
    # for the CN check we only need to find the leaf that carries the
    # required CN — so we walk every printed cert and require at
    # least one match.
    local pkcs7_pem
    pkcs7_pem="$(mktemp -t cisco-sig.XXXXXX.p7)"
    local certs_pem
    certs_pem="$(mktemp -t cisco-sig.XXXXXX.certs)"
    # shellcheck disable=SC2064
    trap "rm -f '${pkcs7_pem}' '${certs_pem}'" RETURN

    if ! osslsigncode extract-signature -pem \
            -in "${path}" \
            -out "${pkcs7_pem}" >/dev/null 2>&1; then
        die 4 "assert-cisco-signature: could not extract PKCS#7 from ${path}"
    fi

    if ! openssl pkcs7 -inform PEM -print_certs \
            -in "${pkcs7_pem}" -out "${certs_pem}" 2>/dev/null; then
        die 4 "assert-cisco-signature: could not decode PKCS#7 from ${path}"
    fi

    # `openssl pkcs7 -print_certs` emits repeated "subject=...\nissuer=
    # ...\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    # blocks. Extract every subject line's CN and require the required
    # publisher CN to appear at least once. This is robust against the
    # chain order osslsigncode picks and matches the pwsh helper's
    # X509Certificate2.GetNameInfo(SimpleName) semantics — publisher
    # match is what matters, not chain position.
    local subject_cns
    subject_cns=$(awk -F'CN[[:space:]]*=[[:space:]]*' '
        /^subject=/ && NF>1 {
            cn = $2
            # CN may be followed by a comma-separated attribute; strip
            # everything from the first comma or slash onward.
            sub(/,.*$/, "", cn)
            sub(/\/.*$/, "", cn)
            print cn
        }
    ' "${certs_pem}")

    if [ -z "${subject_cns}" ]; then
        die 4 "assert-cisco-signature: no certificate subjects found in ${path} PKCS#7"
    fi

    local found=0
    while IFS= read -r cn; do
        [ -z "${cn}" ] && continue
        if [ "${cn}" = "${_DEFENSECLAW_CISCO_PUBLISHER_CN}" ]; then
            found=1
            break
        fi
    done <<EOF
${subject_cns}
EOF

    if [ "${found}" -eq 0 ]; then
        die 4 "assert-cisco-signature: ${path} does not carry a certificate with CN '${_DEFENSECLAW_CISCO_PUBLISHER_CN}' (found: $(printf '%s ' ${subject_cns}))"
    fi
}
