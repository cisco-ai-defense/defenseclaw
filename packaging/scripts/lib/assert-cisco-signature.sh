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

    # `openssl pkcs7 -print_certs` emits one or more "subject=...\n
    # issuer=...\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE
    # -----" blocks. Split into per-cert PEMs, then extract each cert's
    # CN via `openssl x509 -noout -subject -nameopt multiline`. The
    # multiline nameopt emits one attribute per line with a stable
    # `<name> = <value>` shape, so a CN that legitimately contains
    # commas (e.g. `Cisco Systems, Inc.`) is preserved verbatim — the
    # earlier awk-on-oneline path stripped everything after the first
    # comma and turned that CN into "Cisco Systems", failing valid
    # Cisco signatures. See CR spec-002:PRRT_kwDORuAK-s6ahACT.
    #
    # Chain-vs-signer note: this checks that AT LEAST ONE cert in the
    # PKCS#7 chain carries the required publisher CN. `osslsigncode
    # verify -CAfile` is the primary chain-of-trust check — with a
    # correctly-pinned CA bundle, any chain that verifies is by
    # definition Cisco-issued. The CN check here is defense-in-depth
    # against an accidental non-Cisco cert bundled into the PKCS#7
    # container; a full SignerInfo → certificate binding would be
    # stronger and is tracked as a follow-up spec.
    local found=0
    local seen_cns=""
    local cert_pem
    cert_pem="$(mktemp -t cisco-sig.XXXXXX.pem)"
    # shellcheck disable=SC2064
    trap "rm -f '${pkcs7_pem}' '${certs_pem}' '${cert_pem}'" RETURN

    # Split certs.pem into individual BEGIN/END CERTIFICATE blocks.
    # awk keeps the block boundary state without external tools.
    local cn
    while IFS= read -r cn; do
        [ -z "${cn}" ] && continue
        seen_cns="${seen_cns}${cn}$'\n'"
        if [ "${cn}" = "${_DEFENSECLAW_CISCO_PUBLISHER_CN}" ]; then
            found=1
        fi
    done < <(
        awk -v out="${cert_pem}" '
            /-----BEGIN CERTIFICATE-----/ { inblock=1; content="" }
            inblock                       { content = content $0 ORS }
            /-----END CERTIFICATE-----/ && inblock {
                # Write the current cert block to `out`, ask openssl
                # for its CN via -nameopt multiline (one attr per
                # line), and emit ONLY the commonName value.
                printf "%s", content > out
                close(out)
                cmd = "openssl x509 -in " out " -noout -subject -nameopt multiline 2>/dev/null"
                while ((cmd | getline line) > 0) {
                    if (line ~ /commonName/) {
                        # Line shape:  "    commonName                = Cisco Systems, Inc."
                        sub(/.*commonName[[:space:]]*=[[:space:]]*/, "", line)
                        print line
                        break
                    }
                }
                close(cmd)
                inblock=0
            }
        ' "${certs_pem}"
    )

    if [ -z "${seen_cns}" ]; then
        die 4 "assert-cisco-signature: no certificate subjects found in ${path} PKCS#7"
    fi
    if [ "${found}" -eq 0 ]; then
        die 4 "assert-cisco-signature: ${path} does not carry a certificate with CN '${_DEFENSECLAW_CISCO_PUBLISHER_CN}' (found: $(printf '%s ' ${seen_cns}))"
    fi
}
