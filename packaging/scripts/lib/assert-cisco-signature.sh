# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assert-cisco-signature.sh — POSIX port of Assert-CiscoSignature.
#
# Source (dot-include) this file — it defines `defenseclaw_assert_cisco_signature`
# and no side effects. Used by packaging/scripts/lib/assemble.sh during the
# AVC-driven Windows managed-enterprise Setup assembly step when the runner
# is Linux (see docs/specs/002-windows-avc-packaging/tasks.md task 2).
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

    # Extract the leaf signer cert to a temp file and read its Subject
    # CN via openssl. -in <(...) via process substitution would be
    # simpler, but process substitution is bash-only and this file
    # also has to work under dash/ash for a broader CI base image
    # future-proofing; use mktemp instead.
    local cert_pem
    cert_pem="$(mktemp -t cisco-sig.XXXXXX.pem)"
    trap 'rm -f "${cert_pem}"' RETURN

    if ! osslsigncode extract-signature -pem \
            -in "${path}" \
            -out "${cert_pem}" >/dev/null 2>&1; then
        die 4 "assert-cisco-signature: could not extract signer cert from ${path}"
    fi

    local subject_cn
    subject_cn=$(openssl x509 -in "${cert_pem}" -noout -subject -nameopt multiline \
        | awk '/commonName/ { sub(/.*commonName[[:space:]]*=[[:space:]]*/, ""); print; exit }')

    if [ -z "${subject_cn}" ]; then
        die 4 "assert-cisco-signature: could not read signer CN from ${path}"
    fi
    if [ "${subject_cn}" != "${_DEFENSECLAW_CISCO_PUBLISHER_CN}" ]; then
        die 4 "assert-cisco-signature: ${path} signer CN mismatch (expected '${_DEFENSECLAW_CISCO_PUBLISHER_CN}', got '${subject_cn}')"
    fi
}
