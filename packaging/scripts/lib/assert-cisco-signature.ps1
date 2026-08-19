# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assert-cisco-signature.ps1 — Authenticode + Cisco publisher assertion.
#
# Dot-source this file; it exports `Assert-CiscoSignature` and no side
# effects. Used by packaging/scripts/lib/assemble.ps1 during the AVC-driven
# Windows managed-enterprise Setup assembly step (see
# docs/specs/002-windows-avc-packaging/requirements.md REQ-10).
#
# Contract:
#   - The file at $Path MUST carry a valid Authenticode signature
#     (Status == Valid — WinVerifyTrust chain-of-trust check).
#   - The signer certificate's Subject Common Name MUST be exactly
#     "Cisco Systems, Inc." (case-sensitive per the parity plan; matches
#     the retired scripts/build-windows-enterprise-installer.ps1's
#     Assert-CiscoSignature contract).
#   - Any deviation throws a descriptive terminating error so the caller
#     (assemble.ps1) exits with the "signature assertion failed" exit
#     code (4 per design.md § Interfaces).
#
# The bash sibling packaging/scripts/lib/assert-cisco-signature.sh uses
# osslsigncode/openssl to enforce the same contract on Linux runners so
# the round-trip integration test at
# docs/specs/002-windows-avc-packaging/tasks.md task 6 can drive the
# whole flow on ubuntu-latest.

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefenseClawCiscoPublisherCN = 'Cisco Systems, Inc.'

function Assert-CiscoSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "assert-cisco-signature: file not found: $Path"
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') {
        throw "assert-cisco-signature: $Path has invalid Authenticode signature: status=$($sig.Status), message=$($sig.StatusMessage)"
    }
    if ($null -eq $sig.SignerCertificate) {
        throw "assert-cisco-signature: $Path has no signer certificate"
    }
    # X509Certificate2.GetNameInfo(SimpleName, false) returns the Subject
    # CN with the CN= prefix stripped and any trailing metadata gone —
    # the same shape the retired PowerShell helper compared against.
    $simpleName = $sig.SignerCertificate.GetNameInfo(
        [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false)
    if ($simpleName -cne $script:DefenseClawCiscoPublisherCN) {
        throw "assert-cisco-signature: $Path signer CN mismatch (expected '$($script:DefenseClawCiscoPublisherCN)', got '$simpleName')"
    }
}
