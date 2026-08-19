# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# binary-identity.ps1 — VERSIONINFO / product-name assertion for the three
# DefenseClaw Windows PE binaries.
#
# Dot-source this file; it exports `Assert-DefenseClawBinaryIdentity` and
# no side effects. Used by packaging/scripts/lib/assemble.ps1 to refuse a
# payload directory that mislabels a binary (e.g. a wrong-flavour build
# staged into the AVC handoff by accident).
#
# Contract:
#   - The file at $Path MUST have a Win32 VERSIONINFO block whose
#     ProductName matches $ExpectedProductName and whose ProductVersion
#     matches $ExpectedVersion (exact string match, no wildcards).
#   - CompanyName MUST be "Cisco Systems, Inc." to catch a
#     confused-deputy scenario where a third-party binary carrying
#     DefenseClaw's ProductName slips into the payload dir.
#   - Any mismatch throws a terminating error so the caller
#     (assemble.ps1) exits non-zero before the outer Setup EXE is built.
#
# The three PE binaries this helper is called against are:
#   defenseclaw.exe, defenseclaw-gateway.exe, defenseclaw-hook.exe.
# ProductName values are stamped by internal/tools/windowsresources
# during the DefenseClaw-side bundler cross-build; this helper is the
# assemble-side check that they survived the round trip.

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefenseClawCompanyName = 'Cisco Systems, Inc.'

function Assert-DefenseClawBinaryIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedProductName,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "assert-binary-identity: file not found: $Path"
    }
    $info = [Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path -LiteralPath $Path).ProviderPath)
    if ($null -eq $info) {
        throw "assert-binary-identity: $Path has no VERSIONINFO block"
    }
    if ($info.ProductName -cne $ExpectedProductName) {
        throw "assert-binary-identity: $Path ProductName mismatch (expected '$ExpectedProductName', got '$($info.ProductName)')"
    }
    if ($info.ProductVersion -cne $ExpectedVersion) {
        throw "assert-binary-identity: $Path ProductVersion mismatch (expected '$ExpectedVersion', got '$($info.ProductVersion)')"
    }
    if ($info.CompanyName -cne $script:DefenseClawCompanyName) {
        throw "assert-binary-identity: $Path CompanyName mismatch (expected '$($script:DefenseClawCompanyName)', got '$($info.CompanyName)')"
    }
}
