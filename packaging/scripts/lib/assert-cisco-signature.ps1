# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assert-cisco-signature.ps1 — Authenticode + Cisco publisher assertion.
#
# Dot-source this file; it exports `Assert-CiscoSignature` (and its CN
# reader, `Get-CiscoSignatureCommonName`) and no side effects. Used by packaging/scripts/lib/assemble.ps1 during the AVC-driven
# Windows managed-enterprise Setup assembly step (see
# docs/specs/002-windows-avc-packaging/requirements.md REQ-10).
#
# Contract:
#   - The file at $Path MUST carry a valid Authenticode signature
#     (Status == Valid — WinVerifyTrust chain-of-trust check).
#   - The signer certificate's subject MUST carry exactly one Common Name
#     (CN) attribute, and it MUST be exactly "Cisco Systems, Inc."
#     (case-sensitive per the parity plan; matches the retired
#     scripts/build-windows-enterprise-installer.ps1's Assert-CiscoSignature
#     contract).
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

function Get-CiscoSignatureCommonName {
    # Returns the one common name (CN attribute, 2.5.4.3) in the certificate's
    # DER-encoded subject, or $null when the subject is malformed, has no
    # common name, has more than one, or has one that is not a UTF8String,
    # PrintableString, IA5String, or BMPString. GetNameInfo(SimpleName) is
    # not used: for a subject without a CN, Windows returns its OU, O, or
    # e-mail address instead, so OU=Cisco Systems, Inc. would pass as the
    # publisher. The endpoint pins apply the same rule: the lifecycle module
    # (Get-DefenseClawCertificateCommonName), the installer bootstrap, and the
    # CMID broker (internal/managed/cmidbroker/library_trust.go).
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $der = [byte[]]$Certificate.SubjectName.RawData
    if ($null -eq $der -or $der.Length -lt 2) {
        return $null
    }
    # One DER header at $Offset, bounded by $Limit: returns the tag, the first
    # content byte, and the end of the content, or $null.
    $readElement = {
        param([int]$Offset, [int]$Limit)
        if ($Offset + 2 -gt $Limit) {
            return $null
        }
        $length = [int]$der[$Offset + 1]
        $content = $Offset + 2
        if ($length -ge 0x80) {
            $lengthBytes = $length -band 0x7f
            if ($lengthBytes -lt 1 -or $lengthBytes -gt 3 -or
                $content + $lengthBytes -gt $Limit) {
                return $null
            }
            $length = 0
            for ($index = 0; $index -lt $lengthBytes; $index++) {
                $length = ($length -shl 8) -bor [int]$der[$content + $index]
            }
            $content += $lengthBytes
        }
        if ($content + $length -gt $Limit) {
            return $null
        }
        return @([int]$der[$Offset], $content, ($content + $length))
    }
    $name = & $readElement 0 $der.Length
    if ($null -eq $name -or $name[0] -ne 0x30 -or $name[2] -ne $der.Length) {
        return $null
    }
    $commonNames = [Collections.Generic.List[string]]::new()
    $setOffset = $name[1]
    while ($setOffset -lt $name[2]) {
        $set = & $readElement $setOffset $name[2]
        if ($null -eq $set -or $set[0] -ne 0x31) {
            return $null
        }
        $attributeOffset = $set[1]
        while ($attributeOffset -lt $set[2]) {
            $attribute = & $readElement $attributeOffset $set[2]
            if ($null -eq $attribute -or $attribute[0] -ne 0x30) {
                return $null
            }
            $type = & $readElement $attribute[1] $attribute[2]
            if ($null -eq $type -or $type[0] -ne 0x06) {
                return $null
            }
            $value = & $readElement $type[2] $attribute[2]
            if ($null -eq $value -or $value[2] -ne $attribute[2]) {
                return $null
            }
            # id-at-commonName (2.5.4.3) is encoded as 55 04 03.
            if ($type[2] - $type[1] -eq 3 -and
                $der[$type[1]] -eq 0x55 -and
                $der[$type[1] + 1] -eq 0x04 -and
                $der[$type[1] + 2] -eq 0x03) {
                if ($value[0] -eq 0x0c -or $value[0] -eq 0x13 -or $value[0] -eq 0x16) {
                    $encoding = [Text.UTF8Encoding]::new($false, $true)
                }
                elseif ($value[0] -eq 0x1e) {
                    $encoding = [Text.UnicodeEncoding]::new($true, $false, $true)
                }
                else {
                    return $null
                }
                try {
                    $commonNames.Add(
                        $encoding.GetString($der, $value[1], $value[2] - $value[1])
                    )
                }
                catch {
                    return $null
                }
            }
            $attributeOffset = $attribute[2]
        }
        $setOffset = $set[2]
    }
    if ($commonNames.Count -ne 1) {
        return $null
    }
    return $commonNames[0]
}

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
    # The CN attribute itself, not the certificate's display name, which
    # falls back to the OU or O when the subject has no CN. The bash sibling
    # reads the commonName attribute the same way.
    $commonName = Get-CiscoSignatureCommonName -Certificate $sig.SignerCertificate
    if ($commonName -cne $script:DefenseClawCiscoPublisherCN) {
        throw "assert-cisco-signature: $Path signer CN mismatch (expected '$($script:DefenseClawCiscoPublisherCN)', got '$commonName'; subject '$($sig.SignerCertificate.Subject)')"
    }
}
