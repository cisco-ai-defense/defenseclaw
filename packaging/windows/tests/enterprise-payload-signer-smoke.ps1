# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Regression coverage for the enterprise payload signer pin. A payload file
# must carry a valid Authenticode signature from the DefenseClaw publisher, or
# from a certificate an administrator named by SHA-256 fingerprint. A valid
# signature from any other publisher is rejected. -AllowUnsigned keeps its
# certification-only contract. Read-only: this script imports the module and
# the installer's bootstrap helpers and never mutates machine state.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
$installerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\install-enterprise.ps1'))
$assemblyHelperPath = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\scripts\lib\assert-cisco-signature.ps1')
)

function New-SmokeSignerCertificate {
    param([Parameter(Mandatory)][string]$Subject)
    $rsa = [Security.Cryptography.RSACng]::new(2048)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $issued = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        try {
            # Keep only the public certificate, as Get-AuthenticodeSignature does.
            return [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $issued.RawData
            )
        }
        finally {
            $issued.Dispose()
        }
    }
    finally {
        $rsa.Dispose()
    }
}

function Get-SmokeCertificateSha256 {
    param([Parameter(Mandatory)]$Certificate)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $hasher.ComputeHash($Certificate.RawData)
        ) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Assert-SmokeThrows {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        [Parameter(Mandatory)][string]$Expected
    )
    $message = $null
    try {
        & $Script | Out-Null
    }
    catch {
        $message = [string]$_.Exception.Message
    }
    if ($null -eq $message) {
        throw "$Name was accepted"
    }
    if ($message -notmatch $Expected) {
        throw "$Name failed with an unexpected error: $message"
    }
}

$cisco = New-SmokeSignerCertificate -Subject 'CN="Cisco Systems, Inc.", O="Cisco Systems, Inc.", C=US'
$ciscoNearMiss = New-SmokeSignerCertificate -Subject 'CN=Cisco Systems Inc., O="Cisco Systems, Inc.", C=US'
$ciscoCase = New-SmokeSignerCertificate -Subject 'CN="cisco systems, inc.", C=US'
$customer = New-SmokeSignerCertificate -Subject 'CN=Contoso Code Signing, O=Contoso, C=US'
# Without a CN, Windows' simple display name falls back to the OU, then the O,
# so these certificates display as 'Cisco Systems, Inc.' but have no publisher
# common name. Two CNs are ambiguous and are refused as well.
$ciscoUnitOnly = New-SmokeSignerCertificate -Subject 'OU="Cisco Systems, Inc.", O=Example, C=US'
$ciscoOrganizationOnly = New-SmokeSignerCertificate -Subject 'O="Cisco Systems, Inc.", C=US'
$ciscoTwoNames = New-SmokeSignerCertificate -Subject 'CN="Cisco Systems, Inc.", CN=Example, C=US'
$ciscoQuoted = New-SmokeSignerCertificate -Subject 'O="Example, CN=Cisco Systems, Inc.", C=US'
foreach ($premise in @($ciscoUnitOnly, $ciscoOrganizationOnly)) {
    $display = $premise.GetNameInfo(
        [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if ($display -cne 'Cisco Systems, Inc.') {
        throw "fixture premise: '$($premise.Subject)' displays as '$display', not the publisher"
    }
}
$noCommonName = @(
    @('OU-only publisher', $ciscoUnitOnly),
    @('O-only publisher', $ciscoOrganizationOnly),
    @('two common names', $ciscoTwoNames),
    @('common name inside another value', $ciscoQuoted)
)
$customerSha256 = Get-SmokeCertificateSha256 -Certificate $customer
$otherSha256 = 'ab' * 32

# ---------------------------------------------------------------------------
# Installer bootstrap: the module's signer is checked before Import-Module, so
# the installer carries its own copy of the policy. Load exactly those
# functions from the installer AST without executing the installer body.
# ---------------------------------------------------------------------------
$tokens = $null
$parseErrors = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile(
    $installerPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "installer parser errors: $($parseErrors.Message -join '; ')"
}
foreach ($name in @(
    'ConvertTo-DefenseClawBootstrapTrustedSignerSet',
    'Get-DefenseClawBootstrapCertificateCommonName',
    'Assert-DefenseClawBootstrapModuleSigner'
)) {
    $definition = $installerAst.Find(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
        },
        $false
    )
    if ($null -eq $definition) {
        throw "installer does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

# Setup assembly's helper requires PowerShell 7 as a file, but its CN reader
# is the same code, so load just that function on both engines.
$assemblyAst = [Management.Automation.Language.Parser]::ParseFile(
    $assemblyHelperPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "assembly helper parser errors: $($parseErrors.Message -join '; ')"
}
$assemblyReader = $assemblyAst.Find(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Get-CiscoSignatureCommonName'
    },
    $false
)
if ($null -eq $assemblyReader) {
    throw 'assembly helper does not define Get-CiscoSignatureCommonName'
}
. ([scriptblock]::Create($assemblyReader.Extent.Text))

$bootstrapSet = ConvertTo-DefenseClawBootstrapTrustedSignerSet -Value @(
    "$($customerSha256.ToUpperInvariant()), $customerSha256",
    $otherSha256
)
if ($bootstrapSet.Count -ne 2 -or $bootstrapSet[0] -cne $customerSha256 -or
    $bootstrapSet[1] -cne $otherSha256) {
    throw "bootstrap signer set did not normalize and deduplicate: $($bootstrapSet -join ',')"
}
if ((ConvertTo-DefenseClawBootstrapTrustedSignerSet -Value $null).Count -ne 0) {
    throw 'bootstrap signer set of $null is not empty'
}
Assert-SmokeThrows -Name 'bootstrap SHA-1 thumbprint' -Expected 'SHA-1' -Script {
    ConvertTo-DefenseClawBootstrapTrustedSignerSet -Value @($customer.Thumbprint)
}
Assert-SmokeThrows -Name 'bootstrap short fingerprint' -Expected '64-hex' -Script {
    ConvertTo-DefenseClawBootstrapTrustedSignerSet -Value @($customerSha256.Substring(1))
}
Assert-DefenseClawBootstrapModuleSigner `
    -SignerCertificate $cisco `
    -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
    -AdditionalTrustedSignerSha256 @()
Assert-SmokeThrows -Name 'bootstrap foreign module signer' -Expected 'not the DefenseClaw publisher' -Script {
    Assert-DefenseClawBootstrapModuleSigner `
        -SignerCertificate $customer `
        -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
        -AdditionalTrustedSignerSha256 @($otherSha256)
}
Assert-SmokeThrows -Name 'bootstrap near-miss publisher' -Expected 'not the DefenseClaw publisher' -Script {
    Assert-DefenseClawBootstrapModuleSigner `
        -SignerCertificate $ciscoNearMiss `
        -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
        -AdditionalTrustedSignerSha256 @()
}
foreach ($case in $noCommonName) {
    $candidate = $case[1]
    Assert-SmokeThrows -Name "bootstrap $($case[0])" -Expected 'not the DefenseClaw publisher' -Script {
        Assert-DefenseClawBootstrapModuleSigner `
            -SignerCertificate $candidate `
            -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
            -AdditionalTrustedSignerSha256 @()
    }
}
Assert-SmokeThrows -Name 'bootstrap missing signer' -Expected 'no signer certificate' -Script {
    Assert-DefenseClawBootstrapModuleSigner `
        -SignerCertificate $null `
        -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
        -AdditionalTrustedSignerSha256 @()
}
Assert-DefenseClawBootstrapModuleSigner `
    -SignerCertificate $customer `
    -Path 'C:\fixture\DefenseClawEnterprise.psm1' `
    -AdditionalTrustedSignerSha256 $bootstrapSet

# ---------------------------------------------------------------------------
# Enterprise module: payload source policy.
# ---------------------------------------------------------------------------
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClawEnterprise module was not imported'
}

$moduleResult = & $module {
    param($Cisco, $CiscoNearMiss, $CiscoCase, $Customer, $CustomerSha256, $OtherSha256, $NoCommonName)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Assert-ModuleThrows {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][scriptblock]$Script,
            [Parameter(Mandatory)][string]$Expected
        )
        $message = $null
        try {
            & $Script | Out-Null
        }
        catch {
            $message = [string]$_.Exception.Message
        }
        if ($null -eq $message) {
            throw "$Name was accepted"
        }
        if ($message -notmatch $Expected) {
            throw "$Name failed with an unexpected error: $message"
        }
    }

    $set = ConvertTo-DefenseClawTrustedSignerSet -Value @(
        "$($CustomerSha256.ToUpperInvariant());$CustomerSha256 $OtherSha256"
    )
    if ($set.Count -ne 2 -or $set[0] -cne $CustomerSha256 -or $set[1] -cne $OtherSha256) {
        throw "module signer set did not normalize and deduplicate: $($set -join ',')"
    }
    if ((ConvertTo-DefenseClawTrustedSignerSet -Value @()).Count -ne 0) {
        throw 'module signer set of an empty list is not empty'
    }
    Assert-ModuleThrows -Name 'module SHA-1 thumbprint' -Expected 'SHA-1' -Script {
        ConvertTo-DefenseClawTrustedSignerSet -Value @($Customer.Thumbprint)
    }
    Assert-ModuleThrows -Name 'module non-hex fingerprint' -Expected '64-hex' -Script {
        ConvertTo-DefenseClawTrustedSignerSet -Value @('g' * 64)
    }
    Assert-ModuleThrows -Name 'module oversized signer set' -Expected 'at most 16' -Script {
        ConvertTo-DefenseClawTrustedSignerSet -Value @(
            0..16 | ForEach-Object { '{0:x64}' -f $_ }
        )
    }
    if ((Get-DefenseClawCertificateSha256 -Certificate $Customer) -cne $CustomerSha256) {
        throw 'module certificate fingerprint is not SHA-256 over the DER certificate'
    }

    Assert-DefenseClawPayloadSigner `
        -SignerCertificate $Cisco `
        -Label 'fixture' `
        -Path 'C:\fixture\payload.exe' `
        -AdditionalTrustedSignerSha256 @()
    foreach ($case in @(
        @('near-miss publisher', $CiscoNearMiss),
        @('case-folded publisher', $CiscoCase),
        @('foreign publisher', $Customer)
    ) + $NoCommonName) {
        $candidate = $case[1]
        Assert-ModuleThrows -Name "module $($case[0])" -Expected 'not the DefenseClaw publisher' -Script {
            Assert-DefenseClawPayloadSigner `
                -SignerCertificate $candidate `
                -Label 'fixture' `
                -Path 'C:\fixture\payload.exe' `
                -AdditionalTrustedSignerSha256 @($OtherSha256)
        }
    }
    Assert-ModuleThrows -Name 'module missing signer' -Expected 'no signer certificate' -Script {
        Assert-DefenseClawPayloadSigner `
            -SignerCertificate $null `
            -Label 'fixture' `
            -Path 'C:\fixture\payload.exe' `
            -AdditionalTrustedSignerSha256 @()
    }
    Assert-DefenseClawPayloadSigner `
        -SignerCertificate $Customer `
        -Label 'fixture' `
        -Path 'C:\fixture\payload.exe' `
        -AdditionalTrustedSignerSha256 @($CustomerSha256.ToUpperInvariant())

    # A real, validly signed file from another publisher: before the pin, any
    # Valid signature was accepted as a DefenseClaw payload.
    $foreignSigned = $null
    foreach ($candidatePath in @(
        [IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        [IO.Path]::Combine($PSHOME, 'pwsh.exe'),
        [IO.Path]::Combine($PSHOME, 'powershell.exe')
    )) {
        if (-not [IO.File]::Exists($candidatePath)) {
            continue
        }
        $candidateSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $candidatePath
        if ($candidateSignature.Status -eq [Management.Automation.SignatureStatus]::Valid -and
            $null -ne $candidateSignature.SignerCertificate) {
            $foreignSigned = [pscustomobject]@{
                path = $candidatePath
                sha256 = Get-DefenseClawCertificateSha256 `
                    -Certificate $candidateSignature.SignerCertificate
            }
            break
        }
    }
    $foreignSignerRejected = $false
    $foreignDescriptorRecheckPinned = $false
    if ($null -ne $foreignSigned) {
        Assert-ModuleThrows -Name 'validly signed foreign payload' -Expected 'not the DefenseClaw publisher' -Script {
            Assert-DefenseClawRegularSource `
                -Path $foreignSigned.path `
                -Label 'gateway executable' `
                -Authenticode
        }
        Assert-ModuleThrows -Name 'validly signed foreign descriptor' -Expected 'not the DefenseClaw publisher' -Script {
            Get-DefenseClawSourceDescriptor `
                -Path $foreignSigned.path `
                -Label 'gateway executable' `
                -Authenticode
        }
        [void](Assert-DefenseClawRegularSource `
            -Path $foreignSigned.path `
            -Label 'gateway executable' `
            -Authenticode `
            -AdditionalTrustedSignerSha256 @($foreignSigned.sha256))
        # -AllowUnsigned keeps its certification-only contract unchanged.
        [void](Assert-DefenseClawRegularSource `
            -Path $foreignSigned.path `
            -Label 'gateway executable' `
            -Authenticode `
            -AllowUnsigned)
        $foreignSignerRejected = $true

        $descriptor = Get-DefenseClawSourceDescriptor `
            -Path $foreignSigned.path `
            -Label 'gateway executable' `
            -Authenticode `
            -AdditionalTrustedSignerSha256 @($foreignSigned.sha256)
        if (@($descriptor.trusted_signer_sha256) -cnotcontains $foreignSigned.sha256) {
            throw 'source descriptor did not record its signer policy'
        }
        [void](Assert-DefenseClawSourceDescriptorCurrent -Source $descriptor)
        # A descriptor without the recorded policy re-checks against the
        # publisher alone.
        $legacy = @{} + $descriptor
        $legacy.Remove('trusted_signer_sha256')
        Assert-ModuleThrows -Name 'descriptor re-check without recorded policy' -Expected 'not the DefenseClaw publisher' -Script {
            Assert-DefenseClawSourceDescriptorCurrent -Source $legacy
        }
        $foreignDescriptorRecheckPinned = $true
    }

    # The lifecycle entry validates the parameter before any read or mutation.
    Assert-ModuleThrows -Name 'lifecycle malformed fingerprint' -Expected '64-hex' -Script {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -AdditionalTrustedSignerSha256 @('not-a-fingerprint')
    }
    Assert-ModuleThrows -Name 'lifecycle signer list with -AllowUnsigned' -Expected 'cannot be combined with -AllowUnsigned' -Script {
        Invoke-DefenseClawEnterpriseLifecycle `
            -Action Status `
            -AllowUnsigned `
            -AdditionalTrustedSignerSha256 @($CustomerSha256)
    }

    $commonNames = @{}
    foreach ($certificate in @($Cisco, $CiscoNearMiss, $CiscoCase, $Customer) + @(
            $NoCommonName | ForEach-Object { $_[1] }
        )) {
        $commonNames[$certificate.Thumbprint] = Get-DefenseClawCertificateCommonName `
            -Certificate $certificate
    }

    return [pscustomobject]@{
        common_names = $commonNames
        foreign_signer_available = $null -ne $foreignSigned
        foreign_signer_rejected = $foreignSignerRejected
        foreign_descriptor_recheck_pinned = $foreignDescriptorRecheckPinned
    }
} $cisco $ciscoNearMiss $ciscoCase $customer $customerSha256 $otherSha256 $noCommonName

# The module, the installer bootstrap, and Setup assembly read the same CN.
$expectedCommonNames = @(
    @($cisco, 'Cisco Systems, Inc.'),
    @($ciscoNearMiss, 'Cisco Systems Inc.'),
    @($ciscoCase, 'cisco systems, inc.'),
    @($customer, 'Contoso Code Signing')
) + @($noCommonName | ForEach-Object { , @($_[1], $null) })
foreach ($expected in $expectedCommonNames) {
    $certificate = $expected[0]
    $readers = [ordered]@{
        module = $moduleResult.common_names[$certificate.Thumbprint]
        bootstrap = Get-DefenseClawBootstrapCertificateCommonName -Certificate $certificate
        assembly = Get-CiscoSignatureCommonName -Certificate $certificate
    }
    foreach ($reader in $readers.GetEnumerator()) {
        if ($reader.Value -cne $expected[1]) {
            throw (
                "$($reader.Key) common name of '$($certificate.Subject)' is " +
                "'$($reader.Value)', want '$($expected[1])'"
            )
        }
    }
}

foreach ($certificate in @($cisco, $ciscoNearMiss, $ciscoCase, $customer) + @(
        $noCommonName | ForEach-Object { $_[1] }
    )) {
    $certificate.Dispose()
}

[pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    bootstrap_signer_pinned = $true
    module_signer_pinned = $true
    signer_common_name_required = $true
    signer_fingerprint_validated = $true
    lifecycle_parameter_validated = $true
    foreign_signer_available = [bool]$moduleResult.foreign_signer_available
    foreign_signer_rejected = [bool]$moduleResult.foreign_signer_rejected
    foreign_descriptor_recheck_pinned = [bool]$moduleResult.foreign_descriptor_recheck_pinned
} | ConvertTo-Json -Compress
