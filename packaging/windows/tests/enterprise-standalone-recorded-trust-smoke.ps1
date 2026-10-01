# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# A hash-pinned standalone deployment keeps no payload manifest after install,
# so the installed CLI reaches the bootstrap with no pin. The bootstrap admits
# the installed module by the digest the protected deployment metadata
# recorded, and only when the running installer is the recorded one. This
# exercises the production Get-DefenseClawBootstrapRecordedModulePin in a
# disposable scratch directory. The administrator-owned path chain check is
# stubbed here (the bootstrap and exact-ACL smokes own it); a stubbed refusal
# stands in for an untrusted record. The standalone bootstrap runs only on
# PowerShell 7.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerSource = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\install-enterprise.ps1')
)
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $installerSource,
    [ref]$tokens,
    [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw 'could not parse install-enterprise.ps1'
}
$definitions = @(
    $ast.FindAll(
        {
            param($node)
            return (
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                [string]$node.Name -ceq 'Get-DefenseClawBootstrapRecordedModulePin'
            )
        },
        $true
    )
)
if ($definitions.Count -ne 1) {
    throw "expected one Get-DefenseClawBootstrapRecordedModulePin, found $($definitions.Count)"
}
. ([scriptblock]::Create([string]$definitions[0].Extent.Text))

$script:UntrustedMetadata = ''
function Assert-DefenseClawBootstrapModuleTrust {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUnsignedModule,
        [string]$PinnedSHA256,
        [string[]]$AllowedSignerSHA256 = @()
    )
    if (-not $AllowUnsignedModule) {
        throw 'the recorded-pin lookup must check the metadata as an unsigned trust anchor'
    }
    if ([string]::Equals($Path, $script:UntrustedMetadata, [StringComparison]::OrdinalIgnoreCase)) {
        throw "untrusted principal S-1-5-32-545 has write-like access to DefenseClaw enterprise installer module path: $Path"
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-TestSHA256([string]$Path) {
    return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-standalone-recorded-trust-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
$failures = [Collections.Generic.List[string]]::new()
try {
    $utf8 = [Text.UTF8Encoding]::new($false)
    $installer = [IO.Path]::Combine($root, 'install-enterprise.ps1')
    $module = [IO.Path]::Combine($root, 'DefenseClawEnterprise.psm1')
    $otherInstaller = [IO.Path]::Combine($root, 'other-install-enterprise.ps1')
    [IO.File]::WriteAllText($installer, '# installed installer', $utf8)
    [IO.File]::WriteAllText($module, '# installed module', $utf8)
    [IO.File]::WriteAllText($otherInstaller, '# a different installer', $utf8)
    $moduleHash = Get-TestSHA256 $module
    $installerHash = Get-TestSHA256 $installer
    $metadata = [IO.Path]::Combine($root, 'deployment.json')
    function Write-TestMetadata([hashtable]$Document) {
        [IO.File]::WriteAllText($metadata, ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), $utf8)
    }
    function Test-Pin([string]$Label, [string]$Want, [string]$Installer = $installer) {
        $got = Get-DefenseClawBootstrapRecordedModulePin -MetadataPath $metadata -InstallerPath $Installer
        if ($got -cne $Want) {
            $failures.Add("${Label}: pin '$got', want '$Want'")
        }
    }
    $recorded = @{
        schema_version = 1
        installed = $true
        profile = 'standalone'
        trust_mode = 'hash_pinned'
        hashes = @{ module = $moduleHash; installer = $installerHash; gateway = ('0' * 64) }
    }

    Test-Pin 'no metadata' ''

    Write-TestMetadata $recorded
    Test-Pin 'hash-pinned standalone deployment' $moduleHash

    $recorded.installed = $false
    Write-TestMetadata $recorded
    Test-Pin 'hash-pinned tombstone' $moduleHash
    $recorded.installed = $true

    Test-Pin 'a different running installer' '' $otherInstaller

    $script:UntrustedMetadata = $metadata
    Test-Pin 'metadata a standard user could write' ''
    $script:UntrustedMetadata = ''

    $authenticode = $recorded.Clone()
    $authenticode.trust_mode = 'authenticode'
    Write-TestMetadata $authenticode
    Test-Pin 'authenticode deployment' ''

    $secureClient = $recorded.Clone()
    $secureClient.Remove('profile')
    Write-TestMetadata $secureClient
    Test-Pin 'metadata without the standalone profile' ''

    $noModule = $recorded.Clone()
    $noModule.hashes = @{ installer = $installerHash }
    Write-TestMetadata $noModule
    Test-Pin 'metadata without a module digest' ''

    $badDigest = $recorded.Clone()
    $badDigest.hashes = @{ module = $moduleHash.ToUpperInvariant(); installer = $installerHash }
    Write-TestMetadata $badDigest
    Test-Pin 'non-canonical module digest' ''

    [IO.File]::WriteAllText($metadata, 'not json', $utf8)
    Test-Pin 'unparseable metadata' ''

    [IO.File]::WriteAllText($metadata, ('{"trust_mode":"hash_pinned","pad":"' + ('x' * 1048576) + '"}'), $utf8)
    Test-Pin 'oversized metadata' ''
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-recorded-trust-smoke: OK'
