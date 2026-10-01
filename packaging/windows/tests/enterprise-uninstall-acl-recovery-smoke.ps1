# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1'
))
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$fixtureName = 'DefenseClawAclRepair-' + [Guid]::NewGuid().ToString('N')
$fixtureRoot = Microsoft.PowerShell.Management\Join-Path `
    $env:ProgramData `
    $fixtureName
$fixtureFull = [IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\')
$programDataFull = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\')
if (-not $fixtureFull.StartsWith(
        $programDataFull + '\',
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $fixtureName -cnotmatch '^DefenseClawAclRepair-[a-f0-9]{32}$' -or
    (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot)) {
    throw 'disposable ACL recovery fixture path is not unique and bounded'
}

try {
    $result = & $module {
        param([string]$StateRoot)
        Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $WarningPreference = 'SilentlyContinue'

        $installState = Microsoft.PowerShell.Management\Join-Path `
            $StateRoot `
            'install'
        [void](New-DefenseClawProtectedDirectory -Path $StateRoot)
        [void](New-DefenseClawProtectedDirectory -Path $installState)
        $layout = @{
            StateRoot = $StateRoot
            InstallStateDirectory = $installState
            MetadataPath = (Microsoft.PowerShell.Management\Join-Path `
                $installState `
                'deployment.json')
            AgentApplicationControlAttestationPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $installState `
                    'agent-application-control-attestation.json'
            )
            StateRootAncestors = @()
        }
        $metadataPath = [string]$layout.MetadataPath
        $attestationPath = [string]$layout.AgentApplicationControlAttestationPath
        Microsoft.PowerShell.Management\Set-Content `
            -LiteralPath $metadataPath `
            -Value '{"fixture":true}' `
            -Encoding UTF8
        Microsoft.PowerShell.Management\Set-Content `
            -LiteralPath $attestationPath `
            -Value '{"fixture":true}' `
            -Encoding UTF8
        $expected = New-DefenseClawCanonicalPathAcl `
            -IsDirectory:$false `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
        foreach ($path in @($metadataPath, $attestationPath)) {
            Set-DefenseClawPathAcl `
                -Path $path `
                -Kind AdminFile `
                -GatewayServiceSID $script:AdministratorsSID
        }
        $metadataHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $metadataPath `
                -Algorithm SHA256
        ).Hash
        [void](Repair-DefenseClawUninstallAdminFileAcl `
            -Layout $layout `
            -Kind deployment)
        Assert-DefenseClawCanonicalPathAcl `
            -Path $metadataPath `
            -Expected $expected
        foreach ($path in @($metadataPath, $attestationPath)) {
            $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path
            $acl.SetAccessRuleProtection($false, $true)
            if ([string]::Equals(
                    $path,
                    $metadataPath,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $acl.AddAccessRule(
                    [Security.AccessControl.FileSystemAccessRule]::new(
                        'BUILTIN\Users',
                        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                        [Security.AccessControl.AccessControlType]::Allow
                    )
                )
            }
            Microsoft.PowerShell.Security\Set-Acl `
                -LiteralPath $path `
                -AclObject $acl
            if ((Microsoft.PowerShell.Security\Get-Acl `
                    -LiteralPath $path).AreAccessRulesProtected) {
                throw "fixture ACL did not inherit: $path"
            }
        }
        [void](Repair-DefenseClawUninstallAdminFileAcl `
            -Layout $layout `
            -Kind deployment)
        $attestationHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $attestationPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $badAttestationHash = ('0' * 64)
        if ($badAttestationHash -ceq $attestationHash) {
            $badAttestationHash = ('f' * 64)
        }
        $badHashRejected = $false
        try {
            [void](Repair-DefenseClawUninstallAdminFileAcl `
                -Layout $layout `
                -Kind attestation `
                -ExpectedSHA256 $badAttestationHash)
        }
        catch {
            $badHashRejected = $_.Exception.Message -match
                'changed attestation content'
        }
        if (-not $badHashRejected -or
            (Microsoft.PowerShell.Security\Get-Acl `
                -LiteralPath $attestationPath).AreAccessRulesProtected) {
            throw 'uninstall ACL recovery accepted changed attestation evidence'
        }
        [void](Repair-DefenseClawUninstallAdminFileAcl `
            -Layout $layout `
            -Kind attestation `
            -ExpectedSHA256 $attestationHash)
        if ((Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $metadataPath `
                -Algorithm SHA256).Hash -cne $metadataHash) {
            throw 'deployment metadata bytes changed during ACL recovery'
        }
        foreach ($path in @($metadataPath, $attestationPath)) {
            Assert-DefenseClawCanonicalPathAcl `
                -Path $path `
                -Expected $expected
        }
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $metadataPath
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            'BUILTIN\Users',
            [Security.AccessControl.FileSystemRights]::Write,
            [Security.AccessControl.AccessControlType]::Allow
        ))
        Microsoft.PowerShell.Security\Set-Acl `
            -LiteralPath $metadataPath `
            -AclObject $acl
        $foreignWriterRejected = $false
        try {
            [void](Repair-DefenseClawUninstallAdminFileAcl `
                -Layout $layout `
                -Kind deployment)
        }
        catch {
            $foreignWriterRejected = $_.Exception.Message -match
                'untrusted principal'
        }
        if (-not $foreignWriterRejected) {
            throw 'uninstall ACL recovery accepted a foreign writer'
        }
        [pscustomobject]@{
            schema_version = 1
            ok = $true
            canonical_noop = $true
            inherited_acl_repaired = $true
            metadata_bytes_preserved = $true
            hashed_attestation_repaired = $true
            changed_attestation_rejected = $true
            foreign_writer_rejected = $true
        }
    } $fixtureRoot
    $result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
}
finally {
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot) {
        $actual = [IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\')
        if ($actual -cne $fixtureFull) {
            throw 'refusing disposable ACL fixture cleanup after path changed'
        }
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $fixtureRoot `
            -Recurse `
            -Force `
            -ErrorAction Stop
    }
}
