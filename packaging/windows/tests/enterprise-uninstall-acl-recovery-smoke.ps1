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
        # An explicit deny to the trusted Administrators principal defeats
        # ordinary READ_CONTROL/WRITE_DAC opens, but gives no foreign writer
        # access. Uninstall may repair this exact metadata inode through its
        # short-lived backup/restore impersonation scope.
        $nativeSecurity = Initialize-DefenseClawNativeSecurity
        $metadataIdentity = [string](
            $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                [string]$metadataPath
            ).Identity
        )
        $adminFileSddl = $expected.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
        $denyRights = [Security.AccessControl.FileSystemRights](
            [int][Security.AccessControl.FileSystemRights]::ReadData -bor
            [int][Security.AccessControl.FileSystemRights]::ReadPermissions -bor
            [int][Security.AccessControl.FileSystemRights]::ChangePermissions
        )
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $metadataPath
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            'BUILTIN\Administrators',
            $denyRights,
            [Security.AccessControl.AccessControlType]::Deny
        ))
        # The canonical owner is Administrators; Windows gives an owner
        # implicit READ_CONTROL/WRITE_DAC. Move this disposable fixture to the
        # equally trusted SYSTEM owner so the BA deny really blocks the open.
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new(
            $script:SystemSID
        ))
        [void]($nativeSecurity::SetUninstallAdminFileSecurityDescriptorNoFollow(
            [string]$metadataPath,
            $acl.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ),
            $metadataIdentity
        ))
        try {
            $ordinaryDenied = $false
            try {
                [void]($nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                    [string]$metadataPath
                ))
            }
            catch {
                $nativeError = $_.Exception
                while ($null -ne $nativeError.InnerException) {
                    $nativeError = $nativeError.InnerException
                }
                $ordinaryDenied = $nativeError -is
                    [ComponentModel.Win32Exception] -and
                    [int]$nativeError.NativeErrorCode -eq 5
            }
            if (-not $ordinaryDenied) {
                throw 'explicit Admin denial fixture remained readable without backup privilege'
            }
            [void](Repair-DefenseClawUninstallAdminFileAcl `
                -Layout $layout `
                -Kind deployment)
            Assert-DefenseClawCanonicalPathAcl `
                -Path $metadataPath `
                -Expected $expected
            if ((Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $metadataPath `
                    -Algorithm SHA256).Hash -cne $metadataHash) {
                throw 'explicit Admin denial recovery changed deployment metadata bytes'
            }
        }
        finally {
            $currentMetadata =
                $nativeSecurity::GetUninstallAdminFileSecuritySnapshotNoFollowIfExists(
                    [string]$metadataPath
                )
            if ($null -ne $currentMetadata -and
                [string]$currentMetadata.Identity -ceq $metadataIdentity) {
                [void]($nativeSecurity::SetUninstallAdminFileSecurityDescriptorNoFollow(
                    [string]$metadataPath,
                    $adminFileSddl,
                    $metadataIdentity
                ))
            }
        }

        # Purge does not retain arbitrary StateRoot children, so a denied
        # cache leaf must not block its precommit root/tombstone protection.
        # Non-purge uninstall still preserves children and must remain strict.
        $deniedChild = Microsoft.PowerShell.Management\Join-Path `
            $StateRoot `
            'acl-denied-cache.bin'
        Microsoft.PowerShell.Management\Set-Content `
            -LiteralPath $deniedChild `
            -Value 'disposable cache fixture' `
            -Encoding UTF8
        Set-DefenseClawPathAcl `
            -Path $deniedChild `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
        $deniedChildIdentity = [string](
            $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                [string]$deniedChild
            ).Identity
        )
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $deniedChild
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            'BUILTIN\Administrators',
            $denyRights,
            [Security.AccessControl.AccessControlType]::Deny
        ))
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new(
            $script:SystemSID
        ))
        [void]($nativeSecurity::SetUninstallAdminFileSecurityDescriptorNoFollow(
            [string]$deniedChild,
            $acl.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ),
            $deniedChildIdentity
        ))
        try {
            [void](Set-DefenseClawPreservedStateAcls `
                -Layout $layout `
                -GatewayServiceSID $script:AdministratorsSID `
                -Purge)
            $nonPurgeRejected = $false
            try {
                Set-DefenseClawPreservedStateAcls `
                    -Layout $layout `
                    -GatewayServiceSID $script:AdministratorsSID
            }
            catch {
                $nonPurgeRejected = $true
            }
            if (-not $nonPurgeRejected) {
                throw 'non-purge state preservation ignored an ACL-denied child'
            }
        }
        finally {
            $deniedChildSnapshot =
                $nativeSecurity::GetUninstallAdminFileSecuritySnapshotNoFollowIfExists(
                    [string]$deniedChild
                )
            if ($null -ne $deniedChildSnapshot -and
                [string]$deniedChildSnapshot.Identity -ceq
                    $deniedChildIdentity) {
                [void]($nativeSecurity::SetUninstallAdminFileSecurityDescriptorNoFollow(
                    [string]$deniedChild,
                    $adminFileSddl,
                    [string]$deniedChildSnapshot.Identity
                ))
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $deniedChild `
                    -Force
            }
        }
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $metadataPath
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent().User,
            [Security.AccessControl.FileSystemRights]::FullControl,
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
            throw 'uninstall ACL recovery accepted an Explorer-style user Full Control grant'
        }
        [pscustomobject]@{
            schema_version = 1
            ok = $true
            canonical_noop = $true
            inherited_acl_repaired = $true
            metadata_bytes_preserved = $true
            hashed_attestation_repaired = $true
            changed_attestation_rejected = $true
            trusted_admin_deny_repaired = $true
            purge_skipped_denied_state_child = $true
            non_purge_rejected_denied_state_child = $true
            foreign_writer_rejected = $true
            explorer_full_control_rejected = $true
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
