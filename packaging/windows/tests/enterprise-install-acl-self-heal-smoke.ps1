# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Verifies the install-time canonical ACL self-heal: when a managed path
# (e.g. InstallRoot\ipc) carries an orphan NT SERVICE\ SID from a prior
# unsigned certification run with randomized service names, the install's
# canonical ACL re-stamp strips the orphan ACE instead of refusing with
# "untrusted principal ... has write-like access to managed path".
#
# This is the regression gate for the QA scenario that produced:
#   {"ok":false,"error":"untrusted principal S-1-5-80-... has write-like
#   access to managed path: C:\Program Files\Cisco\Cisco Secure Client\
#   DefenseClaw\ipc"}
# Fixed by Set-DefenseClawPathAcl's exact canonical DACL replacement
# plus the icacls /inheritance:r self-heal inside
# Assert-DefenseClawCanonicalRawPathAcl, which re-reads the descriptor
# via native GetFileSecurityDescriptor and warns-and-continues if the
# protected flag still cannot be set (bulldoze posture).

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

$fixtureName = 'DefenseClawInstallSelfHeal-' + [Guid]::NewGuid().ToString('N')
$fixtureRoot = Microsoft.PowerShell.Management\Join-Path `
    $env:ProgramData `
    $fixtureName
$fixtureFull = [IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\')
$programDataFull = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\')
if (-not $fixtureFull.StartsWith(
        $programDataFull + '\',
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $fixtureName -cnotmatch '^DefenseClawInstallSelfHeal-[a-f0-9]{32}$' -or
    (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot)) {
    throw 'disposable install self-heal fixture path is not unique and bounded'
}

try {
    $result = & $module {
        param([string]$FixtureRoot)
        Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $WarningPreference = 'SilentlyContinue'

        $ipcPath = Microsoft.PowerShell.Management\Join-Path `
            $FixtureRoot 'ipc'
        [void](New-DefenseClawProtectedDirectory -Path $FixtureRoot)
        [void](New-DefenseClawProtectedDirectory -Path $ipcPath)

        # Stage an orphan NT SERVICE\ ACE on the IPC directory, mirroring
        # the state left behind by a prior unsigned install whose
        # randomized service names baked a per-service SID into the ACL
        # of \ipc\ and then was uninstalled without removing the ACE.
        # Any well-formed service SID works; we fabricate one that will
        # never match a real managed service on the test box.
        $orphanSID = [Security.Principal.SecurityIdentifier]::new(
            'S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274'
        )
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $ipcPath
        $orphanRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $orphanSID,
            [Security.AccessControl.FileSystemRights]::FullControl,
            @(
                [Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            ),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($orphanRule)
        Microsoft.PowerShell.Security\Set-Acl `
            -LiteralPath $ipcPath `
            -AclObject $acl `
            -ErrorAction Stop

        # Confirm the orphan is actually present before the self-heal runs
        # (otherwise the test is tautological).
        $before = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $ipcPath
        $orphanBefore = @(
            $before.Access |
                Microsoft.PowerShell.Core\Where-Object {
                    (
                        [Security.Principal.SecurityIdentifier](
                            $_.IdentityReference.Translate(
                                [Security.Principal.SecurityIdentifier]
                            )
                        )
                    ).Value -ceq $orphanSID.Value
                }
        )
        if ($orphanBefore.Count -eq 0) {
            throw 'test fixture failed: orphan ACE did not land on the IPC directory'
        }

        # Drive the canonical re-stamp through the same code path install
        # uses for the ManagedIPCDirectory kind. In managed_enterprise mode
        # the gateway service SID is the authorized writer; in this smoke
        # we substitute the Administrators SID for a disposable test fixture.
        Set-DefenseClawPathAcl `
            -Path $ipcPath `
            -Kind ManagedIPCDirectory `
            -GatewayServiceSID $script:AdministratorsSID

        # Verify the orphan SID is gone AND SE_DACL_PROTECTED is set. Read
        # the descriptor via the same native helper the verifier uses - the
        # paired contract test keeps Get-Acl out of the verifier because
        # Get-Acl can strip SE_DACL_PROTECTED on some .NET revisions, and
        # the same hazard applies to the post-stamp check here.
        $nativeSecurity = Initialize-DefenseClawNativeSecurity
        $afterRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
            $nativeSecurity::GetFileSecurityDescriptor($ipcPath), 0
        )
        # The .NET DirectorySecurity view is still used only to enumerate
        # per-SID ACEs for the orphan check below (its listing walks the
        # same DACL and the orphan detection does not depend on the
        # protected-flag re-read above).
        $after = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $ipcPath
        $orphanAfter = @(
            $after.Access |
                Microsoft.PowerShell.Core\Where-Object {
                    (
                        [Security.Principal.SecurityIdentifier](
                            $_.IdentityReference.Translate(
                                [Security.Principal.SecurityIdentifier]
                            )
                        )
                    ).Value -ceq $orphanSID.Value
                }
        )
        $protectedFlag = [int](
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
        )
        return @{
            orphan_before_count = [int]$orphanBefore.Count
            orphan_after_count  = [int]$orphanAfter.Count
            protected_after     = (
                ([int]$afterRaw.ControlFlags -band $protectedFlag) -ne 0
            )
        }
    } $fixtureRoot

    if ([int]$result.orphan_before_count -lt 1) {
        throw 'self-heal smoke: orphan ACE did not stage before Set-DefenseClawPathAcl'
    }
    if ([int]$result.orphan_after_count -ne 0) {
        throw (
            'self-heal smoke: orphan ACE survived canonical re-stamp ' +
            "($($result.orphan_after_count) still present); " +
            'the install path would still fail with the QA-reported ' +
            'untrusted-principal error on reinstall over a prior ' +
            'unsigned-certification residue'
        )
    }
    if (-not [bool]$result.protected_after) {
        throw (
            'self-heal smoke: SE_DACL_PROTECTED is not set after ' +
            'Set-DefenseClawPathAcl - the icacls /inheritance:r self-heal ' +
            'did not fire or did not take effect'
        )
    }
    Microsoft.PowerShell.Utility\Write-Host (
        'enterprise-install-acl-self-heal-smoke: PASS ' +
        '(orphan NT SERVICE SID stripped, SE_DACL_PROTECTED set)'
    )
}
finally {
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot) {
        try {
            # Clear inheritance protection + grant Administrators Delete on
            # the fixture tree so the test runner's cleanup can nuke it
            # even if the canonical ACL left Administrators without Delete.
            $null = & icacls.exe $fixtureRoot '/inheritance:e' '/T' '/C' 2>&1
            $null = & icacls.exe $fixtureRoot `
                '/grant' 'Administrators:(OI)(CI)F' '/T' '/C' 2>&1
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $fixtureRoot `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
        catch {
            Microsoft.PowerShell.Utility\Write-Warning (
                "install self-heal smoke fixture cleanup failed: $_"
            )
        }
    }
    Microsoft.PowerShell.Core\Remove-Module `
        -ModuleInfo $module `
        -Force `
        -ErrorAction SilentlyContinue
}
