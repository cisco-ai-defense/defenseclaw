# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# rel-1-0-10:GAP-0028: after a Programs and Features uninstall the standalone
# lifecycle lock (or a lock created in a folder that left inheritable
# entries) inherits its folder's access list, and every later Setup /ensure
# ended 1603 "managed DACL inherits from an ancestor". A lock SYSTEM,
# Administrators or TrustedInstaller own is re-stamped protected and taken;
# a lock another account owns is still refused.

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), ('dc-lock-acl-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProgramData = $script:ProgramData
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $script:ProgramData = $Root
        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $directory = [IO.Path]::Combine($Root, 'Cisco', 'DefenseClaw-Lifecycle')
            [void][IO.Directory]::CreateDirectory($directory)
            # The folder as the uninstall left it: inheritable entries for
            # SYSTEM and Administrators that a new child takes on.
            $folder = [Security.AccessControl.DirectorySecurity]::new()
            $folder.SetSecurityDescriptorSddlForm(
                'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',
                [Security.AccessControl.AccessControlSections]::All
            )
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $directory -AclObject $folder
            $layout = @{
                LifecycleLockDirectory = $directory
                LifecycleLockPath      = [IO.Path]::Combine($directory, 'lifecycle.lock')
            }
            function Set-TestLock([string]$OwnerSID) {
                if (-not [IO.File]::Exists($layout.LifecycleLockPath)) {
                    [IO.File]::Open($layout.LifecycleLockPath, [IO.FileMode]::CreateNew).Dispose()
                }
                # As the uninstall left it: no explicit entries, the folder's
                # inherited ones apply (icacls /reset), and the given owner.
                $out = & icacls.exe $layout.LifecycleLockPath /reset 2>&1
                if ($LASTEXITCODE -ne 0) { throw "fixture: icacls /reset: $out" }
                $out = & icacls.exe $layout.LifecycleLockPath /setowner ('*' + $OwnerSID) 2>&1
                if ($LASTEXITCODE -ne 0) { throw "fixture: icacls /setowner: $out" }
                if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $layout.LifecycleLockPath).AreAccessRulesProtected) {
                    throw 'fixture: the lock does not inherit'
                }
            }
            function Test-Take([string]$Label, [bool]$ExpectTaken) {
                $lock = $null
                try {
                    $lock = Enter-DefenseClawLifecycleLock -Layout $layout -TimeoutSeconds 5 3>$null
                    if (-not $ExpectTaken) {
                        $failures.Add("${Label}: the lock was taken")
                    }
                    elseif (-not (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $layout.LifecycleLockPath).AreAccessRulesProtected) {
                        $failures.Add("${Label}: the lock still inherits after it was taken")
                    }
                }
                catch {
                    if ($ExpectTaken) {
                        $failures.Add("${Label}: refused: $($_.Exception.Message)")
                    }
                }
                finally {
                    if ($null -ne $lock) {
                        $lock.Dispose()
                    }
                }
            }

            Set-TestLock $script:AdministratorsSID
            Test-Take 'an inheriting lock Administrators own' $true
            Set-TestLock $script:SystemSID
            Test-Take 'an inheriting lock SYSTEM owns' $true
            [IO.File]::Delete($layout.LifecycleLockPath)
            Test-Take 'a new lock in the folder the uninstall left' $true

            # Inheritance beside another fault stays refused: a Users write
            # entry on an inheriting lock Administrators own.
            Set-TestLock $script:AdministratorsSID
            $out = & icacls.exe $layout.LifecycleLockPath /grant '*S-1-5-32-545:(M)' 2>&1
            if ($LASTEXITCODE -ne 0) { throw "fixture: icacls /grant: $out" }
            Test-Take 'an inheriting lock with a Users write entry' $false

            $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if ($user -notin @($script:SystemSID, $script:AdministratorsSID)) {
                Set-TestLock $user
                Test-Take 'an inheriting lock another account owns' $false
            }
        }
        finally {
            $script:ProgramData = $originalProgramData
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-lifecycle-lock-inherited-acl-smoke: OK'
