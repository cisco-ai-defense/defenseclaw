# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Cross-profile lifecycle serialization. Each profile holds its own lifecycle
# lock for a whole mutation; while holding it, a lifecycle must refuse when
# the other profile's protected lock is held, and must ignore a lock file an
# unprivileged user could have planted. Runs elevated inside a disposable
# ProgramData stand-in; no service or real machine root is touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-profile-lock-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProgramData = $script:ProgramData
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $script:ProgramData = $Root
        try {
            function New-TestLock([string]$Profile, [string]$Sddl) {
                $roots = Get-DefenseClawProfileRoots -EnterpriseProfile $Profile
                [void][IO.Directory]::CreateDirectory([string]$roots.LifecycleDirectory)
                $path = [IO.Path]::Combine([string]$roots.LifecycleDirectory, 'lifecycle.lock')
                if (-not [IO.File]::Exists($path)) {
                    [IO.File]::Open($path, [IO.FileMode]::CreateNew).Dispose()
                }
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm(
                    $Sddl,
                    [Security.AccessControl.AccessControlSections]::All
                )
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $path -AclObject $security
                return $path
            }
            function Test-Idle([string]$Label, [bool]$ExpectBusy) {
                try {
                    Assert-DefenseClawOtherProfileLifecycleIdle
                    if ($ExpectBusy) {
                        $failures.Add("${Label}: expected a busy refusal")
                    }
                }
                catch {
                    if (-not $ExpectBusy) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                    elseif ($_.Exception.Message -notmatch 'holds the protected file lock') {
                        $failures.Add("${Label}: refusal lacks the busy marker: $($_.Exception.Message)")
                    }
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            Test-Idle 'no Secure Client footprint' $false

            $protected = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
            $secureClientLock = New-TestLock 'SecureClient' $protected
            Test-Idle 'idle Secure Client lock' $false
            $held = [IO.File]::Open($secureClientLock, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                Test-Idle 'held Secure Client lock' $true
            }
            finally {
                $held.Dispose()
            }

            # The Secure Client lifecycle sees a held standalone lock the same way.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            Test-Idle 'no standalone footprint' $false
            $standaloneLock = New-TestLock 'Standalone' $protected
            $held = [IO.File]::Open($standaloneLock, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                Test-Idle 'held standalone lock' $true
            }
            finally {
                $held.Dispose()
            }

            # A lock a standard user could write is never trusted to block.
            [void](New-TestLock 'Standalone' 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)')
            $held = [IO.File]::Open($standaloneLock, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                Test-Idle 'untrusted standalone lock' $false
            }
            finally {
                $held.Dispose()
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-profile-lifecycle-lock-smoke: OK'
