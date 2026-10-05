# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Cross-profile deployment records. Profiles share SCM service names, so a
# mutation of one profile refuses while the other profile's deployment is
# recorded. Only a record an administrator could have written counts: a
# record or ancestor directory a standard user could have created under the
# default ProgramData ACL is ignored, so it can block neither the Secure
# Client nor the standalone lifecycle. Runs elevated inside a disposable
# ProgramData stand-in; no service or real machine root is touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-profile-deployment-record-smoke: SKIP (requires an elevated token)'
    exit 0
}

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
    ('dc-profile-record-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProgramData = $script:ProgramData
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $protectedDirectory = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $protectedFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        function Set-TestSddl([string]$Path, [string]$Sddl) {
            $security = if ([IO.Directory]::Exists($Path)) {
                [Security.AccessControl.DirectorySecurity]::new()
            }
            else {
                [Security.AccessControl.FileSecurity]::new()
            }
            $security.SetSecurityDescriptorSddlForm(
                $Sddl,
                [Security.AccessControl.AccessControlSections]::All
            )
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $security
        }
        Set-TestSddl $Root $protectedDirectory
        $script:ProgramData = $Root
        # The standalone check also refuses while the Secure Client broker
        # service exists; this smoke covers records only.
        function script:Test-DefenseClawServiceExists {
            param([Parameter(Mandatory)][string]$Name)
            return $false
        }
        try {
            function Reset-TestRecords {
                foreach ($vendor in @('Cisco')) {
                    $path = [IO.Path]::Combine($Root, $vendor)
                    if ([IO.Directory]::Exists($path)) {
                        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Recurse -Force
                    }
                }
            }
            function New-TestRecord(
                [string]$Profile,
                [string]$Body,
                [string]$FileSddl = $protectedFile,
                [string]$StateRootSddl = $protectedDirectory
            ) {
                $roots = Get-DefenseClawProfileRoots -EnterpriseProfile $Profile
                $stateRoot = [string]$roots.StateRoot
                $current = $Root
                foreach ($component in $stateRoot.Substring($Root.Length).Trim('\').Split('\')) {
                    $current = [IO.Path]::Combine($current, $component)
                    if (-not [IO.Directory]::Exists($current)) {
                        [void][IO.Directory]::CreateDirectory($current)
                        Set-TestSddl $current $protectedDirectory
                    }
                }
                Set-TestSddl $stateRoot $StateRootSddl
                $install = [IO.Path]::Combine($stateRoot, 'install')
                [void][IO.Directory]::CreateDirectory($install)
                Set-TestSddl $install $protectedDirectory
                $path = [IO.Path]::Combine($install, 'deployment.json')
                [IO.File]::WriteAllText($path, $Body, [Text.UTF8Encoding]::new($false))
                Set-TestSddl $path $FileSddl
                return $path
            }
            function Test-Conflict([string]$Label, [bool]$ExpectConflict) {
                try {
                    Assert-DefenseClawNoOtherProfileDeployment
                    if ($ExpectConflict) {
                        $failures.Add("${Label}: expected a profile_conflict refusal")
                    }
                }
                catch {
                    if (-not $ExpectConflict) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                    elseif ($_.Exception.Message -notmatch '^profile_conflict: ') {
                        $failures.Add("${Label}: refusal lacks the profile_conflict code: $($_.Exception.Message)")
                    }
                }
            }
            $userWritableFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)'
            $userWritableDirectory = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)'

            foreach ($case in @(
                    @{ Mode = 'SecureClient'; Other = 'Standalone' },
                    @{ Mode = 'Standalone'; Other = 'SecureClient' }
                )) {
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile $case.Mode
                $label = "$($case.Mode) lifecycle"

                Reset-TestRecords
                Test-Conflict "$label, no $($case.Other) record" $false

                [void](New-TestRecord $case.Other '{"installed":true}')
                Test-Conflict "$label, administrator $($case.Other) record" $true

                [void](New-TestRecord $case.Other '{"installed":false}')
                Test-Conflict "$label, administrator $($case.Other) tombstone" $false

                [void](New-TestRecord $case.Other 'not json')
                Test-Conflict "$label, damaged administrator $($case.Other) record" $true

                [void](New-TestRecord $case.Other '{}' $userWritableFile)
                Test-Conflict "$label, user-writable $($case.Other) record" $false

                [void](New-TestRecord $case.Other 'not json' $userWritableFile)
                Test-Conflict "$label, user-writable unparseable $($case.Other) record" $false

                [void](New-TestRecord $case.Other '{"installed":true}' $protectedFile $userWritableDirectory)
                Test-Conflict "$label, $($case.Other) record under a user-writable state root" $false

                $planted = New-TestRecord $case.Other '{}' $userWritableFile
                $probe = Test-DefenseClawProfileDeploymentInstalled -EnterpriseProfile $case.Other
                if ([bool]$probe.installed -or
                    $null -eq $probe.PSObject.Properties['untrusted'] -or
                    -not [bool]$probe.untrusted -or
                    [string]$probe.path -cne $planted) {
                    $failures.Add("${label}: planted record probe is not reported untrusted: $($probe | ConvertTo-Json -Compress)")
                }
                Reset-TestRecords
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-profile-deployment-record-smoke: OK'
