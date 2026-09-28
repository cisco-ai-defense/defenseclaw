# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Regression coverage for the enterprise-owned DisableSelfUpdate machine
# policy. The ownership rules run against a disposable HKCU key, never the
# real HKLM policy, and the key is removed afterwards.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClawEnterprise module was not imported'
}

$token = ([Guid]::NewGuid().ToString('N')).Substring(0, 12)
$smokeRoot = "Software\DefenseClawSelfUpdatePolicySmoke-$token"

try {
    $report = & $module {
        param($SmokeRoot)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            [Microsoft.Win32.RegistryView]::Default
        )
        $valueName = $script:DefenseClawSelfUpdatePolicyValueName
        $ownerName = $script:DefenseClawSelfUpdatePolicyOwnerValueName

        function New-CasePath {
            $script:smokeCase++
            return "$SmokeRoot\case$($script:smokeCase)\Policies\Cisco\DefenseClaw"
        }
        function Get-CaseValues {
            param([string]$Path)
            $key = $root.OpenSubKey($Path, $false)
            if ($null -eq $key) {
                return $null
            }
            try {
                $values = @{}
                foreach ($name in $key.GetValueNames()) {
                    $values[$name] = @($key.GetValueKind($name), $key.GetValue($name))
                }
                return $values
            }
            finally {
                $key.Dispose()
            }
        }
        function Set-CaseValue {
            param([string]$Path, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind)
            $key = $root.CreateSubKey($Path, $true)
            try {
                $key.SetValue($Name, $Value, $Kind)
            }
            finally {
                $key.Dispose()
            }
        }
        function Assert-Equal {
            param($Actual, $Expected, [string]$Message)
            if ($Actual -cne $Expected) {
                throw "$Message (got '$Actual', want '$Expected')"
            }
        }
        $script:smokeCase = 0

        try {
            # Production scope and the machine-wide root.
            if (-not (Test-DefenseClawProductionGatewayService -GatewayServiceName 'DefenseClawGateway') -or
                (Test-DefenseClawProductionGatewayService -GatewayServiceName 'DefenseClawCertGateway_0123456789') -or
                (Test-DefenseClawProductionGatewayService -GatewayServiceName 'defenseclawgateway')) {
                throw 'production gateway service scope is not exact'
            }
            $machine = Open-DefenseClawMachinePolicyRoot
            try {
                if ($machine.Name -cne 'HKEY_LOCAL_MACHINE' -or
                    $machine.View -ne [Microsoft.Win32.RegistryView]::Registry64) {
                    throw "machine policy root is $($machine.Name) $($machine.View)"
                }
            }
            finally {
                $machine.Dispose()
            }
            if ($script:DefenseClawSelfUpdatePolicyKeyPath -cne 'SOFTWARE\Policies\Cisco\DefenseClaw' -or
                $valueName -cne 'DisableSelfUpdate') {
                throw 'machine policy location drifted from the documented contract'
            }

            # Absent: the lifecycle creates and owns the value; repeat is stable.
            $path = New-CasePath
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'created' 'absent policy'
            $values = Get-CaseValues -Path $path
            if ($values[$valueName][0] -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
                [int]$values[$valueName][1] -ne 1 -or
                [string]$values[$ownerName][1] -cne $script:DefenseClawSelfUpdatePolicyOwner) {
                throw 'created policy is not DWORD 1 with the owner marker'
            }
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'owned' 'repeat set'
            Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'removed' 'owned removal'
            if ($null -ne (Get-CaseValues -Path $path)) {
                throw 'owned removal left the empty policy key'
            }
            Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'absent' 'repeat removal'

            # A value set by Group Policy (1 or 0, or another type) is never
            # adopted, changed, or removed.
            foreach ($foreign in @(
                @(1, [Microsoft.Win32.RegistryValueKind]::DWord),
                @(0, [Microsoft.Win32.RegistryValueKind]::DWord),
                @('1', [Microsoft.Win32.RegistryValueKind]::String)
            )) {
                $path = New-CasePath
                Set-CaseValue -Path $path -Name $valueName -Value $foreign[0] -Kind $foreign[1]
                Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'foreign' "foreign $($foreign[1]) $($foreign[0])"
                Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'foreign' "foreign removal $($foreign[1]) $($foreign[0])"
                $values = Get-CaseValues -Path $path
                if ($values.ContainsKey($ownerName) -or
                    $values[$valueName][0] -ne $foreign[1] -or
                    [string]$values[$valueName][1] -cne [string]$foreign[0]) {
                    throw "foreign policy $($foreign[1]) $($foreign[0]) was changed"
                }
            }

            # A later change by someone else to the owned value wins.
            $path = New-CasePath
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'created' 'owned before change'
            Set-CaseValue -Path $path -Name $valueName -Value 0 -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'relinquished' 'changed owned value'
            Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'foreign' 'relinquished removal'
            $values = Get-CaseValues -Path $path
            if ($values.ContainsKey($ownerName) -or [int]$values[$valueName][1] -ne 0) {
                throw 'relinquished policy was not left to its new owner'
            }

            # Removal keeps unrelated policy values and their key.
            $path = New-CasePath
            Set-CaseValue -Path $path -Name 'OtherPolicy' -Value 5 -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'created' 'set beside other policy'
            Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'removed' 'removal beside other policy'
            $values = Get-CaseValues -Path $path
            if ($null -eq $values -or $values.Count -ne 1 -or [int]$values['OtherPolicy'][1] -ne 5) {
                throw 'owned removal changed unrelated policy values'
            }

            # An interrupted set (marker written, value not yet) is completed,
            # and an interrupted removal (value gone, marker left) is finished.
            $path = New-CasePath
            Set-CaseValue -Path $path -Name $ownerName -Value $script:DefenseClawSelfUpdatePolicyOwner -Kind ([Microsoft.Win32.RegistryValueKind]::String)
            Assert-Equal (Set-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'created' 'interrupted set'
            $key = $root.OpenSubKey($path, $true)
            try {
                $key.DeleteValue($valueName)
            }
            finally {
                $key.Dispose()
            }
            Assert-Equal (Remove-DefenseClawOwnedSelfUpdatePolicy -Root $root -KeyPath $path) 'removed' 'interrupted removal'
            if ($null -ne (Get-CaseValues -Path $path)) {
                throw 'interrupted removal left the owner marker'
            }
        }
        finally {
            $root.DeleteSubKeyTree($SmokeRoot, $false)
            $root.Dispose()
        }
        return $script:smokeCase
    } $smokeRoot
}
finally {
    $cleanup = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::CurrentUser,
        [Microsoft.Win32.RegistryView]::Default
    )
    try {
        $cleanup.DeleteSubKeyTree($smokeRoot, $false)
    }
    finally {
        $cleanup.Dispose()
    }
}

[pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    cases = [int]$report
    absent_policy_owned = $true
    foreign_policy_untouched = $true
    changed_policy_relinquished = $true
    unrelated_policy_preserved = $true
    interrupted_transitions_completed = $true
} | ConvertTo-Json -Compress
