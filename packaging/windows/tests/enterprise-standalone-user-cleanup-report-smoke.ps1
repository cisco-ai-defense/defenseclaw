# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Standalone uninstall and the per-user registration cleanup report. After it
# commits, a standalone finalize removes DefenseClaw's own registrations from
# users' agent configurations and reports the users it could not act as. The
# uninstall result must carry that report (lists stay JSON arrays, even with
# one item), and a Secure Client result must stay exactly as it was. Pure
# function test: no service, file, or machine root is touched.

[CmdletBinding()]
param()

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

$failures = & $module {
    Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $failures = [Collections.Generic.List[string]]::new()
    $standalone = @{ BrokerEnabled = $false }
    $secureClient = @{ BrokerEnabled = $true }
    $sid = 'S-1-5-21-1000000000-2000000000-3000000000-1017'
    $finalize = (
        '{"schema_version":4,"action":"finalize","ok":true,' +
        '"user_registrations_removed":1,' +
        '"user_registrations_pending":["devin/' + $sid + '"],' +
        '"user_registrations_failed":["hermes/' + $sid + ': access denied"]}'
    ) | Microsoft.PowerShell.Utility\ConvertFrom-Json

    function New-HarnessResult {
        [pscustomobject][ordered]@{
            ok = $true
            action = 'Uninstall'
            installed = $false
        }
    }
    function ConvertTo-HarnessJson {
        param([Parameter(Mandatory)]$Value)
        return ($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 -Compress)
    }

    $json = ConvertTo-HarnessJson (Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $finalize)
    foreach ($want in @(
        '"user_registrations_removed":1',
        ('"user_registrations_pending":["devin/' + $sid + '"]'),
        ('"user_registrations_failed":["hermes/' + $sid + ': access denied"]')
    )) {
        if (-not $json.Contains($want)) {
            $failures.Add("standalone report lacks $want in $json")
        }
    }

    # Helper output ahead of the report, and a finalize without the fields
    # (an older helper), are tolerated.
    $json = ConvertTo-HarnessJson (Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization @('noise', $finalize))
    if (-not $json.Contains('"user_registrations_removed":1')) {
        $failures.Add("report after helper output was not found: $json")
    }
    $json = ConvertTo-HarnessJson (Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization ([pscustomobject]@{ ok = $true }))
    if (-not $json.Contains(
            '"user_registrations_removed":0,"user_registrations_pending":[],"user_registrations_failed":[]'
        )) {
        $failures.Add("empty standalone report is not explicit: $json")
    }
    $json = ConvertTo-HarnessJson (Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $null)
    if (-not $json.Contains('"user_registrations_removed":0')) {
        $failures.Add("missing finalize report is not explicit: $json")
    }

    # Secure Client, and a layout that does not say it is standalone, keep
    # the exact result.
    foreach ($layout in @($secureClient, @{})) {
        $before = ConvertTo-HarnessJson (New-HarnessResult)
        $after = ConvertTo-HarnessJson (Add-DefenseClawUserRegistrationCleanupResult `
            -Result (New-HarnessResult) `
            -Layout $layout `
            -Finalization $finalize)
        if ($after -cne $before) {
            $failures.Add("Secure Client result changed: $after")
        }
    }
    return , $failures
}

if (@($failures).Count -gt 0) {
    foreach ($failure in @($failures)) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-user-cleanup-report-smoke: OK'
