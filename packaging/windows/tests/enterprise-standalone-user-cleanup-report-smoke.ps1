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

    # Native Claude hooks found in a signed-out profile are removed by the
    # LocalSystem finalize and counted in the same user registration report.
    $claudeFinalize = (
        '{"schema_version":4,"action":"finalize","ok":true,' +
        '"user_registrations_removed":1,' +
        '"user_registrations_pending":[],"user_registrations_failed":[]}'
    ) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $claudeResult = Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $claudeFinalize
    if ($claudeResult.user_registrations_removed -ne 1 -or
        @($claudeResult.user_registrations_pending).Count -ne 0) {
        $failures.Add('signed-out Claude cleanup was not reported')
    }

    # A purge names each account whose per-user data went and each one whose
    # data stayed; both lists carry through.
    $purgeFinalize = (
        '{"schema_version":4,"action":"finalize","ok":true,' +
        '"user_registrations_removed":0,' +
        '"user_state_purged":["alice (' + $sid + '): C:\\Users\\alice\\.defenseclaw"],' +
        '"user_state_remaining":["bob (' + $sid + '): C:\\Users\\bob\\.defenseclaw: access denied"]}'
    ) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $purgeResult = Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $purgeFinalize
    if (@($purgeResult.user_state_purged).Count -ne 1 -or
        -not ([string]@($purgeResult.user_state_purged)[0]).StartsWith('alice (')) {
        $failures.Add("purged accounts were not carried: $(ConvertTo-HarnessJson $purgeResult)")
    }
    if (@($purgeResult.user_state_remaining).Count -ne 1 -or
        -not ([string]@($purgeResult.user_state_remaining)[0]).EndsWith('access denied')) {
        $failures.Add("remaining accounts were not carried: $(ConvertTo-HarnessJson $purgeResult)")
    }

    # Each Claude settings file the finalize edited (#1290) and each
    # DefenseClaw hook command left in one (#1286) carry through.
    $settingsFinalize = (
        '{"schema_version":4,"action":"finalize","ok":true,' +
        '"user_registrations_removed":1,' +
        '"user_settings_edited":["removed 1 DefenseClaw hook command(s) from C:\\Users\\alice\\.claude\\settings.json"],' +
        '"user_settings_hooks_left":["C:\\Users\\alice\\.claude\\settings.json: PreToolUse: a hook command naming defenseclaw-hook (arguments not shown)"]}'
    ) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $settingsResult = Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $settingsFinalize
    if (@($settingsResult.user_settings_edited).Count -ne 1 -or
        -not ([string]@($settingsResult.user_settings_edited)[0]).StartsWith('removed 1 DefenseClaw hook command(s) from ')) {
        $failures.Add("edited settings files were not carried: $(ConvertTo-HarnessJson $settingsResult)")
    }
    if (@($settingsResult.user_settings_hooks_left).Count -ne 1 -or
        -not ([string]@($settingsResult.user_settings_hooks_left)[0]).EndsWith('PreToolUse: a hook command naming defenseclaw-hook (arguments not shown)')) {
        $failures.Add("leftover Claude hook commands were not carried: $(ConvertTo-HarnessJson $settingsResult)")
    }

    # sidecar-r107:GAP-0007: a machine folder the finalize kept joins what the
    # result already names in machine_state_remaining.
    $keptFinalize = (
        '{"schema_version":4,"action":"finalize","ok":true,' +
        '"user_registrations_removed":0,' +
        '"machine_state_remaining":["C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\DefenseClaw\\claude-settings-teardown: kept: it holds an unfinished Claude Code settings cleanup"]}'
    ) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $keptBase = New-HarnessResult
    $keptBase | Microsoft.PowerShell.Utility\Add-Member -MemberType NoteProperty -Name machine_state_remaining -Value ([string[]]@('C:\ProgramData\DefenseClaw-PowerShell-0: in use'))
    $keptResult = Add-DefenseClawUserRegistrationCleanupResult `
        -Result $keptBase `
        -Layout $standalone `
        -Finalization $keptFinalize
    if (@($keptResult.machine_state_remaining).Count -ne 2 -or
        -not ([string]@($keptResult.machine_state_remaining)[0]).EndsWith(': in use') -or
        -not ([string]@($keptResult.machine_state_remaining)[1]).EndsWith('claude-settings-teardown: kept: it holds an unfinished Claude Code settings cleanup')) {
        $failures.Add("kept machine folder was not carried: $(ConvertTo-HarnessJson $keptResult)")
    }
    $keptOnly = Add-DefenseClawUserRegistrationCleanupResult `
        -Result (New-HarnessResult) `
        -Layout $standalone `
        -Finalization $keptFinalize
    if (@($keptOnly.machine_state_remaining).Count -ne 1) {
        $failures.Add("kept machine folder without earlier entries was not carried: $(ConvertTo-HarnessJson $keptOnly)")
    }
    if ($null -ne (Add-DefenseClawUserRegistrationCleanupResult -Result (New-HarnessResult) -Layout $standalone -Finalization $finalize).PSObject.Properties['machine_state_remaining']) {
        $failures.Add('a finalize without kept machine folders added machine_state_remaining')
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

    # Only a standalone uninstall with purge tells the finalize helper to
    # remove the per-user folders. Every helper run sets or clears it, so a
    # caller's value never reaches a helper.
    $purgeVariable = 'DEFENSECLAW_WINDOWS_UNINSTALL_PURGE_USER_STATE'
    function script:Resolve-DefenseClawFullPath {
        param([string]$Path, [switch]$MustExist, [switch]$Leaf)
        return $Path
    }
    function script:Assert-DefenseClawNoReparsePath {
        param([string]$Path)
    }
    function script:Invoke-DefenseClawProcess {
        param([string]$File, [string[]]$Arguments)
        return [pscustomobject]@{
            exit_code = 0
            output = @([string][Environment]::GetEnvironmentVariable(
                'DEFENSECLAW_WINDOWS_UNINSTALL_PURGE_USER_STATE',
                'Process'
            ))
        }
    }
    $gatewayLayout = @{
        BrokerEnabled = $false
        AgentApplicationControlAttested = $false
        ClaudeEffectivePolicyVerified = $false
        GatewayPath = 'C:\harness\defenseclaw-gateway.exe'
        RuntimeDirectory = 'C:\harness\runtime'
        ConfigPath = 'C:\harness\config.yaml'
        AuthorizationDirectory = 'C:\harness\authorization'
    }
    [Environment]::SetEnvironmentVariable($purgeVariable, '1', 'Process')
    foreach ($case in @(
        @{ purge = $true; want = '1' },
        @{ purge = $false; want = '' }
    )) {
        $script:DefenseClawUninstallPurgeUserState = $case.purge
        $probe = Invoke-DefenseClawGatewayCommand `
            -Layout $gatewayLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -Arguments @('probe') `
            -Capture
        $seen = [string]@($probe.output)[0]
        if ($seen -cne [string]$case.want) {
            $failures.Add("purge=$($case.purge) gave the helper '$seen'")
        }
    }
    [Environment]::SetEnvironmentVariable($purgeVariable, $null, 'Process')
    return , $failures
}

if (@($failures).Count -gt 0) {
    foreach ($failure in @($failures)) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-user-cleanup-report-smoke: OK'
