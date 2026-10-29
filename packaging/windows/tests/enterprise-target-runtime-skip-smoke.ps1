# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A fresh Install leaves out a user whose profile folder stays busy and lists
# them in the target-runtime plan. The installer must accept only a well-formed
# list and must record each skipped user, with the reason, as a warning and in
# the hook-guardian log. The helpers are loaded from the module by AST.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @('Get-DefenseClawTargetRuntimeSkippedProfiles', 'Write-DefenseClawTargetRuntimeSkippedProfiles')) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function New-Plan($Skipped, $Repaired = $null) {
    $plan = [ordered]@{ schema_version = 1; roots = @() }
    if ($null -ne $Skipped) {
        $plan.skipped_profiles = @($Skipped)
    }
    if ($null -ne $Repaired) {
        $plan.repaired_profiles = @($Repaired)
    }
    return ($plan | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
}
$busy = [ordered]@{
    sid = 'S-1-5-21-111-222-333-1009'
    user_home = 'C:\Users\dave'
    reason = 'enterprise hooks: open managed runtime profile anchor for S-1-5-21-111-222-333-1009 at C:\Users\dave: another process has the folder open (sharing violation after 10 attempts over 23.8s)'
}

if (@(Get-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan $null)).Count -ne 0) {
    throw 'a plan without skipped_profiles reported skipped users'
}
$profiles = @(Get-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan @($busy)))
if ($profiles.Count -ne 1 -or [string]$profiles[0].sid -cne $busy.sid) {
    throw 'a valid skipped profile was not returned'
}
foreach ($case in @(
        @{ label = 'duplicate'; skipped = @($busy, $busy); roots = @{} },
        @{ label = 'also planned'; skipped = @($busy); roots = @{ 'S-1-5-21-111-222-333-1009' = $true } },
        @{ label = 'extra property'; skipped = @([ordered]@{ sid = $busy.sid; user_home = $busy.user_home; reason = 'x'; extra = 1 }); roots = @{} },
        @{ label = 'empty reason'; skipped = @([ordered]@{ sid = $busy.sid; user_home = $busy.user_home; reason = ' ' }); roots = @{} },
        @{ label = 'bad SID'; skipped = @([ordered]@{ sid = 'nope'; user_home = $busy.user_home; reason = 'x' }); roots = @{} }
    )) {
    $rejected = $false
    try {
        [void](Get-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan $case.skipped) -RootSIDs $case.roots)
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "$($case.label): invalid skipped profile list accepted"
    }
}

$logDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), "dc-skip-smoke-$([Guid]::NewGuid().ToString('N'))")
[void][IO.Directory]::CreateDirectory($logDirectory)
try {
    $logPath = [IO.Path]::Combine($logDirectory, 'hook-guardian.log')
    $warnings = @()
    Write-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan @($busy)) -Layout @{ GuardianLogPath = $logPath } -WarningVariable warnings -WarningAction SilentlyContinue
    $warningText = (@($warnings) | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ }) -join "`n"
    foreach ($expected in @('target_runtime_profile_skipped: user S-1-5-21-111-222-333-1009 at C:\Users\dave', 'sharing violation after 10 attempts')) {
        if (-not $warningText.Contains($expected)) {
            throw "warning does not contain '$expected': $warningText"
        }
    }
    $logged = [IO.File]::ReadAllText($logPath)
    if (-not $logged.Contains('[installer] target_runtime_profile_skipped: user S-1-5-21-111-222-333-1009')) {
        throw "hook-guardian log does not record the skip: $logged"
    }
}
finally {
    [IO.Directory]::Delete($logDirectory, $true)
}

# A repaired retained root is listed with its planned root and logged too.
$repaired = [ordered]@{
    sid = 'S-1-5-21-111-222-333-1010'
    user_home = 'C:\Users\erin'
    reason = 'managed Windows DACL on C:\Users\erin\.defenseclaw is missing the canonical ACE for principal S-1-3-4'
}
$withRoot = @{ 'S-1-5-21-111-222-333-1010' = $true }
if (@(Get-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan $null @($repaired)) -RootSIDs $withRoot -Repaired).Count -ne 1) {
    throw 'a valid repaired profile was not returned'
}
$rejected = $false
try {
    [void](Get-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan $null @($repaired)) -RootSIDs @{ 'S-1-5-21-1-1-1-1' = $true } -Repaired)
}
catch {
    $rejected = $true
}
if (-not $rejected) {
    throw 'a repaired profile without a planned root was accepted'
}
$logDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), "dc-repair-smoke-$([Guid]::NewGuid().ToString('N'))")
[void][IO.Directory]::CreateDirectory($logDirectory)
try {
    $logPath = [IO.Path]::Combine($logDirectory, 'hook-guardian.log')
    $warnings = @()
    Write-DefenseClawTargetRuntimeSkippedProfiles -Plan (New-Plan $null @($repaired)) -Layout @{ GuardianLogPath = $logPath } -WarningVariable warnings -WarningAction SilentlyContinue
    $warningText = (@($warnings) | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ }) -join "`n"
    if (-not $warningText.Contains('target_runtime_profile_repaired: user S-1-5-21-111-222-333-1010 at C:\Users\erin')) {
        throw "repair warning missing: $warningText"
    }
    if (-not ([IO.File]::ReadAllText($logPath)).Contains('[installer] target_runtime_profile_repaired: user S-1-5-21-111-222-333-1010')) {
        throw 'hook-guardian log does not record the repair'
    }
}
finally {
    [IO.Directory]::Delete($logDirectory, $true)
}

'target runtime skip smoke passed'
