# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A rollback restores the deployment that was there before the transaction.
# When its guardian already had failed targets, the restored guardian's fresh
# reconcile reports ok=false, and the rollback must still accept it. Only the
# rollback lane (no manifest digest, -AllowFailedTargets) relaxes this; an
# activation with a digest, an incomplete reconcile, or a report with no state
# stays rejected. The helpers are loaded from the module by AST.

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
foreach ($name in @(
        'Test-DefenseClawGuardianCoverageReport',
        'Test-DefenseClawGuardianReportCompletedWithFailedTargets',
        'Get-DefenseClawGuardianGeneration'
    )) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$startedAfter = [DateTime]::Parse('2026-10-29T00:00:00Z').ToUniversalTime()
function New-Report([int]$Failures, [int]$Rows = 3, [bool]$WithState = $true) {
    $report = [ordered]@{
        ok = ($Failures -eq 0)
        errors = @($(if ($Failures -gt 0) { 'claudecode target S-1-5-21-1-2-3-1003 failed' }))
    }
    if ($WithState) {
        $report.state = [pscustomobject][ordered]@{
            updated_at = '2026-10-29T00:00:05Z'
            target_count = 3
            success_count = 3 - $Failures - 1
            failure_count = $Failures
            pending_count = 1
            results = @(1..$Rows)
        }
    }
    return ($report | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
}
function Test-Coverage($Report, [string]$Digest = '', [switch]$Allow) {
    return Test-DefenseClawGuardianCoverageReport `
        -Report $Report `
        -PriorReconcileID '' `
        -PriorGeneration '2026-10-28T00:00:00Z' `
        -PriorStateIdentity 'old' `
        -CurrentStateIdentity 'new' `
        -ExpectedManifestSHA256 $Digest `
        -StartedAfter $startedAfter `
        -AllowFailedTargets:$Allow
}
function Assert-Result($Result, [bool]$Ok, [string]$Label) {
    if ([bool]$Result.ok -ne $Ok) {
        throw "${Label}: ok=$($Result.ok), want $Ok (reason: $($Result.reason))"
    }
}

Assert-Result (Test-Coverage (New-Report -Failures 0)) $true 'healthy reconcile'
Assert-Result (Test-Coverage (New-Report -Failures 1) -Allow) $true 'degraded reconcile on the rollback lane'
Assert-Result (Test-Coverage (New-Report -Failures 1)) $false 'degraded reconcile without -AllowFailedTargets'
Assert-Result (Test-Coverage (New-Report -Failures 1) -Digest ('a' * 64) -Allow) $false 'degraded reconcile on the activation lane'
Assert-Result (Test-Coverage (New-Report -Failures 1 -Rows 2) -Allow) $false 'incomplete degraded reconcile'
Assert-Result (Test-Coverage (New-Report -Failures 1 -WithState $false) -Allow) $false 'not-ok report without state'

'degraded guardian rollback smoke passed'
