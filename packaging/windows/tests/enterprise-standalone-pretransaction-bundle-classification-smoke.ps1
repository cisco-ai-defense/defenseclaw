# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-0822: before an upgrade or repair with no committed journal opens its
# transaction, Setup has the replacement gateway classify the per-user
# managed runtime bundles. Only a bundle that classification refuses stops
# the lifecycle. An elevated administrator's Setup /ensure or /repair, and
# any other failure of this early check, goes on to the transaction, whose
# retire after the commit classifies as before. The gateway is mocked here;
# the Go tests check what it classifies and that it changes nothing.

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$failures = & $module {
    $failures = [Collections.Generic.List[string]]::new()
    $layout = @{ ManagedHooksLifecycleJournalPath = 'C:\ProgramData\DefenseClaw\install\managed-hooks-lifecycle-journal.json' }
    $script:TestSnapshotError = $null
    $script:TestSnapshotCalls = [Collections.Generic.List[string]]::new()
    function Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
        param([hashtable]$Layout, [string]$GatewayServiceName, [string]$Action, [hashtable]$GatewaySource)
        $script:TestSnapshotCalls.Add("$Action staged=$($null -ne $GatewaySource)")
        if ($null -eq $script:TestSnapshotError) {
            return [pscustomobject]@{ ok = $true }
        }
        if ($script:TestSnapshotError -is [string]) {
            throw $script:TestSnapshotError
        }
        $reportError = [string]$script:TestSnapshotError.report
        $exception = [Management.Automation.RuntimeException]::new("managed-hook lifecycle snapshot retire failed: $reportError")
        $exception.Data['DefenseClawLifecycleAction'] = 'retire'
        $exception.Data['DefenseClawLifecycleReportError'] = $reportError
        throw $exception
    }
    $cases = @(
        @{ name = 'healthy bundles'; error = $null; wantThrow = $false },
        @{ name = 'malformed selected bundle'; wantThrow = $true
            error = @{ report = 'classify opencode managed runtime generations for SID S-1-5-21-1-2-3-1017 (CONTOSO\std1): enterprise hooks: decode managed runtime bundle: unexpected EOF' } },
        @{ name = 'unsupported schema'; wantThrow = $true
            error = @{ report = 'classify kiro managed runtime generations for SID S-1-5-21-1-2-3-1018: enterprise hooks: refusing to collect managed runtime bundle C:\Users\std2\.defenseclaw\hooks\x.json: unsupported schema version 2' } },
        # A gateway from before refix round 1 refused an elevated
        # administrator here; that and any other early failure goes on.
        @{ name = 'administrator identity refusal'; wantThrow = $false
            error = @{ report = 'staged managed-hook retirement: managed enterprise hook mutations require the LocalSystem guardian on native Windows' } },
        @{ name = 'staged image refusal'; wantThrow = $false
            error = @{ report = 'staged managed-hook retirement requires protected installed deployment metadata' } },
        @{ name = 'unreported failure'; wantThrow = $false; error = 'gateway process could not start' }
    )
    foreach ($case in $cases) {
        $script:TestSnapshotError = $case.error
        $script:TestSnapshotCalls.Clear()
        $threw = $false
        $message = ''
        try {
            Assert-DefenseClawStagedRuntimeBundleClassification `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GatewaySource @{ path = 'authenticated replacement gateway' } `
                -Action 'Repair' `
                -WarningAction SilentlyContinue
        }
        catch {
            $threw = $true
            $message = [string]$_.Exception.Message
        }
        if ($threw -ne $case.wantThrow) {
            $failures.Add("$($case.name): threw=$threw ($message), want $($case.wantThrow)")
            continue
        }
        if (($script:TestSnapshotCalls -join ',') -cne 'retire staged=True') {
            $failures.Add("$($case.name): gateway calls '$($script:TestSnapshotCalls -join ',')', want one staged retire")
        }
        if ($threw) {
            if (-not $message.StartsWith('Repair stopped before it changed anything:', [StringComparison]::Ordinal) -or
                -not $message.Contains([string]$case.error.report)) {
                $failures.Add("$($case.name): refusal lost its remedy or the gateway error: $message")
            }
        }
    }
    return , $failures
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-pretransaction-bundle-classification-smoke: OK'
