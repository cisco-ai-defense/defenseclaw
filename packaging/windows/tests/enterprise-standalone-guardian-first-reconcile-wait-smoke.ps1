# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0401: Setup waits for the first reconcile of the standalone guardian it
# started. Past the usual wait it keeps waiting, up to the hard limit, while
# that guardian process is alive and its startup record shows the reconcile
# still moving; a stopped, replaced, stalled or finished guardian, a guardian
# without the record and Secure Client keep the usual limit. The error names
# the cause and the guardian log. Runs in a disposable scratch directory with
# the service and status calls replaced.

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
    ('dc-guardian-first-reconcile-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $saved = @(
            $script:GuardianFirstReconcileTimeoutSeconds,
            $script:GuardianFirstReconcileStallSeconds,
            $script:GuardianFirstReconcileCheckSeconds
        )
        $runtime = [IO.Path]::Combine($Root, 'runtime')
        [void][IO.Directory]::CreateDirectory($runtime)
        $layout = @{
            RuntimeDirectory = $runtime
            StateRoot = $Root
            GuardianLogPath = [IO.Path]::Combine($Root, 'logs', 'guardian', 'hook-guardian.log')
        }
        $script:SmokeRecordPath = [IO.Path]::Combine($runtime, 'hook_guardian_startup.json')
        $script:SmokeStart = [DateTime]::UtcNow

        function script:Write-SmokeStartupRecord {
            param([string]$State, [DateTime]$UpdatedAt, [int64]$ProcessId)
            $body = [ordered]@{
                version = 1
                pid = $ProcessId
                state = $State
                started_at = $script:SmokeStart.ToString('o')
                updated_at = $UpdatedAt.ToUniversalTime().ToString('o')
                targets_done = 3
                targets_total = 10
            }
            [IO.File]::WriteAllText(
                $script:SmokeRecordPath,
                (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $body -Compress)
            )
        }
        function script:Stop-DefenseClawService { param([string]$Name) }
        function script:Start-DefenseClawService {
            param([string]$Name, [string]$FailureLogPath)
            $script:SmokeStart = [DateTime]::UtcNow
            if (-not [string]::IsNullOrEmpty($script:SmokeRecordState)) {
                Write-SmokeStartupRecord -State $script:SmokeRecordState -UpdatedAt $script:SmokeStart -ProcessId $script:SmokeRecordPid
            }
        }
        function script:Get-DefenseClawGuardianStatusReport {
            param($Layout, $GatewayServiceName)
            return $null
        }
        function script:Get-DefenseClawGuardianStateIdentity { param($Layout) return $null }
        function script:Get-DefenseClawServiceProcessId {
            param([string]$Name)
            if ($null -ne $script:SmokeGoneAfter -and
                ([DateTime]::UtcNow - $script:SmokeStart).TotalSeconds -ge $script:SmokeGoneAfter) {
                return [uint32]0
            }
            return [uint32]4242
        }
        function script:Test-DefenseClawGuardianCoverageReport {
            param(
                $Report, $PriorReconcileID, $PriorGeneration, $PriorStateIdentity,
                $CurrentStateIdentity, $ExpectedManifestSHA256, $StartedAfter
            )
            $elapsed = ([DateTime]::UtcNow - $script:SmokeStart).TotalSeconds
            if ($script:SmokeHeartbeat) {
                # The guardian moves on to its next target. Antivirus may
                # hold the file for a moment; the next poll writes it again.
                try {
                    Write-SmokeStartupRecord -State $script:SmokeRecordState -UpdatedAt ([DateTime]::UtcNow) -ProcessId $script:SmokeRecordPid
                }
                catch {
                }
            }
            if ($null -ne $script:SmokeCoveredAfter -and $elapsed -ge $script:SmokeCoveredAfter) {
                return [pscustomobject]@{ ok = $true; generation = 'smoke-generation'; reason = '' }
            }
            return [pscustomobject]@{
                ok = $false
                generation = ''
                reason = 'hook guardian has not completed a reconcile'
            }
        }
        $run = {
            param(
                [string]$Name,
                [string]$RecordState = 'reconciling',
                [int64]$RecordPid = 4242,
                [bool]$Heartbeat = $true,
                $CoveredAfter = $null,
                $GoneAfter = $null
            )
            [IO.File]::Delete($script:SmokeRecordPath)
            $script:SmokeRecordState = $RecordState
            $script:SmokeRecordPid = $RecordPid
            $script:SmokeHeartbeat = $Heartbeat -and -not [string]::IsNullOrEmpty($RecordState)
            $script:SmokeCoveredAfter = $CoveredAfter
            $script:SmokeGoneAfter = $GoneAfter
            $started = [DateTime]::UtcNow
            $result = [ordered]@{ name = $Name; generation = $null; message = ''; seconds = 0.0 }
            try {
                $result.generation = Wait-DefenseClawFreshGuardianReconcile `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName 'DefenseClawHookGuardian' `
                    -TimeoutSeconds 1
            }
            catch {
                $result.message = [string]$_.Exception.Message
            }
            $result.seconds = ([DateTime]::UtcNow - $started).TotalSeconds
            return [pscustomobject]$result
        }
        $expect = {
            param($Result, [double]$AtLeast, [double]$AtMost, [string[]]$Contains, [string[]]$Lacks = @())
            if ($Result.seconds -lt $AtLeast -or $Result.seconds -gt $AtMost) {
                $failures.Add("$($Result.name): waited $([Math]::Round($Result.seconds, 1)) s, want $AtLeast-$AtMost s ($($Result.message))")
            }
            foreach ($text in $Contains) {
                if (-not ([string]$Result.message).Contains($text)) {
                    $failures.Add("$($Result.name): error lacks '$text': '$($Result.message)'")
                }
            }
            foreach ($text in $Lacks) {
                if (([string]$Result.message).Contains($text)) {
                    $failures.Add("$($Result.name): error has '$text': '$($Result.message)'")
                }
            }
        }
        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'Standalone'
            $script:GuardianFirstReconcileTimeoutSeconds = 12
            $script:GuardianFirstReconcileStallSeconds = 4
            $script:GuardianFirstReconcileCheckSeconds = 1
            $log = [string]$layout.GuardianLogPath

            # A long first reconcile that still moves is waited for.
            $result = & $run -Name 'long first reconcile' -CoveredAfter 3
            if ($result.generation -cne 'smoke-generation') {
                $failures.Add("long first reconcile: no coverage after $([Math]::Round($result.seconds, 1)) s: $($result.message)")
            }
            & $expect $result 2.5 7.0 @()

            # One still running at the hard limit names the cause and the log.
            $result = & $run -Name 'hard limit'
            & $expect $result 11.5 15.5 @("first reconcile is still running after", '3 of 10 targets done', $log, 'last_status=hook guardian has not completed a reconcile')

            # A guardian that stops fails at the usual time, well before the limit
            # (the bounds leave room for a busy host).
            $result = & $run -Name 'stopped guardian' -GoneAfter 0.5
            & $expect $result 0.9 5.0 @('process 4242 is no longer running during its first reconcile', $log)

            # A reconcile that stops moving fails at the stall limit.
            $result = & $run -Name 'stalled reconcile' -Heartbeat $false
            & $expect $result 0.9 9.0 @("first reconcile is still running after", 'last progress', $log)

            # A finished reconcile gets one more read of its records.
            $result = & $run -Name 'finished, then covered' -RecordState 'finished' -CoveredAfter 1.6
            if ($result.generation -cne 'smoke-generation') {
                $failures.Add("finished, then covered: $($result.message)")
            }
            $result = & $run -Name 'finished, not covered' -RecordState 'finished'
            & $expect $result 0.9 6.0 @('did not publish fresh required coverage within', $log) @('still running')

            # Without a record of this guardian the usual limit stands.
            $result = & $run -Name 'no record' -RecordState ''
            & $expect $result 0.9 5.0 @('did not publish fresh required coverage within', $log)
            $result = & $run -Name 'record of another process' -RecordPid 999
            & $expect $result 0.9 5.0 @('did not publish fresh required coverage within') @('still running')

            # The record reader refuses a record older than this start, of
            # another version or oversized.
            $script:SmokeStart = [DateTime]::UtcNow
            Write-SmokeStartupRecord -State 'reconciling' -UpdatedAt ([DateTime]::UtcNow) -ProcessId 4242
            $read = Get-DefenseClawGuardianStartupProgress -Layout $layout -ProcessId 4242 -StartedAfter $script:SmokeStart.AddSeconds(-1)
            if ($null -eq $read -or $read.state -cne 'reconciling' -or $read.targets_done -ne 3 -or $read.targets_total -ne 10) {
                $failures.Add("record reader: a valid record read as '$read'")
            }
            if ($null -ne (Get-DefenseClawGuardianStartupProgress -Layout $layout -ProcessId 4242 -StartedAfter $script:SmokeStart.AddSeconds(5))) {
                $failures.Add('record reader: a record from before this start was accepted')
            }
            [IO.File]::WriteAllText($script:SmokeRecordPath, ([IO.File]::ReadAllText($script:SmokeRecordPath) -replace '"version":1', '"version":2'))
            if ($null -ne (Get-DefenseClawGuardianStartupProgress -Layout $layout -ProcessId 4242 -StartedAfter $script:SmokeStart.AddSeconds(-1))) {
                $failures.Add('record reader: a version 2 record was accepted')
            }
            [IO.File]::WriteAllText($script:SmokeRecordPath, (' ' * 5000))
            if ($null -ne (Get-DefenseClawGuardianStartupProgress -Layout $layout -ProcessId 4242 -StartedAfter $script:SmokeStart.AddSeconds(-1))) {
                $failures.Add('record reader: an oversized record was accepted')
            }

            # Secure Client keeps its wait and its error.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'SecureClient'
            $result = & $run -Name 'Secure Client'
            & $expect $result 0.9 5.0 @('did not publish fresh required coverage within 1 seconds; last_status=') @($log)
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
            $script:GuardianFirstReconcileTimeoutSeconds = $saved[0]
            $script:GuardianFirstReconcileStallSeconds = $saved[1]
            $script:GuardianFirstReconcileCheckSeconds = $saved[2]
        }
        return @($failures)
    } $root
    if (@($failures).Count -gt 0) {
        throw ("guardian first-reconcile wait smoke failed:`n" + (@($failures) -join "`n"))
    }
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-guardian-first-reconcile-wait-smoke: OK'
}
finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
