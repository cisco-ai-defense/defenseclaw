# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A rollback restores the deployment that was there before the transaction.
# When its guardian already had failed targets, the restored guardian's fresh
# reconcile reports ok=false, and the rollback must still accept it. Install
# and Upgrade activation (with a manifest digest) accept the same complete
# degraded reconcile as long as its activation identity matches, and log each
# failed target. An incomplete reconcile, a report with no state, or a live
# verify failure on a target the Guardian reported healthy stays rejected, as
# does any authorization error other than an incomplete-authorization count
# within the Guardian's failed plus pending targets (with at least one failed).
# The helpers are loaded from the module by AST.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The readiness probe names [ServiceProcess.ServiceControllerStatus]. Windows
# PowerShell 5.1 loads that assembly only once a service cmdlet has run, and
# this smoke stubs those out, so load it explicitly where it exists.
try {
    Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
}
catch {
    # Not available off Windows; the stub then reports a string status.
}

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
        'Test-DefenseClawGuardianReportErrorsAttributable',
        'Get-DefenseClawGuardianGeneration',
        'Get-DefenseClawGuardianReadinessProbe',
        'Invoke-DefenseClawGuardianReadinessCommand',
        'Get-DefenseClawGuardianFailedTargets',
        'Test-DefenseClawGuardianFailedTargetsWithinSIDs',
        'Get-DefenseClawAllowedFailedTargetSIDs',
        'Get-DefenseClawGuardianPendingTargets',
        'Write-DefenseClawGuardianDegradedTargets',
        'Get-DefenseClawVerifyFailedTargetKeys'
    )) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    # The module calls Get-Service module-qualified so it cannot be shadowed;
    # point the readiness probe at the stub below so the smoke also runs where
    # that cmdlet does not exist.
    $text = $definition.Extent.Text.Replace('Microsoft.PowerShell.Management\Get-Service', 'Get-DefenseClawSmokeService')
    . ([scriptblock]::Create($text))
}

$script:Events = [Collections.Generic.List[string]]::new()
function Write-DefenseClawResilienceEvent {
    param([string]$Marker, [hashtable]$Fields)
    $script:Events.Add("$Marker connector=$($Fields['connector']) sid=$($Fields['sid'])")
}
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value) [string]$Value }
# The module is not imported here: the profile is a flag. Standalone reads both label forms, Secure Client the old one only.
$script:SmokeStandalone = $true
function Test-DefenseClawStandaloneProfile { return [bool]$script:SmokeStandalone }

$startedAfter = [DateTime]::Parse('2026-10-29T00:00:00Z').ToUniversalTime()
$digest = 'a' * 64
function New-Report([int]$Failures, [int]$Rows = 3, [bool]$WithState = $true, [string]$ActivationDigest = '', [string]$FailedLabel = 'claudecode@S-1-5-21-1-2-3-1003') {
    $report = [ordered]@{
        ok = ($Failures -eq 0)
        # The exact lines `enterprise hooks status` emits for a failed target.
        errors = @($(if ($Failures -gt 0) {
                    "last guardian reconcile failed for ${FailedLabel}: hook write denied"
                    "last guardian reconcile is incomplete ($(3 - $Failures - 1) succeeded, 1 pending, 3 total)"
                    "protected guardian authorization is incomplete ($(3 - $Failures - 1) succeeded, 1 pending, 3 total)"
                }))
    }
    if ($WithState) {
        $targetRows = @(
            [ordered]@{ connector = 'claudecode'; sid = 'S-1-5-21-1-2-3-1003'; ok = ($Failures -eq 0); error = 'hook write denied' },
            [ordered]@{ connector = 'codex'; sid = 'S-1-5-21-1-2-3-1001'; ok = $true },
            [ordered]@{ connector = 'cursor'; sid = 'S-1-5-21-1-2-3-1002'; ok = $false; pending = $true }
        )
        $report.state = [pscustomobject][ordered]@{
            updated_at = '2026-10-29T00:00:05Z'
            target_count = 3
            success_count = 3 - $Failures - 1
            failure_count = $Failures
            pending_count = 1
            results = @($targetRows | Select-Object -First $Rows)
        }
    }
    if (-not [string]::IsNullOrEmpty($ActivationDigest)) {
        $report.activation = [ordered]@{
            version = 1
            updated_at = '2026-10-29T00:00:05Z'
            reconcile_id = 'b' * 32
            manifest_sha256 = $ActivationDigest
        }
    }
    return ($report | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
}
function Test-Coverage($Report, [string]$Digest = '', [switch]$Allow, [string[]]$AllowedSIDs) {
    return Test-DefenseClawGuardianCoverageReport `
        -Report $Report `
        -PriorReconcileID '' `
        -PriorGeneration '2026-10-28T00:00:00Z' `
        -PriorStateIdentity 'old' `
        -CurrentStateIdentity 'new' `
        -ExpectedManifestSHA256 $Digest `
        -StartedAfter $startedAfter `
        -AllowFailedTargets:$Allow `
        -AllowedFailedTargetSIDs $AllowedSIDs
}
function Assert-Result($Result, [bool]$Ok, [string]$Label) {
    if ([bool]$Result.ok -ne $Ok) {
        throw "${Label}: ok=$($Result.ok), want $Ok (reason: $($Result.reason))"
    }
}

Assert-Result (Test-Coverage (New-Report -Failures 0)) $true 'healthy reconcile'
Assert-Result (Test-Coverage (New-Report -Failures 1) -Allow) $true 'degraded reconcile on the rollback lane'
Assert-Result (Test-Coverage (New-Report -Failures 1)) $false 'degraded reconcile without -AllowFailedTargets'
Assert-Result (Test-Coverage (New-Report -Failures 1) -Digest $digest -Allow) $false 'degraded reconcile without activation identity'
Assert-Result (Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) -Digest $digest -Allow) $true 'degraded reconcile on the activation lane'
Assert-Result (Test-Coverage (New-Report -Failures 1 -ActivationDigest ('c' * 64)) -Digest $digest -Allow) $false 'degraded reconcile for another manifest'
Assert-Result (Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) -Digest $digest) $false 'degraded activation without -AllowFailedTargets'
Assert-Result (Test-Coverage (New-Report -Failures 1 -Rows 2) -Allow) $false 'incomplete degraded reconcile'
Assert-Result (Test-Coverage (New-Report -Failures 1 -WithState $false) -Allow) $false 'not-ok report without state'
# GAP-0900: Windows names the account of a row as "user (SID)" (GAP-2290), and the
# acceptance of a degraded reconcile read only the old "connector@SID" label, so a
# rollback or a recovery that met any failed row stayed pending with the services stopped.
$accountLabel = 'claudecode@EC2AMAZ-X\alice (S-1-5-21-1-2-3-1003)'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel $accountLabel) -Allow) $true 'degraded reconcile, row named as user (SID), rollback lane'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel $accountLabel -ActivationDigest $digest) -Digest $digest -Allow) $true 'degraded reconcile, row named as user (SID), activation lane'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'claudecode@Bob Smith (S-1-5-21-1-2-3-1003)') -Allow) $true 'degraded reconcile, user name with a space'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel $accountLabel)) $false 'user (SID) row without -AllowFailedTargets'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'claudecode@EC2AMAZ-X\alice (S-1-5-21-9-9-9-9)') -Allow) $false 'row named with a SID that is not a failed row'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'codex@EC2AMAZ-X\alice (S-1-5-21-1-2-3-1003)') -Allow) $false 'row named with another connector'
# A crafted account name: the SID of the row is the last "(S-1-...)" before the first ": ".
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'claudecode@evil (S-1-5-21-9-9-9-9) (S-1-5-21-1-2-3-1003)') -Allow) $true 'a name that holds another SID, with the real SID last'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'claudecode@evil (S-1-5-21-1-2-3-1003) (S-1-5-21-9-9-9-9)') -Allow) $false 'a name that holds the failed SID, with another SID last'
Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel 'claudecode@evil: x (S-1-5-21-1-2-3-1003)') -Allow) $false 'a name that holds a colon before the SID'
# Secure Client keeps its text and behaviour: only the old connector@SID label is read.
$script:SmokeStandalone = $false
try {
    Assert-Result (Test-Coverage (New-Report -Failures 1) -Allow) $true 'Secure Client: the connector@SID label'
    Assert-Result (Test-Coverage (New-Report -Failures 1 -FailedLabel $accountLabel) -Allow) $false 'Secure Client: the user (SID) label is not read'
}
finally {
    $script:SmokeStandalone = $true
}
$skippedSID = 'S-1-5-21-1-2-3-1003'
$otherSID = 'S-1-5-21-1-2-3-1001'
Assert-Result (Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) -Digest $digest -Allow -AllowedSIDs @($skippedSID)) $true 'failed skipped account'
Assert-Result (Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) -Digest $digest -Allow -AllowedSIDs @($otherSID)) $false 'failed unlisted account'

# The readiness wait that follows uses `enterprise hooks status`, which exits
# non-zero for a degraded Guardian. The same rollback-only allowance applies.
$script:StatusReport = New-Report -Failures 1
function Get-DefenseClawSmokeService { param($Name, $ErrorAction) [pscustomobject]@{ Status = 'Running' } }
$script:VerifyOutput = @()
function Invoke-DefenseClawGatewayCommand { param($Layout, $GatewayServiceName, $Arguments, [switch]$Capture, [switch]$AllowFailure) [pscustomobject]@{ exit_code = 1; output = @($script:VerifyOutput) } }
function Get-DefenseClawGuardianStatusReport { param($Layout, $GatewayServiceName) $script:StatusReport }
function Get-DefenseClawGuardianVerificationFailureDiagnostic { param($Probe) 'guardian not ready' }
# The live-verify probe picks its verb by profile; this lane is Secure Client.
$script:StandaloneProfile = $false
function Test-DefenseClawStandaloneProfile { $script:StandaloneProfile }
function Get-DefenseClawTargetRuntimeSkippedProfiles {
    param($Plan)
    return @($Plan.skipped_profiles)
}
$plan = [pscustomobject]@{
    skipped_profiles = @([pscustomobject]@{ sid = $otherSID })
}
$secureClientSIDs = [string[]](Get-DefenseClawAllowedFailedTargetSIDs -Plan $plan)
if ($secureClientSIDs.Count -ne 0 -or
    -not [bool](Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) `
        -Digest $digest -Allow -AllowedSIDs $secureClientSIDs).ok) {
    throw 'Secure Client rejected an unrelated failed target after one skipped profile'
}
$script:StandaloneProfile = $true
$standaloneSIDs = [string[]](Get-DefenseClawAllowedFailedTargetSIDs -Plan $plan)
if ($standaloneSIDs.Count -ne 1 -or $standaloneSIDs[0] -cne $otherSID -or
    [bool](Test-Coverage (New-Report -Failures 1 -ActivationDigest $digest) `
        -Digest $digest -Allow -AllowedSIDs $standaloneSIDs).ok) {
    throw 'standalone accepted a failure outside its skipped account'
}
$script:StandaloneProfile = $false
$probeArgs = @{ Layout = @{ ManifestPath = 'C:\targets.yaml' }; GatewayServiceName = 'gw'; GuardianServiceName = 'guardian' }
if (-not [bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets).ready) {
    throw 'rollback readiness rejected a complete degraded reconcile'
}
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs).ready) {
    throw 'readiness accepted a degraded Guardian without -AllowFailedTargets'
}
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification accepted a degraded Guardian without a per-target verify report'
}
$script:VerifyOutput = @('{"ok":false,"results":[{"connector":"claudecode","sid":"S-1-5-21-1-2-3-1003","ok":false,"error":"hook missing"},{"connector":"codex","sid":"S-1-5-21-1-2-3-1001","ok":true}]}')
$script:Events.Clear()
if (-not [bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify -AllowedFailedTargetSIDs @($skippedSID)).ready) {
    throw 'live verification rejected the failed skipped account'
}
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify -AllowedFailedTargetSIDs @($otherSID)).ready) {
    throw 'live verification accepted a failure outside the skipped account'
}
$script:Events.Clear()
if (-not [bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification rejected a failure confined to the Guardian-failed target'
}
if (@($script:Events | Where-Object { $_ -eq 'defenseclaw_degraded connector=claudecode sid=S-1-5-21-1-2-3-1003' }).Count -ne 1 -or
    @($script:Events).Count -ne 1) {
    throw "degraded activation did not log exactly the failed target: $($script:Events -join '; ')"
}
$script:VerifyOutput = @('{"ok":false,"results":[{"connector":"codex","sid":"S-1-5-21-1-2-3-1001","ok":false,"error":"hook drift"}]}')
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification accepted a failure on a target the Guardian reported healthy'
}
# `enterprise hooks verify --json` after a degraded reconcile, in the shape
# runEnterpriseHooksVerify encodes it: the reconcile wrote an ok=false
# authorization (1 succeeded, 1 pending, 1 failed of 3), which verify reports
# as authorization_error, and the failed target is outside the protected set.
function New-VerifyOutput([string]$AuthorizationError, [bool]$CodexOK = $true, [bool]$CursorOK = $true) {
    $codex = [ordered]@{
        user = 'dana'; user_home = 'C:\Users\dana'; sid = 'S-1-5-21-1-2-3-1001'
        connector = 'codex'; ok = $CodexOK
    }
    if (-not $CodexOK) {
        $codex.error = 'hook drift'
    }
    $payload = [ordered]@{
        authorization_error = $AuthorizationError
        claude_effective_policy_verified = $false
        manifest = 'C:\ProgramData\Cisco\DefenseClaw\targets.yaml'
        ok = $false
        results = @(
            [ordered]@{
                user = 'erin'; user_home = 'C:\Users\erin'; sid = 'S-1-5-21-1-2-3-1003'
                connector = 'claudecode'; ok = $false
                error = 'protected authorization does not cover target'
            },
            $codex,
            $(if ($CursorOK) {
                [ordered]@{
                    user = 'finn'; user_home = 'C:\Users\finn'; sid = 'S-1-5-21-1-2-3-1002'
                    connector = 'cursor'; ok = $true
                }
            } else {
                [ordered]@{
                    user = 'finn'; user_home = 'C:\Users\finn'; sid = 'S-1-5-21-1-2-3-1002'
                    connector = 'cursor'; ok = $false
                    error = 'protected authorization does not cover target'
                }
            })
        )
    }
    return @($payload | ConvertTo-Json -Depth 6 -Compress)
}
$degradedAuthorization = 'protected hook guardian authorization is incomplete (1 succeeded, 1 pending, 3 total)'
$script:VerifyOutput = New-VerifyOutput -AuthorizationError $degradedAuthorization
$script:Events.Clear()
if (-not [bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification rejected the incomplete authorization a degraded reconcile writes'
}
if (@($script:Events).Count -ne 1) {
    throw "degraded live verification did not log exactly the failed target: $($script:Events -join '; ')"
}
foreach ($case in @(
        @{ error = 'protected hook guardian authorization is not fresh: updated_at is too old'; label = 'an unrelated authorization error' },
        @{ error = 'protected hook guardian authorization is incomplete (0 succeeded, 0 pending, 3 total)'; label = 'an incomplete authorization with more failures than the Guardian failed and pending targets' },
        @{ error = "$degradedAuthorization; protected enrollment set is not exact: extra enrollment"; label = 'a compound authorization error' },
        @{ error = 'denied'; label = 'a protected-authorization failure' }
    )) {
    $script:VerifyOutput = New-VerifyOutput -AuthorizationError $case.error
    if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
        throw "live verification accepted $($case.label)"
    }
}
# Under the degraded authorization verify no longer credits the signed-out
# cursor target as pending: it counts it as a failure and fails its row. Both
# stay within the Guardian's failed plus pending targets.
$script:VerifyOutput = New-VerifyOutput `
    -AuthorizationError 'protected hook guardian authorization is incomplete (1 succeeded, 0 pending, 3 total)' `
    -CursorOK $false
$script:Events.Clear()
if (-not [bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification rejected a degraded install that also has a pending target'
}
if (@($script:Events).Count -ne 1) {
    throw "degraded+pending live verification did not log exactly the failed target: $($script:Events -join '; ')"
}
# Without a Guardian-failed target an incomplete authorization is never
# excused, even when its count fits the pending targets.
$pendingOnly = [pscustomobject]@{
    output = @(New-VerifyOutput -AuthorizationError 'protected hook guardian authorization is incomplete (2 succeeded, 0 pending, 3 total)')
}
if ($null -ne (Get-DefenseClawVerifyFailedTargetKeys -Probe $pendingOnly -GuardianFailedTargetCount 0 -GuardianPendingTargetCount 1)) {
    throw 'verify keys accepted an incomplete authorization without a Guardian-failed target'
}
$script:StatusReport = New-Report -Failures 0
$script:VerifyOutput = $pendingOnly.output
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification accepted an incomplete authorization when the Guardian reported no failed target'
}
$script:StatusReport = New-Report -Failures 1
$script:VerifyOutput = New-VerifyOutput -AuthorizationError $degradedAuthorization -CodexOK $false
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification accepted the degraded authorization with a failure on a Guardian-healthy target'
}
$script:VerifyOutput = @('{"ok":false,"results":[{"connector":"codex","sid":"S-1-5-21-1-2-3-1001","ok":true}]}')
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets -LiveVerify).ready) {
    throw 'live verification accepted a failed report with no failing target and no authorization verdict'
}
$script:VerifyOutput = @()
$script:StatusReport = New-Report -Failures 1 -Rows 2
if ([bool](Get-DefenseClawGuardianReadinessProbe @probeArgs -AllowFailedTargets).ready) {
    throw 'rollback readiness accepted an incomplete reconcile'
}

# A degraded report also carrying an error that is not about the failed
# target (a missing authorization) is not degraded coverage.
$unattributable = New-Report -Failures 1
$unattributable.errors = @($unattributable.errors) + 'protected hook guardian authorization is missing'
if (Test-DefenseClawGuardianReportCompletedWithFailedTargets -Report ([pscustomobject]$unattributable)) {
    throw 'a degraded report with a missing authorization was accepted as degraded coverage'
}
$foreignTarget = New-Report -Failures 1
$foreignTarget.errors = @('last guardian reconcile failed for codex@S-1-5-21-1-2-3-1001: denied')
if (Test-DefenseClawGuardianReportCompletedWithFailedTargets -Report ([pscustomobject]$foreignTarget)) {
    throw 'a failure line for a target the state reports healthy was accepted as degraded coverage'
}

'degraded guardian rollback smoke passed'
