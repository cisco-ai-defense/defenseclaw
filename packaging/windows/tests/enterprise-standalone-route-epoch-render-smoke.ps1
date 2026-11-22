# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# rel-1-0-10:GAP-0937: the guardian publishes the activation reconcile while
# the gateway is still disabled, so a route epoch the gateway publishes when
# Setup starts it was not in that render, and the live verify ended Setup
# /ensure 1603 with route_config_drift. After gateway readiness Setup waits,
# bounded, for a published epoch, and has the guardian publish one fresh
# reconcile when it differs from the one the guardian rendered from. An
# unchanged epoch, an epoch that never appears, and the Secure Client profile
# run no extra reconcile. Runs in a disposable scratch directory with the
# guardian reconcile replaced.

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
    ('dc-route-epoch-render-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $runtime = [IO.Path]::Combine($Root, 'runtime')
        $hooks = [IO.Path]::Combine($runtime, 'hooks')
        [void][IO.Directory]::CreateDirectory($hooks)
        $epochPath = [IO.Path]::Combine($hooks, 'route-epoch.json')
        $layout = @{ RuntimeDirectory = $runtime; StateRoot = $Root }
        $script:SmokeReconciles = [Collections.Generic.List[object]]::new()
        function script:Wait-DefenseClawFreshGuardianReconcile {
            param($Layout, $GatewayServiceName, $GuardianServiceName, $ExpectedManifestSHA256, [switch]$AllowFailedTargets)
            $script:SmokeReconciles.Add([pscustomobject]@{ manifest = $ExpectedManifestSHA256; degraded = [bool]$AllowFailedTargets })
            return 'smoke-generation'
        }
        function script:Write-DefenseClawLifecyclePhase { param([string]$Stage) }
        $writeEpoch = {
            param([string]$Value)
            [IO.File]::WriteAllText($epochPath, ('{"version":1,"epoch":"' + $Value + '"}'))
        }
        $sync = {
            param([string]$Prior, [int]$Timeout = 2)
            return [bool](Sync-DefenseClawGuardianRouteEpochRender `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -PriorEpochIdentity $Prior `
                -ExpectedManifestSHA256 ('a' * 64) `
                -TimeoutSeconds $Timeout `
                -AllowFailedTargets)
        }
        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'Standalone'

            # The first epoch of the host: none before the gateway started,
            # published by it.
            $before = Get-DefenseClawRouteEpochIdentity -Layout $layout
            if ($before -ne '') {
                $failures.Add("no epoch: identity = '$before', want ''")
            }
            & $writeEpoch ('1' * 64)
            if (-not (& $sync $before)) {
                $failures.Add('a newly published epoch did not get a fresh guardian reconcile')
            }
            if ($script:SmokeReconciles.Count -ne 1 -or
                $script:SmokeReconciles[0].manifest -cne ('a' * 64) -or
                -not $script:SmokeReconciles[0].degraded) {
                $failures.Add("fresh reconcile calls: $($script:SmokeReconciles | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress)")
            }

            # A normal restart keeps the published epoch: no extra reconcile.
            $script:SmokeReconciles.Clear()
            $kept = Get-DefenseClawRouteEpochIdentity -Layout $layout
            if (& $sync $kept) {
                $failures.Add('a kept epoch ran a fresh guardian reconcile')
            }

            # A rotation (the API port was held during the restart).
            & $writeEpoch ('2' * 64)
            if (-not (& $sync $kept) -or $script:SmokeReconciles.Count -ne 1) {
                $failures.Add('a rotated epoch did not get a fresh guardian reconcile')
            }

            # The epoch appears while Setup waits for it.
            $script:SmokeReconciles.Clear()
            [IO.File]::Delete($epochPath)
            $job = [PowerShell]::Create()
            [void]$job.AddScript({
                param([string]$Path)
                Start-Sleep -Milliseconds 700
                [IO.File]::WriteAllText($Path, ('{"version":1,"epoch":"' + ('3' * 64) + '"}'))
            }).AddArgument($epochPath)
            $handle = $job.BeginInvoke()
            try {
                if (-not (& $sync '' 10) -or $script:SmokeReconciles.Count -ne 1) {
                    $failures.Add('an epoch published during the wait did not get a fresh guardian reconcile')
                }
            }
            finally {
                [void]$job.EndInvoke($handle)
                $job.Dispose()
            }

            # No epoch within the bound: no reconcile and no error here; the
            # live verify reports it.
            $script:SmokeReconciles.Clear()
            [IO.File]::Delete($epochPath)
            $started = [DateTime]::UtcNow
            if (& $sync '' 1) {
                $failures.Add('a missing epoch ran a fresh guardian reconcile')
            }
            $waited = ([DateTime]::UtcNow - $started).TotalSeconds
            if ($waited -lt 0.9 -or $waited -gt 5) {
                $failures.Add("missing epoch: waited $waited s, want about 1 s")
            }

            # Secure Client publishes no epoch and keeps its sequence.
            & $writeEpoch ('4' * 64)
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'SecureClient'
            if ((Get-DefenseClawRouteEpochIdentity -Layout $layout) -ne '' -or (& $sync '')) {
                $failures.Add('Secure Client ran the route epoch render')
            }
            if ($script:SmokeReconciles.Count -ne 0) {
                $failures.Add('Secure Client ran a fresh guardian reconcile')
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return @($failures)
    } $root
    if (@($failures).Count -gt 0) {
        throw ("route epoch render smoke failed:`n" + (@($failures) -join "`n"))
    }
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-route-epoch-render-smoke: OK'
}
finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}
