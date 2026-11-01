# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1886: after a recovery puts a 1.0.2 deployment back, its gateway has no
# 'enterprise hooks readiness' and answers 'unknown flag: --manifest'. The
# guardian proof then asks it with verify, as 1.0.2 proved itself, instead of
# failing a recovered deployment; any other readiness failure stands.

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
    $layout = @{ ManifestPath = 'C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml' }
    $script:TestVerbs = [Collections.Generic.List[string]]::new()
    $script:TestReadinessOutput = ''
    function Invoke-DefenseClawGatewayCommand {
        param($Layout, $GatewayServiceName, $Arguments, [switch]$Capture, [switch]$AllowFailure)
        $verb = [string]$Arguments[2]
        $script:TestVerbs.Add($verb)
        if ($verb -eq 'readiness') {
            return [pscustomobject]@{ exit_code = 1; output = @($script:TestReadinessOutput) }
        }
        return [pscustomobject]@{ exit_code = 0; output = @('{"ok":true}') }
    }
    foreach ($case in @(
            @{ name = '1.0.2 gateway'; output = 'Error: unknown flag: --manifest'; verbs = 'readiness,verify'; exit = 0 },
            @{ name = 'readiness failure'; output = '{"ok":false,"results":[]}'; verbs = 'readiness'; exit = 1 }
        )) {
        $script:TestVerbs.Clear()
        $script:TestReadinessOutput = $case.output
        $probe = Invoke-DefenseClawGuardianReadinessCommand -Layout $layout -GatewayServiceName 'DefenseClawGateway' -Verb 'readiness'
        if (($script:TestVerbs -join ',') -cne $case.verbs -or [int]$probe.exit_code -ne $case.exit) {
            $failures.Add("$($case.name): verbs '$($script:TestVerbs -join ',')' exit $($probe.exit_code), want '$($case.verbs)' exit $($case.exit)")
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-guardian-readiness-older-gateway-smoke: OK'
