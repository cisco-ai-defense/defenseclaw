# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1902: the printed Setup /uninstall FORCE=1 removes DefenseClaw's own
# residue beside the installed files (a guardian's <hook>.restore-<hex>
# temporary, replacement backups) before the exact-scope purge, whose
# descriptor check refused it as foreign; a refusal there still restores what
# the preparation changed.

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
    $script:TestCalls = [Collections.Generic.List[string]]::new()
    $script:TestResidueError = $null
    function Invoke-DefenseClawForcedUninstallPreparation { param($Layout, $GatewayServiceName, $GuardianServiceName) $script:TestCalls.Add('prepare'); return @{ moved_state_root = ''; moved_install_rollback_intent = '' } }
    function Move-DefenseClawForcedUninstallInstallReceipt { param($Layout, $Preparation) $script:TestCalls.Add('receipt') }
    function Remove-DefenseClawStandaloneInstallTreeReplacementBackups {
        param($Layout)
        $script:TestCalls.Add('residue')
        if ($null -ne $script:TestResidueError) { throw $script:TestResidueError }
    }
    function Invoke-DefenseClawPreLayoutRecovery { $script:TestCalls.Add('purge'); return @{ handled = $true; result = [pscustomobject]@{ ok = $true } } }
    function Restore-DefenseClawForcedUninstallPreparation { param($Preparation) $script:TestCalls.Add('restore'); return @() }
    function Complete-DefenseClawForcedUninstall { param($Result, $MovedStateRoot, $MovedInstallReceipt, $Layout) $script:TestCalls.Add('complete'); return $Result }

    [void](Invoke-DefenseClawForcedUninstall -Layout @{} -GatewayServiceName 'DefenseClawGateway' -GuardianServiceName 'DefenseClawHookGuardian')
    if (($script:TestCalls -join ',') -cne 'prepare,receipt,residue,purge,complete') {
        $failures.Add("forced uninstall order '$($script:TestCalls -join ',')', want the residue removed before the purge")
    }
    $script:TestCalls.Clear()
    $script:TestResidueError = 'a program started before the last DefenseClaw upgrade still runs the earlier copy'
    $threw = $false
    try {
        [void](Invoke-DefenseClawForcedUninstall -Layout @{} -GatewayServiceName 'DefenseClawGateway' -GuardianServiceName 'DefenseClawHookGuardian')
    }
    catch {
        $threw = $_.Exception.Message.Contains('still runs the earlier copy')
    }
    if (-not $threw -or ($script:TestCalls -join ',') -cne 'prepare,receipt,residue,restore') {
        $failures.Add("held residue: threw=$threw calls '$($script:TestCalls -join ',')', want the refusal named and the preparation restored")
    }
    return , $failures
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-forced-uninstall-residue-smoke: OK'
