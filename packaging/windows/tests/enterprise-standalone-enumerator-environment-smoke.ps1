# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A replaced manifest retires the Claude Code attestation, and the service
# assertion compares the enumerator's environment pins against the layout.
# The standalone lifecycle therefore rewrites the enumerator's pins from the
# layout too; Secure Client is unchanged. Writes no registry: the service
# environment writer is replaced inside the module for the test.

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
    $failures = [Collections.Generic.List[string]]::new()
    $originalProfile = Get-DefenseClawEnterpriseProfile
    $originalWriter = ${function:script:Set-DefenseClawServiceEnvironment}
    $script:EnumeratorSmokeWrites = [Collections.Generic.List[string]]::new()
    ${function:script:Set-DefenseClawServiceEnvironment} = {
        param($Name, $RuntimeDirectory, $ConfigPath, $AuthorizationDirectory,
            $GatewayServiceName, $LogPath, [switch]$AgentApplicationControlAttested,
            [switch]$ClaudeEffectivePolicyVerified)
        $script:EnumeratorSmokeWrites.Add(('{0} claude={1}' -f $Name, [bool]$ClaudeEffectivePolicyVerified))
    }
    $layout = @{
        RuntimeDirectory = 'C:\dc-smoke\runtime'
        ConfigPath = 'C:\dc-smoke\config.yaml'
        AuthorizationDirectory = 'C:\dc-smoke\authorization'
        GuardianLogPath = 'C:\dc-smoke\guardian.log'
        AgentApplicationControlAttested = $false
        ClaudeEffectivePolicyVerified = $false
    }
    $enumerator = Get-DefenseClawEnumeratorServiceName -GuardianServiceName 'DefenseClawHookGuardian'
    try {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'Standalone'
        Set-DefenseClawStandaloneEnumeratorEnvironment `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian'
        $want = "$enumerator claude=False"
        if (($script:EnumeratorSmokeWrites -join ';') -cne $want) {
            $failures.Add("standalone writes were '$($script:EnumeratorSmokeWrites -join ';')', want '$want'")
        }

        $script:EnumeratorSmokeWrites.Clear()
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'SecureClient'
        Set-DefenseClawStandaloneEnumeratorEnvironment `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian'
        if ($script:EnumeratorSmokeWrites.Count -ne 0) {
            $failures.Add("Secure Client wrote '$($script:EnumeratorSmokeWrites -join ';')'")
        }
    }
    finally {
        ${function:script:Set-DefenseClawServiceEnvironment} = $originalWriter
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
    }
    , $failures
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-enumerator-environment-smoke: OK'
