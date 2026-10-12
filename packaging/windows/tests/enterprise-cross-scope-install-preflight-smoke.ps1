# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

param(
    [string]$ModulePath = (
        Microsoft.PowerShell.Management\Join-Path `
            (Microsoft.PowerShell.Management\Split-Path -Parent $PSScriptRoot) `
            'DefenseClawEnterprise.psm1'
    ),
    [switch]$InspectLiveOwners
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Microsoft.PowerShell.Core\Import-Module -Name $ModulePath -Force
$module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClawEnterprise module was not imported'
}

# The lock-protected Install guard must precede pre-layout recovery, since
# recovery itself can restore the shared machine-hook policy. Check this
# boundary without invoking the live lifecycle or mutating the VM.
$parseTokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $ModulePath, [ref]$parseTokens, [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw 'enterprise module failed to parse'
}
$lifecycleAst = $moduleAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-DefenseClawEnterpriseLifecycle'
}, $true)
if ($null -eq $lifecycleAst) {
    throw 'enterprise lifecycle entry point was not found'
}
$lifecycleCommands = @($lifecycleAst.Body.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true))
$lockCalls = @($lifecycleCommands | Microsoft.PowerShell.Core\Where-Object {
    $_.GetCommandName() -ceq 'Enter-DefenseClawLifecycleLock'
})
$preflightCalls = @($lifecycleCommands | Microsoft.PowerShell.Core\Where-Object {
    $_.GetCommandName() -ceq 'Assert-DefenseClawInstallSharedHookScopeExclusive'
})
$recoveryCalls = @($lifecycleCommands | Microsoft.PowerShell.Core\Where-Object {
    $_.GetCommandName() -ceq 'Invoke-DefenseClawPreLayoutRecovery'
})
if ($lockCalls.Count -ne 1 -or $preflightCalls.Count -ne 1 -or
    $recoveryCalls.Count -ne 1 -or
    $lockCalls[0].Extent.StartOffset -ge $preflightCalls[0].Extent.StartOffset -or
    $preflightCalls[0].Extent.StartOffset -ge $recoveryCalls[0].Extent.StartOffset) {
    throw 'Install shared-hook preflight does not precede pre-layout recovery under the lifecycle lock'
}
$installGuarded = $false
foreach ($ifAst in @($lifecycleAst.Body.FindAll({
            param($node)
            $node -is [Management.Automation.Language.IfStatementAst]
        }, $true))) {
    foreach ($clause in @($ifAst.Clauses)) {
        if ([string]$clause.Item1.Extent.Text -cmatch '^\$Action\s+-eq\s+''Install''$' -and
            $clause.Item2.Extent.StartOffset -lt $preflightCalls[0].Extent.StartOffset -and
            $preflightCalls[0].Extent.EndOffset -lt $clause.Item2.Extent.EndOffset) {
            $installGuarded = $true
        }
    }
}
if (-not $installGuarded) {
    throw 'early shared-hook preflight is not limited to Install'
}

& $module {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $layout = @{ BrokerServiceName = 'DefenseClawCMIDBroker' }
    $ownServices = @(
        [pscustomobject]@{ Name = 'DefenseClawGateway'; Status = 'Running' },
        [pscustomobject]@{ Name = 'DefenseClawHookGuardian'; Status = 'Running' },
        [pscustomobject]@{ Name = 'DefenseClawHookEnumerator'; Status = 'Running' },
        [pscustomobject]@{ Name = 'DefenseClawCMIDBroker'; Status = 'Running' }
    )
    Assert-DefenseClawNoForeignManagedService `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Services $ownServices `
        -Operation 'managed-hook install' `
        -ActiveOnly `
        -SharedHookOwners @('DefenseClawGateway')
    $foreignServices = @($ownServices) + @(
        [pscustomobject]@{ Name = 'DefenseClawCertGateway_1165c1ff8a'; Status = 'Running' }
    )
    $foreignFailure = ''
    try {
        Assert-DefenseClawNoForeignManagedService `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -Services $foreignServices `
            -Operation 'managed-hook install' `
            -ActiveOnly
    }
    catch {
        $foreignFailure = [string]$_.Exception.Message
    }
    if ($foreignFailure -notmatch 'another managed DefenseClaw scope exists: DefenseClawCertGateway_1165c1ff8a') {
        throw "foreign enterprise scope was not rejected: $foreignFailure"
    }
    $pendingForeignServices = @($ownServices) + @(
        [pscustomobject]@{ Name = 'DefenseClawCertGateway_1165c1ff8a'; Status = 'StartPending' }
    )
    $pendingFailure = ''
    try {
        Assert-DefenseClawNoForeignManagedService `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -Services $pendingForeignServices `
            -Operation 'managed-hook install' `
            -ActiveOnly
    }
    catch {
        $pendingFailure = [string]$_.Exception.Message
    }
    if ($pendingFailure -notmatch 'another managed DefenseClaw scope exists: DefenseClawCertGateway_1165c1ff8a') {
        throw "starting foreign enterprise scope was not rejected: $pendingFailure"
    }
    $stoppedForeignServices = @($ownServices) + @(
        [pscustomobject]@{ Name = 'DefenseClawCertGateway_f09a6214cd'; Status = 'Stopped' }
    )
    Assert-DefenseClawNoForeignManagedService `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Services $stoppedForeignServices `
        -Operation 'managed-hook install' `
        -ActiveOnly
    $stoppedOwnerFailure = ''
    try {
        Assert-DefenseClawNoForeignManagedService `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -Services $stoppedForeignServices `
            -Operation 'managed-hook install' `
            -ActiveOnly `
            -SharedHookOwners @('DefenseClawCertGateway_f09a6214cd')
    }
    catch {
        $stoppedOwnerFailure = [string]$_.Exception.Message
    }
    if ($stoppedOwnerFailure -notmatch 'another managed DefenseClaw scope owns shared hooks: DefenseClawCertGateway_f09a6214cd') {
        throw "stopped foreign owner was not rejected: $stoppedOwnerFailure"
    }
    $missingServiceOwnerFailure = ''
    try {
        Assert-DefenseClawNoForeignManagedService `
            -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -Services $ownServices `
            -Operation 'managed-hook install' `
            -ActiveOnly `
            -SharedHookOwners @('DefenseClawCertGateway_1165c1ff8a')
    }
    catch {
        $missingServiceOwnerFailure = [string]$_.Exception.Message
    }
    if ($missingServiceOwnerFailure -notmatch 'another managed DefenseClaw scope owns shared hooks: DefenseClawCertGateway_1165c1ff8a') {
        throw "foreign hook owner without SCM service was not rejected: $missingServiceOwnerFailure"
    }

    # Exercise the actual fresh-install preparation boundary. A rejected
    # scope must fail before its first durable intent write, which also means
    # the later transaction and shared connector writers cannot run. The real
    # guard runs, so this also proves the wrapper forwards the shared-hook
    # owners and -ActiveOnly; the guard rejects a foreign owner before its SCM
    # service loop, so no matching service is needed.
    $realGet = (Microsoft.PowerShell.Core\Get-Command `
        -Name Get-DefenseClawInstallRollbackIntent `
        -CommandType Function).ScriptBlock
    $realWrite = (Microsoft.PowerShell.Core\Get-Command `
        -Name Write-DefenseClawInstallRollbackIntent `
        -CommandType Function).ScriptBlock
    $realOwnerRead = (Microsoft.PowerShell.Core\Get-Command `
        -Name Get-DefenseClawSharedManagedHookOwners `
        -CommandType Function).ScriptBlock
    $script:CrossScopeIntentWrites = 0
    function script:Get-DefenseClawInstallRollbackIntent { return $null }
    function script:Get-DefenseClawSharedManagedHookOwners {
        return @('DefenseClawCertGateway_1165c1ff8a')
    }
    function script:Write-DefenseClawInstallRollbackIntent {
        $script:CrossScopeIntentWrites++
        throw 'unexpected install intent write'
    }
    try {
        $preparationFailure = ''
        try {
            [void](New-DefenseClawInstallPreparationIntent `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -InstallRootBaseline $null `
                -StateRootBaseline $null)
        }
        catch {
            $preparationFailure = [string]$_.Exception.Message
        }
        if ($preparationFailure -cne (
                'refusing managed-hook install while another managed ' +
                'DefenseClaw scope owns shared hooks: DefenseClawCertGateway_1165c1ff8a'
            ) -or
            $script:CrossScopeIntentWrites -ne 0) {
            throw (
                'fresh install crossed the foreign-scope preflight boundary: ' +
                "$preparationFailure; intent writes=$script:CrossScopeIntentWrites"
            )
        }
    }
    finally {
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Get-DefenseClawInstallRollbackIntent' `
            -Value $realGet
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Write-DefenseClawInstallRollbackIntent' `
            -Value $realWrite
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Get-DefenseClawSharedManagedHookOwners' `
            -Value $realOwnerRead
    }
}

if ($InspectLiveOwners) {
    & $module {
        $layout = @{
            CodexManagedHooksStatePath = [IO.Path]::Combine(
                $env:ProgramData, 'OpenAI', 'Codex',
                '.defenseclaw-managed-hooks.state'
            )
            CodexMachinePolicyPath = [IO.Path]::Combine(
                $env:ProgramData, 'OpenAI', 'Codex', 'requirements.toml'
            )
        }
        @(Get-DefenseClawSharedManagedHookOwners -Layout $layout) |
            Microsoft.PowerShell.Utility\Write-Output
    }
}

Microsoft.PowerShell.Utility\Write-Output 'enterprise cross-scope install preflight smoke passed'
