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
        [pscustomobject]@{ Name = 'DefenseClawCMIDBroker'; Status = 'Running' },
        [pscustomobject]@{ Name = 'DefenseClawSensorHelper'; Status = 'Running' }
    )
    # Both profiles include the sensor helper. This scope's helper must pass
    # both the install and cleanup checks, including during failed installs.
    foreach ($profile in @('SecureClient', 'Standalone')) {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $profile
        $profileLayout = @{
            BrokerServiceName = if ($profile -ceq 'Standalone') {
                ''
            }
            else {
                'DefenseClawCMIDBroker'
            }
        }
        $profileServices = @($ownServices | Microsoft.PowerShell.Core\Where-Object {
                $profile -cne 'Standalone' -or $_.Name -cne 'DefenseClawCMIDBroker'
            })
        foreach ($activeOnly in @($true, $false)) {
            Assert-DefenseClawNoForeignManagedService `
                -Layout $profileLayout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -Services $profileServices `
                -Operation 'managed-hook scope regression' `
                -ActiveOnly:$activeOnly `
                -SharedHookOwners @('DefenseClawGateway')
        }
    }
    Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
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

    # GAP-0023: PowerShell 7.4 and 7.5 write a PermissionDenied error for
    # each service whose configuration SYSTEM cannot read (IsolationSession
    # on Windows 11 24H2), and the scope checks used to list every service
    # with Get-Service -ErrorAction Stop. The harness replaces only the
    # lowest seam the module uses: the module-qualified
    # Microsoft.PowerShell.Management\Get-Service call. A script-scope alias
    # of that exact name in the module wins over the module lookup on
    # Windows PowerShell 5.1 and PowerShell 7. Behind it is a fake SCM that
    # honours -Name wildcards and, like Get-Service, writes a non-terminating
    # PermissionDenied error for each matched service it cannot read. The
    # production query (Read-DefenseClawPrefixedServiceQuery) and both scope
    # checks run unchanged, so an unfiltered query, or the old
    # Get-Service -ErrorAction Stop, fails this block.
    function script:New-HarnessServiceQueryError([string]$Name, [object]$Target) {
        return [Management.Automation.ErrorRecord]::new(
            [InvalidOperationException]::new(
                "Service '$Name ($Name)' cannot be queried due to the " +
                'following error: PermissionDenied'
            ),
            'CouldNotGetServiceInfo,Microsoft.PowerShell.Commands.GetServiceCommand',
            [Management.Automation.ErrorCategory]::PermissionDenied,
            $Target
        )
    }
    function New-HarnessScmEntry([string]$Name, [switch]$Unreadable, [switch]$Nameless) {
        $service = [pscustomobject]@{
            Name = $Name
            ServiceName = $Name
            Status = 'Running'
        }
        return [pscustomobject]@{
            Name = $Name
            Service = $service
            Unreadable = [bool]$Unreadable
            Target = if ($Nameless) { $null } else { $service }
        }
    }
    function script:Get-HarnessScmService {
        [CmdletBinding()]
        param([string[]]$Name = @('*'))
        foreach ($entry in @($script:HarnessScm)) {
            $matched = $false
            foreach ($pattern in @($Name)) {
                if ($entry.Name -like $pattern) { $matched = $true }
            }
            # HarnessScmOpensEveryService models a PowerShell that reads every
            # service's configuration before it applies -Name.
            if (-not $matched -and -not $script:HarnessScmOpensEveryService) {
                continue
            }
            $script:HarnessScmOpened += @($entry.Name)
            if ($entry.Unreadable) {
                $PSCmdlet.WriteError(
                    (New-HarnessServiceQueryError $entry.Name $entry.Target)
                )
                continue
            }
            if ($matched) { $entry.Service }
        }
    }
    function Set-HarnessScm([object[]]$Entries, [switch]$OpensEveryService) {
        $script:HarnessScm = @($Entries)
        $script:HarnessScmOpensEveryService = [bool]$OpensEveryService
        $script:HarnessScmOpened = @()
    }
    function Get-HarnessOwnScm {
        return @($ownServices | Microsoft.PowerShell.Core\ForEach-Object {
                New-HarnessScmEntry ([string]$_.Name)
            })
    }
    # The intent install preparation builds reads these before its write.
    $installLayout = $layout.Clone()
    $installLayout.PurgeScopeSHA256 = '0' * 64
    $installLayout.InstallRoot = 'C:\DefenseClawHarness\install'
    $installLayout.StateRoot = 'C:\DefenseClawHarness\state'
    function Invoke-HarnessInstallPreparation {
        $script:HarnessIntentWrites = 0
        try {
            [void](New-DefenseClawInstallPreparationIntent `
                -Layout $installLayout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -InstallRootBaseline $null `
                -StateRootBaseline $null)
        }
        catch {
            return [string]$_.Exception.Message
        }
        return ''
    }
    # The cleanup check scans the lifecycle lock directory for rollback
    # receipts right after its service check; a missing directory stops it
    # there, so reaching that error proves the service check passed.
    $cleanupLayout = $layout.Clone()
    $cleanupLayout.LifecycleLockDirectory = Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) ('dc-gap23-no-lock-' + [guid]::NewGuid().ToString('N'))
    function Invoke-HarnessCleanupCheck {
        try {
            Assert-DefenseClawTargetRuntimeCleanupScopeExclusive `
                -Layout $cleanupLayout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian'
        }
        catch {
            return $_
        }
        return $null
    }
    $seam = 'Microsoft.PowerShell.Management\Get-Service'
    $realGetIntent = (Microsoft.PowerShell.Core\Get-Command `
        -Name Get-DefenseClawInstallRollbackIntent `
        -CommandType Function).ScriptBlock
    $realWriteIntent = (Microsoft.PowerShell.Core\Get-Command `
        -Name Write-DefenseClawInstallRollbackIntent `
        -CommandType Function).ScriptBlock
    $realOwners = (Microsoft.PowerShell.Core\Get-Command `
        -Name Get-DefenseClawSharedManagedHookOwners `
        -CommandType Function).ScriptBlock
    $script:HarnessIntentWrites = 0
    function script:Get-DefenseClawInstallRollbackIntent { return $null }
    function script:Get-DefenseClawSharedManagedHookOwners {
        return @('DefenseClawGateway')
    }
    function script:Write-DefenseClawInstallRollbackIntent {
        $script:HarnessIntentWrites++
        throw 'harness stop at the install intent write'
    }
    Microsoft.PowerShell.Utility\Set-Alias -Name $seam -Value Get-HarnessScmService -Scope Script
    try {
        # An unreadable third-party service: install preparation reaches its
        # first intent write. The production query asks the SCM for
        # DefenseClaw* only, so the service is never opened and no error comes
        # back; the opened list also proves the call went through the seam.
        Set-HarnessScm (@(Get-HarnessOwnScm) + @(
                (New-HarnessScmEntry 'IsolationSession' -Unreadable),
                (New-HarnessScmEntry 'Spooler')
            ))
        $proceedFailure = Invoke-HarnessInstallPreparation
        if ($proceedFailure -cne 'harness stop at the install intent write' -or
            $script:HarnessIntentWrites -ne 1) {
            throw (
                'an unreadable third-party service stopped install ' +
                "preparation: $proceedFailure; intent writes=$script:HarnessIntentWrites"
            )
        }
        $opened = @($script:HarnessScmOpened)
        if ($opened.Count -ne $ownServices.Count -or $opened -contains 'IsolationSession' -or
            $opened -contains 'Spooler') {
            throw "install preparation did not query DefenseClaw* through the seam: opened $($opened -join ', ')"
        }
        Set-HarnessScm (@(Get-HarnessOwnScm) + @(
                (New-HarnessScmEntry 'IsolationSession' -Unreadable),
                (New-HarnessScmEntry 'Spooler')
            ))
        $query = Read-DefenseClawPrefixedServiceQuery
        $queryNames = @(@($query.Services) | Microsoft.PowerShell.Core\ForEach-Object { [string]$_.Name })
        if (@($query.Errors).Count -ne 0 -or $queryNames.Count -ne $ownServices.Count -or
            @($queryNames | Microsoft.PowerShell.Core\Where-Object {
                    -not $_.StartsWith('DefenseClaw', [StringComparison]::OrdinalIgnoreCase)
                }).Count -ne 0) {
            throw (
                'the production service query is not limited to DefenseClaw*: ' +
                "services=$($queryNames -join ', '); errors=$(@($query.Errors).Count)"
            )
        }
        Set-HarnessScm (@(Get-HarnessOwnScm) + @(
                New-HarnessScmEntry 'IsolationSession' -Unreadable
            ))
        $cleanupFailure = Invoke-HarnessCleanupCheck
        if ($null -eq $cleanupFailure -or
            $cleanupFailure.FullyQualifiedErrorId -notlike 'PathNotFound*') {
            throw "an unreadable third-party service stopped the cleanup scope check: $cleanupFailure"
        }

        # A PowerShell that opens every service before it filters: the
        # third-party error does reach the module, which skips it and names
        # it in the verbose output, and install preparation still proceeds.
        Set-HarnessScm (@(Get-HarnessOwnScm) + @(
                New-HarnessScmEntry 'IsolationSession' -Unreadable
            )) -OpensEveryService
        $VerbosePreference = 'Continue'
        try {
            $output = @(Get-DefenseClawPrefixedServices 4>&1)
        }
        finally {
            $VerbosePreference = 'SilentlyContinue'
        }
        $skipped = @($output | Microsoft.PowerShell.Core\Where-Object {
                $_ -is [Management.Automation.VerboseRecord]
            })
        $listed = @($output | Microsoft.PowerShell.Core\Where-Object {
                $_ -isnot [Management.Automation.VerboseRecord]
            })
        if ($skipped.Count -ne 1 -or [string]$skipped[0].Message -notmatch (
                '^skipped unreadable non-DefenseClaw service IsolationSession: .*PermissionDenied$'
            )) {
            throw "the skipped service was not named in the verbose output: $(@($skipped | Microsoft.PowerShell.Core\ForEach-Object { $_.Message }) -join '; ')"
        }
        if ($listed.Count -ne $ownServices.Count) {
            throw "prefixed service list is wrong: $(@($listed | Microsoft.PowerShell.Core\ForEach-Object { $_.Name }) -join ', ')"
        }
        $proceedFailure = Invoke-HarnessInstallPreparation
        if ($proceedFailure -cne 'harness stop at the install intent write' -or
            $script:HarnessIntentWrites -ne 1) {
            throw (
                'a skipped third-party service stopped install ' +
                "preparation: $proceedFailure; intent writes=$script:HarnessIntentWrites"
            )
        }

        # An unreadable DefenseClaw service, ours or a foreign scope, fails
        # both scope checks before install preparation writes its intent and
        # before cleanup scans for rollback receipts.
        foreach ($unreadable in @(
                'DefenseClawHookGuardian',
                'DefenseClawCertGateway_1165c1ff8a'
            )) {
            $entries = @(Get-HarnessOwnScm | Microsoft.PowerShell.Core\Where-Object {
                    $_.Name -cne $unreadable
                }) + @(New-HarnessScmEntry $unreadable -Unreadable)
            Set-HarnessScm $entries
            $unreadableFailure = Invoke-HarnessInstallPreparation
            if ($unreadableFailure -notmatch (
                    "^DefenseClaw service $unreadable cannot be read: .*PermissionDenied$"
                ) -or $script:HarnessIntentWrites -ne 0) {
                throw (
                    "unreadable DefenseClaw service $unreadable did not fail " +
                    "install preparation: $unreadableFailure; " +
                    "intent writes=$script:HarnessIntentWrites"
                )
            }
            Set-HarnessScm $entries
            $cleanupFailure = Invoke-HarnessCleanupCheck
            if ($null -eq $cleanupFailure -or [string]$cleanupFailure.Exception.Message -notmatch (
                    "^DefenseClaw service $unreadable cannot be read: .*PermissionDenied$"
                )) {
                throw "unreadable DefenseClaw service $unreadable did not fail the cleanup scope check: $cleanupFailure"
            }
        }

        # A query error that names no service fails: it may be ours.
        Set-HarnessScm (@(Get-HarnessOwnScm) + @(
                New-HarnessScmEntry 'DefenseClawUnnamed' -Unreadable -Nameless
            ))
        $anonymousFailure = Invoke-HarnessInstallPreparation
        if ($anonymousFailure -notmatch '^DefenseClaw service query failed: ' -or
            $script:HarnessIntentWrites -ne 0) {
            throw "a service query error without a service name passed: $anonymousFailure"
        }
    }
    finally {
        # Drop the seam before the live query; a leftover alias would shadow
        # Get-Service in this module.
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath "Alias:$seam" -Force
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Get-DefenseClawInstallRollbackIntent' `
            -Value $realGetIntent
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Write-DefenseClawInstallRollbackIntent' `
            -Value $realWriteIntent
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath 'Function:script:Get-DefenseClawSharedManagedHookOwners' `
            -Value $realOwners
    }

    # The production query on this runner: DefenseClaw* services only, and
    # none of them unreadable.
    $live = Read-DefenseClawPrefixedServiceQuery
    if (@($live.Errors).Count -ne 0 -or @(@($live.Services) | Microsoft.PowerShell.Core\Where-Object {
                -not ([string]$_.Name).StartsWith(
                    'DefenseClaw',
                    [StringComparison]::OrdinalIgnoreCase
                )
            }).Count -ne 0) {
        throw "live prefixed service query: services=$(@(@($live.Services) | Microsoft.PowerShell.Core\ForEach-Object { $_.Name }) -join ', '); errors=$(@($live.Errors) -join '; ')"
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
