# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Run the production bounded recovery decision without touching a service or
# real managed root. A committed tombstone with no pending.json finishes the
# hook teardown in exactly the uninstall mode it recorded, and only while the
# uninstall is unsettled: a settled state-keeping uninstall is left alone.
$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
foreach ($name in @(
        'Invoke-DefenseClawTimeoutRecovery',
        'Get-DefenseClawTombstonePurgeRequested',
        'Test-DefenseClawCommittedUninstallUnsettled',
        'Test-DefenseClawPathPresentNoFollow',
        'Get-DefenseClawTombstonePurgeUserStateRequested',
        'Complete-DefenseClawCommittedManagedHooksFinalization',
        'New-DefenseClawDeploymentMetadata'
    )) {
    $functionAst = @($moduleAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
        },
        $true
    ))
    if ($functionAst.Count -ne 1) {
        throw "expected exactly one production function $name"
    }
    . ([scriptblock]::Create($functionAst[0].Extent.Text))
}

$root = Microsoft.PowerShell.Management\Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('defenseclaw-postcommit-' + [Guid]::NewGuid().ToString('N'))
$layout = @{
    PendingPath = [IO.Path]::Combine($root, 'state', 'install', 'pending.json')
    InstallRoot = [IO.Path]::Combine($root, 'program-files', 'DefenseClaw')
    ManagedHooksTeardownJournalPath = [IO.Path]::Combine(
        $root, 'state', 'install', 'managed-hooks-teardown-journal.json')
}

$script:NoRecordedMode = [object]::new()
function Reset-Case {
    param(
        [bool]$Installed = $false,
        $RecordedPurge = $script:NoRecordedMode,
        [bool]$WithInstallRoot = $false,
        [bool]$Journal = $false,
        [bool]$Receipt = $false
    )
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($layout.PendingPath))
    if ($WithInstallRoot) { [void][IO.Directory]::CreateDirectory($layout.InstallRoot) }
    if ($Journal) { [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, '{}') }
    $script:metadata = [pscustomobject]@{ installed = $Installed }
    if (-not [object]::ReferenceEquals($RecordedPurge, $script:NoRecordedMode)) {
        $script:metadata | Add-Member -MemberType NoteProperty `
            -Name uninstall_purge_requested -Value $RecordedPurge
    }
    $script:standaloneProfile = $true
    $script:authenticated = $true
    $script:receiptAuthenticates = $true
    $script:receipt = $Receipt
    $script:cleanupFails = $false
    $script:purgeKeepsReceipt = $false
    $script:cleanupModes = [Collections.Generic.List[bool]]::new()
    $script:receiptChecks = 0
    $script:pendingCalls = 0
}

function Test-DefenseClawStandaloneProfile {
    return $script:standaloneProfile
}
function Get-DefenseClawDeploymentMetadata {
    param([hashtable]$Layout)
    return $script:metadata
}
function Assert-DefenseClawMetadataIdentity {
    param($Metadata, [string]$GatewayServiceName, [string]$GuardianServiceName)
    if (-not $script:authenticated) {
        throw 'untrusted uninstall tombstone'
    }
}
function Test-DefenseClawMetadataInstalled {
    param($Metadata)
    return [bool]$Metadata.installed
}
function Recover-DefenseClawPendingTransaction {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
    $script:pendingCalls++
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Layout.PendingPath -Force
    $script:metadata = [pscustomobject]@{ installed = $true }
    return [pscustomobject]@{ recovered = $true }
}
function Invoke-DefenseClawCommittedUninstallCleanup {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        [switch]$Purge
    )
    $script:cleanupModes.Add([bool]$Purge)
    if ($script:cleanupFails) {
        throw 'hook finalization failed'
    }
    if ([IO.Directory]::Exists($Layout.InstallRoot)) { [IO.Directory]::Delete($Layout.InstallRoot, $true) }
    [IO.File]::Delete($Layout.ManagedHooksTeardownJournalPath)
    if ($Purge) {
        # A completed purge removes StateRoot, its tombstone included, and
        # the connector cleanup receipt it applied.
        $script:metadata = $null
        if (-not $script:purgeKeepsReceipt) { $script:receipt = $false }
    }
}
function Get-DefenseClawManagedHookContractCleanupReceipt {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        $Metadata,
        [switch]$Required
    )
    $script:receiptChecks++
    if ($null -eq $Metadata -or [bool]$Metadata.installed -or -not $Required) {
        throw 'receipt was not bound to the state-keeping tombstone'
    }
    if (-not $script:receiptAuthenticates) {
        throw 'contract cleanup receipt does not match the inactive deployment tombstone'
    }
    return [pscustomobject]@{ phase = 'prepared' }
}
function Get-DefenseClawLifecycleStatus {
    param([string]$Action, [hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
    return [pscustomobject]@{
        ok = $true
        installed = ($null -ne $script:metadata -and [bool]$script:metadata.installed)
        transaction_pending = $false
    }
}
function Get-DefenseClawUnfinishedLifecycleEvidence {
    param([hashtable]$Layout)
    $found = [Collections.Generic.List[string]]::new()
    if ([IO.File]::Exists($Layout.ManagedHooksTeardownJournalPath)) {
        $found.Add('managed-hook teardown journal')
    }
    if ($script:receipt) { $found.Add('connector cleanup receipt') }
    return $found.ToArray()
}

function Invoke-Recovery {
    return Invoke-DefenseClawTimeoutRecovery `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian'
}
function Assert-Modes([string]$Case, [bool[]]$Want) {
    $got = @($script:cleanupModes.ToArray())
    if ($got.Count -ne $Want.Count -or
        (($got -join ',') -cne ($Want -join ','))) {
        throw "${Case}: cleanup purge modes [$($got -join ',')], want [$($Want -join ',')]"
    }
}
function Assert-Refused([string]$Case, [string]$Message) {
    try {
        [void](Invoke-Recovery)
    }
    catch {
        if (-not $_.Exception.Message.Contains($Message)) {
            throw "${Case}: refused with '$($_.Exception.Message)', want '$Message'"
        }
        return
    }
    throw "${Case}: recovery was reported settled"
}

try {
    # An interrupted purge replays the purge it recorded.
    Reset-Case -RecordedPurge $true -Journal $true -Receipt $true
    $result = Invoke-Recovery
    Assert-Modes 'recorded purge' @($true)
    if ([bool]$result.installed) { throw 'recorded purge: reported installed' }

    # A recorded purge with no folder left still has its tombstone: the
    # state purge itself is the unfinished part.
    Reset-Case -RecordedPurge $true
    [void](Invoke-Recovery)
    Assert-Modes 'recorded purge, folders gone' @($true)

    # An interrupted state-keeping uninstall replays without purge and is
    # settled with its tombstone-bound connector cleanup receipt kept.
    Reset-Case -RecordedPurge $false -WithInstallRoot $true -Journal $true -Receipt $true
    $result = Invoke-Recovery
    Assert-Modes 'recorded keep-state' @($false)
    if ($script:receiptChecks -ne 1 -or -not $script:receipt -or $null -eq $script:metadata) {
        throw 'recorded keep-state: kept state or its receipt was not preserved and authenticated'
    }
    if ([bool]$result.installed) { throw 'recorded keep-state: reported installed' }

    # A settled state-keeping uninstall is not replayed at all.
    Reset-Case -RecordedPurge $false -Receipt $true
    [void](Invoke-Recovery)
    Assert-Modes 'settled keep-state' @()
    if ($script:receiptChecks -ne 1) { throw 'settled keep-state: receipt was not authenticated' }

    # A tombstone from before 1.0.4 records no mode: it replays as the
    # state-keeping uninstall, never as a purge.
    Reset-Case -Journal $true -Receipt $true
    [void](Invoke-Recovery)
    Assert-Modes 'pre-1.0.4 tombstone' @($false)
    Reset-Case
    [void](Invoke-Recovery)
    Assert-Modes 'settled pre-1.0.4 tombstone' @()

    # A malformed mode is refused before any cleanup, never guessed.
    foreach ($bad in @('false', 1, $null)) {
        Reset-Case -RecordedPurge $bad -Journal $true
        Assert-Refused "recorded mode '$bad'" 'invalid recorded purge mode'
        Assert-Modes "recorded mode '$bad'" @()
    }

    # A receipt that does not authenticate against the kept tombstone is
    # not mistaken for the settled record.
    Reset-Case -RecordedPurge $false -Receipt $true
    $script:receiptAuthenticates = $false
    Assert-Refused 'foreign receipt' 'does not match the inactive deployment tombstone'

    # A purge that left its receipt did not settle: the exemption is only
    # for the receipt a state-keeping uninstall keeps.
    Reset-Case -RecordedPurge $true -Receipt $true
    $script:purgeKeepsReceipt = $true
    Assert-Refused 'purge kept its receipt' 'connector cleanup receipt'
    Reset-Case -RecordedPurge $true -Receipt $true
    $script:cleanupFails = $true
    Assert-Refused 'failed purge' 'hook finalization failed'
    Reset-Case -RecordedPurge $false -Journal $true
    $script:cleanupFails = $true
    Assert-Refused 'failed keep-state replay' 'hook finalization failed'

    # Secure Client recovery is unchanged.
    Reset-Case -RecordedPurge $true -Journal $true
    $script:standaloneProfile = $false
    Assert-Refused 'Secure Client' 'managed-hook teardown journal'
    Assert-Modes 'Secure Client' @()

    # A refused uninstall leaves installed metadata alone.
    Reset-Case -Installed $true -WithInstallRoot $true
    [void](Invoke-Recovery)
    Assert-Modes 'installed' @()

    # An untrusted tombstone never reaches cleanup.
    Reset-Case -RecordedPurge $true -Journal $true
    $script:authenticated = $false
    Assert-Refused 'untrusted tombstone' 'untrusted uninstall tombstone'
    Assert-Modes 'untrusted tombstone' @()

    # A pending rollback is replayed before settlement and restores an
    # installed deployment; no postcommit cleanup follows.
    Reset-Case -Installed $true -WithInstallRoot $true
    [IO.File]::WriteAllText($layout.PendingPath, 'test pending marker')
    [void](Invoke-Recovery)
    if ($script:pendingCalls -ne 1 -or [IO.File]::Exists($layout.PendingPath)) {
        throw 'pending rollback was not replayed before settlement'
    }
    Assert-Modes 'pending rollback' @()
}
finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}


# Setup /uninstall PURGE=1 also removes each enrolled account's per-user data
# and binaries; the managed-hook finalize does that removal. The tombstone
# records the request at commit, and every finalize of that tombstone (the
# watcher's Recover, a timeout recovery, a plain retry) replays it, so the
# tombstone, which the state purge removes only after the finalize, is the
# retry evidence until that removal ran.
$finalLayout = @{
    PendingPath = $layout.PendingPath
    InstallRoot = $layout.InstallRoot
    ManagedHooksTeardownJournalPath = $layout.ManagedHooksTeardownJournalPath
    CodexTargetEnabled = $false
}
function Get-DefenseClawManagedServiceNames {
    param([string]$GatewayServiceName, [string]$GuardianServiceName)
    return @($GatewayServiceName, $GuardianServiceName)
}
function Test-DefenseClawServiceExists { param([string]$Name) return $false }
function Assert-DefenseClawRecordedArtifactHashes { param($Metadata, [hashtable]$Layout, [string]$Action) }
function Assert-DefenseClawInstallTreeRetirementState {
    param([hashtable]$Layout, [switch]$AllowUnretiredAcls, [switch]$NativeSealed)
}
function Get-DefenseClawManagedHooksTeardownJournalPhase {
    param([hashtable]$Layout, $Metadata, [string]$GatewayServiceName, [switch]$AllowLegacyInactive)
    return $script:journalPhase
}
function Remove-DefenseClawStandaloneOpenCodeManagedPlugin { param([hashtable]$Layout) }
function Set-DefenseClawInstallTreeRetirementAcls { param([hashtable]$Layout, [switch]$Committed) }
function Invoke-DefenseClawManagedHooksTeardownCommand {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        [string]$Action,
        [switch]$PurgeContractLocks
    )
    $script:teardownCalls.Add(
        "${Action}:$([bool]$script:DefenseClawUninstallPurgeUserState)")
    if ($Action -ceq 'finalize' -and $script:finalizeFails) {
        throw 'finalize helper failed'
    }
    return [pscustomobject]@{ phase = $Action }
}
function Reset-FinalizationCase {
    param(
        $RecordedPurge = $script:NoRecordedMode,
        $RecordedUserState = $script:NoRecordedMode,
        [bool]$CallerUserState = $false,
        [string]$JournalPhase = 'prepared'
    )
    Reset-Case -RecordedPurge $RecordedPurge -WithInstallRoot $true -Journal $true
    if (-not [object]::ReferenceEquals($RecordedUserState, $script:NoRecordedMode)) {
        $script:metadata | Add-Member -MemberType NoteProperty `
            -Name uninstall_purge_user_state_requested -Value $RecordedUserState
    }
    $script:journalPhase = $JournalPhase
    $script:finalizeFails = $false
    $script:teardownCalls = [Collections.Generic.List[string]]::new()
    $script:DefenseClawUninstallPurgeUserState = $CallerUserState
}
function Invoke-Finalization {
    return Complete-DefenseClawCommittedManagedHooksFinalization `
        -Layout $finalLayout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Purge:$true
}
function Assert-Finalize([string]$Case, [string[]]$Want, [bool]$CallerAfter) {
    $got = @($script:teardownCalls.ToArray())
    if (($got -join ',') -cne ($Want -join ',')) {
        throw "${Case}: teardown calls [$($got -join ',')], want [$($Want -join ',')]"
    }
    if ([bool]$script:DefenseClawUninstallPurgeUserState -ne $CallerAfter) {
        throw "${Case}: the run's own per-user purge request was not restored"
    }
}
function Assert-FinalizationRefused([string]$Case, [string]$Message) {
    try {
        [void](Invoke-Finalization)
    }
    catch {
        if (-not $_.Exception.Message.Contains($Message)) {
            throw "${Case}: refused with '$($_.Exception.Message)', want '$Message'"
        }
        if ($script:teardownCalls.Count -ne 0) {
            throw "${Case}: refused after the teardown ran: $($script:teardownCalls -join ',')"
        }
        return
    }
    throw "${Case}: finalization went on"
}

# The writer: the tombstone records the run's per-user purge request with
# its purge, standalone only.
$script:SchemaVersion = 2
$script:AgentApplicationControlPrerequisite = 'test'
$script:DefenseClawTrustMode = 'Authenticode'
$script:brokerEnabled = $false
function Assert-DefenseClawManagedHooksActivationRecord { param($Record) return $Record }
function Get-DefenseClawOptionalLayoutValue { param([hashtable]$Layout, [string]$Name) return $null }
function Get-DefenseClawGatewayServiceAccount { return 'NT SERVICE\DefenseClawGateway' }
function Get-DefenseClawClaudeMinimumClientVersion { return '' }
function Test-DefenseClawLayoutBrokerEnabled { param([hashtable]$Layout) return $script:brokerEnabled }
# Every layout value the writer reads; no payload file exists, so it
# records no hash.
$writerLayout = @{ InstallRoot = $layout.InstallRoot; StateRoot = [IO.Path]::Combine($root, 'state') }
foreach ($name in @(
        'ACPPath', 'AgentApplicationControlAttestationPath', 'BrokerAuthKeyPath',
        'BrokerPath', 'BrokerPipeName', 'BrokerServiceName', 'CLIPath',
        'CertificationCodexHome', 'CodexMachinePolicyDirectory',
        'CodexMachinePolicyPath', 'CodexManagedHooksDirectory',
        'CodexManagedHooksStatePath', 'CodexRequirementsAclBackupPath',
        'CodexRequirementsOwnershipPath', 'GatewayPath', 'HookPath',
        'InstallerPath', 'ManagedHooksTeardownJournalPath', 'ModulePath',
        'ProductVersion', 'ProviderLibraryPath', 'SensorHelperPath'
    )) {
    $writerLayout[$name] = ''
}
foreach ($name in @(
        'AgentApplicationControlAttested', 'ClaudeEffectivePolicyVerified',
        'ClaudeTargetEnabled', 'CodexTargetEnabled', 'CoreHardeningCertification',
        'CursorTargetEnabled'
    )) {
    $writerLayout[$name] = $false
}
function New-Tombstone {
    param([bool]$Installed = $false, [bool]$Purge, [bool]$UserState)
    return New-DefenseClawDeploymentMetadata `
        -Layout $writerLayout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Installed $Installed `
        -ManagedHooksActivation ([pscustomobject]@{ state = 'active' }) `
        -UninstallPurgeRequested $Purge `
        -UninstallPurgeUserStateRequested $UserState
}
function Assert-WriterRefused([string]$Case, [string]$Message, [scriptblock]$Write) {
    try {
        [void](& $Write)
    }
    catch {
        if (-not $_.Exception.Message.Contains($Message)) {
            throw "${Case}: refused with '$($_.Exception.Message)', want '$Message'"
        }
        return
    }
    throw "${Case}: the tombstone was written"
}

try {
    foreach ($mode in @($true, $false)) {
        $tombstone = New-Tombstone -Purge $true -UserState $mode
        if ($tombstone['uninstall_purge_requested'] -isnot [bool] -or
            -not $tombstone['uninstall_purge_requested'] -or
            $tombstone['uninstall_purge_user_state_requested'] -isnot [bool] -or
            $tombstone['uninstall_purge_user_state_requested'] -ne $mode) {
            throw "writer: the tombstone did not record per-user purge $mode"
        }
    }
    Assert-WriterRefused 'installed per-user purge' 'only an uninstall tombstone' {
        New-Tombstone -Installed $true -Purge $false -UserState $true
    }
    Assert-WriterRefused 'per-user purge without purge' 'requires the uninstall purge' {
        New-Tombstone -Purge $false -UserState $true
    }
    $script:brokerEnabled = $true
    Assert-WriterRefused 'Secure Client per-user purge' 'only a standalone uninstall tombstone' {
        New-Tombstone -Purge $true -UserState $true
    }
    if ((New-Tombstone -Purge $true -UserState $false).Contains(
            'uninstall_purge_user_state_requested')) {
        throw 'writer: a Secure Client tombstone gained a per-user purge field'
    }
    $script:brokerEnabled = $false

    # The watcher's Recover (no PURGE=1 of its own) replays the recorded
    # per-user purge; the run's own request is restored after it.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $true
    [void](Invoke-Finalization)
    Assert-Finalize 'recorded per-user purge' @('finalize:True') $false
    # Also when the interrupted run died before the hook teardown began.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $true -JournalPhase ''
    [void](Invoke-Finalization)
    Assert-Finalize 'recorded per-user purge, before prepare' @(
        'prepare:False', 'verify:False', 'finalize:True') $false
    # An explicit PURGE=1 retry over a tombstone without the request purges.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $false -CallerUserState $true
    [void](Invoke-Finalization)
    Assert-Finalize 'explicit per-user purge retry' @('finalize:True') $true
    # Without either request nothing per-user is purged.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $false
    [void](Invoke-Finalization)
    Assert-Finalize 'recorded purge without per-user purge' @('finalize:False') $false
    # A 1.0.0-1.0.3 tombstone records no mode.
    Reset-FinalizationCase
    [void](Invoke-Finalization)
    Assert-Finalize 'pre-1.0.4 tombstone' @('finalize:False') $false
    # A finalize that fails keeps the tombstone for the next replay and the
    # run's own request.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $true
    $script:finalizeFails = $true
    try {
        [void](Invoke-Finalization)
        throw 'failed finalize: reported done'
    }
    catch {
        if (-not $_.Exception.Message.Contains('finalize helper failed')) { throw }
    }
    Assert-Finalize 'failed finalize' @('finalize:True') $false
    if ($null -eq $script:metadata) { throw 'failed finalize: the tombstone went' }
    # A malformed or orphaned per-user mode is refused before any teardown.
    foreach ($bad in @('true', 1, $null)) {
        Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $bad
        Assert-FinalizationRefused "per-user mode '$bad'" 'invalid recorded per-user purge mode'
    }
    Reset-FinalizationCase -RecordedPurge $false -RecordedUserState $true
    Assert-FinalizationRefused 'per-user purge without purge' 'without its uninstall purge'
    Reset-FinalizationCase -RecordedUserState $true
    Assert-FinalizationRefused 'per-user purge, no recorded purge' 'without its uninstall purge'
    # Secure Client finalize is unchanged.
    Reset-FinalizationCase -RecordedPurge $true -RecordedUserState $true
    $script:standaloneProfile = $false
    [void](Invoke-Finalization)
    Assert-Finalize 'Secure Client' @('finalize:False') $false

    # The recovery decision refuses a malformed per-user mode before any
    # cleanup and treats a recorded per-user purge as unsettled work.
    Reset-Case -RecordedPurge $true
    $script:metadata | Add-Member -MemberType NoteProperty `
        -Name uninstall_purge_user_state_requested -Value 'yes'
    Assert-Refused 'recovery: per-user mode' 'invalid recorded per-user purge mode'
    Assert-Modes 'recovery: per-user mode' @()
    Reset-Case -RecordedPurge $false
    $script:metadata | Add-Member -MemberType NoteProperty `
        -Name uninstall_purge_user_state_requested -Value $true
    Assert-Refused 'recovery: orphaned per-user purge' 'without its uninstall purge'
    Assert-Modes 'recovery: orphaned per-user purge' @()
    Reset-Case -RecordedPurge $true
    $script:metadata | Add-Member -MemberType NoteProperty `
        -Name uninstall_purge_user_state_requested -Value $true
    [void](Invoke-Recovery)
    Assert-Modes 'recovery: recorded per-user purge' @($true)
}
finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}

'enterprise-uninstall-postcommit-recovery-smoke: PASS'
