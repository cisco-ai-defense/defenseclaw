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
        'Test-DefenseClawPathPresentNoFollow'
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

'enterprise-uninstall-postcommit-recovery-smoke: PASS'
