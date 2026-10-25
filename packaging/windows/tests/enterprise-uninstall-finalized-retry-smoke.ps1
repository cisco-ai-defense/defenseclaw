# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Execute only the committed-finalization function from the real module.
# Mocks keep this retry regression independent of SCM and enrolled clients.
$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
$functionAst = @($moduleAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Complete-DefenseClawCommittedManagedHooksFinalization'
    },
    $true
))
if ($functionAst.Count -ne 1) {
    throw 'expected exactly one committed managed-hook finalizer'
}
. ([scriptblock]::Create($functionAst[0].Extent.Text))

$script:phase = 'finalized'
$script:receiptPhase = 'prepared'
$script:installed = $false
$script:hashChecks = 0
$script:goCalls = 0
$script:purgeContractLocks = $null
# The caller's per-user purge request (Setup sets it before finalization).
$script:DefenseClawUninstallPurgeUserState = $false
# The retry contract is the profile-neutral finalization (no standalone
# post-commit preparation).
function Test-DefenseClawStandaloneProfile { return $false }

function Get-DefenseClawDeploymentMetadata {
    param([hashtable]$Layout, [switch]$Required)
    return [pscustomobject]@{ installed = $script:installed }
}
function Assert-DefenseClawMetadataIdentity {
    param($Metadata, [string]$GatewayServiceName, [string]$GuardianServiceName)
}
function Test-DefenseClawMetadataInstalled {
    param($Metadata)
    return [bool]$Metadata.installed
}
function Get-DefenseClawManagedServiceNames {
    param([string]$GatewayServiceName, [string]$GuardianServiceName)
    return @()
}
function Assert-DefenseClawInstallTreeRetirementState {
    param([hashtable]$Layout, [switch]$NativeSealed)
}
function Assert-DefenseClawRecordedArtifactHashes {
    param($Metadata, [hashtable]$Layout, [string]$Action)
    $script:hashChecks++
}
function Get-DefenseClawManagedHooksTeardownJournalPhase {
    param(
        [hashtable]$Layout,
        $Metadata,
        [string]$GatewayServiceName,
        [switch]$AllowLegacyInactive
    )
    return $script:phase
}
function Get-DefenseClawManagedHookContractCleanupReceipt {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        $Metadata,
        [switch]$Required
    )
    return [pscustomobject]@{ phase = $script:receiptPhase }
}
function Invoke-DefenseClawManagedHooksTeardownCommand {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        [string]$Action,
        [switch]$PurgeContractLocks
    )
    $script:goCalls++
    $script:purgeContractLocks = [bool]$PurgeContractLocks
    return [pscustomobject]@{ ok = $true }
}

$layout = @{
    PendingPath = Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('defenseclaw-finalized-retry-' + [Guid]::NewGuid().ToString('N'))
}
if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.PendingPath) {
    throw 'retry smoke pending-path sentinel unexpectedly exists'
}

function Invoke-RetryCase {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$ReceiptPhase,
        [bool]$Purge = $false,
        [Parameter(Mandatory)][int]$WantGoCalls
    )
    $script:phase = $Phase
    $script:receiptPhase = $ReceiptPhase
    $script:goCalls = 0
    $script:hashChecks = 0
    $script:purgeContractLocks = $null
    [void](Complete-DefenseClawCommittedManagedHooksFinalization `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Purge:$Purge)
    if ($script:hashChecks -ne 1 -or $script:goCalls -ne $WantGoCalls) {
        throw (
            "phase=$Phase receipt=$ReceiptPhase purge=${Purge}: " +
            "hash checks=$($script:hashChecks), Go calls=$($script:goCalls); " +
            "wanted 1 and $WantGoCalls"
        )
    }
    # The Go teardown must receive the caller's purge choice unchanged.
    if ($WantGoCalls -gt 0 -and $script:purgeContractLocks -ne $Purge) {
        throw (
            "phase=$Phase receipt=$ReceiptPhase purge=${Purge}: " +
            "teardown received PurgeContractLocks=$($script:purgeContractLocks)"
        )
    }
}

Invoke-RetryCase -Phase finalized -ReceiptPhase prepared -WantGoCalls 0
Invoke-RetryCase -Phase finalized -ReceiptPhase finalized -Purge $true -WantGoCalls 0
Invoke-RetryCase -Phase finalized -ReceiptPhase prepared -Purge $true -WantGoCalls 1
Invoke-RetryCase -Phase prepared -ReceiptPhase prepared -WantGoCalls 1

$script:phase = 'captured'
$script:goCalls = 0
try {
    [void](Complete-DefenseClawCommittedManagedHooksFinalization `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian')
    throw 'non-finalizable journal was accepted'
}
catch {
    # Only the journal-phase rejection proves this case; any earlier failure
    # (metadata, receipt, service checks) must fail the smoke.
    if ($_.Exception.Message -cne
        'managed-hook finalization requires a prepared or finalized journal: captured') {
        throw
    }
}
if ($script:goCalls -ne 0) {
    throw 'non-finalizable journal invoked Go finalizer'
}

'enterprise-uninstall-finalized-retry-smoke: PASS'
