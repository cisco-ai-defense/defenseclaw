# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Run the production bounded recovery decision without touching a service or
# real managed root. A committed tombstone with no pending.json must finish
# the hook teardown before recovery can report the uninstall settled.
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
$functionAst = @($moduleAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-DefenseClawTimeoutRecovery'
    },
    $true
))
if ($functionAst.Count -ne 1) {
    throw 'expected exactly one bounded recovery function'
}
. ([scriptblock]::Create($functionAst[0].Extent.Text))

$script:installed = $false
$script:standaloneProfile = $true
$script:authenticated = $true
$script:cleanupFails = $false
$script:hooksComplete = $false
$script:cleanupCalls = 0
$script:pendingCalls = 0

function Test-DefenseClawStandaloneProfile {
    return $script:standaloneProfile
}
function Get-DefenseClawDeploymentMetadata {
    param([hashtable]$Layout)
    return [pscustomobject]@{ installed = $script:installed }
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
    $script:installed = $true
    return [pscustomobject]@{ recovered = $true }
}
function Invoke-DefenseClawCommittedUninstallCleanup {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string]$GuardianServiceName,
        [switch]$Purge
    )
    if (-not $Purge) {
        throw 'committed standalone cleanup omitted machine state purge'
    }
    $script:cleanupCalls++
    if ($script:cleanupFails) {
        throw 'hook finalization failed'
    }
    $script:hooksComplete = $true
}
function Get-DefenseClawLifecycleStatus {
    param([string]$Action, [hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
    return [pscustomobject]@{
        ok = $true
        installed = $script:installed
        transaction_pending = $false
    }
}
function Get-DefenseClawUnfinishedLifecycleEvidence {
    param([hashtable]$Layout)
    if (-not $script:installed -and -not $script:hooksComplete) {
        return 'managed-hook teardown journal'
    }
    return @()
}

$layout = @{
    PendingPath = Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('defenseclaw-postcommit-' + [Guid]::NewGuid().ToString('N'))
}
if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.PendingPath) {
    throw 'pending-path sentinel unexpectedly exists'
}

$result = Invoke-DefenseClawTimeoutRecovery `
    -Layout $layout `
    -GatewayServiceName 'DefenseClawGateway' `
    -GuardianServiceName 'DefenseClawHookGuardian'
if ($script:cleanupCalls -ne 1 -or -not $script:hooksComplete -or
    [bool]$result.installed) {
    throw 'committed uninstall was reported settled before hook finalization'
}

$script:standaloneProfile = $false
$script:cleanupCalls = 0
[void](Invoke-DefenseClawTimeoutRecovery `
    -Layout $layout `
    -GatewayServiceName 'DefenseClawGateway' `
    -GuardianServiceName 'DefenseClawHookGuardian')
if ($script:cleanupCalls -ne 0) {
    throw 'standalone postcommit replay changed Secure Client recovery'
}
$script:standaloneProfile = $true

$script:installed = $true
$script:cleanupCalls = 0
$script:hooksComplete = $false
[void](Invoke-DefenseClawTimeoutRecovery `
    -Layout $layout `
    -GatewayServiceName 'DefenseClawGateway' `
    -GuardianServiceName 'DefenseClawHookGuardian')
if ($script:cleanupCalls -ne 0) {
    throw 'a refused uninstall changed a still-installed deployment'
}

$script:installed = $false
$script:authenticated = $false
try {
    [void](Invoke-DefenseClawTimeoutRecovery `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian')
    throw 'untrusted tombstone was accepted'
}
catch {
    if ($_.Exception.Message -cne 'untrusted uninstall tombstone') { throw }
}
if ($script:cleanupCalls -ne 0) {
    throw 'untrusted tombstone reached hook cleanup'
}

$script:authenticated = $true
$script:cleanupFails = $true
try {
    [void](Invoke-DefenseClawTimeoutRecovery `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian')
    throw 'failed hook finalization was reported settled'
}
catch {
    if ($_.Exception.Message -cne 'hook finalization failed') { throw }
}

$script:cleanupFails = $false
$script:installed = $true
$script:hooksComplete = $false
[IO.File]::WriteAllText($layout.PendingPath, 'test pending marker')
try {
    [void](Invoke-DefenseClawTimeoutRecovery `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian')
    if ($script:pendingCalls -ne 1 -or
        (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.PendingPath)) {
        throw 'pending rollback was not replayed before settlement'
    }
}
finally {
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $layout.PendingPath `
        -Force `
        -ErrorAction SilentlyContinue
}

'enterprise-uninstall-postcommit-recovery-smoke: PASS'
