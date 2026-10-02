# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath -Force -PassThru -ErrorAction Stop

$fixtureName = 'DefenseClawUntrustedPurge-' + [Guid]::NewGuid().ToString('N')
$fixtureRoot = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) $fixtureName
)).TrimEnd('\')
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
if ($fixtureName -cnotmatch '^DefenseClawUntrustedPurge-[a-f0-9]{32}$' -or
    -not $fixtureRoot.StartsWith(
        $tempRoot + '\', [StringComparison]::OrdinalIgnoreCase
    ) -or
    (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot)) {
    throw 'untrusted purge fixture is not a unique temporary child'
}

try {
    [void](Microsoft.PowerShell.Management\New-Item `
        -ItemType Directory -Path $fixtureRoot -ErrorAction Stop)
    $result = & $module {
        param([string]$FixtureRoot)
        Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $stateRoot = Microsoft.PowerShell.Management\Join-Path `
            $FixtureRoot 'state'
        $installState = Microsoft.PowerShell.Management\Join-Path `
            $stateRoot 'install'
        $lifecycle = Microsoft.PowerShell.Management\Join-Path `
            $FixtureRoot 'lifecycle'
        $transactions = Microsoft.PowerShell.Management\Join-Path `
            $installState 'transactions'
        foreach ($directory in @(
            $stateRoot, $installState, $lifecycle, $transactions
        )) {
            [void](Microsoft.PowerShell.Management\New-Item `
                -ItemType Directory -Path $directory -ErrorAction Stop)
        }
        $layout = @{
            StateRoot = $stateRoot
            TransactionsDirectory = $transactions
            PendingPath = (Microsoft.PowerShell.Management\Join-Path `
                $installState 'pending.json')
            ManagedHooksLifecycleJournalPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $installState 'managed-hooks-lifecycle-journal.json')
            ManagedHooksTeardownJournalPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $installState 'managed-hooks-teardown-journal.json')
            PurgeIntentPath = (Microsoft.PowerShell.Management\Join-Path `
                $lifecycle 'purge.json')
            SelfUninstallReceiptPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $lifecycle 'self-uninstall.json')
            InstallRollbackIntentPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $lifecycle 'install-rollback.json')
            ManagedHookContractCleanupReceiptPath = (
                Microsoft.PowerShell.Management\Join-Path `
                    $lifecycle 'contract-cleanup.json')
        }
        $script:FallbackCalls = 0
        function script:Invoke-DefenseClawExactScopeRecoveryPurge {
            param(
                [hashtable]$Layout,
                [hashtable]$Sources,
                [string]$GatewayServiceName,
                [string]$GuardianServiceName,
                [switch]$UntrustedStateRoot,
                [string]$UntrustedEvidenceReason
            )
            if (-not $UntrustedStateRoot -or
                $UntrustedEvidenceReason -cne 'untrusted deployment') {
                throw 'untrusted metadata did not select the partial recovery path'
            }
            $script:FallbackCalls++
            # Bulldoze posture: the real function now returns ok:true,
            # purged:true even when StateRoot cleanup is skipped (deployment
            # evidence untrusted). AVC MSI treats uninstall as complete so
            # the box is not stranded. The next install's canonical ACL
            # re-stamp handles any surviving DACL drift.
            return [pscustomobject]@{
                ok = $true
                purged = $true
                partial_cleanup = $true
                state_root_cleanup_skipped = $true
            }
        }
        $arguments = @{
            Layout = $layout
            Sources = @{ native_cleanup = @{ path = 'protected-setup.exe' } }
            GatewayServiceName = 'DefenseClawGateway'
            GuardianServiceName = 'DefenseClawHookGuardian'
            Reason = 'untrusted deployment'
        }
        $partial = Invoke-DefenseClawUntrustedMetadataRecoveryPurge `
            @arguments
        if ($script:FallbackCalls -ne 1 -or -not [bool]$partial.ok -or
            -not [bool]$partial.purged -or -not [bool]$partial.partial_cleanup) {
            throw 'untrusted metadata did not dispatch bulldoze exact-scope cleanup'
        }

        foreach ($evidencePath in @(
            $layout.PendingPath,
            $layout.ManagedHooksLifecycleJournalPath,
            $layout.ManagedHooksTeardownJournalPath,
            $layout.PurgeIntentPath,
            $layout.SelfUninstallReceiptPath,
            $layout.InstallRollbackIntentPath,
            $layout.ManagedHookContractCleanupReceiptPath
        )) {
            [IO.File]::WriteAllText([string]$evidencePath, '{}')
            try {
                $blocked = $false
                try {
                    [void](Invoke-DefenseClawUntrustedMetadataRecoveryPurge `
                        @arguments)
                }
                catch {
                    $blocked = $_.Exception.Message -like `
                        '*exact-scope fallback did not modify the deployment*'
                }
                if (-not $blocked -or $script:FallbackCalls -ne 1) {
                    throw "protected recovery evidence was bypassed: $evidencePath"
                }
            }
            finally {
                [IO.File]::Delete([string]$evidencePath)
            }
        }
        $orphan = Microsoft.PowerShell.Management\Join-Path `
            $transactions 'orphan.json'
        [IO.File]::WriteAllText($orphan, '{}')
        try {
            $blocked = $false
            try {
                [void](Invoke-DefenseClawUntrustedMetadataRecoveryPurge `
                    @arguments)
            }
            catch {
                $blocked = $_.Exception.Message -like `
                    '*unfinished transaction directory*'
            }
            if (-not $blocked -or $script:FallbackCalls -ne 1) {
                throw 'orphaned transaction was bypassed'
            }
        }
        finally {
            [IO.File]::Delete($orphan)
        }
        return [pscustomobject]@{
            schema_version = 1
            ok = $true
            partial_dispatch = $true
            protected_evidence_blocks_fallback = $true
        }
    } $fixtureRoot
    $result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
}
finally {
    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot) -and
        $fixtureRoot.StartsWith(
            $tempRoot + '\', [StringComparison]::OrdinalIgnoreCase
        ) -and $fixtureName -cmatch
            '^DefenseClawUntrustedPurge-[a-f0-9]{32}$') {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction Stop
    }
}
