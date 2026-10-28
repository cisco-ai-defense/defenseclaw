# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# A previously installed gateway may refuse to retire a committed lifecycle
# journal. This smoke checks which gateway Setup asks next and whether a
# failure keeps the journal. The replacement is mocked here; the Go managed
# runtime generation tests check which bundles it can actually collect.

#Requires -Version 5.1

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-stale-lifecycle-journal-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $layout = @{
            ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($Root, 'managed-hooks-lifecycle-journal.json')
            PendingPath = [IO.Path]::Combine($Root, 'pending.json')
            GatewayPath = [IO.Path]::Combine($Root, 'installed', 'defenseclaw-gateway.exe')
            ManifestPath = [IO.Path]::Combine($Root, 'targets.yaml')
        }
        $gcRefusal = 'retire kiro managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: refusing to collect an invalid managed runtime bundle'
        $selectorRefusal = 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: managed runtime bundle does not match its protected selector'
        $identityRefusal = 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: refusing to collect a managed runtime bundle with a foreign identity: C:\Users\stale\.defenseclaw\hooks\.managed-runtime-claudecode-0123456789abcdef0123456789abcdef.json'
        $unknownRefusal = 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: cannot decode a newer managed runtime bundle'
        $untrustedFolder = 'retire claudecode managed runtime generations for SID S-1-5-21-1-2-3-1103 (CONTOSO\stale): enterprise hooks: managed runtime generation directory is untrusted: C:\Users\stale\.defenseclaw\hooks: access denied'
        $script:TestRetireError = ''
        $script:TestRetireShape = 'report'
        $script:TestReplacementError = ''
        $script:TestReplacementCalled = $false
        $script:TestReplacementKeepsJournal = $false
        function Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
            param([hashtable]$Layout, [string]$GatewayServiceName, [string]$Action, [hashtable]$GatewaySource)
            if ($Action -cne 'retire') {
                throw "unexpected action $Action"
            }
            if ($null -ne $GatewaySource) {
                $script:TestReplacementCalled = $true
                if ($script:TestReplacementError) {
                    throw $script:TestReplacementError
                }
                if (-not $script:TestReplacementKeepsJournal) {
                    [IO.File]::Delete($Layout.ManagedHooksLifecycleJournalPath)
                }
                return [pscustomobject]@{ ok = $true }
            }
            if ($script:TestRetireError) {
                $text = "managed-hook lifecycle snapshot retire failed: $($script:TestRetireError)"
                if ($script:TestRetireShape -ceq 'plain') {
                    throw $text
                }
                $exception = [Management.Automation.RuntimeException]::new($text)
                $exception.Data['DefenseClawLifecycleAction'] = if ($script:TestRetireShape -ceq 'phase') { 'capture' } else { 'retire' }
                $exception.Data['DefenseClawLifecycleReportError'] = $script:TestRetireError
                throw $exception
            }
            [IO.File]::Delete($Layout.ManagedHooksLifecycleJournalPath)
            return [pscustomobject]@{ ok = $true }
        }
        $run = {
            param(
                [string]$Name,
                [string]$Profile,
                [string]$RetireError,
                [bool]$Pending,
                [string]$Shape,
                [string]$ReplacementError,
                [bool]$ReplacementKeepsJournal,
                [bool]$WantReplacement,
                [bool]$WantThrow,
                [bool]$WantRemoved,
                [bool]$SupplySource = $true
            )
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $Profile
            [IO.File]::WriteAllText($layout.ManagedHooksLifecycleJournalPath, '{}')
            if ($Pending) {
                [IO.File]::WriteAllText($layout.PendingPath, '{}')
            }
            $script:TestRetireError = $RetireError
            $script:TestRetireShape = $Shape
            $script:TestReplacementError = $ReplacementError
            $script:TestReplacementKeepsJournal = $ReplacementKeepsJournal
            $script:TestReplacementCalled = $false
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
            $threw = $false
            try {
                Invoke-DefenseClawCommittedManagedHooksLifecycleRetire `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GatewaySource $(if ($SupplySource) { @{ path = 'authenticated replacement gateway' } } else { $null })
            }
            catch {
                $threw = $true
                $wantedError = if ($ReplacementError -and $WantReplacement) {
                    $ReplacementError
                }
                elseif ($ReplacementKeepsJournal -and $WantReplacement) {
                    'replacement gateway left the committed managed-hook lifecycle journal behind'
                }
                else {
                    $RetireError
                }
                if (-not ([string]$_.Exception.Message).Contains($wantedError)) {
                    $failures.Add("${Name}: error changed to '$($_.Exception.Message)'")
                }
                if ($Pending -and $RetireError -ceq $untrustedFolder -and
                    -not ([string]$_.Exception.Message).Contains('Have an administrator inspect')) {
                    $failures.Add("${Name}: pending untrusted-folder remedy is missing")
                }
            }
            $removed = -not [IO.File]::Exists($layout.ManagedHooksLifecycleJournalPath)
            $recorded = -not [string]::IsNullOrEmpty($script:DefenseClawStaleLifecycleJournalRemoved)
            $wantRecorded = $WantReplacement -and $WantRemoved
            if ($script:TestReplacementCalled -ne $WantReplacement -or
                $threw -ne $WantThrow -or
                $removed -ne $WantRemoved -or
                $recorded -ne $wantRecorded) {
                $failures.Add(
                    "${Name}: replacement=$script:TestReplacementCalled threw=$threw removed=$removed recorded=$recorded; " +
                    "want replacement=$WantReplacement threw=$WantThrow removed=$WantRemoved recorded=$wantRecorded"
                )
            }
            [IO.File]::Delete($layout.ManagedHooksLifecycleJournalPath)
            [IO.File]::Delete($layout.PendingPath)
        }
        try {
            & $run 'installed gateway retired' 'Standalone' '' $false 'report' '' $false $false $false $true
            foreach ($refusal in @($gcRefusal, $selectorRefusal, $identityRefusal, $unknownRefusal, $untrustedFolder,
                    'deployment managed-hook activation binding is invalid')) {
                & $run "staged gateway retries $refusal" 'Standalone' $refusal $false 'report' '' $false $true $false $true
            }
            & $run 'staged gateway failure keeps journal and Go reason' 'Standalone' $identityRefusal $false 'report' 'replacement GC rejected the bundle' $false $true $true $false
            & $run 'staged gateway leaving journal is an error' 'Standalone' $unknownRefusal $false 'report' '' $true $true $true $false
            & $run 'missing authenticated replacement keeps journal' 'Standalone' $identityRefusal $false 'report' '' $false $false $true $false $false
            & $run 'pending untrusted folder keeps remedy' 'Standalone' $untrustedFolder $true 'report' '' $false $false $true $false
            & $run 'pending foreign identity stays pending' 'Standalone' $identityRefusal $true 'report' '' $false $false $true $false
            & $run 'Secure Client keeps installed failure' 'SecureClient' $gcRefusal $false 'report' '' $false $false $true $false
            & $run 'command error is not a gateway report' 'Standalone' $identityRefusal $false 'plain' '' $false $false $true $false
            & $run 'another phase is not a retire report' 'Standalone' $identityRefusal $false 'phase' '' $false $false $true $false

            # GAP-1041: only a rolled-back teardown journal without a
            # pending transaction is stale.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $layout['ManagedHooksTeardownJournalPath'] = [IO.Path]::Combine($Root, 'managed-hooks-teardown-journal.json')
            foreach ($case in @(
                    @('rolled_back', $false, $true),
                    @('prepared', $false, $false),
                    @('rolled_back', $true, $false)
                )) {
                [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, ('{"schema_version":6,"phase":"' + $case[0] + '"}'))
                if ($case[1]) {
                    [IO.File]::WriteAllText($layout.PendingPath, '{}')
                }
                $script:DefenseClawStaleTeardownJournalRemoved = ''
                $removed = Remove-DefenseClawRolledBackTeardownJournal -Layout $layout -Stale
                $gone = -not [IO.File]::Exists($layout.ManagedHooksTeardownJournalPath)
                $recorded = -not [string]::IsNullOrEmpty($script:DefenseClawStaleTeardownJournalRemoved)
                if ($removed -ne $case[2] -or $gone -ne $case[2] -or $recorded -ne $case[2]) {
                    $failures.Add("teardown $($case[0]) pending=$($case[1]): removed=$removed gone=$gone recorded=$recorded")
                }
                [IO.File]::Delete($layout.ManagedHooksTeardownJournalPath)
                [IO.File]::Delete($layout.PendingPath)
            }

            # Setup /uninstall supplies a protected stage beside its installer.
            # Resolve that source through the same lifecycle entry used by
            # production, then enter the uninstall path with a stale journal.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $stageRoot = [IO.Path]::Combine($Root, 'setup')
            [void][IO.Directory]::CreateDirectory($stageRoot)
            $installer = [IO.Path]::Combine($stageRoot, 'install-enterprise.ps1')
            $gateway = [IO.Path]::Combine($stageRoot, 'defenseclaw-gateway.exe')
            $manifest = [IO.Path]::Combine($stageRoot, 'payload-manifest.json')
            [IO.File]::WriteAllText($installer, 'test installer')
            [IO.File]::WriteAllText($gateway, 'test gateway')
            # The source's NTFS owner/DACL contract has its own smoke. Keep
            # the actual source descriptor, signature and hash-pin checks.
            function script:Assert-DefenseClawTrustedSource {
                param([string]$Path, [string]$Label)
                return $Path
            }
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $gatewayHash = ([BitConverter]::ToString(
                    $sha256.ComputeHash([IO.File]::ReadAllBytes($gateway))
                )).Replace('-', '').ToLowerInvariant()
            }
            finally {
                $sha256.Dispose()
            }
            [IO.File]::WriteAllText($manifest, (
                @{ schema_version = 1; files = @{ 'defenseclaw-gateway.exe' = ('0' * 64) } } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
            ))
            Initialize-DefenseClawStandalonePayloadTrust -TrustMode HashPinned -PayloadManifest $manifest
            try {
                [void](Get-DefenseClawLifecycleSources -Action Uninstall -InstallerSource $installer)
                $failures.Add('standalone Uninstall admitted a gateway without its payload hash pin')
            }
            catch {
                if (-not ([string]$_.Exception.Message).Contains('not admitted by the standalone payload trust policy')) {
                    $failures.Add("standalone Uninstall rejected an unpinned gateway for the wrong reason: $($_.Exception.Message)")
                }
            }
            [IO.File]::WriteAllText($manifest, (
                @{ schema_version = 1; files = @{ 'defenseclaw-gateway.exe' = $gatewayHash } } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
            ))
            Initialize-DefenseClawStandalonePayloadTrust -TrustMode HashPinned -PayloadManifest $manifest
            $sources = Get-DefenseClawLifecycleSources -Action Uninstall -InstallerSource $installer
            if (-not $sources.ContainsKey('gateway') -or
                -not [string]::Equals([string]$sources['gateway'].path, $gateway, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([string]$sources['gateway'].sha256, $gatewayHash, [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add('standalone Uninstall did not authenticate the Setup gateway source')
            }
            $explicitSources = Get-DefenseClawLifecycleSources -Action Uninstall -GatewayBinary $gateway
            if (-not $explicitSources.ContainsKey('gateway') -or
                -not [string]::Equals([string]$explicitSources['gateway'].sha256, $gatewayHash, [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add('standalone Uninstall did not authenticate an explicit gateway source')
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $secureClientSources = Get-DefenseClawLifecycleSources -Action Uninstall -InstallerSource $installer
            if ($secureClientSources.ContainsKey('gateway')) {
                $failures.Add('Secure Client Uninstall gained a staged gateway source')
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            # A helper that removes hooks after the commit also answers the
            # read-only pre-commit check (GAP-0571); that check has its own
            # cases in enterprise-standalone-uninstall-hook-commit-smoke.ps1.
            # Here it passes, so the uninstall reaches the stale journal.
            function script:Invoke-DefenseClawManagedHooksTeardownCommand {
                param($Layout, $GatewayServiceName, $GuardianServiceName, $Action, [switch]$PurgeContractLocks)
                if ($Action -cne 'check') { throw "unexpected managed-hook teardown action $Action before the stale journal" }
            }
            function script:Get-DefenseClawDeploymentMetadata {
                param([hashtable]$Layout, [switch]$Required)
                return [pscustomobject]@{ managed_hooks_activation = [pscustomobject]@{ state = 'activated' } }
            }
            function script:Assert-DefenseClawMetadataIdentity { param($Metadata, $GatewayServiceName, $GuardianServiceName) }
            function script:Test-DefenseClawMetadataInstalled { param($Metadata) return $true }
            function script:Assert-DefenseClawManagedHooksActivationRecord { param($Record) return $Record }
            function script:Assert-DefenseClawOwnedServiceOrAbsent { param($Name, $ExpectedGatewayPath, $ExpectedManifestPath, [switch]$Guardian) }
            function script:Assert-DefenseClawManagedServiceConfigurations { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$AnyStartMode) }
            function script:Remove-DefenseClawStandaloneInstallTreeReplacementBackups { param($Layout) }
            function script:Assert-DefenseClawStandaloneInstallTreeNotInUse { param($Layout, $GatewayServiceName, $GuardianServiceName, $SelfUninstallCallerPID) }
            function script:Assert-DefenseClawStandaloneUninstallInstallTree { param($Layout) }
            function script:Assert-DefenseClawRecordedArtifactHashes { param($Metadata, $Layout, $Action) }
            function script:Assert-DefenseClawUninstallStateTreeNoReparse { param($Layout) }
            function script:Remove-DefenseClawRolledBackTeardownJournal { param($Layout, [switch]$Stale) throw 'uninstall reached teardown after stale journal retirement' }
            foreach ($refusal in @($gcRefusal, $selectorRefusal, $identityRefusal, $unknownRefusal, $untrustedFolder)) {
                [IO.File]::WriteAllText($layout.ManagedHooksLifecycleJournalPath, '{}')
                $script:TestRetireError = $refusal
                $script:TestRetireShape = 'report'
                $script:TestReplacementError = ''
                $script:TestReplacementKeepsJournal = $false
                $script:TestReplacementCalled = $false
                $threwTeardown = $false
                try {
                    [void](Invoke-DefenseClawUninstallLifecycle `
                        -Layout $layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -GuardianServiceName 'DefenseClawHookGuardian' `
                        -GatewaySource $sources['gateway'])
                }
                catch {
                    $threwTeardown = ([string]$_.Exception.Message).Contains(
                        'uninstall reached teardown after stale journal retirement')
                    if (-not $threwTeardown) {
                        $failures.Add("Uninstall $refusal failed before teardown: $($_.Exception.Message)")
                    }
                }
                if (-not $threwTeardown -or -not $script:TestReplacementCalled -or
                    [IO.File]::Exists($layout.ManagedHooksLifecycleJournalPath)) {
                    $failures.Add("Uninstall $refusal did not retire the stale journal with the Setup gateway")
                }
                [IO.File]::Delete($layout.ManagedHooksLifecycleJournalPath)
            }

            # GAP-0748: recovery itself retires the rolled-back journal once
            # Complete-DefenseClawTransaction removes pending.json. A later
            # timeout must not mistake this old record for unfinished work.
            function script:Restore-DefenseClawTransactionWithManagedHooksRollback {
                param([string]$SnapshotPath, [hashtable]$Layout)
                return [pscustomobject]@{
                    install_root_created = $false
                    state_root_created = $false
                }
            }
            function script:Complete-DefenseClawTransaction {
                param([string]$SnapshotPath, [hashtable]$Layout, [switch]$Rollback)
                [IO.File]::Delete($Layout.PendingPath)
            }
            [IO.File]::WriteAllText($layout.PendingPath, '{"snapshot":"test-snapshot"}')
            [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, '{"phase":"rolled_back"}')
            $recovery = Recover-DefenseClawPendingTransaction `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian
            if (-not $recovery.recovered -or
                [IO.File]::Exists($layout.PendingPath) -or
                [IO.File]::Exists($layout.ManagedHooksTeardownJournalPath)) {
                $failures.Add('a completed pending recovery retained its rolled-back teardown journal')
            }

            # GAP-0758: an older deferred Install could leave an unclaimed
            # preparation intent over an active install. Repair must retire
            # that receipt, keep the active deployment, and continue.
            if (-not ('DcsfNoPendingNative' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class DcsfNoPendingNative { public static object GetDirectorySecuritySnapshotNoFollowIfExists(string path) { return null; } }'
            }
            $layout['StateRoot'] = [IO.Path]::Combine($Root, 'state')
            $layout['PurgeIntentPath'] = [IO.Path]::Combine($Root, 'purge.json')
            $layout['MetadataPath'] = [IO.Path]::Combine($Root, 'deployment.json')
            function script:Invoke-DefenseClawSelfUninstallRecovery {
                param([string]$Action, [hashtable]$Layout, [string]$GatewayServiceName,
                    [string]$GuardianServiceName, [switch]$Purge, [int]$SelfUninstallCallerPID)
                return [pscustomobject]@{ handled = $false }
            }
            function script:Get-DefenseClawInstallRollbackIntent {
                param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
                return [pscustomobject]@{ phase = 'preparing_layout'; snapshot_path = '' }
            }
            function script:Get-DefenseClawDeploymentMetadata {
                param([hashtable]$Layout, [switch]$Required)
                return [pscustomobject]@{ installed = $true }
            }
            function script:Test-DefenseClawMetadataInstalled {
                param($Metadata)
                return $true
            }
            function script:Initialize-DefenseClawNativeSecurity {
                return [DcsfNoPendingNative]
            }
            $script:UnclaimedIntentRemoved = $false
            function script:Remove-DefenseClawUnclaimedInstallPreparationIntent {
                param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
                $script:UnclaimedIntentRemoved = $true
            }
            try {
                Assert-DefenseClawDeferredInstallIsFresh -Layout $layout
                $failures.Add('deferred Install accepted an active deployment')
            }
            catch {
                if ($_.Exception.Message -notmatch 'invalid_arguments:.*nothing was changed') {
                    $failures.Add("deferred Install returned an unexpected refusal: $($_.Exception.Message)")
                }
            }
            $oldIntentRecovery = Invoke-DefenseClawPreLayoutRecovery `
                -Action Repair `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian
            if (-not $script:UnclaimedIntentRemoved -or $oldIntentRecovery.handled) {
                $failures.Add('Repair failed to clear only the unclaimed deferred-Install receipt')
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-stale-lifecycle-journal-smoke: OK'
