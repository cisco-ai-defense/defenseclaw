# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$installerPath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\install-enterprise.ps1')
)
$testRoot = Microsoft.PowerShell.Management\Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('dcut-' + [Guid]::NewGuid().ToString('N'))
Microsoft.PowerShell.Management\New-Item `
    -ItemType Directory `
    -Path $testRoot `
    -Force | Microsoft.PowerShell.Core\Out-Null

try {
    Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
    $module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
    if ($null -eq $module) {
        throw 'DefenseClawEnterprise module was not imported'
    }

    $result = & $module {
        param(
            [Parameter(Mandatory)][string]$TestRoot,
            [Parameter(Mandatory)][string]$InstallerPath
        )

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $script:HarnessRealStartTransactionServices = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Start-DefenseClawTransactionServices `
                -CommandType Function
        ).ScriptBlock
        $script:HarnessRealRestoreTransaction = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Restore-DefenseClawTransaction `
                -CommandType Function
        ).ScriptBlock
        $script:HarnessRealGatewayCommand = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Invoke-DefenseClawGatewayCommand `
                -CommandType Function
        ).ScriptBlock
        $script:HarnessRealTargetRuntimeCleanupScope = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Assert-DefenseClawTargetRuntimeCleanupScopeExclusive `
                -CommandType Function
        ).ScriptBlock
        $script:HarnessRealSetPathAcl = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Set-DefenseClawPathAcl `
                -CommandType Function
        ).ScriptBlock
        $script:HarnessRealSourceReplacementDecision = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Test-DefenseClawSourceDescriptorPublishesReplacement `
                -CommandType Function
        ).ScriptBlock

        function Assert-Harness {
            param(
                [Parameter(Mandatory)][bool]$Condition,
                [Parameter(Mandatory)][string]$Message
            )
            if (-not $Condition) {
                throw $Message
            }
        }

        # Windows PowerShell 5.1 runs on .NET Framework and still reaches the
        # legacy MAX_PATH boundary for ordinary file APIs. Keep filesystem
        # fixture names compact; retain descriptive case names in the report.
        $script:HarnessCaseSequence = 0
        function New-HarnessCaseRoot {
            param(
                [Parameter(Mandatory)][string]$Parent,
                [Parameter(Mandatory)][string]$Label
            )
            $script:HarnessCaseSequence++
            $root = Microsoft.PowerShell.Management\Join-Path `
                $Parent `
                ('c{0:d3}' -f $script:HarnessCaseSequence)
            $receiptProbe = Microsoft.PowerShell.Management\Join-Path `
                (Microsoft.PowerShell.Management\Join-Path $root 'lifecycle') `
                ('purge-' + ('1' * 64) + '.json')
            if ($receiptProbe.Length -ge 240) {
                throw "PowerShell 5.1 fixture path is too long for ${Label}: $receiptProbe"
            }
            return $root
        }

        function Get-HarnessSHA256 {
            param([Parameter(Mandatory)][byte[]]$Bytes)
            $algorithm = [Security.Cryptography.SHA256]::Create()
            try {
                return (
                    [BitConverter]::ToString(
                        $algorithm.ComputeHash($Bytes)
                    ).Replace('-', '').ToLowerInvariant()
                )
            }
            finally {
                $algorithm.Dispose()
            }
        }

        function Write-HarnessJournal {
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$Phase
            )
            $parent = [IO.Path]::GetDirectoryName($Path)
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parent)) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $parent `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            $body = [Text.Encoding]::UTF8.GetBytes(
                ('{{"schema_version":4,"phase":"{0}","nonce":"fixed"}}' -f $Phase)
            )
            [IO.File]::WriteAllBytes($Path, $body)
        }

        function Get-HarnessJournalPhase {
            param([Parameter(Mandatory)][string]$Path)
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Leaf)) {
                return ''
            }
            return [string](
                Microsoft.PowerShell.Management\Get-Content `
                    -LiteralPath $Path `
                    -Raw |
                    Microsoft.PowerShell.Utility\ConvertFrom-Json
            ).phase
        }

        function New-HarnessLayout {
            param([Parameter(Mandatory)][string]$Root)
            $installRoot = Microsoft.PowerShell.Management\Join-Path $Root 'install'
            $stateRoot = Microsoft.PowerShell.Management\Join-Path $Root 'state'
            $installState = Microsoft.PowerShell.Management\Join-Path $stateRoot 'install'
            $binDirectory = Microsoft.PowerShell.Management\Join-Path $installRoot 'bin'
            $agentDirectory = Microsoft.PowerShell.Management\Join-Path $installRoot 'agents'
            $libexecDirectory = Microsoft.PowerShell.Management\Join-Path $installRoot 'libexec'
            $lifecycleDirectory = Microsoft.PowerShell.Management\Join-Path `
                $Root `
                'lifecycle'
            $purgeScope = ('1' * 64)
            $transactions = Microsoft.PowerShell.Management\Join-Path `
                $installState `
                'transactions'
            $codexVendorDirectory = Microsoft.PowerShell.Management\Join-Path `
                $Root `
                'shared\OpenAI'
            $codexMachinePolicyDirectory = Microsoft.PowerShell.Management\Join-Path `
                $codexVendorDirectory `
                'Codex'
            $brokerStateDirectory = Microsoft.PowerShell.Management\Join-Path `
                $stateRoot `
                'broker'
            $brokerLogDirectory = Microsoft.PowerShell.Management\Join-Path `
                $stateRoot `
                'logs\broker'
            $managedIPCDirectory = Microsoft.PowerShell.Management\Join-Path `
                $Root `
                'managed-ipc'
            foreach ($directory in @(
                $installRoot,
                $stateRoot,
                $installState,
                $transactions,
                $lifecycleDirectory
            )) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $directory `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            return @{
                InstallRoot = $installRoot
                StateRoot = $stateRoot
                # Harness roots sit directly under a temporary directory.
                StateRootAncestors = @()
                BinDirectory = $binDirectory
                AgentDirectory = $agentDirectory
                LibexecDirectory = $libexecDirectory
                GatewayPath = (
                    Microsoft.PowerShell.Management\Join-Path $binDirectory 'defenseclaw-gateway.exe'
                )
                BrokerPath = (
                    Microsoft.PowerShell.Management\Join-Path $binDirectory 'defenseclaw-cmid-broker.exe'
                )
                BrokerServiceName = 'DefenseClawCMIDBroker'
                BrokerPipeName = '\\.\pipe\DefenseClawCMIDBroker'
                BrokerStateDirectory = $brokerStateDirectory
                BrokerAuthKeyPath = (
                    Microsoft.PowerShell.Management\Join-Path $brokerStateDirectory 'broker-auth.key'
                )
                BrokerLogDirectory = $brokerLogDirectory
                BrokerLogPath = (
                    Microsoft.PowerShell.Management\Join-Path $brokerLogDirectory 'cmid-broker.log'
                )
                ProviderLibraryPath = (
                    Microsoft.PowerShell.Management\Join-Path $Root 'provider-fixture.dll'
                )
                HookPath = (
                    Microsoft.PowerShell.Management\Join-Path $binDirectory 'defenseclaw-hook.exe'
                )
                CLIPath = (
                    Microsoft.PowerShell.Management\Join-Path $binDirectory 'defenseclaw.exe'
                )
                InstallerPath = (
                    Microsoft.PowerShell.Management\Join-Path $libexecDirectory 'install-enterprise.ps1'
                )
                ModulePath = (
                    Microsoft.PowerShell.Management\Join-Path $libexecDirectory 'DefenseClawEnterprise.psm1'
                )
                ConfigPath = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'config.yaml'
                )
                ManifestPath = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'targets.yaml'
                )
                RuntimeDirectory = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'runtime'
                )
                ManagedIPCDirectory = $managedIPCDirectory
                ManagedIPCSocketPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $managedIPCDirectory `
                        'defenseclaw_ipc.sock'
                )
                AuthorizationDirectory = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'authorization'
                )
                GatewayLogPath = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'gateway.log'
                )
                GuardianLogPath = (
                    Microsoft.PowerShell.Management\Join-Path $stateRoot 'guardian.log'
                )
                MetadataPath = (
                    Microsoft.PowerShell.Management\Join-Path $installState 'deployment.json'
                )
                PendingPath = (
                    Microsoft.PowerShell.Management\Join-Path $installState 'pending.json'
                )
                TransactionsDirectory = $transactions
                LifecycleLockDirectory = $lifecycleDirectory
                LifecycleLockPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        'lifecycle.lock'
                )
                PurgeScopeSHA256 = $purgeScope
                PurgeIntentPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        "purge-$purgeScope.json"
                )
                InstallRollbackIntentPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        "install-rollback-$purgeScope.json"
                )
                SelfUninstallReceiptPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        "self-uninstall-$purgeScope.json"
                )
                SelfUninstallHelperPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        "self-uninstall-$purgeScope.ps1"
                )
                SelfUninstallEnvironmentRoot = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $lifecycleDirectory `
                        "self-uninstall-$purgeScope.environment"
                )
                ManagedHooksTeardownJournalPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $installState `
                        'managed-hooks-teardown-journal.json'
                )
                ManagedHooksLifecycleJournalPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $installState `
                        'managed-hooks-lifecycle-journal.json'
                )
                AgentApplicationControlAttestationPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $installState `
                        'agent-application-control.json'
                )
                CodexVendorDirectory = $codexVendorDirectory
                CodexMachinePolicyDirectory = $codexMachinePolicyDirectory
                CodexManagedHooksLockPath = (
                    Microsoft.PowerShell.Management\Join-Path `
                        $codexMachinePolicyDirectory `
                        '.defenseclaw-managed-hooks.lock'
                )
                CodexTargetEnabled = $false
                ClaudeTargetEnabled = $true
                CursorTargetEnabled = $false
                AgentApplicationControlAttested = $true
                ClaudeEffectivePolicyVerified = $true
                CoreHardeningCertification = $false
                CertificationCodexHome = ''
            }
        }

        function Write-HarnessSnapshot {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$SnapshotPath,
                [Parameter(Mandatory)][bool]$Prepared,
                [Parameter(Mandatory)][bool]$PreimageExisted,
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [string]$PreimageSHA256,
                [Parameter(Mandatory)][bool]$ServicesRunning,
                [bool]$ServicesExisted = $true
            )
            $files = @()
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.MetadataPath `
                -PathType Leaf) {
                $metadataBackup = $SnapshotPath + '.metadata.bak'
                Microsoft.PowerShell.Management\Copy-Item `
                    -LiteralPath $Layout.MetadataPath `
                    -Destination $metadataBackup `
                    -Force
                $files = @(
                    [ordered]@{
                        path = $Layout.MetadataPath
                        existed = $true
                        backup = $metadataBackup
                        security_descriptor = ''
                    }
                )
            }
            $snapshot = [ordered]@{
                schema_version = 1
                gateway_service = 'DefenseClawGateway'
                guardian_service = 'DefenseClawHookGuardian'
                service_activation_phase = 'quiesced'
                services_disabled_and_stopped_at = (
                    [DateTime]::UtcNow.AddMinutes(-2).ToString('o')
                )
                certification_codex_home = ''
                core_hardening_certification = [bool](
                    $Layout.CoreHardeningCertification
                )
                managed_hooks_teardown_prepared = $Prepared
                managed_hooks_teardown_journal_preserved = $true
                managed_hooks_teardown_journal_preimage_existed = $PreimageExisted
                managed_hooks_teardown_journal_preimage_sha256 = $PreimageSHA256
                files = $files
                services = @(
                    [ordered]@{
                        name = 'DefenseClawGateway'
                        existed = $ServicesExisted
                        running = $ServicesRunning
                        start_mode = $(if ($ServicesExisted) { 2 } else { 0 })
                    },
                    [ordered]@{
                        name = 'DefenseClawHookGuardian'
                        existed = $ServicesExisted
                        running = $ServicesRunning
                        start_mode = $(if ($ServicesExisted) { 2 } else { 0 })
                    }
                )
                created_shared_directories = @()
                created_target_runtime_roots = @()
            }
            [IO.File]::WriteAllText(
                $SnapshotPath,
                (
                    $snapshot |
                        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12
                ),
                [Text.UTF8Encoding]::new($false)
            )
            [IO.File]::WriteAllText(
                $Layout.PendingPath,
                (
                    [ordered]@{
                        schema_version = 1
                        snapshot = $SnapshotPath
                    } |
                        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4
                ),
                [Text.UTF8Encoding]::new($false)
            )
        }

        # The recovery tests execute the real orchestration helper and replace
        # only its external effects. This makes ordering and crash decisions
        # observable without requiring an elevated SCM token.
        function script:Assert-DefenseClawNoReparsePath {
            param(
                [Parameter(Mandatory)][string]$Path,
                [switch]$AllowMissingLeaf
            )
        }
        function script:Assert-DefenseClawDescendant {
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$Root,
                [Parameter(Mandatory)][string]$Label
            )
            return $Path
        }
        function script:Assert-DefenseClawPathAcl {
            param(
                [Parameter(Mandatory)][string]$Path,
                [string[]]$AllowedWriterSIDs,
                [string[]]$AllowedReaderSIDs,
                [hashtable]$RequiredRights,
                [switch]$AllowInheritance,
                [switch]$AllowUsersRead,
                [switch]$RejectUntrustedRead
            )
            if ($script:HarnessState.ContainsKey('purge_acl_invalid') -and
                [bool]$script:HarnessState.purge_acl_invalid -and
                [string]::Equals(
                    $Path,
                    [string]$script:HarnessState.layout.PurgeIntentPath,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw 'injected world-writable purge receipt'
            }
        }
        function script:Set-DefenseClawPathAcl {
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$Kind,
                [Parameter(Mandatory)][string]$GatewayServiceSID
            )
            $isManagedReplacementManifest = [bool](
                $script:HarnessState.ContainsKey('layout') -and
                $script:HarnessState.ContainsKey('events') -and
                [string]::Equals(
                    $Path,
                    [string]$script:HarnessState.layout.ManifestPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                $script:HarnessState.events.IndexOf(
                    'manifest-published'
                ) -ge 0
            )
            if ($isManagedReplacementManifest) {
                if ($Kind -cne 'AdminFile' -or
                    $GatewayServiceSID -cne $script:AdministratorsSID) {
                    throw 'install-like lifecycle used a noncanonical manifest ACL contract'
                }
                & $script:HarnessRealSetPathAcl @PSBoundParameters
                $script:HarnessState.manifest_admin_acl = $true
                $script:HarnessState.events.Add('manifest-admin-acl')
                return
            }
            if ($script:HarnessState.ContainsKey('layout') -and
                [string]::Equals(
                    $Path,
                    [string]$script:HarnessState.layout.PurgeIntentPath,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $script:HarnessState.events.Add('purge-intent-acl')
            }
        }
        function script:New-DefenseClawRequiredRights {
            param(
                [Parameter(Mandatory)][string]$Kind,
                [string]$GatewayServiceSID
            )
            return @{}
        }

        function script:Restore-DefenseClawTransaction {
            param(
                [Parameter(Mandatory)][string]$SnapshotPath,
                [Parameter(Mandatory)][hashtable]$Layout,
                [switch]$DeferServiceRestart
            )
            $script:HarnessState.restore_calls++
            if ($script:HarnessState.expect_rollback -and -not $DeferServiceRestart) {
                throw 'transaction restore restarted services before managed-hook rollback'
            }
            if ($script:HarnessState.expect_journal_at_restore -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                    -PathType Leaf)) {
                throw 'generic restore lost the live managed-hook journal'
            }
            $script:HarnessState.binary_present = $true
            $script:HarnessState.services_running = -not [bool]$DeferServiceRestart
        }

        function script:Invoke-DefenseClawManagedHooksTeardownCommand {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)]
                [ValidateSet('prepare', 'verify', 'rollback', 'finalize')]
                [string]$Action
            )
            if ($Action -ne 'rollback') {
                throw "unexpected direct recovery action: $Action"
            }
            $script:HarnessState.rollback_calls++
            if (-not [bool]$script:HarnessState.binary_present) {
                throw 'managed-hook rollback ran before the gateway binary was restored'
            }
            if ([bool]$script:HarnessState.services_running) {
                throw 'managed-hook rollback ran after services were restarted'
            }
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                -PathType Leaf)) {
                throw 'managed-hook rollback journal is missing'
            }
            $actual = [IO.File]::ReadAllBytes(
                $Layout.ManagedHooksTeardownJournalPath
            )
            if ($null -ne $script:HarnessState.expected_journal_bytes -and
                -not [Linq.Enumerable]::SequenceEqual(
                    [byte[]]$actual,
                    [byte[]]$script:HarnessState.expected_journal_bytes
                )) {
                throw 'generic restore changed the live managed-hook journal'
            }
            $phase = Get-HarnessJournalPhase `
                -Path $Layout.ManagedHooksTeardownJournalPath
            if ($phase -eq 'rolled_back') {
                if (-not [bool]$script:HarnessState.active_references) {
                    throw 'rolled-back journal has missing active references'
                }
                $script:HarnessState.rollback_verification_only++
            }
            else {
                $script:HarnessState.active_references = $true
                Write-HarnessJournal `
                    -Path $Layout.ManagedHooksTeardownJournalPath `
                    -Phase 'rolled_back'
            }
            return [pscustomobject]@{ ok = $true }
        }

        function script:Assert-DefenseClawRestoredTransactionReadyForActivation {
            param(
                [Parameter(Mandatory)]$Snapshot,
                [Parameter(Mandatory)][hashtable]$Layout
            )
            if ($script:HarnessState.expect_rollback -and
                $script:HarnessState.rollback_calls -ne 1) {
                throw 'restored deployment was validated before managed-hook rollback'
            }
            return $true
        }

        function script:Start-DefenseClawTransactionServices {
            param(
                [Parameter(Mandatory)]$Services,
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$ServicesQuiescedAt,
                [switch]$TrustInProcessQuiescence,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $script:HarnessState.start_calls++
            if ($script:HarnessState.expect_rollback -and
                $script:HarnessState.rollback_calls -ne 1) {
                throw 'services restarted before exactly one managed-hook rollback'
            }
            $script:HarnessState.services_running = [bool](
                @(
                    $Services |
                        Microsoft.PowerShell.Core\Where-Object {
                            [bool]$_.existed -and [bool]$_.running
                        }
                ).Count -gt 0
            )
        }

        $recoveryResults = [Collections.Generic.List[object]]::new()
        function Invoke-HarnessRecoveryCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][bool]$PreparedMarker,
                [Parameter(Mandatory)][bool]$PreimageExisted,
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [string]$PreimagePhase,
                [Parameter(Mandatory)][bool]$LiveJournalExists,
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [string]$LivePhase,
                [Parameter(Mandatory)][bool]$ExpectRollback,
                [bool]$BinaryPresent = $true,
                [bool]$ServicesRunning = $true,
                [bool]$ExpectFailure = $false
            )
            $root = New-HarnessCaseRoot -Parent $TestRoot -Label $Name
            $layout = New-HarnessLayout -Root $root
            $journalPath = [string]$layout.ManagedHooksTeardownJournalPath
            $preimageBytes = $null
            $preimageHash = ''
            if ($PreimageExisted) {
                Write-HarnessJournal -Path $journalPath -Phase $PreimagePhase
                $preimageBytes = [IO.File]::ReadAllBytes($journalPath)
                $preimageHash = Get-HarnessSHA256 -Bytes $preimageBytes
            }
            if ($LiveJournalExists) {
                Write-HarnessJournal -Path $journalPath -Phase $LivePhase
            }
            elseif (Microsoft.PowerShell.Management\Test-Path -LiteralPath $journalPath) {
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $journalPath `
                    -Force
            }
            $snapshotPath = Microsoft.PowerShell.Management\Join-Path `
                ([string]$layout.StateRoot) `
                'snapshot.json'
            Write-HarnessSnapshot `
                -Layout $layout `
                -SnapshotPath $snapshotPath `
                -Prepared $PreparedMarker `
                -PreimageExisted $PreimageExisted `
                -PreimageSHA256 $preimageHash `
                -ServicesRunning $ServicesRunning
            $expectedBytes = if ($LiveJournalExists) {
                [IO.File]::ReadAllBytes($journalPath)
            }
            else {
                $null
            }
            $script:HarnessState = @{
                expect_rollback = $ExpectRollback
                expect_journal_at_restore = $LiveJournalExists
                expected_journal_bytes = $expectedBytes
                binary_present = $BinaryPresent
                services_running = $false
                active_references = (
                    -not $LiveJournalExists -or $LivePhase -eq 'rolled_back'
                )
                restore_calls = 0
                rollback_calls = 0
                rollback_verification_only = 0
                start_calls = 0
            }

            $failed = $false
            try {
                [void](Restore-DefenseClawTransactionWithManagedHooksRollback `
                    -SnapshotPath $snapshotPath `
                    -Layout $layout)
            }
            catch {
                $failed = $true
                if (-not $ExpectFailure) {
                    throw
                }
            }
            Assert-Harness `
                -Condition ($failed -eq $ExpectFailure) `
                -Message "$Name failure result did not match expectation"
            Assert-Harness `
                -Condition ($script:HarnessState.restore_calls -eq 1) `
                -Message "$Name did not restore the generic transaction exactly once"
            if ($ExpectFailure) {
                Assert-Harness `
                    -Condition (-not [bool]$script:HarnessState.services_running) `
                    -Message "$Name restarted services after rollback became impossible"
            }
            elseif ($ExpectRollback) {
                Assert-Harness `
                    -Condition ($script:HarnessState.rollback_calls -eq 1) `
                    -Message "$Name did not run exactly one authenticated rollback"
                if ($LivePhase -eq 'rolled_back') {
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.rollback_verification_only -eq 1
                        ) `
                        -Message "$Name repeated an already-completed hook rollback"
                }
                Assert-Harness `
                    -Condition ([bool]$script:HarnessState.active_references) `
                    -Message "$Name did not restore machine hook references"
                Assert-Harness `
                    -Condition (
                        [bool]$script:HarnessState.services_running -eq $ServicesRunning
                    ) `
                    -Message "$Name did not restore the prior service running state"
            }
            else {
                Assert-Harness `
                    -Condition ($script:HarnessState.rollback_calls -eq 0) `
                    -Message "$Name unexpectedly invoked managed-hook rollback"
                Assert-Harness `
                    -Condition ([bool]$script:HarnessState.services_running) `
                    -Message "$Name did not restore services when no teardown began"
            }
            $recoveryResults.Add([pscustomobject]@{
                name = $Name
                rollback = $script:HarnessState.rollback_calls
                failed_closed = $failed
                services_running = $script:HarnessState.services_running
            })
        }

        Invoke-HarnessRecoveryCase `
            -Name 'before-prepare-no-journal' `
            -PreparedMarker:$false `
            -PreimageExisted:$false `
            -PreimagePhase '' `
            -LiveJournalExists:$false `
            -LivePhase '' `
            -ExpectRollback:$false
        Invoke-HarnessRecoveryCase `
            -Name 'captured-before-removal' `
            -PreparedMarker:$false `
            -PreimageExisted:$false `
            -PreimagePhase '' `
            -LiveJournalExists:$true `
            -LivePhase 'captured' `
            -ExpectRollback:$true
        Invoke-HarnessRecoveryCase `
            -Name 'prepared-before-marker' `
            -PreparedMarker:$false `
            -PreimageExisted:$false `
            -PreimagePhase '' `
            -LiveJournalExists:$true `
            -LivePhase 'prepared' `
            -ExpectRollback:$true
        Invoke-HarnessRecoveryCase `
            -Name 'preexisting-prepared-unchanged' `
            -PreparedMarker:$false `
            -PreimageExisted:$true `
            -PreimagePhase 'prepared' `
            -LiveJournalExists:$true `
            -LivePhase 'prepared' `
            -ExpectRollback:$true `
            -ServicesRunning:$false
        Invoke-HarnessRecoveryCase `
            -Name 'preexisting-rolled-back-unchanged' `
            -PreparedMarker:$false `
            -PreimageExisted:$true `
            -PreimagePhase 'rolled_back' `
            -LiveJournalExists:$true `
            -LivePhase 'rolled_back' `
            -ExpectRollback:$true
        Invoke-HarnessRecoveryCase `
            -Name 'marked-post-binary-delete' `
            -PreparedMarker:$true `
            -PreimageExisted:$false `
            -PreimagePhase '' `
            -LiveJournalExists:$true `
            -LivePhase 'prepared' `
            -ExpectRollback:$true `
            -BinaryPresent:$false
        Invoke-HarnessRecoveryCase `
            -Name 'marked-journal-deleted' `
            -PreparedMarker:$true `
            -PreimageExisted:$false `
            -PreimagePhase '' `
            -LiveJournalExists:$false `
            -LivePhase '' `
            -ExpectRollback:$true `
            -ExpectFailure:$true
        Invoke-HarnessRecoveryCase `
            -Name 'preexisting-journal-deleted' `
            -PreparedMarker:$false `
            -PreimageExisted:$true `
            -PreimagePhase 'rolled_back' `
            -LiveJournalExists:$false `
            -LivePhase '' `
            -ExpectRollback:$true `
            -ExpectFailure:$true
        $invalidCoreRoot = New-HarnessCaseRoot `
            -Parent $TestRoot `
            -Label 'snapshot-core-without-scope'
        $invalidCoreLayout = New-HarnessLayout -Root $invalidCoreRoot
        $invalidCoreSnapshot = Microsoft.PowerShell.Management\Join-Path `
            $invalidCoreLayout.StateRoot `
            'snapshot.json'
        Write-HarnessSnapshot `
            -Layout $invalidCoreLayout `
            -SnapshotPath $invalidCoreSnapshot `
            -Prepared:$false `
            -PreimageExisted:$false `
            -PreimageSHA256 '' `
            -ServicesRunning:$true
        $invalidCoreState = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $invalidCoreSnapshot `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $invalidCoreState.core_hardening_certification = $true
        [IO.File]::WriteAllText(
            $invalidCoreSnapshot,
            (
                $invalidCoreState |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12
            ),
            [Text.UTF8Encoding]::new($false)
        )
        $invalidCoreFailed = $false
        try {
            [void](& $script:HarnessRealRestoreTransaction `
                -SnapshotPath $invalidCoreSnapshot `
                -Layout $invalidCoreLayout)
        }
        catch {
            $invalidCoreFailed = $true
        }
        Assert-Harness `
            -Condition $invalidCoreFailed `
            -Message 'snapshot core mode without exact certification scope was accepted'
        $recoveryResults.Add([pscustomobject]@{
            name = 'snapshot-core-without-scope'
            rollback = 0
            failed_closed = $true
            services_running = $false
        })

        # Exercise the actual uninstall orchestration with stateful mocks. The
        # New-Transaction mock models a guardian event at its entry: old
        # prepare-before-stop ordering deterministically re-heals a reference,
        # while the fixed quiesce-before-prepare ordering cannot.
        function script:Get-DefenseClawDeploymentMetadata {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [switch]$Required
            )
            if ($script:HarnessState.operation -eq 'install' -and
                -not [bool]$script:HarnessState.installed -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.MetadataPath `
                    -PathType Leaf)) {
                return $null
            }
            return [pscustomobject]@{
                installed = [bool]$script:HarnessState.installed
                codex_target_enabled = $false
            }
        }
        function script:Assert-DefenseClawMetadataIdentity {
            param(
                [Parameter(Mandatory)]$Metadata,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
        }
        function script:Test-DefenseClawMetadataInstalled {
            param([Parameter(Mandatory)]$Metadata)
            return [bool]$Metadata.installed
        }
        function script:Test-DefenseClawServiceExists {
            param([Parameter(Mandatory)][string]$Name)
            if (-not $script:HarnessState.ContainsKey('service_exists')) {
                return $false
            }
            return [bool]$script:HarnessState.service_exists[$Name]
        }
        function script:Assert-DefenseClawOwnedServiceOrAbsent {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$ExpectedGatewayPath,
                [string]$ExpectedManifestPath,
                [switch]$Guardian,
                # Spec 005 D1: the uninstall path now also calls this
                # helper with -Enumerator to verify the third service
                # before removing it. Accepted for parity with the
                # real function; the mock records the ownership check
                # without differentiating the switch value.
                [switch]$Enumerator
            )
            $script:HarnessState.events.Add("owned:$Name")
            $script:HarnessState.owned_checks++
            if ($script:HarnessState.ContainsKey('foreign_service') -and
                [string]::Equals(
                    [string]$script:HarnessState.foreign_service,
                    $Name,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "refusing foreign service $Name"
            }
        }
        function script:Assert-DefenseClawCMIDBrokerServiceOrAbsent {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$ExpectedImage,
                [switch]$AllowArgumentUpgrade
            )
            $script:HarnessState.events.Add("owned:$Name")
            $script:HarnessState.owned_checks++
        }
        function script:Assert-DefenseClawManagedServiceConfigurations {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [switch]$PendingTransaction,
                [switch]$ServicingTransaction,
                [switch]$AnyStartMode
            )
            $script:HarnessState.service_contract_checks++
            $script:HarnessState.events.Add(
                "service-contract:$($script:HarnessState.service_contract_checks)"
            )
            $expectedModes = if ($ServicingTransaction) {
                @(4)
            }
            elseif ($PendingTransaction) {
                @(3)
            }
            elseif ($AnyStartMode) {
                @(2, 3, 4)
            }
            else {
                @(2)
            }
            foreach ($name in @(
                $GatewayServiceName,
                $Layout.BrokerServiceName,
                $GuardianServiceName
            )) {
                if ($script:HarnessState.service_start_modes[$name] -notin
                    $expectedModes) {
                    throw "service $name mode is $($script:HarnessState.service_start_modes[$name]), expected $($expectedModes -join ' or ')"
                }
            }
            if ($script:HarnessState.crash_at -eq 'service-drift-preflight' -and
                $script:HarnessState.service_contract_checks -eq 1) {
                throw 'injected service registry DACL drift'
            }
            if (($script:HarnessState.crash_at -eq 'service-drift-predelete' -or
                    $script:HarnessState.crash_at -eq 'marked') -and
                $script:HarnessState.service_contract_checks -eq 2) {
                throw 'injected service contract drift at deletion boundary'
            }
        }
        function script:Assert-DefenseClawManagedInstallTree {
            param([Parameter(Mandatory)][hashtable]$Layout)
        }
        function script:Assert-DefenseClawRecordedArtifactHashes {
            param(
                [Parameter(Mandatory)]$Metadata,
                [Parameter(Mandatory)][hashtable]$Layout,
                [string[]]$ReplacedArtifacts = @(),
                [string]$Action = 'this action'
            )
        }
        function script:Get-DefenseClawServiceSID {
            param([Parameter(Mandatory)][string]$ServiceName)
            if ($ServiceName -ceq 'DefenseClawGatewayScopeB') {
                return 'S-1-5-80-6-7-8-9-10'
            }
            return 'S-1-5-80-1-2-3-4-5'
        }
        function script:Get-DefenseClawServiceSIDForRecovery {
            param([Parameter(Mandatory)][string]$ServiceName)
            return Get-DefenseClawServiceSID -ServiceName $ServiceName
        }
        function script:Write-DefenseClawJsonAtomic {
            param(
                [Parameter(Mandatory)]$Value,
                [Parameter(Mandatory)][string]$Path
            )
            $isPurgeIntent = (
                $script:HarnessState.ContainsKey('layout') -and
                [string]::Equals(
                    $Path,
                    [string]$script:HarnessState.layout.PurgeIntentPath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            )
            if ($isPurgeIntent -and
                [string]$script:HarnessState.crash_at -ceq
                    'purge-receipt-write') {
                throw 'injected state-purge receipt write failure'
            }
            $parent = [IO.Path]::GetDirectoryName($Path)
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parent)) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $parent `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            [IO.File]::WriteAllText(
                $Path,
                (
                    $Value |
                        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 16
                ),
                [Text.UTF8Encoding]::new($false)
            )
            if ($isPurgeIntent) {
                $script:HarnessState.events.Add('purge-intent-write')
            }
        }
        function script:New-DefenseClawTransaction {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [switch]$PriorDeploymentActive,
                [switch]$IncludeCodexMachineState,
                [switch]$ManagedHooksTeardownPrepared,
                [switch]$PreserveManagedHooksTeardownJournal,
                [switch]$InstallRootCreatedForTransaction,
                [switch]$StateRootCreatedForTransaction
            )
            if (-not $PSBoundParameters.ContainsKey(
                    'PriorDeploymentActive'
                )) {
                throw 'transaction omitted the prior deployment activity contract'
            }
            if ([bool]$PriorDeploymentActive -ne
                [bool]$script:HarnessState.installed) {
                throw (
                    'transaction prior deployment activity did not match ' +
                    'the authenticated metadata fixture'
                )
            }
            $script:HarnessState.events.Add('transaction')
            $script:HarnessState.transaction_calls++
            $script:HarnessState.service_start_modes[
                $GatewayServiceName
            ] = 4
            $script:HarnessState.service_start_modes[
                $Layout.BrokerServiceName
            ] = 4
            $script:HarnessState.service_start_modes[
                $GuardianServiceName
            ] = 4
            if ($script:HarnessState.ContainsKey('queued_gateway_restart') -and
                [bool]$script:HarnessState.queued_gateway_restart) {
                $script:HarnessState.events.Add(
                    'queued-gateway-restart-during-servicing'
                )
                if ($script:HarnessState.service_start_modes[
                        $GatewayServiceName
                    ] -eq 4) {
                    $script:HarnessState.queued_restart_blocked = $true
                }
                else {
                    $script:HarnessState.gateway_started_before_guardian =
                        $true
                    $script:HarnessState.gateway_running = $true
                }
            }
            if ($script:HarnessState.operation -eq 'install') {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.ManagedHooksTeardownJournalPath) {
                    throw 'direct reinstall opened a transaction before retiring the committed journal'
                }
                $script:HarnessState.install_saw_retired_journal = $true
                $script:HarnessState.guardian_running = $false
                $script:HarnessState.gateway_running = $false
                $snapshotPath = Microsoft.PowerShell.Management\Join-Path `
                    ([string]$Layout.StateRoot) `
                    'install-snapshot.json'
                $servicesExisted = $true
                if ($script:HarnessState.ContainsKey(
                        'track_fresh_install_services'
                    ) -and
                    [bool]$script:HarnessState.track_fresh_install_services) {
                    $servicesExisted = [bool](
                        $script:HarnessState.service_exists[
                            $GatewayServiceName
                        ] -or
                        $script:HarnessState.service_exists[
                            $GuardianServiceName
                        ]
                    )
                    $script:HarnessState.fresh_services_existed =
                        $servicesExisted
                }
                Write-HarnessSnapshot `
                    -Layout $Layout `
                    -SnapshotPath $snapshotPath `
                    -Prepared:$false `
                    -PreimageExisted:$false `
                    -PreimageSHA256 '' `
                    -ServicesRunning:$false `
                    -ServicesExisted:$servicesExisted
                $script:HarnessState.snapshot_path = $snapshotPath
                return $snapshotPath
            }
            if (-not $PreserveManagedHooksTeardownJournal) {
                throw 'uninstall transaction did not preserve its live teardown journal'
            }
            if ([bool]$script:HarnessState.guardian_running -and
                -not [bool]$script:HarnessState.active_references) {
                $script:HarnessState.active_references = $true
                $script:HarnessState.reheal_observed = $true
                $script:HarnessState.events.Add('guardian-reheal')
            }
            $script:HarnessState.guardian_running = $false
            $script:HarnessState.gateway_running = $false

            $journalPath = [string]$Layout.ManagedHooksTeardownJournalPath
            $preimageExisted = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $journalPath `
                -PathType Leaf
            $preimageHash = ''
            if ($preimageExisted) {
                $preimageHash = Get-HarnessSHA256 `
                    -Bytes ([IO.File]::ReadAllBytes($journalPath))
            }
            $snapshotPath = Microsoft.PowerShell.Management\Join-Path `
                ([string]$Layout.StateRoot) `
                'uninstall-snapshot.json'
            Write-HarnessSnapshot `
                -Layout $Layout `
                -SnapshotPath $snapshotPath `
                -Prepared:$false `
                -PreimageExisted:$preimageExisted `
                -PreimageSHA256 $preimageHash `
                -ServicesRunning:$script:HarnessState.services_were_running
            $script:HarnessState.snapshot_path = $snapshotPath
            return $snapshotPath
        }
        function script:Invoke-DefenseClawManagedHooksTeardownCommand {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)]
                [ValidateSet('prepare', 'verify', 'rollback', 'finalize')]
                [string]$Action
            )
            $script:HarnessState.events.Add("teardown:$Action")
            switch ($Action) {
                'prepare' {
                    $script:HarnessState.prepare_calls++
                    if ([bool]$script:HarnessState.guardian_running) {
                        $script:HarnessState.prepare_while_guardian_running = $true
                    }
                    $existingPhase = Get-HarnessJournalPhase `
                        -Path $Layout.ManagedHooksTeardownJournalPath
                    if ($script:HarnessState.crash_at -eq
                            'preexisting-prepared-before-marker' -and
                        $existingPhase -eq 'prepared') {
                        if ([bool]$script:HarnessState.active_references) {
                            throw 'preexisting prepared journal was not clean'
                        }
                        return [pscustomobject]@{ ok = $true }
                    }
                    Write-HarnessJournal `
                        -Path $Layout.ManagedHooksTeardownJournalPath `
                        -Phase 'captured'
                    if ($script:HarnessState.crash_at -eq 'captured') {
                        throw 'injected crash after captured journal publication'
                    }
                    if ($script:HarnessState.crash_at -eq
                            'failed-teardown-self-restored') {
                        $script:HarnessState.active_references = $false
                        $script:HarnessState.active_references = $true
                        Write-HarnessJournal `
                            -Path $Layout.ManagedHooksTeardownJournalPath `
                            -Phase 'rolled_back'
                        throw (
                            'injected disconnected target teardown incomplete ' +
                            'after exact self-rollback'
                        )
                    }
                    $script:HarnessState.active_references = $false
                    Write-HarnessJournal `
                        -Path $Layout.ManagedHooksTeardownJournalPath `
                        -Phase 'prepared'
                    if ($script:HarnessState.crash_at -eq
                            'prepared-before-marker') {
                        throw 'injected crash after prepare before marker'
                    }
                    return [pscustomobject]@{ ok = $true }
                }
                'verify' {
                    $script:HarnessState.verify_calls++
                    if ([bool]$script:HarnessState.guardian_running -or
                        [bool]$script:HarnessState.active_references -or
                        (Get-HarnessJournalPhase `
                            -Path $Layout.ManagedHooksTeardownJournalPath) -ne
                            'prepared') {
                        throw 'verify observed a surviving machine reference'
                    }
                    if ($script:HarnessState.crash_at -eq
                            'preexisting-prepared-before-marker') {
                        throw 'injected crash after idempotent prepare before marker'
                    }
                    return [pscustomobject]@{ ok = $true }
                }
                'rollback' {
                    $script:HarnessState.rollback_calls++
                    if (-not [bool]$script:HarnessState.binary_present) {
                        throw 'rollback ran before binary restoration'
                    }
                    if ([bool]$script:HarnessState.services_running) {
                        throw 'rollback ran after service restart'
                    }
                    $phase = Get-HarnessJournalPhase `
                        -Path $Layout.ManagedHooksTeardownJournalPath
                    if ($phase -notin @('captured', 'prepared', 'rolled_back')) {
                        throw "rollback received invalid journal phase: $phase"
                    }
                    if ($phase -eq 'rolled_back') {
                        if (-not [bool]$script:HarnessState.active_references) {
                            throw 'rolled-back journal has missing active references'
                        }
                        $script:HarnessState.rollback_verification_only++
                    }
                    else {
                        $script:HarnessState.active_references = $true
                        Write-HarnessJournal `
                            -Path $Layout.ManagedHooksTeardownJournalPath `
                            -Phase 'rolled_back'
                    }
                    return [pscustomobject]@{ ok = $true }
                }
                'finalize' {
                    if ([bool]$script:HarnessState.active_references) {
                        throw 'finalize observed a surviving machine reference'
                    }
                    if (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $Layout.PendingPath) {
                        throw 'finalize ran before transaction commit'
                    }
                    $phase = Get-HarnessJournalPhase `
                        -Path $Layout.ManagedHooksTeardownJournalPath
                    if ($phase -notin @('prepared', 'finalized')) {
                        throw "finalize received invalid journal phase: $phase"
                    }
                    Write-HarnessJournal `
                        -Path $Layout.ManagedHooksTeardownJournalPath `
                        -Phase 'finalized'
                    return [pscustomobject]@{ ok = $true }
                }
            }
        }
        function script:Complete-DefenseClawCommittedManagedHooksFinalization {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            return Invoke-DefenseClawManagedHooksTeardownCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action finalize
        }
        function script:Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)]
                [ValidateSet('capture', 'restore', 'retire')]
                [string]$Action
            )
            $null = $GatewayServiceName
            $script:HarnessState.events.Add("lifecycle-snapshot:$Action")
            switch ($Action) {
                'capture' {
                    if ($script:HarnessState.ContainsKey(
                            'track_fresh_install_services'
                        ) -and
                        [bool]$script:HarnessState.track_fresh_install_services) {
                        foreach ($serviceName in @(
                            $GatewayServiceName,
                            'DefenseClawCMIDBroker',
                            'DefenseClawHookGuardian',
                            [string]$script:HarnessState.enumerator_service_name
                        )) {
                            if (-not [bool]$script:HarnessState.service_exists[
                                    $serviceName
                                ]) {
                                throw 'snapshot capture ran before all four service identities existed'
                            }
                            if ($script:HarnessState.service_start_modes[
                                    $serviceName
                                ] -ne 4) {
                                throw 'snapshot capture observed a startable fresh service'
                            }
                        }
                        if ($script:HarnessState.events.IndexOf(
                                'managed-core-acls'
                            ) -lt 0) {
                            throw 'snapshot capture ran before service-SID ACL setup'
                        }
                    }
                    $script:HarnessState.lifecycle_preimage_active = [bool](
                        $script:HarnessState.active_references
                    )
                    [IO.File]::WriteAllText(
                        $Layout.ManagedHooksLifecycleJournalPath,
                        '{"schema_version":1,"phase":"captured"}',
                        [Text.UTF8Encoding]::new($false)
                    )
                    if ($script:HarnessState.ContainsKey(
                            'fail_fresh_install_capture'
                        ) -and
                        [bool]$script:HarnessState.fail_fresh_install_capture) {
                        throw 'injected fresh-install snapshot failure'
                    }
                }
                'restore' {
                    if (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
                        -PathType Leaf)) {
                        throw 'lifecycle snapshot restore lost its journal'
                    }
                    $script:HarnessState.active_references = [bool](
                        $script:HarnessState.lifecycle_preimage_active
                    )
                }
                'retire' {
                    if (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
                        -PathType Leaf) {
                        Microsoft.PowerShell.Management\Remove-Item `
                            -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
                            -Force
                    }
                }
            }
            return [pscustomobject]@{ ok = $true; action = $Action }
        }
        function script:Restore-DefenseClawTransaction {
            param(
                [Parameter(Mandatory)][string]$SnapshotPath,
                [Parameter(Mandatory)][hashtable]$Layout,
                [switch]$DeferServiceRestart
            )
            $script:HarnessState.events.Add('restore')
            $script:HarnessState.restore_calls++
            if ($script:HarnessState.operation -eq 'install') {
                if (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
                        -PathType Leaf) {
                    [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
                        -Layout $Layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -Action restore)
                    [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
                        -Layout $Layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -Action retire)
                }
                $targetRuntimeSnapshot =
                    Get-HarnessTargetRuntimeRequest -Path $SnapshotPath
                if ($null -ne $targetRuntimeSnapshot.PSObject.Properties[
                        'target_runtime_plan'
                    ]) {
                    # Exercise the real rollback orchestrator while the
                    # target-runtime gateway boundary is case-scoped below.
                    # The pending journal and protected plan/report files must
                    # remain live until the helper proves every created root
                    # absent; generic restore may then retire the staged binary.
                    [void](Invoke-DefenseClawTargetRuntimeRollbackCleanup `
                        -SnapshotPath $SnapshotPath `
                        -Layout $Layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -GuardianServiceName 'DefenseClawHookGuardian')
                    $targetRuntimeSnapshot =
                        Get-HarnessTargetRuntimeRequest -Path $SnapshotPath
                    $cleanupReportProperty =
                        $targetRuntimeSnapshot.PSObject.Properties[
                            'target_runtime_cleanup_report'
                        ]
                    if ($null -eq $cleanupReportProperty -or
                        -not [bool]$cleanupReportProperty.Value.ok -or
                        @(
                            $targetRuntimeSnapshot.created_target_runtime_roots
                        ).Count -ne 0 -or
                        [bool]$script:HarnessState.target_runtime_root_live -or
                        -not (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $Layout.PendingPath `
                            -PathType Leaf)) {
                        throw 'target-runtime cleanup was not durably journaled'
                    }
                    $script:HarnessState.events.Add(
                        'target-runtime:cleanup-authority-persisted'
                    )
                }
                if ($script:HarnessState.ContainsKey(
                        'track_fresh_install_services'
                    ) -and
                    [bool]$script:HarnessState.track_fresh_install_services -and
                    -not [bool]$script:HarnessState.fresh_services_existed) {
                    # Model the exact absent file preimage recorded by a real
                    # fresh-install transaction. Leaving the staged hook
                    # binary behind makes the committed-uninstall preflight
                    # correctly reject the retry before it opens a transaction.
                    foreach ($path in @(
                        $Layout.GatewayPath,
                        $Layout.HookPath,
                        $Layout.CLIPath,
                        $Layout.ConfigPath,
                        $Layout.ManifestPath,
                        $Layout.InstallerPath,
                        $Layout.ModulePath
                    )) {
                        if (Microsoft.PowerShell.Management\Test-Path `
                                -LiteralPath $path) {
                            Microsoft.PowerShell.Management\Remove-Item `
                                -LiteralPath $path `
                                -Force
                        }
                    }
                    # The self-uninstall shortcut mock fakes removal of all
                    # four services to stay consistent with the full path.
                    foreach ($name in @(
                        'DefenseClawGateway',
                        'DefenseClawCMIDBroker',
                        'DefenseClawHookGuardian',
                        'DefenseClawHookEnumerator'
                    )) {
                        if ($name -eq 'DefenseClawGateway') {
                            [void](Revoke-DefenseClawManagedIPCServiceAccess `
                                -Layout $Layout `
                                -GatewayServiceName $name `
                                -GatewayServiceSID 'S-1-5-80-1-2-3-4-5' `
                                -TransactionCreatedServicePresent)
                        }
                        $script:HarnessState.events.Add(
                            "remove-service:$name"
                        )
                        $script:HarnessState.service_exists[$name] = $false
                        $script:HarnessState.service_start_modes[$name] = 0
                    }
                    $script:HarnessState.removed_services += 4
                    $script:HarnessState.installed = $false
                    $script:HarnessState.services_running = $false
                    $retainedGatewaySID =
                        Get-DefenseClawServiceSIDForRecovery `
                            -ServiceName 'DefenseClawGateway'
                    Set-DefenseClawPreservedStateAcls `
                        -Layout $Layout `
                        -GatewayServiceSID $retainedGatewaySID
                    return
                }
                $script:HarnessState.installed = $true
                $script:HarnessState.services_running = $false
                $script:HarnessState.service_start_modes[
                    'DefenseClawGateway'
                ] = 4
                $script:HarnessState.service_start_modes[
                    'DefenseClawHookGuardian'
                ] = 4
                return
            }
            if (-not $DeferServiceRestart) {
                throw 'uninstall recovery did not defer service restart'
            }
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                -PathType Leaf)) {
                throw 'uninstall recovery lost the live teardown journal'
            }
            $script:HarnessState.binary_present = $true
            $script:HarnessState.installed = $true
            $script:HarnessState.services_running = $false
            $script:HarnessState.service_start_modes[
                'DefenseClawGateway'
            ] = 4
            $script:HarnessState.service_start_modes[
                'DefenseClawCMIDBroker'
            ] = 4
            $script:HarnessState.service_start_modes[
                'DefenseClawHookGuardian'
            ] = 4
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath `
                -PathType Leaf)) {
                [IO.File]::WriteAllText(
                    $Layout.AgentApplicationControlAttestationPath,
                    '{}',
                    [Text.UTF8Encoding]::new($false)
                )
            }
        }
        function script:Assert-DefenseClawRestoredTransactionReadyForActivation {
            param(
                [Parameter(Mandatory)]$Snapshot,
                [Parameter(Mandatory)][hashtable]$Layout
            )
            $script:HarnessState.events.Add('validate-restored-disabled')
            if ($script:HarnessState.rollback_calls -ne 1) {
                throw 'restored deployment was validated before managed-hook rollback completed'
            }
            return $true
        }
        function script:Start-DefenseClawTransactionServices {
            param(
                [Parameter(Mandatory)]$Services,
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$ServicesQuiescedAt,
                [switch]$TrustInProcessQuiescence,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $script:HarnessState.events.Add('restart-services')
            if ($script:HarnessState.operation -eq 'uninstall' -and
                $script:HarnessState.rollback_calls -ne 1) {
                throw 'services restarted before managed-hook rollback completed'
            }
            $script:HarnessState.services_running = [bool](
                @(
                    $Services |
                        Microsoft.PowerShell.Core\Where-Object {
                            [bool]$_.existed -and [bool]$_.running
                        }
                ).Count -gt 0
            )
        }
        function script:Remove-DefenseClawService {
            param([Parameter(Mandatory)][string]$Name)
            $expected = "owned:$Name"
            $last = if ($script:HarnessState.events.Count -eq 0) {
                ''
            }
            else {
                [string]$script:HarnessState.events[
                    $script:HarnessState.events.Count - 1
                ]
            }
            if ($last -cne $expected) {
                throw "service $Name deletion lacked an immediate owned identity recheck"
            }
            $script:HarnessState.events.Add("remove-service:$Name")
            $script:HarnessState.removed_services++
            if ($script:HarnessState.ContainsKey('service_exists')) {
                $script:HarnessState.service_exists[$Name] = $false
            }
        }
        function script:New-DefenseClawDeploymentMetadata {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [bool]$Installed = $true
            )
            $script:HarnessState.installed = [bool]$Installed
            return [pscustomobject]@{
                installed = [bool]$Installed
                hashes = [ordered]@{ prior = 'hash' }
            }
        }
        function script:Set-DefenseClawPreservedStateAcls {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceSID
            )
            if ([string]::IsNullOrWhiteSpace($GatewayServiceSID)) {
                throw 'preserved-state ACL restoration lost its gateway SID'
            }
            if ($script:HarnessState.ContainsKey(
                    'track_fresh_install_services'
                ) -and
                [bool]$script:HarnessState.track_fresh_install_services) {
                if (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $Layout.PendingPath `
                        -PathType Leaf)) {
                    throw 'preserved-state ACL restoration lost its recovery authority'
                }
                if ([bool]$script:HarnessState.service_exists[
                        'DefenseClawGateway'
                    ]) {
                    throw 'preserved-state ACL restoration preceded service rollback'
                }
            }
            $script:HarnessState.events.Add(
                "preserved-state-acls:$GatewayServiceSID"
            )
        }
        function script:Stop-DefenseClawService {
            param([Parameter(Mandatory)][string]$Name)
            $script:HarnessState.events.Add("stop-service:$Name")
            if ($Name -eq 'DefenseClawHookGuardian') {
                $script:HarnessState.guardian_running = $false
                if ($script:HarnessState.ContainsKey('guardian_fresh')) {
                    $script:HarnessState.guardian_fresh = $false
                }
            }
            if ($Name -eq 'DefenseClawGateway') {
                $script:HarnessState.gateway_running = $false
            }
            $script:HarnessState.services_running = $false
        }
        function script:Set-DefenseClawServiceStartMode {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)]
                [ValidateSet(2, 3, 4)]
                [int]$StartMode
            )
            if ($Name -eq 'DefenseClawGateway' -and
                $StartMode -in @(2, 3) -and
                $script:HarnessState.ContainsKey('barrier_required') -and
                [bool]$script:HarnessState.barrier_required -and
                -not [bool]$script:HarnessState.barrier_complete) {
                throw 'gateway became startable before failure-restart quiescence completed'
            }
            $script:HarnessState.events.Add("mode:${Name}:$StartMode")
            $script:HarnessState.service_start_modes[$Name] = $StartMode
            if ($Name -eq 'DefenseClawGateway' -and
                $StartMode -eq 3 -and
                $script:HarnessState.ContainsKey('queued_gateway_restart') -and
                [bool]$script:HarnessState.queued_gateway_restart) {
                $script:HarnessState.events.Add('queued-gateway-restart')
                if (-not [bool]$script:HarnessState.guardian_running -or
                    -not [bool]$script:HarnessState.guardian_fresh) {
                    $script:HarnessState.gateway_started_before_guardian =
                        $true
                }
                $script:HarnessState.gateway_running = $true
                $script:HarnessState.services_running = $true
            }
        }
        function script:Start-DefenseClawService {
            param([Parameter(Mandatory)][string]$Name)
            if ($script:HarnessState.service_start_modes[$Name] -eq 4) {
                throw "queued or explicit start was blocked while $Name was disabled"
            }
            $script:HarnessState.events.Add("start-service:$Name")
            if ($script:HarnessState.ContainsKey('start_service_calls')) {
                $script:HarnessState.start_service_calls++
            }
            if ($script:HarnessState.ContainsKey('fail_start_service') -and
                [string]::Equals(
                    [string]$script:HarnessState.fail_start_service,
                    $Name,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "injected start failure for $Name"
            }
            if ($Name -eq 'DefenseClawHookGuardian') {
                $script:HarnessState.guardian_running = $true
                $script:HarnessState.active_references = $true
            }
            if ($Name -eq 'DefenseClawGateway') {
                $script:HarnessState.gateway_running = $true
            }
            $script:HarnessState.services_running = $true
        }
        function script:Get-DefenseClawAgentApplicationControlAttestation {
            param([Parameter(Mandatory)][hashtable]$Layout)
            return [pscustomobject]@{
                agent_application_control_enforced = $true
                claude_effective_policy_verified = $true
            }
        }
        function script:Set-DefenseClawManagedServices {
            param(
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [Parameter(Mandatory)][string]$BrokerServiceName,
                [Parameter(Mandatory)][string]$BrokerPath,
                [Parameter(Mandatory)][string]$BrokerPipeName,
                [Parameter(Mandatory)][string]$BrokerAuthKeyPath,
                [Parameter(Mandatory)][string]$ProviderLibraryPath,
                [Parameter(Mandatory)][string]$BrokerLogPath,
                [Parameter(Mandatory)][string]$GatewayPath,
                [Parameter(Mandatory)][string]$ManifestPath,
                [Parameter(Mandatory)][string]$RuntimeDirectory,
                [Parameter(Mandatory)][string]$ConfigPath,
                [Parameter(Mandatory)][string]$AuthorizationDirectory,
                [Parameter(Mandatory)][string]$GatewayLogPath,
                [Parameter(Mandatory)][string]$GuardianLogPath,
                [switch]$AgentApplicationControlAttested,
                [switch]$ClaudeEffectivePolicyVerified,
                [switch]$DeferAutomaticStart
            )
            $script:HarnessState.events.Add('managed-services')
            $mode = if ($DeferAutomaticStart) { 4 } else { 2 }
            $script:HarnessState.service_start_modes[$GatewayServiceName] =
                $mode
            $script:HarnessState.service_start_modes[$BrokerServiceName] =
                $mode
            $script:HarnessState.service_start_modes[$GuardianServiceName] =
                $mode
            $enumeratorServiceName =
                Get-DefenseClawEnumeratorServiceName `
                    -GuardianServiceName $GuardianServiceName
            $script:HarnessState.enumerator_service_name =
                $enumeratorServiceName
            $script:HarnessState.service_start_modes[$enumeratorServiceName] =
                $mode
            if ($script:HarnessState.ContainsKey('service_exists')) {
                $script:HarnessState.service_exists[$GatewayServiceName] = $true
                $script:HarnessState.service_exists[$BrokerServiceName] = $true
                $script:HarnessState.service_exists[$GuardianServiceName] = $true
                $script:HarnessState.service_exists[
                    $enumeratorServiceName
                ] = $true
            }
        }
        function script:Set-DefenseClawInstallPreparationGatewayServiceSID {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $null = $Layout
            if ($GatewayServiceName -cne 'DefenseClawGateway' -or
                $GuardianServiceName -cne 'DefenseClawHookGuardian') {
                throw 'fresh install bound the wrong service SID authority'
            }
            $script:HarnessState.events.Add('install-service-sid-bound')
        }
        function script:Set-DefenseClawManagedCoreAcls {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName
            )
            $script:HarnessState.events.Add('managed-core-acls')
        }
        function script:Set-DefenseClawRetainedRuntimeAcls {
            param(
                [Parameter(Mandatory)][string]$RuntimeDirectory,
                [Parameter(Mandatory)][string]$GatewayServiceSID
            )
            if (-not [string]::Equals(
                    $RuntimeDirectory,
                    [string]$script:HarnessState.layout.RuntimeDirectory,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or $GatewayServiceSID -cne 'S-1-5-80-1-2-3-4-5') {
                throw 'retained runtime ACL mock received the wrong identity'
            }
            $script:HarnessState.events.Add('retained-runtime-acls')
        }
        function script:Initialize-DefenseClawManagedIPCDirectory {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName
            )
            if ([string]::IsNullOrWhiteSpace(
                    [string]$Layout.ManagedIPCDirectory
                )) {
                throw 'managed IPC mock received an empty contract path'
            }
            if ($script:HarnessState.ContainsKey('ipc_service_sids')) {
                $gatewaySID = Get-DefenseClawServiceSID `
                    -ServiceName $GatewayServiceName
                $foreignSIDs = @(
                    $script:HarnessState.ipc_service_sids |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]$_ -cne $gatewaySID
                        }
                )
                if ($foreignSIDs.Count -gt 0) {
                    throw (
                        'managed IPC mock rejected a stale writable service ' +
                        "SID: $($foreignSIDs -join ',')"
                    )
                }
                $script:HarnessState.ipc_service_sids = @($gatewaySID)
            }
            $script:HarnessState.events.Add('managed-ipc-directory')
        }
        function script:Revoke-DefenseClawManagedIPCServiceAccess {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [string]$GatewayServiceSID,
                [switch]$TransactionCreatedServicePresent
            )
            $null = $Layout
            $serviceExists = Test-DefenseClawServiceExists -Name $GatewayServiceName
            if ($TransactionCreatedServicePresent -and -not $serviceExists) {
                throw 'transaction IPC cleanup mock lost its live service'
            }
            if (-not $TransactionCreatedServicePresent -and $serviceExists) {
                throw 'managed IPC cleanup mock observed a live service'
            }
            $resolvedSID = Get-DefenseClawServiceSIDForRecovery `
                -ServiceName $GatewayServiceName
            if (-not [string]::IsNullOrWhiteSpace($GatewayServiceSID) -and
                $GatewayServiceSID -cne $resolvedSID) {
                throw 'managed IPC cleanup mock received a mismatched SID'
            }
            $removed = $false
            if ($script:HarnessState.ContainsKey('ipc_service_sids')) {
                $beforeCount = @(
                    $script:HarnessState.ipc_service_sids
                ).Count
                $script:HarnessState.ipc_service_sids = @(
                    $script:HarnessState.ipc_service_sids |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]$_ -cne $resolvedSID
                        }
                )
                $removed = (
                    @($script:HarnessState.ipc_service_sids).Count -lt
                    $beforeCount
                )
            }
            $script:HarnessState.events.Add(
                "managed-ipc-revoke:$resolvedSID"
            )
            return $removed
        }
        function script:Set-DefenseClawManagedAcls {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [switch]$SkipCodexMachineState
            )
        }
        function script:Invoke-DefenseClawEnumeratorRefresh {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName
            )
            $expectedManifestAcl = New-DefenseClawCanonicalPathAcl `
                -IsDirectory $false `
                -Kind AdminFile `
                -GatewayServiceSID $script:AdministratorsSID
            Assert-DefenseClawCanonicalPathAcl `
                -Path $Layout.ManifestPath `
                -Expected $expectedManifestAcl
            if ($script:HarnessState.ContainsKey(
                    'track_fresh_install_services'
                ) -and
                [bool]$script:HarnessState.track_fresh_install_services) {
                $enumeratorServiceName = [string](
                    $script:HarnessState.enumerator_service_name
                )
                if ([string]::IsNullOrWhiteSpace($enumeratorServiceName)) {
                    throw 'fresh Install did not record its Enumerator identity'
                }
                foreach ($serviceName in @(
                    $GatewayServiceName,
                    'DefenseClawCMIDBroker',
                    'DefenseClawHookGuardian',
                    $enumeratorServiceName
                )) {
                    if (-not [bool]$script:HarnessState.service_exists[
                            $serviceName
                        ] -or
                        $script:HarnessState.service_start_modes[
                            $serviceName
                        ] -ne 4) {
                        throw (
                            'fresh Install enumerated before every managed ' +
                            'service was created disabled'
                        )
                    }
                }
                if ([bool]$script:HarnessState.services_running -or
                    $script:HarnessState.events.IndexOf(
                        'install-service-sid-bound'
                    ) -lt 0) {
                    throw (
                        'fresh Install enumerated before its disabled gateway ' +
                        'service identity and SID binding existed'
                    )
                }
                $script:HarnessState.events.Add(
                    'enumerator-refresh-enter'
                )
                if ($script:HarnessState.ContainsKey(
                        'fail_fresh_install_enumeration'
                    ) -and
                    [bool]$script:HarnessState.fail_fresh_install_enumeration) {
                    throw 'injected fresh-install enumeration failure'
                }
            }
            $script:HarnessState.events.Add('enumerator-refresh')
        }
        function script:Invoke-DefenseClawCodexRequirementsCommand {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$Action
            )
            if ($script:HarnessState.ContainsKey(
                    'require_inactive_tombstone_adoption'
                ) -and
                [bool]$script:HarnessState.require_inactive_tombstone_adoption -and
                $Action -in @('inspect', 'reconcile')) {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.MetadataPath `
                    -PathType Leaf) {
                    throw 'protected deployment metadata marks this installation inactive'
                }
                $script:HarnessState.events.Add(
                    "codex-requirements:$Action`:metadata-absent"
                )
            }
            return [pscustomobject]@{
                ok = $true
                codex_target_enabled = $false
            }
        }
        function script:Write-DefenseClawAgentApplicationControlAttestation {
            param([Parameter(Mandatory)][hashtable]$Layout)
            [IO.File]::WriteAllText(
                $Layout.AgentApplicationControlAttestationPath,
                '{}',
                [Text.UTF8Encoding]::new($false)
            )
        }
        function script:Set-DefenseClawServiceEnvironment {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$RuntimeDirectory,
                [Parameter(Mandatory)][string]$ConfigPath,
                [Parameter(Mandatory)][string]$AuthorizationDirectory,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$LogPath,
                [string]$BrokerPipeName,
                [string]$BrokerServiceName,
                [string]$BrokerAuthKeyPath,
                [switch]$AgentApplicationControlAttested,
                [switch]$ClaudeEffectivePolicyVerified
            )
        }
        function script:Assert-DefenseClawInstalledConfig {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName
            )
        }
        function script:Wait-DefenseClawEnterpriseReadiness {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [int]$TimeoutSeconds = 90
            )
            $script:HarnessState.active_references = $true
        }
        function script:Wait-DefenseClawFreshGuardianReconcile {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [string]$ExpectedManifestSHA256,
                [int]$TimeoutSeconds = 90
            )
            if ($script:HarnessState.service_start_modes[
                    $GatewayServiceName
                ] -ne 4) {
                throw 'fresh guardian reconcile began after gateway became startable'
            }
            $legacyRecovery = [bool](
                $script:HarnessState.ContainsKey('operation') -and
                [string]$script:HarnessState.operation -ceq
                    'quiescing-recovery'
            )
            if ([string]::IsNullOrWhiteSpace($ExpectedManifestSHA256)) {
                if (-not $legacyRecovery) {
                    throw 'fresh guardian reconcile was not bound to the target-runtime manifest digest'
                }
                # Production deliberately supports transactions written by a
                # prior strict-v1 build before activation digests existed. It
                # still requires a fresh healthy generation and a newly
                # published protected Guardian state inode.
                $script:HarnessState.events.Add(
                    'guardian-legacy-fresh-state'
                )
            }
            elseif ($ExpectedManifestSHA256 -cnotmatch '^[0-9a-f]{64}$' -or
                -not $script:HarnessState.ContainsKey(
                    'target_runtime_manifest_sha256'
                ) -or
                $ExpectedManifestSHA256 -cne
                    [string]$script:HarnessState.target_runtime_manifest_sha256) {
                throw 'fresh guardian reconcile was not bound to the target-runtime manifest digest'
            }
            Start-DefenseClawService -Name $GuardianServiceName
            if ($script:HarnessState.ContainsKey('fail_fresh_guardian') -and
                [bool]$script:HarnessState.fail_fresh_guardian) {
                # Model a first activation that published only part of the
                # machine enrollment before its causal failure.
                $script:HarnessState.active_references = $true
                throw 'injected stale guardian generation'
            }
            $script:HarnessState.guardian_fresh = $true
            $script:HarnessState.events.Add('guardian-fresh-reconcile')
            return [DateTime]::UtcNow.ToString('o')
        }
        function script:Wait-DefenseClawServiceFailureRestartQuiescence {
            param(
                [Parameter(Mandatory)][string]$ServicesQuiescedAt,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            [void](ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
                -Value $ServicesQuiescedAt)
            $script:HarnessState.events.Add('failure-restart-barrier')
            if ($script:HarnessState.service_start_modes[
                    $GatewayServiceName
                ] -notin @(0, 4) -or
                $script:HarnessState.service_start_modes[
                    $GuardianServiceName
                ] -notin @(0, 4)) {
                throw 'failure-restart barrier observed a startable service'
            }
            # Model the latest delayed restart attempt at the barrier. It must
            # drain against disabled services.
            $script:HarnessState.queued_restart_blocked = $true
            $script:HarnessState.barrier_complete = $true
        }
        function script:Assert-DefenseClawEnterpriseDeployment {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [switch]$RequireReadiness,
                [switch]$PendingTransaction,
                [switch]$ServicingTransaction
            )
            if (-not [bool]$script:HarnessState.installed) {
                throw 'reinstall verification did not observe installed metadata'
            }
            $expectedMode = if ($ServicingTransaction) {
                4
            }
            elseif ($PendingTransaction) {
                3
            }
            else {
                2
            }
            foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
                if ($script:HarnessState.service_start_modes[$name] -ne
                    $expectedMode) {
                    throw "deployment verification saw service $name mode $($script:HarnessState.service_start_modes[$name]), expected $expectedMode"
                }
            }
        }
        function script:Install-DefenseClawSourceDescriptor {
            param(
                [Parameter(Mandatory)]$Source,
                [Parameter(Mandatory)][string]$Destination
            )
            $sourcePath = if ($Source -is [Collections.IDictionary] -and
                $Source.Contains('path')) {
                [string]$Source['path']
            }
            else {
                ''
            }
            $samePathManifest = [bool](
                -not [string]::IsNullOrWhiteSpace($sourcePath) -and
                [string]::Equals(
                    [IO.Path]::GetFullPath($sourcePath),
                    $Destination,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                [string]::Equals(
                    $Destination,
                    [string]$script:HarnessState.layout.ManifestPath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            )
            if ($samePathManifest) {
                # The real installer validates the in-place source digest but
                # publishes no replacement inode and must not heal its ACL.
                return
            }
            $parent = [IO.Path]::GetDirectoryName($Destination)
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parent)) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $parent `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            [IO.File]::WriteAllText(
                $Destination,
                [string]$Source,
                [Text.UTF8Encoding]::new($false)
            )
            if ([string]::Equals(
                $Destination,
                [string]$script:HarnessState.layout.HookPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                $script:HarnessState.binary_present = $true
            }
            if ([string]::Equals(
                $Destination,
                [string]$script:HarnessState.layout.ManifestPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                $script:HarnessState.events.Add('manifest-published')
            }
        }
        function script:Test-DefenseClawSourceDescriptorPublishesReplacement {
            param(
                [Parameter(Mandatory)]$Source,
                [Parameter(Mandatory)][string]$Destination
            )
            if ($Source -is [hashtable] -and $Source.ContainsKey('path')) {
                return [bool](
                    & $script:HarnessRealSourceReplacementDecision `
                        -Source $Source `
                        -Destination $Destination
                )
            }
            return $true
        }
        function script:Remove-DefenseClawManagedTree {
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$RequiredBase,
                [Parameter(Mandatory)][string]$Label
            )
            $script:HarnessState.events.Add("remove-tree:$Label")
            if ($Label -eq 'StateRoot') {
                $script:HarnessState.purged_state = $true
                if ([string]$script:HarnessState.crash_at -ceq
                    'purge-after-receipt-publication') {
                    throw 'injected crash after state-purge receipt publication'
                }
                if ([string]$script:HarnessState.crash_at -ceq
                    'purge-after-metadata-delete') {
                    if (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $script:HarnessState.layout.MetadataPath) {
                        Microsoft.PowerShell.Management\Remove-Item `
                            -LiteralPath $script:HarnessState.layout.MetadataPath `
                            -Force
                    }
                    throw 'injected crash after partial StateRoot deletion'
                }
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path) {
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $Path `
                        -Recurse `
                        -Force
                }
                if ([string]$script:HarnessState.crash_at -ceq
                    'purge-after-full-state-delete') {
                    throw 'injected crash after full StateRoot deletion'
                }
                return
            }
            if ([bool]$script:HarnessState.active_references) {
                throw 'binary tree removal observed a surviving machine hook reference'
            }
            $script:HarnessState.binary_present = $false
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path) {
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $Path `
                    -Recurse `
                    -Force
            }
            if ($script:HarnessState.crash_at -eq 'post-binary-delete') {
                throw 'injected crash after binary tree deletion'
            }
        }
        function script:Complete-DefenseClawTransaction {
            param(
                [Parameter(Mandatory)][string]$SnapshotPath,
                [Parameter(Mandatory)][hashtable]$Layout,
                [switch]$Rollback
            )
            $script:HarnessState.complete_calls++
            if (-not $Rollback -and
                $script:HarnessState.ContainsKey(
                    'track_fresh_install_services'
                ) -and
                [bool]$script:HarnessState.track_fresh_install_services) {
                # JSON round-trip the affected schema-v2 shape without
                # committed_at. The production commit-state helper must add
                # the property under StrictMode rather than assigning a
                # missing PSCustomObject member.
                $legacyCommitIntent = (
                    [ordered]@{
                        phase = 'preparing_layout'
                        gateway_service_sid = ''
                    } |
                        Microsoft.PowerShell.Utility\ConvertTo-Json `
                            -Compress |
                        Microsoft.PowerShell.Utility\ConvertFrom-Json
                )
                $committedIntent =
                    Set-DefenseClawInstallRollbackIntentCommitState `
                        -Intent $legacyCommitIntent `
                        -GatewayServiceSID 'S-1-5-80-1-2-3-4-5'
                $commitTimestamp = $committedIntent.PSObject.Properties[
                    'committed_at'
                ]
                if ([string]$committedIntent.phase -cne 'committed' -or
                    [string]$committedIntent.gateway_service_sid -cne
                        'S-1-5-80-1-2-3-4-5' -or
                    $null -eq $commitTimestamp -or
                    [string]::IsNullOrWhiteSpace(
                        [string]$commitTimestamp.Value
                    )) {
                    throw 'fresh install did not publish its committed receipt schema'
                }
                $parsedCommitTimestamp =
                    [DateTime]::ParseExact(
                        [string]$commitTimestamp.Value,
                        'o',
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind
                    )
                if ($parsedCommitTimestamp.Kind -eq
                    [DateTimeKind]::Unspecified) {
                    throw 'fresh install committed timestamp has no timezone'
                }
                $script:HarnessState.events.Add('install-receipt:committed')
            }
            if ($Rollback -and
                $script:HarnessState.ContainsKey(
                    'target_runtime_cleanup_required'
                ) -and
                [bool]$script:HarnessState.target_runtime_cleanup_required) {
                $rollbackSnapshot =
                    Get-HarnessTargetRuntimeRequest -Path $SnapshotPath
                $cleanupProperty = $rollbackSnapshot.PSObject.Properties[
                    'target_runtime_cleanup_report'
                ]
                if ($null -eq $cleanupProperty -or
                    -not [bool]$cleanupProperty.Value.ok -or
                    [bool]$script:HarnessState.target_runtime_root_live -or
                    'S-1-5-80-1-2-3-4-5' -in
                        @($script:HarnessState.ipc_service_sids) -or
                    [bool]$script:HarnessState.service_exists[
                        'DefenseClawGateway'
                    ] -or
                    -not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $Layout.PendingPath `
                        -PathType Leaf)) {
                    throw (
                        'rollback retired authenticated authority before ' +
                        'target-runtime and IPC cleanup completed'
                    )
                }
                $script:HarnessState.events.Add(
                    'target-runtime:rollback-authority-retired'
                )
            }
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.PendingPath) {
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $Layout.PendingPath `
                    -Force
            }
            $script:HarnessState.events.Add('complete')
        }
        function script:Get-DefenseClawLifecycleStatus {
            param(
                [Parameter(Mandatory)][string]$Action,
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            return [ordered]@{
                ok = $true
                installed = $false
            }
        }
        function script:Get-DefenseClawSelfUninstallCallerIdentity {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][int]$CallerPID
            )
            $script:HarnessState.events.Add('self-caller-authenticated')
            return [ordered]@{
                pid = [int64]$CallerPID
                creation_filetime = [int64]123456789
                image_path = $Layout.CLIPath
                file_identity = '12345678:1234567890abcdef'
                sha256 = ('a' * 64)
            }
        }
        function script:Set-DefenseClawInstallTreeRetirementAcls {
            param([Parameter(Mandatory)][hashtable]$Layout)
            if ([bool]$script:HarnessState.active_references) {
                throw 'retirement ACL strip preceded verified reference removal'
            }
            $script:HarnessState.events.Add('self-strip-users-rx')
        }
        function script:Publish-DefenseClawSelfUninstallReceipt {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [Parameter(Mandatory)]$CallerIdentity,
                [switch]$Purge
            )
            if ([bool]$script:HarnessState.active_references) {
                throw 'retirement receipt preceded verified reference removal'
            }
            $script:HarnessState.events.Add('self-receipt-prepared')
            return [pscustomobject]@{
                schema_version = 1
                phase = 'prepared_install_retirement'
                retired_install_root = (
                    $Layout.InstallRoot +
                    '.retired-0123456789abcdef0123456789abcdef'
                )
                purge_requested = [bool]$Purge
                helper_sha256 = ''
            }
        }
        function script:Set-DefenseClawRetiredInstallTreeAcls {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$RetiredRoot
            )
            $script:HarnessState.events.Add('self-retired-admin-only')
            $script:HarnessState.binary_present = $false
        }
        function script:Set-DefenseClawSelfUninstallReceiptCommitted {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $script:HarnessState.events.Add('self-receipt-committed')
            return [pscustomobject]@{
                schema_version = 1
                phase = 'committed_install_retirement'
                retired_install_root = (
                    $Layout.InstallRoot +
                    '.retired-0123456789abcdef0123456789abcdef'
                )
                purge_requested = [bool]$script:HarnessState.self_purge
                helper_sha256 = ('b' * 64)
            }
        }
        function script:Start-DefenseClawSelfUninstallHelper {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessState.events.Add('self-helper-started')
            return [int64]9876
        }

        $uninstallResults = [Collections.Generic.List[object]]::new()
        function Invoke-HarnessUninstallCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [string]$CrashAt,
                [Parameter(Mandatory)][bool]$ExpectSuccess,
                [bool]$PreexistingPrepared = $false,
                [bool]$ServicesRunning = $true,
                [bool]$InitialReferences = $true,
                [bool]$AlreadyUninstalled = $false,
                [bool]$Purge = $false,
                [bool]$SelfUninstall = $false
            )
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label ('uninstall-' + $Name)
            $layout = New-HarnessLayout -Root $root
            [IO.File]::WriteAllText(
                $layout.AgentApplicationControlAttestationPath,
                '{}',
                [Text.UTF8Encoding]::new($false)
            )
            if ($PreexistingPrepared) {
                Write-HarnessJournal `
                    -Path $layout.ManagedHooksTeardownJournalPath `
                    -Phase 'prepared'
            }
            if ($AlreadyUninstalled) {
                [IO.File]::WriteAllText(
                    $layout.MetadataPath,
                    '{"installed":false}',
                    [Text.UTF8Encoding]::new($false)
                )
                if (-not $PreexistingPrepared) {
                    Write-HarnessJournal `
                        -Path $layout.ManagedHooksTeardownJournalPath `
                        -Phase 'finalized'
                }
            }
            $events = [Collections.Generic.List[string]]::new()
            $script:HarnessState = @{
                crash_at = $CrashAt
                operation = 'uninstall'
                events = $events
                active_references = $InitialReferences
                binary_present = -not $AlreadyUninstalled
                installed = -not $AlreadyUninstalled
                guardian_running = $ServicesRunning
                gateway_running = $ServicesRunning
                services_running = $ServicesRunning
                services_were_running = $ServicesRunning
                reheal_observed = $false
                prepare_while_guardian_running = $false
                transaction_calls = 0
                prepare_calls = 0
                verify_calls = 0
                rollback_calls = 0
                rollback_verification_only = 0
                restore_calls = 0
                complete_calls = 0
                service_contract_checks = 0
                owned_checks = 0
                removed_services = 0
                purged_state = $false
                self_purge = [bool]$Purge
                install_saw_retired_journal = $false
                snapshot_path = ''
                service_start_modes = @{
                    DefenseClawGateway = 2
                    DefenseClawCMIDBroker = 2
                    DefenseClawHookGuardian = 2
                }
                service_exists = @{
                    DefenseClawGateway = -not $AlreadyUninstalled
                    DefenseClawCMIDBroker = -not $AlreadyUninstalled
                    DefenseClawHookGuardian = -not $AlreadyUninstalled
                }
                ipc_service_sids = @('S-1-5-80-1-2-3-4-5')
                guardian_fresh = $ServicesRunning
                queued_gateway_restart = $true
                queued_restart_blocked = $false
                gateway_started_before_guardian = $false
                barrier_required = $true
                barrier_complete = $false
            }
            $failed = $false
            $failureMessage = ''
            try {
                [void](Invoke-DefenseClawUninstallLifecycle `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName 'DefenseClawHookGuardian' `
                    -Purge:$Purge `
                    -SelfUninstallCallerPID $(if ($SelfUninstall) {
                        4242
                    } else {
                        0
                    }))
            }
            catch {
                $failed = $true
                $failureMessage = [string]$_.Exception.Message
                if ($ExpectSuccess) {
                    throw
                }
            }
            Assert-Harness `
                -Condition ($failed -ne $ExpectSuccess) `
                -Message "$Name success result did not match expectation"

            if ($ExpectSuccess) {
                Assert-Harness `
                    -Condition (
                        'S-1-5-80-1-2-3-4-5' -notin
                            @($script:HarnessState.ipc_service_sids)
                    ) `
                    -Message "$Name retained its gateway SID on the shared IPC path"
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.events.IndexOf(
                            'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                        ) -ge 0
                    ) `
                    -Message "$Name did not run managed IPC permission cleanup"
            }

            if ($AlreadyUninstalled) {
                Assert-Harness `
                    -Condition ($script:HarnessState.transaction_calls -eq 0) `
                    -Message "$Name opened a new transaction after durable uninstall"
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.ManagedHooksTeardownJournalPath)) `
                    -Message "$Name did not retire the stale committed journal"
                Assert-Harness `
                    -Condition (
                        [bool]$script:HarnessState.purged_state -eq $Purge
                    ) `
                    -Message "$Name did not preserve exact purge retry semantics"
            }
            elseif ($CrashAt -eq 'service-drift-preflight') {
                Assert-Harness `
                    -Condition ($script:HarnessState.transaction_calls -eq 0) `
                    -Message "$Name mutated lifecycle state after service drift"
                Assert-Harness `
                    -Condition ($script:HarnessState.prepare_calls -eq 0) `
                    -Message "$Name began hook teardown after service drift"
                Assert-Harness `
                    -Condition ([bool]$script:HarnessState.binary_present) `
                    -Message "$Name removed a binary after service drift"
            }
            elseif ($CrashAt -ceq 'post-binary-delete') {
                Assert-Harness `
                    -Condition (
                        -not [bool]$script:HarnessState.binary_present -and
                        -not [bool]$script:HarnessState.installed
                    ) `
                    -Message "$Name restored a committed, retired installation"
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.rollback_calls -eq 0 -and
                        $script:HarnessState.complete_calls -eq 1
                    ) `
                    -Message "$Name crossed the commit boundary with rollback semantics"
                Assert-Harness `
                    -Condition (
                        $failureMessage -like
                            '*retry Uninstall to finish cleanup*'
                    ) `
                    -Message "$Name did not report retryable committed cleanup: $failureMessage"
            }
            elseif ($ExpectSuccess) {
                Assert-Harness `
                    -Condition (
                        -not [bool]$script:HarnessState.reheal_observed -and
                        -not [bool]$script:HarnessState.prepare_while_guardian_running
                    ) `
                    -Message "$Name exposed prepare/verify to a live guardian writer"
                Assert-Harness `
                    -Condition (
                        -not [bool]$script:HarnessState.active_references -and
                        -not [bool]$script:HarnessState.binary_present
                    ) `
                    -Message "$Name did not remove references before the binary"
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.service_contract_checks -eq 2
                    ) `
                    -Message "$Name did not verify the full service contract twice"
                # The full uninstall path removes enumerator, guardian,
                # gateway, and credential broker. Each mocked removal is
                # preceded by its corresponding ownership recheck.
                Assert-Harness `
                    -Condition ($script:HarnessState.removed_services -eq 4) `
                    -Message "$Name did not delete all four exactly rechecked services"
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.events.IndexOf(
                            'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                        ) -gt
                        $script:HarnessState.events.IndexOf(
                            'remove-service:DefenseClawGateway'
                        )
                    ) `
                    -Message "$Name revoked IPC access before gateway deletion"
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.ManagedHooksTeardownJournalPath)) `
                    -Message "$Name left a prepared journal after committed uninstall"
            }
            else {
                Assert-Harness `
                    -Condition ([bool]$script:HarnessState.binary_present) `
                    -Message "$Name did not restore the binary after failure"
                Assert-Harness `
                    -Condition ([bool]$script:HarnessState.active_references) `
                    -Message "$Name did not restore every machine hook reference"
                Assert-Harness `
                    -Condition ($script:HarnessState.rollback_calls -eq 1) `
                    -Message "$Name did not execute exactly one rollback"
                Assert-Harness `
                    -Condition (
                        [bool]$script:HarnessState.services_running -eq
                            $ServicesRunning
                    ) `
                    -Message "$Name did not restore prior service running state"
                if ($CrashAt -eq 'service-drift-predelete') {
                    Assert-Harness `
                        -Condition ($script:HarnessState.removed_services -eq 0) `
                        -Message "$Name deleted a service after deletion-boundary drift"
                }
                if ($CrashAt -eq 'failed-teardown-self-restored') {
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.rollback_verification_only -eq 1
                        ) `
                        -Message "$Name repeated an already-completed hook rollback"
                    Assert-Harness `
                        -Condition (
                            $failureMessage -like
                                '*disconnected target teardown incomplete*' -and
                            $failureMessage -notmatch
                                '(?i)rollback also failed|Replace|path exception'
                        ) `
                        -Message "$Name replaced the original teardown diagnostic: $failureMessage"
                }
            }
            $transactionIndex = $script:HarnessState.events.IndexOf(
                'transaction'
            )
            $prepareIndex = $script:HarnessState.events.IndexOf(
                'teardown:prepare'
            )
            if ($script:HarnessState.transaction_calls -gt 0) {
                Assert-Harness `
                    -Condition (
                        $transactionIndex -ge 0 -and
                        $prepareIndex -gt $transactionIndex
                    ) `
                    -Message "$Name did not quiesce transactionally before prepare"
            }
            if ($SelfUninstall -and $ExpectSuccess) {
                $verifyIndex = $script:HarnessState.events.IndexOf(
                    'teardown:verify'
                )
                $stripIndex = $script:HarnessState.events.IndexOf(
                    'self-strip-users-rx'
                )
                $prepareReceiptIndex = $script:HarnessState.events.IndexOf(
                    'self-receipt-prepared'
                )
                $retiredIndex = $script:HarnessState.events.IndexOf(
                    'self-retired-admin-only'
                )
                $completeIndex = $script:HarnessState.events.IndexOf(
                    'complete'
                )
                $finalizeIndex = $script:HarnessState.events.IndexOf(
                    'teardown:finalize'
                )
                $commitReceiptIndex = $script:HarnessState.events.IndexOf(
                    'self-receipt-committed'
                )
                $helperIndex = $script:HarnessState.events.IndexOf(
                    'self-helper-started'
                )
                Assert-Harness `
                    -Condition (
                        $verifyIndex -ge 0 -and
                        $stripIndex -gt $verifyIndex -and
                        $prepareReceiptIndex -gt $stripIndex -and
                        $completeIndex -gt $prepareReceiptIndex -and
                        $finalizeIndex -gt $completeIndex -and
                        $retiredIndex -gt $finalizeIndex -and
                        $commitReceiptIndex -gt $retiredIndex -and
                        $helperIndex -gt $commitReceiptIndex
                    ) `
                    -Message "$Name violated reference-clean retirement/commit/helper ordering"
            }
            $uninstallResults.Add([pscustomobject]@{
                name = $Name
                failed = $failed
                rollback = $script:HarnessState.rollback_calls
                service_contract_checks = (
                    $script:HarnessState.service_contract_checks
                )
                no_surviving_reference_before_delete = (
                    -not [bool]$script:HarnessState.reheal_observed
                )
                failure = $failureMessage
            })
        }

        function Write-HarnessTargetRuntimeExchange {
            param(
                [Parameter(Mandatory)]$Value,
                [Parameter(Mandatory)][string]$Path
            )
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Path `
                    -PathType Leaf)) {
                throw 'target-runtime mock received an unpublished exchange file'
            }
            # The general lifecycle harness replaces Set-DefenseClawPathAcl
            # with an event-only mock. Authenticate and harden the pre-created
            # exchange before the synthetic CLI truncates it, matching the real
            # helper; the unchanged production reader then proves that the
            # write preserved the protected AdminFile contract.
            & $script:HarnessRealSetPathAcl `
                -Path $Path `
                -Kind AdminFile `
                -GatewayServiceSID $script:AdministratorsSID
            [IO.File]::WriteAllText(
                $Path,
                ($Value |
                    Microsoft.PowerShell.Utility\ConvertTo-Json `
                        -Depth 12 `
                        -Compress),
                [Text.UTF8Encoding]::new($false)
            )
        }

        function Get-HarnessTargetRuntimeRequest {
            param([Parameter(Mandatory)][string]$Path)
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Path `
                    -PathType Leaf)) {
                throw 'target-runtime mock request is missing'
            }
            return Microsoft.PowerShell.Management\Get-Content `
                -LiteralPath $Path `
                -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        }

        function New-HarnessTargetRuntimeReport {
            param(
                [Parameter(Mandatory)]$Plan,
                [Parameter(Mandatory)]
                [ValidateSet('stage', 'finalize', 'cleanup')]
                [string]$Action
            )
            $claims = [Collections.Generic.List[object]]::new()
            foreach ($root in @($Plan.roots)) {
                $absentBaseline = [string]$root.baseline -ceq 'absent'
                $state = switch ($Action) {
                    'stage' {
                        if ($absentBaseline) { 'staged' } else { 'canonical' }
                    }
                    'finalize' { 'canonical' }
                    'cleanup' {
                        if ($absentBaseline) { 'absent' } else { 'canonical' }
                    }
                }
                $claim = [ordered]@{
                    user_home = [string]$root.user_home
                    data_dir = [string]$root.data_dir
                    sid = [string]$root.sid
                    created = [bool]($absentBaseline -and
                        $Action -cne 'cleanup')
                    state = $state
                }
                if ($state -cne 'absent') {
                    $claim['identity'] = if ($absentBaseline) {
                        '00000001:0000000000000001'
                    }
                    else {
                        [string]$root.baseline_identity
                    }
                }
                $claims.Add([pscustomobject]$claim)
            }
            return [ordered]@{
                schema_version = 1
                action = $Action
                ok = $true
                claims = @($claims)
            }
        }

        function Invoke-HarnessTargetRuntimeGatewayCommand {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string[]]$Arguments,
                [switch]$Capture,
                [switch]$AllowFailure
            )
            $isTargetRuntime = [bool](
                $Arguments.Count -ge 4 -and
                [string]$Arguments[0] -ceq 'enterprise' -and
                [string]$Arguments[1] -ceq 'windows' -and
                [string]$Arguments[2] -ceq 'target-runtime'
            )
            if (-not $isTargetRuntime) {
                return & $script:HarnessRealGatewayCommand @PSBoundParameters
            }
            if (-not $Capture -or -not $AllowFailure -or
                $GatewayServiceName -cne 'DefenseClawGateway') {
                throw 'target-runtime mock received an unexpected invocation contract'
            }
            $action = [string]$Arguments[3]
            $plan = $null
            $outputPath = ''
            switch ($action) {
                'plan' {
                    if ($Arguments.Count -ne 8 -or
                        [string]$Arguments[4] -cne '--manifest' -or
                        [string]$Arguments[6] -cne '--output') {
                        throw 'target-runtime plan mock received unexpected arguments'
                    }
                    $manifestPath = [IO.Path]::GetFullPath(
                        [string]$Arguments[5]
                    )
                    if (-not [string]::Equals(
                            $manifestPath,
                            [IO.Path]::GetFullPath(
                                [string]$Layout.ManifestPath
                            ),
                            [StringComparison]::OrdinalIgnoreCase
                        )) {
                        throw 'target-runtime plan mock received the wrong manifest'
                    }
                    $script:HarnessState.events.Add(
                        'target-runtime:plan-enter'
                    )
                    if ($script:HarnessState.events.IndexOf(
                            'enumerator-refresh'
                        ) -lt 0) {
                        throw 'target-runtime planning preceded synchronous enumeration'
                    }
                    $manifestWasReplaced = [bool](
                        $script:HarnessState.events.IndexOf(
                            'manifest-published'
                        ) -ge 0
                    )
                    if ($manifestWasReplaced) {
                        if (-not [bool]$script:HarnessState.manifest_admin_acl) {
                            throw 'target-runtime plan preceded the replacement manifest ACL'
                        }
                    }
                    # Validation-only Repair/Upgrade must check the same exact
                    # contract without using publication as an ACL-healing
                    # opportunity. This also proves no-source and same-path
                    # drift fail closed in both PowerShell engines.
                    $expectedManifestAcl =
                        New-DefenseClawCanonicalPathAcl `
                            -IsDirectory $false `
                            -Kind AdminFile `
                            -GatewayServiceSID $script:AdministratorsSID
                    Assert-DefenseClawCanonicalPathAcl `
                        -Path $manifestPath `
                        -Expected $expectedManifestAcl
                    $baseline = if ([bool]$script:HarnessState.installed) {
                        'canonical'
                    }
                    else {
                        'absent'
                    }
                    $root = [ordered]@{
                        user_home = 'C:\Users\Alice'
                        data_dir = 'C:\Users\Alice\.defenseclaw'
                        sid = 'S-1-5-21-111-222-333-1001'
                        baseline = $baseline
                        staging_leaf = (
                            '.defenseclaw.setup-' + ('1' * 32)
                        )
                        marker_sid = 'S-1-5-21-1-2-3-4-5-6-7-8'
                    }
                    if ($baseline -ceq 'canonical') {
                        $root['baseline_identity'] =
                            '00000001:0000000000000001'
                    }
                    $plan = [ordered]@{
                        schema_version = 1
                        manifest_path = $manifestPath
                        manifest_sha256 = (
                            Get-HarnessSHA256 `
                                -Bytes ([IO.File]::ReadAllBytes($manifestPath))
                        )
                        roots = @([pscustomobject]$root)
                    }
                    $script:HarnessState.target_runtime_manifest_sha256 =
                        [string]$plan.manifest_sha256
                    $outputPath = [string]$Arguments[7]
                    $script:HarnessState.events.Add('target-runtime:plan')
                    Write-HarnessTargetRuntimeExchange `
                        -Value $plan `
                        -Path $outputPath
                }
                'stage' {
                    if ($Arguments.Count -ne 8 -or
                        [string]$Arguments[4] -cne '--request' -or
                        [string]$Arguments[6] -cne '--output') {
                        throw 'target-runtime stage mock received unexpected arguments'
                    }
                    $requestPath = [string]$Arguments[5]
                    $plan = Get-HarnessTargetRuntimeRequest `
                        -Path $requestPath
                    $snapshot = Get-HarnessTargetRuntimeRequest `
                        -Path ([string]$script:HarnessState.snapshot_path)
                    if ($null -eq $snapshot.PSObject.Properties[
                            'target_runtime_plan'
                        ] -or
                        [string]$snapshot.target_runtime_plan_path -cne
                            $requestPath -or
                        -not (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $Layout.PendingPath `
                            -PathType Leaf)) {
                        throw 'target-runtime mutation preceded durable plan authority'
                    }
                    $script:HarnessState.events.Add(
                        'target-runtime:plan-authority-persisted'
                    )
                    $script:HarnessState.events.Add('target-runtime:stage')
                    $script:HarnessState.target_runtime_cleanup_required =
                        [bool](@($plan.roots |
                            Microsoft.PowerShell.Core\Where-Object {
                                [string]$_.baseline -ceq 'absent'
                            }).Count -gt 0)
                    $script:HarnessState.target_runtime_root_live =
                        [bool]$script:HarnessState.target_runtime_cleanup_required
                    $outputPath = [string]$Arguments[7]
                    Write-HarnessTargetRuntimeExchange `
                        -Value (New-HarnessTargetRuntimeReport `
                            -Plan $plan `
                            -Action stage) `
                        -Path $outputPath
                }
                'finalize' {
                    if ($Arguments.Count -ne 10 -or
                        [string]$Arguments[4] -cne '--request' -or
                        [string]$Arguments[6] -cne '--claims' -or
                        [string]$Arguments[8] -cne '--output') {
                        throw 'target-runtime finalize mock received unexpected arguments'
                    }
                    $plan = Get-HarnessTargetRuntimeRequest `
                        -Path ([string]$Arguments[5])
                    $snapshot = Get-HarnessTargetRuntimeRequest `
                        -Path ([string]$script:HarnessState.snapshot_path)
                    if ($null -eq $snapshot.PSObject.Properties[
                            'target_runtime_stage_report'
                        ] -or
                        [string]$snapshot.target_runtime_stage_report_path -cne
                            [string]$Arguments[7]) {
                        throw 'target-runtime finalize preceded durable stage authority'
                    }
                    $script:HarnessState.events.Add(
                        'target-runtime:stage-authority-persisted'
                    )
                    $script:HarnessState.events.Add('target-runtime:finalize')
                    $outputPath = [string]$Arguments[9]
                    Write-HarnessTargetRuntimeExchange `
                        -Value (New-HarnessTargetRuntimeReport `
                            -Plan $plan `
                            -Action finalize) `
                        -Path $outputPath
                }
                'cleanup' {
                    $hasClaims = $Arguments.Count -eq 10
                    if (($Arguments.Count -notin @(8, 10)) -or
                        [string]$Arguments[4] -cne '--request' -or
                        ($hasClaims -and
                            [string]$Arguments[6] -cne '--claims') -or
                        [string]$Arguments[$Arguments.Count - 2] -cne
                            '--output') {
                        throw 'target-runtime cleanup mock received unexpected arguments'
                    }
                    $requestPath = [string]$Arguments[5]
                    $plan = Get-HarnessTargetRuntimeRequest `
                        -Path $requestPath
                    $snapshot = Get-HarnessTargetRuntimeRequest `
                        -Path ([string]$script:HarnessState.snapshot_path)
                    if ($null -eq $snapshot.PSObject.Properties[
                            'target_runtime_plan'
                        ] -or
                        [string]$snapshot.target_runtime_plan_path -cne
                            $requestPath -or
                        -not (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $Layout.PendingPath `
                            -PathType Leaf) -or
                        ([bool]$script:HarnessState.target_runtime_cleanup_required -and
                            -not [bool]$script:HarnessState.target_runtime_root_live)) {
                        throw 'target-runtime cleanup lost its authenticated authority'
                    }
                    if ($hasClaims) {
                        $claimsPath = [string]$Arguments[7]
                        if ($claimsPath -cne
                                [string]$snapshot.target_runtime_final_report_path -and
                            $claimsPath -cne
                                [string]$snapshot.target_runtime_stage_report_path) {
                            throw 'target-runtime cleanup received unjournaled claims'
                        }
                    }
                    $script:HarnessState.events.Add('target-runtime:cleanup')
                    $outputPath = [string]$Arguments[$Arguments.Count - 1]
                    Write-HarnessTargetRuntimeExchange `
                        -Value (New-HarnessTargetRuntimeReport `
                            -Plan $plan `
                            -Action cleanup) `
                        -Path $outputPath
                    $script:HarnessState.target_runtime_root_live = $false
                }
                default {
                    throw "target-runtime mock rejected action: $action"
                }
            }
            return [ordered]@{
                exit_code = 0
                output = @()
            }
        }

        function Assert-HarnessTargetRuntimeCleanupScopeExclusive {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $null = $GatewayServiceName
            $null = $GuardianServiceName
            if ([bool]$script:HarnessState.gateway_running -or
                [bool]$script:HarnessState.guardian_running -or
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.PendingPath `
                    -PathType Leaf)) {
                throw 'target-runtime cleanup scope was not quiesced and journaled'
            }
            $script:HarnessState.events.Add(
                'target-runtime:exclusive-cleanup'
            )
        }

        function Invoke-HarnessFreshInstallServiceBootstrapSequence {
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label 'fresh-install-service-bootstrap'
            $layout = New-HarnessLayout -Root $root
            $manifest = @'
version: 1
targets:
  - connector: claudecode
    sid: S-1-5-21-111-222-333-1001
    user_home: C:\Users\Alice
    data_dir: C:\Users\Alice\.defenseclaw
    agent_version: 2.9.999
    enabled: true
'@
            $sources = @{
                broker = 'fresh-broker'
                gateway = 'fresh-gateway'
                hook = 'fresh-hook'
                installer = 'fresh-installer'
                module = 'fresh-module'
                config = 'listen_addr: 127.0.0.1:18970'
                manifest = $manifest
                provider_library = [pscustomobject]@{
                    path = $layout.ProviderLibraryPath
                }
            }
            $script:HarnessState = @{
                operation = 'install'
                crash_at = ''
                events = [Collections.Generic.List[string]]::new()
                layout = $layout
                active_references = $false
                lifecycle_preimage_active = $false
                binary_present = $false
                installed = $false
                guardian_running = $false
                gateway_running = $false
                services_running = $false
                services_were_running = $false
                reheal_observed = $false
                prepare_while_guardian_running = $false
                transaction_calls = 0
                prepare_calls = 0
                verify_calls = 0
                rollback_calls = 0
                restore_calls = 0
                complete_calls = 0
                service_contract_checks = 0
                owned_checks = 0
                removed_services = 0
                purged_state = $false
                install_saw_retired_journal = $false
                snapshot_path = ''
                track_fresh_install_services = $true
                fresh_services_existed = $false
                fail_fresh_install_enumeration = $true
                fail_fresh_install_capture = $false
                service_start_modes = @{
                    DefenseClawGateway = 0
                    DefenseClawCMIDBroker = 0
                    DefenseClawHookGuardian = 0
                    DefenseClawHookEnumerator = 0
                }
                service_exists = @{
                    DefenseClawGateway = $false
                    DefenseClawCMIDBroker = $false
                    DefenseClawHookGuardian = $false
                    DefenseClawHookEnumerator = $false
                }
                ipc_service_sids = @()
                guardian_fresh = $false
                queued_gateway_restart = $false
                queued_restart_blocked = $true
                gateway_started_before_guardian = $false
                barrier_required = $true
                barrier_complete = $false
                manifest_admin_acl = $false
            }

            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $script:HarnessState.events.Clear()
                $script:HarnessState.manifest_admin_acl = $false
                $failure = ''
                try {
                    [void](Invoke-DefenseClawInstallLikeLifecycle `
                        -Action 'Install' `
                        -Layout $layout `
                        -Sources $sources `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -GuardianServiceName 'DefenseClawHookGuardian' `
                        -NoStart)
                }
                catch {
                    $failure = [string]$_.Exception.Message
                }

                $transaction = $script:HarnessState.events.IndexOf(
                    'transaction'
                )
                $manifestPublished = $script:HarnessState.events.IndexOf(
                    'manifest-published'
                )
                $manifestAcl = $script:HarnessState.events.IndexOf(
                    'manifest-admin-acl'
                )
                $enumeratorRefresh = $script:HarnessState.events.IndexOf(
                    'enumerator-refresh'
                )
                $enumeratorRefreshEnter =
                    $script:HarnessState.events.IndexOf(
                        'enumerator-refresh-enter'
                    )
                $targetPlan = $script:HarnessState.events.IndexOf(
                    'target-runtime:plan'
                )
                $targetPlanAuthority = $script:HarnessState.events.IndexOf(
                    'target-runtime:plan-authority-persisted'
                )
                $targetStage = $script:HarnessState.events.IndexOf(
                    'target-runtime:stage'
                )
                $targetFinalize = $script:HarnessState.events.IndexOf(
                    'target-runtime:finalize'
                )
                $services = $script:HarnessState.events.IndexOf(
                    'managed-services'
                )
                $managedServicesCount = @(
                    $script:HarnessState.events |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]$_ -ceq 'managed-services'
                        }
                ).Count
                $serviceSIDBound = $script:HarnessState.events.IndexOf(
                    'install-service-sid-bound'
                )
                $managedIPC = $script:HarnessState.events.IndexOf(
                    'managed-ipc-directory'
                )
                $retainedRuntimeAcls = $script:HarnessState.events.IndexOf(
                    'retained-runtime-acls'
                )
                $coreAcls = $script:HarnessState.events.IndexOf(
                    'managed-core-acls'
                )
                $capture = $script:HarnessState.events.IndexOf(
                    'lifecycle-snapshot:capture'
                )
                $preservedStateAcls = $script:HarnessState.events.IndexOf(
                    'preserved-state-acls:S-1-5-80-1-2-3-4-5'
                )
                $preservedStateAclCount = @(
                    $script:HarnessState.events |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]$_ -ceq
                                'preserved-state-acls:S-1-5-80-1-2-3-4-5'
                        }
                ).Count
                $eventTrace = [string]::Join(
                    ', ',
                    @($script:HarnessState.events)
                )
                $preEnumerationOrder = [bool](
                    $transaction -ge 0 -and
                    $manifestPublished -gt $transaction -and
                    $manifestAcl -gt $manifestPublished -and
                    $services -gt $manifestAcl -and
                    $managedServicesCount -eq 1 -and
                    $serviceSIDBound -gt $services -and
                    $managedIPC -gt $serviceSIDBound -and
                    $retainedRuntimeAcls -gt $managedIPC -and
                    $coreAcls -gt $retainedRuntimeAcls -and
                    $enumeratorRefreshEnter -gt $coreAcls
                )
                $postEnumerationOrder = [bool](
                    $enumeratorRefresh -gt $enumeratorRefreshEnter -and
                    $targetPlan -gt $enumeratorRefresh -and
                    $targetPlanAuthority -gt $targetPlan -and
                    $targetStage -gt $targetPlanAuthority -and
                    $targetFinalize -gt $targetStage -and
                    $capture -gt $targetFinalize
                )
                Assert-Harness `
                    -Condition (
                        $preEnumerationOrder -and
                        ($attempt -eq 1 -or $postEnumerationOrder)
                    ) `
                    -Message (
                        "fresh install attempt $attempt violated " +
                        'transaction/target/service/IPC/ACL/snapshot ordering ' +
                        "(transaction=$transaction services=$services " +
                        "manifest_published=$manifestPublished " +
                        "manifest_acl=$manifestAcl " +
                        "enumerator_refresh_enter=$enumeratorRefreshEnter " +
                        "enumerator_refresh=$enumeratorRefresh " +
                        "target_plan=$targetPlan " +
                        "target_authority=$targetPlanAuthority " +
                        "target_stage=$targetStage " +
                        "target_finalize=$targetFinalize " +
                        "service_sid_bound=$serviceSIDBound " +
                        "managed_ipc=$managedIPC core_acls=$coreAcls " +
                        "retained_runtime_acls=$retainedRuntimeAcls " +
                        "managed_services_count=$managedServicesCount " +
                        "capture=$capture; " +
                        "failure=$failure; events=[$eventTrace])"
                    )

                if ($attempt -eq 1) {
                    Assert-Harness `
                        -Condition (
                            $failure -match
                                'injected fresh-install enumeration failure' -and
                            $enumeratorRefresh -lt 0 -and
                            $targetPlan -lt 0 -and
                            $capture -lt 0
                        ) `
                        -Message (
                            'fresh install enumeration fault crossed the ' +
                            "target-runtime boundary: $failure"
                        )
                    $ipcRevoke = $script:HarnessState.events.IndexOf(
                        'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                    )
                    $gatewayDelete = $script:HarnessState.events.IndexOf(
                        'remove-service:DefenseClawGateway'
                    )
                    $finalServiceDelete = $script:HarnessState.events.IndexOf(
                        'remove-service:DefenseClawHookEnumerator'
                    )
                    $transactionComplete = $script:HarnessState.events.IndexOf(
                        'complete'
                    )
                    Assert-Harness `
                        -Condition (
                            $ipcRevoke -gt $enumeratorRefreshEnter -and
                            $gatewayDelete -gt $ipcRevoke -and
                            $finalServiceDelete -gt $gatewayDelete -and
                            $preservedStateAclCount -eq 1 -and
                            $preservedStateAcls -gt $finalServiceDelete -and
                            $transactionComplete -gt $preservedStateAcls
                        ) `
                        -Message (
                            'fresh enumeration rollback did not revoke IPC ' +
                            'and restore retained-state ACLs before ' +
                            'authority retirement'
                        )
                    foreach ($serviceName in @(
                        'DefenseClawGateway',
                        'DefenseClawCMIDBroker',
                        'DefenseClawHookGuardian',
                        'DefenseClawHookEnumerator'
                    )) {
                        Assert-Harness `
                            -Condition (
                                -not [bool]$script:HarnessState.service_exists[
                                    $serviceName
                                ] -and
                                $script:HarnessState.service_start_modes[
                                    $serviceName
                                ] -eq 0
                            ) `
                            -Message (
                                'fresh enumeration rollback retained ' +
                                "transaction-created service $serviceName"
                            )
                    }
                    $script:HarnessState.fail_fresh_install_enumeration =
                        $false
                    $script:HarnessState.fail_fresh_install_capture = $true
                }
                elseif ($attempt -eq 2) {
                    Assert-Harness `
                        -Condition ($failure -match 'injected fresh-install snapshot failure') `
                        -Message "fresh install fault lost its causal failure: $failure"
                    $exclusiveCleanup = $script:HarnessState.events.IndexOf(
                        'target-runtime:exclusive-cleanup'
                    )
                    $targetCleanup = $script:HarnessState.events.IndexOf(
                        'target-runtime:cleanup'
                    )
                    $cleanupAuthority = $script:HarnessState.events.IndexOf(
                        'target-runtime:cleanup-authority-persisted'
                    )
                    $ipcRevoke = $script:HarnessState.events.IndexOf(
                        'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                    )
                    $gatewayDelete = $script:HarnessState.events.IndexOf(
                        'remove-service:DefenseClawGateway'
                    )
                    $finalServiceDelete = $script:HarnessState.events.IndexOf(
                        'remove-service:DefenseClawHookEnumerator'
                    )
                    $authorityRetired = $script:HarnessState.events.IndexOf(
                        'target-runtime:rollback-authority-retired'
                    )
                    $transactionComplete = $script:HarnessState.events.IndexOf(
                        'complete'
                    )
                    Assert-Harness `
                        -Condition (
                            $exclusiveCleanup -gt $capture -and
                            $targetCleanup -gt $exclusiveCleanup -and
                            $cleanupAuthority -gt $targetCleanup -and
                            $ipcRevoke -gt $cleanupAuthority -and
                            $gatewayDelete -gt $ipcRevoke -and
                            $finalServiceDelete -gt $gatewayDelete -and
                            $preservedStateAclCount -eq 1 -and
                            $preservedStateAcls -gt $finalServiceDelete -and
                            $authorityRetired -gt $preservedStateAcls -and
                            $transactionComplete -gt $authorityRetired
                        ) `
                        -Message (
                            'fresh install rollback retired authenticated ' +
                            'authority before exact target/IPC cleanup'
                        )
                    Assert-Harness `
                        -Condition (
                            -not [bool]$script:HarnessState.service_exists[
                                'DefenseClawGateway'
                            ] -and
                            -not [bool]$script:HarnessState.service_exists[
                                'DefenseClawCMIDBroker'
                            ] -and
                            -not [bool]$script:HarnessState.service_exists[
                                'DefenseClawHookGuardian'
                            ] -and
                            -not [bool]$script:HarnessState.service_exists[
                                'DefenseClawHookEnumerator'
                            ] -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawGateway'
                            ] -eq 0 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawCMIDBroker'
                            ] -eq 0 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawHookGuardian'
                            ] -eq 0 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawHookEnumerator'
                            ] -eq 0
                        ) `
                        -Message 'fresh install rollback retained a transaction-created service'
                    Assert-Harness `
                        -Condition (
                            'S-1-5-80-1-2-3-4-5' -notin
                                @($script:HarnessState.ipc_service_sids) -and
                            $script:HarnessState.events.IndexOf(
                                'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                            ) -ge 0 -and
                            $script:HarnessState.events.IndexOf(
                                'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                            ) -lt $script:HarnessState.events.IndexOf(
                                'remove-service:DefenseClawGateway'
                            )
                        ) `
                        -Message 'fresh install rollback retained its shared IPC gateway grant'
                    Assert-Harness `
                        -Condition (
                            -not (Microsoft.PowerShell.Management\Test-Path `
                                -LiteralPath $layout.PendingPath) -and
                            -not (Microsoft.PowerShell.Management\Test-Path `
                                -LiteralPath $layout.ManagedHooksLifecycleJournalPath)
                        ) `
                        -Message 'fresh install rollback retained protected transaction state'
                    $script:HarnessState.fail_fresh_install_capture = $false
                }
                else {
                    Assert-Harness `
                        -Condition (
                            [string]::IsNullOrWhiteSpace($failure) -and
                            $preservedStateAcls -lt 0 -and
                            $preservedStateAclCount -eq 0
                        ) `
                        -Message "fresh install retry failed: $failure"
                    $receiptCommit = $script:HarnessState.events.IndexOf(
                        'install-receipt:committed'
                    )
                    $completeEvent = $script:HarnessState.events.IndexOf(
                        'complete'
                    )
                    Assert-Harness `
                        -Condition (
                            $receiptCommit -gt $capture -and
                            $completeEvent -gt $receiptCommit
                        ) `
                        -Message 'fresh install did not commit and retire its receipt after activation'
                    Assert-Harness `
                        -Condition (
                            [bool]$script:HarnessState.installed -and
                            [bool]$script:HarnessState.service_exists[
                                'DefenseClawGateway'
                            ] -and
                            [bool]$script:HarnessState.service_exists[
                                'DefenseClawCMIDBroker'
                            ] -and
                            [bool]$script:HarnessState.service_exists[
                                'DefenseClawHookGuardian'
                            ] -and
                            [bool]$script:HarnessState.service_exists[
                                'DefenseClawHookEnumerator'
                            ] -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawGateway'
                            ] -eq 4 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawCMIDBroker'
                            ] -eq 4 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawHookGuardian'
                            ] -eq 4 -and
                            $script:HarnessState.service_start_modes[
                                'DefenseClawHookEnumerator'
                            ] -eq 4
                        ) `
                        -Message 'fresh Install -NoStart retry did not leave the broker-backed service set disabled'
                }
            }
            # Rollback removes all four transaction-created services:
            # broker, gateway, guardian, and enumerator.
            Assert-Harness `
                -Condition (
                    $script:HarnessState.transaction_calls -eq 3 -and
                    $script:HarnessState.restore_calls -eq 2 -and
                    $script:HarnessState.removed_services -eq 8
                ) `
                -Message 'fresh install fault/retry did not use exact transactional rollback'
            $uninstallResults.Add([pscustomobject]@{
                name = 'fresh-install-service-bootstrap-rollback-retry'
                failed = $false
                rollback = $script:HarnessState.restore_calls
                service_contract_checks = 0
                no_surviving_reference_before_delete = $true
            })
        }

        function Invoke-HarnessDirectReinstallSequence {
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label 'direct-reinstall-after-committed-crash'
            $layout = New-HarnessLayout -Root $root
            [IO.File]::WriteAllText(
                $layout.MetadataPath,
                '{"schema_version":1,"installed":false}',
                [Text.UTF8Encoding]::new($false)
            )
            $oldJournal = [ordered]@{
                schema_version = 4
                phase = 'finalized'
                manifest_fingerprint = ('a' * 64)
                gateway_service_name = 'DEFENSECLAWGATEWAY'
                targets = @(
                    [ordered]@{
                        connector = 'claudecode'
                        sid = 'S-1-5-21-111-222-333-1001'
                        data_dir = 'C:\Users\Alice\.defenseclaw'
                        agent_version = '2.1.152'
                    }
                )
            }
            [IO.File]::WriteAllText(
                $layout.ManagedHooksTeardownJournalPath,
                (
                    $oldJournal |
                        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8
                ),
                [Text.UTF8Encoding]::new($false)
            )
            $events = [Collections.Generic.List[string]]::new()
            $script:HarnessState = @{
                operation = 'install'
                crash_at = ''
                events = $events
                layout = $layout
                active_references = $false
                binary_present = $false
                installed = $false
                guardian_running = $false
                gateway_running = $false
                services_running = $false
                services_were_running = $false
                reheal_observed = $false
                prepare_while_guardian_running = $false
                transaction_calls = 0
                prepare_calls = 0
                verify_calls = 0
                rollback_calls = 0
                restore_calls = 0
                complete_calls = 0
                service_contract_checks = 0
                owned_checks = 0
                removed_services = 0
                purged_state = $false
                install_saw_retired_journal = $false
                require_inactive_tombstone_adoption = $true
                snapshot_path = ''
                service_start_modes = @{
                    DefenseClawGateway = 2
                    DefenseClawCMIDBroker = 2
                    DefenseClawHookGuardian = 2
                }
                service_exists = @{
                    DefenseClawGateway = $false
                    DefenseClawCMIDBroker = $false
                    DefenseClawHookGuardian = $false
                }
                ipc_service_sids = @('S-1-5-80-1-2-3-4-5')
                guardian_fresh = $false
                queued_gateway_restart = $true
                queued_restart_blocked = $false
                gateway_started_before_guardian = $false
                barrier_required = $true
                barrier_complete = $false
            }
            $newManifest = @'
version: 1
targets:
  - connector: claudecode
    sid: S-1-5-21-111-222-333-1001
    user_home: c:\USERS\ALICE
    data_dir: c:\USERS\ALICE\.defenseclaw
    agent_version: 2.9.999
    enabled: true
'@
            $sources = @{
                broker = 'new-broker'
                gateway = 'new-gateway'
                hook = 'new-hook'
                installer = 'new-installer'
                module = 'new-module'
                config = 'listen_addr: 127.0.0.1:18970'
                manifest = $newManifest
                provider_library = [pscustomobject]@{
                    path = $layout.ProviderLibraryPath
                }
            }
            [void](Invoke-DefenseClawInstallLikeLifecycle `
                -Action 'Install' `
                -Layout $layout `
                -Sources $sources `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian')
            $reinstalledMetadata =
                Microsoft.PowerShell.Management\Get-Content `
                    -LiteralPath $layout.MetadataPath `
                    -Raw |
                    Microsoft.PowerShell.Utility\ConvertFrom-Json
            Assert-Harness `
                -Condition ([bool]$script:HarnessState.install_saw_retired_journal) `
                -Message 'direct reinstall did not retire changed-identity journal before transaction'
            Assert-Harness `
                -Condition (
                    $script:HarnessState.events.IndexOf(
                        'codex-requirements:inspect:metadata-absent'
                    ) -ge 0 -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.MetadataPath `
                        -PathType Leaf) -and
                    [bool]$reinstalledMetadata.installed
                ) `
                -Message 'direct reinstall did not transactionally replace the inactive tombstone with active metadata'
            Assert-Harness `
                -Condition (
                    [bool]$script:HarnessState.queued_restart_blocked -and
                    -not [bool]$script:HarnessState.gateway_started_before_guardian
                ) `
                -Message 'direct reinstall did not block queued gateway restart during servicing'
            Assert-Harness `
                -Condition (
                    [bool]$script:HarnessState.installed -and
                    [bool]$script:HarnessState.binary_present -and
                    [bool]$script:HarnessState.active_references
                ) `
                -Message 'direct reinstall did not reactivate installed hooks'
            Assert-Harness `
                -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.ManagedHooksTeardownJournalPath)) `
                -Message 'direct reinstall retained the changed-identity stale journal'

            $script:HarnessState.operation = 'uninstall'
            $script:HarnessState.transaction_calls = 0
            $script:HarnessState.prepare_calls = 0
            $script:HarnessState.verify_calls = 0
            $script:HarnessState.rollback_calls = 0
            $script:HarnessState.restore_calls = 0
            $script:HarnessState.complete_calls = 0
            $script:HarnessState.service_contract_checks = 0
            $script:HarnessState.owned_checks = 0
            $script:HarnessState.removed_services = 0
            $script:HarnessState.reheal_observed = $false
            $script:HarnessState.prepare_while_guardian_running = $false
            $script:HarnessState.services_were_running = $true
            $script:HarnessState.events.Clear()
            [void](Invoke-DefenseClawUninstallLifecycle `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian')
            Assert-Harness `
                -Condition (
                    -not [bool]$script:HarnessState.installed -and
                    -not [bool]$script:HarnessState.binary_present -and
                    -not [bool]$script:HarnessState.active_references
                ) `
                -Message 'second uninstall after direct reinstall was not reference-clean'
            Assert-Harness `
                -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.ManagedHooksTeardownJournalPath)) `
                -Message 'second uninstall retained a prepared journal'
            Assert-Harness `
                -Condition (
                    'S-1-5-80-1-2-3-4-5' -notin
                        @($script:HarnessState.ipc_service_sids)
                ) `
                -Message 'second uninstall retained its shared IPC service SID'
            $uninstallResults.Add([pscustomobject]@{
                name = 'crash-direct-reinstall-changed-identity-second-uninstall'
                failed = $false
                rollback = $script:HarnessState.rollback_calls
                service_contract_checks = (
                    $script:HarnessState.service_contract_checks
                )
                no_surviving_reference_before_delete = (
                    -not [bool]$script:HarnessState.reheal_observed
                )
            })
        }

        function Invoke-HarnessFirstActivationFailureSequence {
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label 'first-activation-failure'
            $layout = New-HarnessLayout -Root $root
            $manifest = @'
version: 1
targets:
  - connector: claudecode
    sid: S-1-5-21-111-222-333-1001
    user_home: C:\Users\Alice
    data_dir: C:\Users\Alice\.defenseclaw
    agent_version: 2.9.999
    enabled: true
'@
            $sources = @{
                broker = 'activation-broker'
                gateway = 'activation-gateway'
                hook = 'activation-hook'
                installer = 'activation-installer'
                module = 'activation-module'
                config = 'listen_addr: 127.0.0.1:18970'
                manifest = $manifest
                provider_library = [pscustomobject]@{
                    path = $layout.ProviderLibraryPath
                }
            }
            foreach ($entry in @(
                @($layout.ConfigPath, 'listen_addr: 127.0.0.1:18969'),
                @($layout.ManifestPath, $manifest)
            )) {
                $parent = [IO.Path]::GetDirectoryName([string]$entry[0])
                if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $parent `
                    -PathType Container)) {
                    Microsoft.PowerShell.Management\New-Item `
                        -ItemType Directory `
                        -Path $parent `
                        -Force | Microsoft.PowerShell.Core\Out-Null
                }
                [IO.File]::WriteAllText(
                    [string]$entry[0],
                    [string]$entry[1],
                    [Text.UTF8Encoding]::new($false)
                )
            }
            $setManifestAclDrift = {
                $driftedManifestAcl =
                    [Security.AccessControl.FileSecurity]::new()
                $driftedManifestAcl.SetSecurityDescriptorSddlForm(
                    'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)',
                    [Security.AccessControl.AccessControlSections]::All
                )
                Microsoft.PowerShell.Security\Set-Acl `
                    -LiteralPath $layout.ManifestPath `
                    -AclObject $driftedManifestAcl
            }
            $script:HarnessState = @{
                operation = 'install'
                crash_at = ''
                events = [Collections.Generic.List[string]]::new()
                layout = $layout
                active_references = $false
                lifecycle_preimage_active = $false
                binary_present = $true
                installed = $true
                guardian_running = $false
                gateway_running = $false
                services_running = $false
                services_were_running = $false
                reheal_observed = $false
                prepare_while_guardian_running = $false
                transaction_calls = 0
                prepare_calls = 0
                verify_calls = 0
                rollback_calls = 0
                restore_calls = 0
                complete_calls = 0
                service_contract_checks = 0
                owned_checks = 0
                removed_services = 0
                purged_state = $false
                install_saw_retired_journal = $false
                snapshot_path = ''
                service_start_modes = @{
                    DefenseClawGateway = 4
                    DefenseClawCMIDBroker = 4
                    DefenseClawHookGuardian = 4
                }
                guardian_fresh = $false
                fail_fresh_guardian = $true
                queued_gateway_restart = $false
                queued_restart_blocked = $true
                gateway_started_before_guardian = $false
                barrier_required = $true
                barrier_complete = $false
                manifest_admin_acl = $false
            }

            $samePathSources = @{}
            $noManifestSources = @{}
            foreach ($name in @($sources.Keys)) {
                $samePathSources[$name] = $sources[$name]
                if ($name -cne 'manifest') {
                    $noManifestSources[$name] = $sources[$name]
                }
            }
            $samePathSources['manifest'] = @{
                path = $layout.ManifestPath
            }
            $validationOnlyManifestDriftRejected = @{}
            foreach ($validationCase in @(
                [pscustomobject]@{
                    name = 'same-path'
                    action = 'Repair'
                    sources = $samePathSources
                },
                [pscustomobject]@{
                    name = 'no-source'
                    action = 'Upgrade'
                    sources = $noManifestSources
                }
            )) {
                & $setManifestAclDrift
                $script:HarnessState.events.Clear()
                $script:HarnessState.barrier_complete = $false
                $script:HarnessState.active_references = $false
                $script:HarnessState.manifest_admin_acl = $false
                $validationFailure = ''
                try {
                    [void](Invoke-DefenseClawInstallLikeLifecycle `
                        -Action ([string]$validationCase.action) `
                        -Layout $layout `
                        -Sources ([hashtable]$validationCase.sources) `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -GuardianServiceName 'DefenseClawHookGuardian')
                }
                catch {
                    $validationFailure = [string]$_.Exception.Message
                }
                Assert-Harness `
                    -Condition (
                        $validationFailure -match
                            'managed DACL is not protected'
                    ) `
                    -Message (
                        [string]$validationCase.action + ' ' +
                        [string]$validationCase.name +
                        ' manifest drift was not rejected exactly: ' +
                        $validationFailure
                    )
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.events.IndexOf(
                            'lifecycle-snapshot:capture'
                        ) -ge 0 -and
                        $script:HarnessState.events.IndexOf(
                            'manifest-published'
                        ) -lt 0 -and
                        $script:HarnessState.events.IndexOf(
                            'manifest-admin-acl'
                        ) -lt 0 -and
                        $script:HarnessState.events.IndexOf(
                            'target-runtime:plan-enter'
                        ) -lt 0 -and
                        $script:HarnessState.events.IndexOf(
                            'target-runtime:plan'
                        ) -lt 0
                    ) `
                    -Message (
                        [string]$validationCase.action + ' ' +
                        [string]$validationCase.name +
                        ' manifest drift crossed the validation-only boundary'
                    )
                Assert-Harness `
                    -Condition (
                        -not (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $layout.ManagedHooksLifecycleJournalPath) -and
                        -not (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $layout.PendingPath)
                    ) `
                    -Message (
                        [string]$validationCase.action + ' ' +
                        [string]$validationCase.name +
                        ' manifest rejection retained recovery residue'
                    )
                $validationOnlyManifestDriftRejected[
                    [string]$validationCase.name
                ] = $true
            }
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                $installLikeAction = if ($attempt -eq 1) {
                    'Repair'
                }
                else {
                    'Upgrade'
                }
                $script:HarnessState.events.Clear()
                $script:HarnessState.barrier_complete = $false
                $script:HarnessState.active_references = $false
                $script:HarnessState.manifest_admin_acl = $false
                $failure = ''
                try {
                    [void](Invoke-DefenseClawInstallLikeLifecycle `
                        -Action $installLikeAction `
                        -Layout $layout `
                        -Sources $sources `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -GuardianServiceName 'DefenseClawHookGuardian')
                }
                catch {
                    $failure = [string]$_.Exception.Message
                }
                Assert-Harness `
                    -Condition ($failure -match 'injected stale guardian generation') `
                    -Message "$installLikeAction activation attempt lost its causal failure: $failure"
                Assert-Harness `
                    -Condition (-not [bool]$script:HarnessState.active_references) `
                    -Message "$installLikeAction activation attempt retained partial machine enrollment"
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.ManagedHooksLifecycleJournalPath)) `
                    -Message "$installLikeAction activation attempt retained its completed lifecycle journal"
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PendingPath)) `
                    -Message "$installLikeAction activation attempt retained pending recovery after exact rollback"
                $manifestPublished = $script:HarnessState.events.IndexOf(
                    'manifest-published'
                )
                $manifestAcl = $script:HarnessState.events.IndexOf(
                    'manifest-admin-acl'
                )
                $targetPlan = $script:HarnessState.events.IndexOf(
                    'target-runtime:plan'
                )
                $capture = $script:HarnessState.events.IndexOf(
                    'lifecycle-snapshot:capture'
                )
                Assert-Harness `
                    -Condition (
                        $capture -ge 0 -and
                        $manifestPublished -gt $capture -and
                        $manifestAcl -gt $manifestPublished -and
                        $targetPlan -gt $manifestAcl
                    ) `
                    -Message (
                        "$installLikeAction validated its replacement " +
                        'manifest before the exact AdminFile ACL was applied'
                    )
                $restore = $script:HarnessState.events.IndexOf(
                    'lifecycle-snapshot:restore'
                )
                $complete = $script:HarnessState.events.IndexOf('complete')
                $retire = $script:HarnessState.events.IndexOf(
                    'lifecycle-snapshot:retire'
                )
                Assert-Harness `
                    -Condition (
                        $capture -ge 0 -and
                        $restore -gt $capture -and
                        $retire -gt $restore -and
                        $complete -gt $retire
                    ) `
                    -Message "$installLikeAction activation attempt violated capture/restore/retire ordering"
            }
            $uninstallResults.Add([pscustomobject]@{
                name = 'repeated-first-activation-failure-exact-rollback'
                failed = $false
                rollback = $script:HarnessState.restore_calls
                service_contract_checks = (
                    $script:HarnessState.service_contract_checks
                )
                no_surviving_reference_before_delete = $true
                same_path_manifest_drift_rejected = [bool](
                    $validationOnlyManifestDriftRejected['same-path']
                )
                no_source_manifest_drift_rejected = [bool](
                    $validationOnlyManifestDriftRejected['no-source']
                )
            })
        }

        $purgeResults = [Collections.Generic.List[object]]::new()
        function New-HarnessCommittedPurgeCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [string]$CrashAt = '',
                [switch]$OmitTeardownJournal
            )
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label ('purge-' + $Name)
            $layout = New-HarnessLayout -Root $root
            [IO.File]::WriteAllText(
                $layout.MetadataPath,
                '{"schema_version":1,"installed":false}',
                [Text.UTF8Encoding]::new($false)
            )
            if (-not $OmitTeardownJournal) {
                Write-HarnessJournal `
                    -Path $layout.ManagedHooksTeardownJournalPath `
                    -Phase 'prepared'
            }
            $events = [Collections.Generic.List[string]]::new()
            $script:HarnessState = @{
                operation = 'purge'
                crash_at = $CrashAt
                events = $events
                layout = $layout
                active_references = $false
                binary_present = $false
                installed = $false
                guardian_running = $false
                gateway_running = $false
                services_running = $false
                services_were_running = $false
                reheal_observed = $false
                prepare_while_guardian_running = $false
                transaction_calls = 0
                prepare_calls = 0
                verify_calls = 0
                rollback_calls = 0
                restore_calls = 0
                complete_calls = 0
                service_contract_checks = 0
                owned_checks = 0
                removed_services = 0
                purged_state = $false
                purge_acl_invalid = $false
                install_saw_retired_journal = $false
                snapshot_path = ''
                service_start_modes = @{
                    DefenseClawGateway = 4
                    DefenseClawCMIDBroker = 4
                    DefenseClawHookGuardian = 4
                }
                service_exists = @{
                    DefenseClawGateway = $false
                    DefenseClawCMIDBroker = $false
                    DefenseClawHookGuardian = $false
                }
                ipc_service_sids = @('S-1-5-80-1-2-3-4-5')
                guardian_fresh = $false
                queued_gateway_restart = $false
                queued_restart_blocked = $true
                gateway_started_before_guardian = $false
                barrier_required = $false
                barrier_complete = $true
            }
            return $layout
        }

        function Publish-HarnessPurgeReceipt {
            param([Parameter(Mandatory)][hashtable]$Layout)
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout $Layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian')
            Remove-DefenseClawCommittedEmptyInstallRoot -Layout $Layout
            [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
                -Layout $Layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian')
            [void](Publish-DefenseClawStatePurgeIntent `
                -Layout $Layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian')
        }

        function Invoke-HarnessPurgeRetry {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [string]$Action = 'Uninstall'
            )
            return Invoke-DefenseClawPreLayoutRecovery `
                -Action $Action `
                -Layout $Layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -Purge:($Action -eq 'Uninstall')
        }

        function Add-HarnessPurgeResult {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][bool]$FailedClosed,
                [Parameter(Mandatory)][bool]$Retried
            )
            $purgeResults.Add([pscustomobject]@{
                name = $Name
                failed_closed = $FailedClosed
                retried = $Retried
            })
        }

        $missingJournalExecutableLayout = New-HarnessCommittedPurgeCase `
            -Name 'missing-journal-executable' `
            -OmitTeardownJournal
        Microsoft.PowerShell.Management\New-Item `
            -ItemType Directory `
            -Path $missingJournalExecutableLayout.BinDirectory `
            -Force | Microsoft.PowerShell.Core\Out-Null
        [IO.File]::WriteAllText(
            $missingJournalExecutableLayout.HookPath,
            'unexpected managed hook executable',
            [Text.UTF8Encoding]::new($false)
        )
        $missingJournalPath = [string](
            $missingJournalExecutableLayout.ManagedHooksTeardownJournalPath
        )
        $missingJournalExecutableFailed = $false
        try {
            [void](Invoke-DefenseClawCommittedUninstallCleanup `
                -Layout $missingJournalExecutableLayout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -Purge)
        }
        catch {
            $missingJournalExecutableFailed = $true
        }
        Assert-Harness `
            -Condition (
                $missingJournalExecutableFailed -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $missingJournalExecutableLayout.InstallRoot `
                    -PathType Container) -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $missingJournalExecutableLayout.HookPath `
                    -PathType Leaf) -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $missingJournalExecutableLayout.StateRoot `
                    -PathType Container) -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $missingJournalPath) -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $missingJournalExecutableLayout.PurgeIntentPath) -and
                'S-1-5-80-1-2-3-4-5' -in
                    @($script:HarnessState.ipc_service_sids) -and
                $script:HarnessState.events.IndexOf(
                    'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                ) -lt 0 -and
                $script:HarnessState.events.IndexOf('purge-intent-write') -lt 0
            ) `
            -Message 'missing teardown journal authorized executable or purge cleanup'
        Add-HarnessPurgeResult `
            -Name 'missing-journal-executable-fails-closed' `
            -FailedClosed:$true `
            -Retried:$false

        $orderedLayout = New-HarnessCommittedPurgeCase -Name 'ordered'
        [void](Invoke-DefenseClawCommittedUninstallCleanup `
            -Layout $orderedLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -Purge)
        $intentWriteIndex = $script:HarnessState.events.IndexOf(
            'purge-intent-write'
        )
        $stateDeleteIndex = $script:HarnessState.events.IndexOf(
            'remove-tree:StateRoot'
        )
        Assert-Harness `
            -Condition (
                $intentWriteIndex -ge 0 -and
                $stateDeleteIndex -gt $intentWriteIndex -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $orderedLayout.StateRoot) -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $orderedLayout.PurgeIntentPath)
            ) `
            -Message 'purge did not publish its authenticated receipt before first StateRoot deletion'
        Assert-Harness `
            -Condition (
                'S-1-5-80-1-2-3-4-5' -notin
                    @($script:HarnessState.ipc_service_sids)
            ) `
            -Message 'scope A purge retained its shared IPC service SID'
        Initialize-DefenseClawManagedIPCDirectory `
            -Layout $orderedLayout `
            -GatewayServiceName 'DefenseClawGatewayScopeB'
        Assert-Harness `
            -Condition (
                @($script:HarnessState.ipc_service_sids).Count -eq 1 -and
                [string]$script:HarnessState.ipc_service_sids[0] -ceq
                    'S-1-5-80-6-7-8-9-10'
            ) `
            -Message 'scope B could not claim the shared IPC contract after scope A purge'
        Add-HarnessPurgeResult `
            -Name 'receipt-before-state-delete' `
            -FailedClosed:$false `
            -Retried:$false
        Add-HarnessPurgeResult `
            -Name 'scope-a-purge-allows-scope-b-install' `
            -FailedClosed:$false `
            -Retried:$true

        foreach ($crashCase in @(
            'purge-after-receipt-publication',
            'purge-after-metadata-delete',
            'purge-after-full-state-delete'
        )) {
            $layout = New-HarnessCommittedPurgeCase `
                -Name $crashCase `
                -CrashAt $crashCase
            $failed = $false
            try {
                [void](Invoke-DefenseClawCommittedUninstallCleanup `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName 'DefenseClawHookGuardian' `
                    -Purge)
            }
            catch {
                $failed = $true
            }
            Assert-Harness `
                -Condition (
                    $failed -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PurgeIntentPath `
                        -PathType Leaf)
                ) `
                -Message "$crashCase did not retain its authenticated receipt"
            $script:HarnessState.crash_at = ''
            $retry = Invoke-HarnessPurgeRetry -Layout $layout
            Assert-Harness `
                -Condition (
                    [bool]$retry.handled -and
                    -not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.StateRoot) -and
                    -not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PurgeIntentPath)
                ) `
                -Message "$crashCase did not resume before layout creation"
            Assert-Harness `
                -Condition (
                    'S-1-5-80-1-2-3-4-5' -notin
                        @($script:HarnessState.ipc_service_sids) -and
                    @($script:HarnessState.events |
                        Microsoft.PowerShell.Core\Where-Object {
                            $_ -ceq 'managed-ipc-revoke:S-1-5-80-1-2-3-4-5'
                        }).Count -ge 2
                ) `
                -Message "$crashCase did not idempotently resume IPC SID cleanup"
            Add-HarnessPurgeResult `
                -Name $crashCase `
                -FailedClosed:$true `
                -Retried:$true
        }

        $writeFailureLayout = New-HarnessCommittedPurgeCase `
            -Name 'receipt-write-failure' `
            -CrashAt 'purge-receipt-write'
        $writeFailed = $false
        try {
            [void](Invoke-DefenseClawCommittedUninstallCleanup `
                -Layout $writeFailureLayout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian' `
                -Purge)
        }
        catch {
            $writeFailed = $true
        }
        Assert-Harness `
            -Condition (
                $writeFailed -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $writeFailureLayout.StateRoot `
                    -PathType Container) -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $writeFailureLayout.MetadataPath `
                    -PathType Leaf) -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $writeFailureLayout.PurgeIntentPath)
            ) `
            -Message 'receipt write failure did not leave tombstone state retryable'
        $script:HarnessState.crash_at = ''
        $writeRetry = Invoke-HarnessPurgeRetry -Layout $writeFailureLayout
        Assert-Harness `
            -Condition (
                [bool]$writeRetry.handled -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $writeFailureLayout.StateRoot)
            ) `
            -Message 'receipt write failure could not be retried from tombstone'
        Add-HarnessPurgeResult `
            -Name 'receipt-write-failure' `
            -FailedClosed:$true `
            -Retried:$true

        foreach ($invalidCase in @(
            'world-writable',
            'corrupt-json',
            'schema',
            'scope',
            'install-root',
            'state-root',
            'gateway-service',
            'guardian-service',
            'tombstone',
            'missing-certification-home',
            'missing-core-mode',
            'nonboolean-core-mode',
            'core-without-certification-home',
            'certification-home-mismatch',
            'requested-core-mismatch'
        )) {
            $layout = New-HarnessCommittedPurgeCase -Name "invalid-$invalidCase"
            Publish-HarnessPurgeReceipt -Layout $layout
            if ($invalidCase -eq 'world-writable') {
                $script:HarnessState.purge_acl_invalid = $true
            }
            elseif ($invalidCase -eq 'corrupt-json') {
                [IO.File]::WriteAllText(
                    $layout.PurgeIntentPath,
                    '{invalid',
                    [Text.UTF8Encoding]::new($false)
                )
            }
            else {
                $intent = Microsoft.PowerShell.Management\Get-Content `
                    -LiteralPath $layout.PurgeIntentPath `
                    -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
                switch ($invalidCase) {
                    'schema' {
                        $intent.schema_version = 2
                    }
                    'scope' {
                        $intent.scope_sha256 = ('2' * 64)
                    }
                    'install-root' {
                        $intent.install_root = "$($layout.InstallRoot)-other"
                    }
                    'state-root' {
                        $intent.state_root = "$($layout.StateRoot)-other"
                    }
                    'gateway-service' {
                        $intent.gateway_service = 'OtherGateway'
                    }
                    'guardian-service' {
                        $intent.guardian_service = 'OtherGuardian'
                    }
                    'tombstone' {
                        $intent.tombstone_sha256 = ('f' * 64)
                    }
                    'missing-certification-home' {
                        $intent.PSObject.Properties.Remove(
                            'certification_codex_home'
                        )
                    }
                    'missing-core-mode' {
                        $intent.PSObject.Properties.Remove(
                            'core_hardening_certification'
                        )
                    }
                    'nonboolean-core-mode' {
                        $intent.core_hardening_certification = 'false'
                    }
                    'core-without-certification-home' {
                        $intent.certification_codex_home = ''
                        $intent.core_hardening_certification = $true
                    }
                    'certification-home-mismatch' {
                        $layout.CertificationCodexHome =
                            'C:\requested\.codex-defenseclaw-cert-0123456789'
                    }
                    'requested-core-mismatch' {
                        $layout.CoreHardeningCertification = $true
                        $intent.core_hardening_certification = $false
                    }
                }
                [IO.File]::WriteAllText(
                    $layout.PurgeIntentPath,
                    (
                        $intent |
                            Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8
                    ),
                    [Text.UTF8Encoding]::new($false)
                )
            }
            $failed = $false
            try {
                [void](Invoke-HarnessPurgeRetry -Layout $layout)
            }
            catch {
                $failed = $true
            }
            Assert-Harness `
                -Condition (
                    $failed -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.StateRoot `
                        -PathType Container) -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PurgeIntentPath `
                        -PathType Leaf)
                ) `
                -Message "invalid purge receipt $invalidCase did not fail closed"
            Add-HarnessPurgeResult `
                -Name "invalid-$invalidCase" `
                -FailedClosed:$true `
                -Retried:$false
        }

        foreach ($staleCase in @(
            'installed-metadata',
            'service-reappeared',
            'install-root-reappeared'
        )) {
            $layout = New-HarnessCommittedPurgeCase -Name "stale-$staleCase"
            Publish-HarnessPurgeReceipt -Layout $layout
            switch ($staleCase) {
                'installed-metadata' {
                    $script:HarnessState.installed = $true
                }
                'service-reappeared' {
                    $script:HarnessState.service_exists[
                        'DefenseClawGateway'
                    ] = $true
                }
                'install-root-reappeared' {
                    Microsoft.PowerShell.Management\New-Item `
                        -ItemType Directory `
                        -Path $layout.InstallRoot `
                        -Force | Microsoft.PowerShell.Core\Out-Null
                }
            }
            $failed = $false
            try {
                [void](Invoke-HarnessPurgeRetry -Layout $layout)
            }
            catch {
                $failed = $true
            }
            Assert-Harness `
                -Condition (
                    $failed -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.StateRoot `
                        -PathType Container) -and
                    (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PurgeIntentPath `
                        -PathType Leaf)
                ) `
                -Message "stale receipt $staleCase did not fail closed"
            Add-HarnessPurgeResult `
                -Name "stale-$staleCase" `
                -FailedClosed:$true `
                -Retried:$false
        }

        $installResumeLayout = New-HarnessCommittedPurgeCase `
            -Name 'install-resume-exact'
        Publish-HarnessPurgeReceipt -Layout $installResumeLayout
        $installResume = Invoke-HarnessPurgeRetry `
            -Layout $installResumeLayout `
            -Action 'Install'
        Assert-Harness `
            -Condition (
                -not [bool]$installResume.handled -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $installResumeLayout.StateRoot) -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $installResumeLayout.PurgeIntentPath)
            ) `
            -Message 'fresh Install did not retire the exact committed purge receipt'
        Add-HarnessPurgeResult `
            -Name 'install-retires-exact-receipt' `
            -FailedClosed:$false `
            -Retried:$true

        $nonPurgeLayout = New-HarnessCommittedPurgeCase `
            -Name 'nonpurge-no-install-root'
        [void](Complete-DefenseClawCommittedManagedHooksFinalization `
            -Layout $nonPurgeLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian')
        Remove-DefenseClawCommittedEmptyInstallRoot -Layout $nonPurgeLayout
        $nonPurge = Invoke-DefenseClawPreLayoutRecovery `
            -Action 'Uninstall' `
            -Layout $nonPurgeLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian'
        Assert-Harness `
            -Condition (
                [bool]$nonPurge.handled -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $nonPurgeLayout.InstallRoot) -and
                (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $nonPurgeLayout.StateRoot `
                    -PathType Container)
            ) `
            -Message 'non-purge tombstone retry recreated InstallRoot or removed StateRoot'
        Add-HarnessPurgeResult `
            -Name 'nonpurge-no-install-root-recreation' `
            -FailedClosed:$false `
            -Retried:$true

        foreach ($rootCase in @('broad-state-root', 'lifecycle-overlap')) {
            $failed = $false
            try {
                $rootState = if ($rootCase -eq 'broad-state-root') {
                    Microsoft.PowerShell.Management\Join-Path `
                        $script:ProgramData `
                        'Cisco'
                }
                else {
                    Microsoft.PowerShell.Management\Join-Path `
                        $script:ProgramData `
                        'Cisco\Cisco Secure Client\DefenseClaw-Lifecycle\DefenseClaw'
                }
                [void](Get-DefenseClawLayout `
                    -InstallRoot (
                        Microsoft.PowerShell.Management\Join-Path `
                            $script:ProgramFiles `
                            'Cisco\PurgeScopeTest\DefenseClaw'
                    ) `
                    -StateRoot $rootState `
                    -GatewayServiceName 'DefenseClawGatewayScopeTest' `
                    -GuardianServiceName 'DefenseClawGuardianScopeTest')
            }
            catch {
                $failed = $true
            }
            Assert-Harness `
                -Condition $failed `
                -Message "$rootCase was accepted as a recursively deletable managed root"
            Add-HarnessPurgeResult `
                -Name $rootCase `
                -FailedClosed:$true `
                -Retried:$false
        }

        # Quiescing recovery exercises the production disabled→demand→start
        # →exact-mode helper. Only its SCM effects remain mocked.
        function script:Start-DefenseClawTransactionServices {
            param(
                [Parameter(Mandatory)]$Services,
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$ServicesQuiescedAt,
                [switch]$TrustInProcessQuiescence,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $hasOperation = $script:HarnessState.ContainsKey('operation')
            if (-not $hasOperation) {
                $script:HarnessState.start_calls++
                if ($script:HarnessState.expect_rollback -and
                    $script:HarnessState.rollback_calls -ne 1) {
                    throw 'services restarted before exactly one managed-hook rollback'
                }
                $script:HarnessState.services_running = [bool](
                    @(
                        $Services |
                            Microsoft.PowerShell.Core\Where-Object {
                                [bool]$_.existed -and [bool]$_.running
                            }
                    ).Count -gt 0
                )
                return
            }

            if ([string]$script:HarnessState.operation -ceq 'uninstall') {
                $script:HarnessState.events.Add('restart-services')
                if ($script:HarnessState.rollback_calls -ne 1) {
                    throw 'services restarted before managed-hook rollback completed'
                }
                $script:HarnessState.services_running = [bool](
                    @(
                        $Services |
                            Microsoft.PowerShell.Core\Where-Object {
                                [bool]$_.existed -and [bool]$_.running
                            }
                    ).Count -gt 0
                )
                return
            }

            # Quiescing recovery intentionally exercises the real production
            # activation ordering. Other explicitly modeled operations retain
            # the same real-helper behavior this final fixture previously used.
            & $script:HarnessRealStartTransactionServices `
                -Services $Services `
                -Layout $Layout `
                -ServicesQuiescedAt $ServicesQuiescedAt `
                -TrustInProcessQuiescence:$TrustInProcessQuiescence `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }

        $quiescingResults = [Collections.Generic.List[object]]::new()
        function Invoke-HarnessQuiescingRecoveryCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][bool]$GatewayCurrentlyRunning,
                [Parameter(Mandatory)][bool]$GuardianCurrentlyRunning,
                [bool]$PriorGatewayExisted = $true,
                [bool]$PriorGuardianExisted = $true,
                [bool]$PriorGatewayRunning = $true,
                [bool]$PriorGuardianRunning = $true,
                [ValidateSet(2, 3, 4)]
                [int]$PriorGatewayStartMode = 2,
                [ValidateSet(2, 3, 4)]
                [int]$PriorGuardianStartMode = 2,
                [bool]$CreatePartialPreimage = $false,
                [bool]$DirectoryAlreadyMissing = $false,
                [ValidateSet(
                    '',
                    'identity',
                    'root',
                    'certification',
                    'core',
                    'duplicate',
                    'boolean',
                    'foreign',
                    'fresh',
                    'start'
                )]
                [string]$InvalidMode = ''
            )
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label ('quiescing-' + $Name)
            $layout = New-HarnessLayout -Root $root
            $id = [Guid]::NewGuid().ToString('N')
            $transactionDirectory = Microsoft.PowerShell.Management\Join-Path `
                $layout.TransactionsDirectory `
                $id
            if (-not $DirectoryAlreadyMissing) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $transactionDirectory `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            if ($CreatePartialPreimage -and -not $DirectoryAlreadyMissing) {
                [IO.File]::WriteAllText(
                    (
                        Microsoft.PowerShell.Management\Join-Path `
                            $transactionDirectory `
                            'file-00.bak'
                    ),
                    'partial-preimage',
                    [Text.UTF8Encoding]::new($false)
                )
            }
            $recordedGateway = if ($InvalidMode -eq 'identity') {
                'ForeignGateway'
            }
            else {
                'DefenseClawGateway'
            }
            $recordedStateRoot = if ($InvalidMode -eq 'root') {
                $layout.StateRoot + '-foreign'
            }
            else {
                $layout.StateRoot
            }
            $gatewayRunningValue = if ($InvalidMode -eq 'boolean') {
                'true'
            }
            else {
                $PriorGatewayRunning
            }
            $guardianServiceName = if ($InvalidMode -eq 'duplicate') {
                'DefenseClawGateway'
            }
            else {
                'DefenseClawHookGuardian'
            }
            $intent = [ordered]@{
                schema_version = 1
                phase = 'quiescing'
                id = $id
                directory = $transactionDirectory
                install_root = $layout.InstallRoot
                state_root = $recordedStateRoot
                gateway_service = $recordedGateway
                guardian_service = 'DefenseClawHookGuardian'
                certification_codex_home = $(if (
                    $InvalidMode -eq 'certification'
                ) {
                    'C:\unexpected\.codex-defenseclaw-cert-0123456789'
                } else {
                    ''
                })
                core_hardening_certification = $(if (
                    $InvalidMode -eq 'core'
                ) {
                    'true'
                } else {
                    $false
                })
                services = @(
                    [ordered]@{
                        name = 'DefenseClawGateway'
                        existed = $PriorGatewayExisted
                        running = $gatewayRunningValue
                        start_mode = $(if ($PriorGatewayExisted) {
                            $PriorGatewayStartMode
                        } else {
                            0
                        })
                    },
                    [ordered]@{
                        name = $guardianServiceName
                        existed = $PriorGuardianExisted
                        running = $PriorGuardianRunning
                        start_mode = $(if ($PriorGuardianExisted) {
                            $PriorGuardianStartMode
                        } else {
                            0
                        })
                    }
                )
                created_at = [DateTime]::UtcNow.ToString('o')
            }
            [IO.File]::WriteAllText(
                $layout.PendingPath,
                (
                    $intent |
                        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8
                ),
                [Text.UTF8Encoding]::new($false)
            )
            $events = [Collections.Generic.List[string]]::new()
            $script:HarnessState = @{
                operation = 'quiescing-recovery'
                crash_at = ''
                events = $events
                layout = $layout
                installed = $true
                binary_present = $true
                active_references = $GuardianCurrentlyRunning
                guardian_running = $GuardianCurrentlyRunning
                gateway_running = $GatewayCurrentlyRunning
                services_running = (
                    $GatewayCurrentlyRunning -or $GuardianCurrentlyRunning
                )
                start_service_calls = 0
                owned_checks = 0
                guardian_fresh = $false
                queued_gateway_restart = $true
                queued_restart_blocked = $true
                gateway_started_before_guardian = $false
                barrier_required = $true
                barrier_complete = $false
                service_start_modes = @{
                    DefenseClawGateway = $(if ($PriorGatewayExisted) {
                        4
                    } else {
                        0
                    })
                    DefenseClawCMIDBroker = 0
                    DefenseClawHookGuardian = $(
                        if ($PriorGuardianExisted) { 4 } else { 0 }
                    )
                }
                foreign_service = $(if ($InvalidMode -eq 'foreign') {
                    'DefenseClawGateway'
                } else {
                    ''
                })
                fail_start_service = $(if ($InvalidMode -eq 'start') {
                    'DefenseClawHookGuardian'
                } else {
                    ''
                })
                fail_fresh_guardian = ($InvalidMode -eq 'fresh')
            }
            $failed = $false
            try {
                [void](Recover-DefenseClawPendingTransaction `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName 'DefenseClawHookGuardian')
            }
            catch {
                $failed = $true
                if ([string]::IsNullOrEmpty($InvalidMode)) {
                    throw
                }
            }
            if (-not [string]::IsNullOrEmpty($InvalidMode)) {
                Assert-Harness `
                    -Condition $failed `
                    -Message "$Name accepted a mismatched quiescing service identity"
                Assert-Harness `
                    -Condition (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PendingPath `
                        -PathType Leaf) `
                    -Message "$Name discarded invalid protected recovery evidence"
                Assert-Harness `
                    -Condition (
                        ($InvalidMode -in @('start', 'fresh') -and
                            $script:HarnessState.start_service_calls -eq 1) -or
                        ($InvalidMode -notin @('start', 'fresh') -and
                            $script:HarnessState.start_service_calls -eq 0)
                    ) `
                    -Message "$Name did not preserve fail-closed service recovery ordering"
                if ($InvalidMode -in @('start', 'fresh')) {
                    Assert-Harness `
                        -Condition (Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $transactionDirectory `
                            -PathType Container) `
                        -Message "$Name deleted recovery preimages after restart failure"
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.service_start_modes[
                                'DefenseClawGateway'
                            ] -eq 4 -and
                            -not [bool]$script:HarnessState.gateway_running
                        ) `
                        -Message "$Name made gateway startable before a fresh guardian reconcile"
                }
            }
            else {
                $gatewayNeedsProtection = (
                    $PriorGatewayExisted -and (
                        $PriorGatewayRunning -or
                        $PriorGatewayStartMode -eq 2
                    )
                )
                $guardianTemporarilyRequired = (
                    $PriorGuardianRunning -or $gatewayNeedsProtection
                )
                $expectedStartCalls = @(
                    $PriorGatewayRunning,
                    $guardianTemporarilyRequired
                ) | Microsoft.PowerShell.Core\Where-Object { [bool]$_ }
                Assert-Harness `
                    -Condition (-not $failed) `
                    -Message "$Name did not recover a valid quiescing intent"
                Assert-Harness `
                    -Condition (
                        [bool]$script:HarnessState.gateway_running -eq
                            $PriorGatewayRunning -and
                        [bool]$script:HarnessState.guardian_running -eq
                            $PriorGuardianRunning
                    ) `
                    -Message "$Name did not restore the exact prior service state"
                Assert-Harness `
                    -Condition (
                        $script:HarnessState.start_service_calls -eq
                            @($expectedStartCalls).Count
                    ) `
                    -Message "$Name did not start the exact prior running set"
                Assert-Harness `
                    -Condition (
                        -not [bool]$script:HarnessState.gateway_started_before_guardian
                    ) `
                    -Message "$Name let a queued gateway restart beat fresh guardian reconciliation"
                if ($guardianTemporarilyRequired) {
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.events.IndexOf(
                                'guardian-legacy-fresh-state'
                            ) -ge 0
                        ) `
                        -Message "$Name did not exercise legacy fresh-state Guardian coverage"
                }
                if ($PriorGatewayExisted) {
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.service_start_modes[
                                'DefenseClawGateway'
                            ] -eq $PriorGatewayStartMode
                        ) `
                        -Message "$Name did not restore the gateway startup mode"
                }
                if ($PriorGuardianExisted) {
                    Assert-Harness `
                        -Condition (
                            $script:HarnessState.service_start_modes[
                                'DefenseClawHookGuardian'
                            ] -eq $PriorGuardianStartMode
                        ) `
                        -Message "$Name did not restore the guardian startup mode"
                }
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.PendingPath)) `
                    -Message "$Name retained completed quiescing intent"
                Assert-Harness `
                    -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $transactionDirectory)) `
                    -Message "$Name retained partial transaction preimages"
            }
            $quiescingResults.Add([pscustomobject]@{
                name = $Name
                failed_closed = $failed
                start_calls = $script:HarnessState.start_service_calls
                guardian_running = $script:HarnessState.guardian_running
            })
        }

        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'hard-stop-after-intent-before-stop' `
            -GatewayCurrentlyRunning:$true `
            -GuardianCurrentlyRunning:$true
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'hard-stop-after-guardian-stop' `
            -GatewayCurrentlyRunning:$true `
            -GuardianCurrentlyRunning:$false
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'hard-stop-after-gateway-stop' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'hard-stop-during-preimage-copy' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -CreatePartialPreimage:$true
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'prior-guardian-stopped' `
            -GatewayCurrentlyRunning:$true `
            -GuardianCurrentlyRunning:$false `
            -PriorGatewayRunning:$true `
            -PriorGuardianRunning:$false
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'prior-running-disabled-services' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -PriorGatewayRunning:$true `
            -PriorGuardianRunning:$true `
            -PriorGatewayStartMode 4 `
            -PriorGuardianStartMode 4
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'prior-services-absent' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -PriorGatewayExisted:$false `
            -PriorGuardianExisted:$false `
            -PriorGatewayRunning:$false `
            -PriorGuardianRunning:$false
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'repeat-after-directory-cleanup' `
            -GatewayCurrentlyRunning:$true `
            -GuardianCurrentlyRunning:$true `
            -DirectoryAlreadyMissing:$true
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'mismatched-service-identity' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'identity'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'mismatched-state-root' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'root'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'mismatched-certification-home' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'certification'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'malformed-core-certification-mode' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'core'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'duplicate-service' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'duplicate'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'malformed-running-boolean' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'boolean'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'foreign-live-service' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'foreign'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'stale-guardian-generation-retains-recovery' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'fresh'
        Invoke-HarnessQuiescingRecoveryCase `
            -Name 'restart-failure-retains-recovery' `
            -GatewayCurrentlyRunning:$false `
            -GuardianCurrentlyRunning:$false `
            -InvalidMode 'start'

        Invoke-HarnessUninstallCase `
            -Name 'quiesce-prevents-reheal' `
            -CrashAt '' `
            -ExpectSuccess:$true
        Invoke-HarnessUninstallCase `
            -Name 'crash-after-complete-retry-retirement' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -PreexistingPrepared:$true `
            -ServicesRunning:$false `
            -InitialReferences:$false `
            -AlreadyUninstalled:$true
        Invoke-HarnessUninstallCase `
            -Name 'tombstone-purge-existing-journal' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -PreexistingPrepared:$true `
            -ServicesRunning:$false `
            -InitialReferences:$false `
            -AlreadyUninstalled:$true `
            -Purge:$true
        Invoke-HarnessUninstallCase `
            -Name 'tombstone-purge-after-retirement' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -ServicesRunning:$false `
            -InitialReferences:$false `
            -AlreadyUninstalled:$true `
            -Purge:$true
        Invoke-HarnessUninstallCase `
            -Name 'tombstone-nonpurge-preserves-state' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -ServicesRunning:$false `
            -InitialReferences:$false `
            -AlreadyUninstalled:$true
        Invoke-HarnessUninstallCase `
            -Name 'stale-prepared-after-reinstall' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -PreexistingPrepared:$true `
            -InitialReferences:$true
        Invoke-HarnessUninstallCase `
            -Name 'service-drift-preflight' `
            -CrashAt 'service-drift-preflight' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'captured' `
            -CrashAt 'captured' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'failed-teardown-self-restored' `
            -CrashAt 'failed-teardown-self-restored' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'prepared-before-marker' `
            -CrashAt 'prepared-before-marker' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'preexisting-prepared-before-marker' `
            -CrashAt 'preexisting-prepared-before-marker' `
            -ExpectSuccess:$false `
            -PreexistingPrepared:$true `
            -ServicesRunning:$false `
            -InitialReferences:$false
        Invoke-HarnessUninstallCase `
            -Name 'marked' `
            -CrashAt 'marked' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'service-drift-predelete' `
            -CrashAt 'service-drift-predelete' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'post-binary-delete' `
            -CrashAt 'post-binary-delete' `
            -ExpectSuccess:$false
        Invoke-HarnessUninstallCase `
            -Name 'installed-cli-atomic-retirement' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -SelfUninstall:$true
        Invoke-HarnessUninstallCase `
            -Name 'installed-cli-purge-atomic-retirement' `
            -CrashAt '' `
            -ExpectSuccess:$true `
            -SelfUninstall:$true `
            -Purge:$true
        $targetRuntimeGatewayMock = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Invoke-HarnessTargetRuntimeGatewayCommand `
                -CommandType Function
        ).ScriptBlock
        $targetRuntimeCleanupScopeMock = (
            Microsoft.PowerShell.Core\Get-Command `
                -Name Assert-HarnessTargetRuntimeCleanupScopeExclusive `
                -CommandType Function
        ).ScriptBlock
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath (
                'Function:script:Invoke-DefenseClawGatewayCommand'
            ) `
            -Value $targetRuntimeGatewayMock
        Microsoft.PowerShell.Management\Set-Item `
            -LiteralPath (
                'Function:script:' +
                'Assert-DefenseClawTargetRuntimeCleanupScopeExclusive'
            ) `
            -Value $targetRuntimeCleanupScopeMock
        try {
            Invoke-HarnessFreshInstallServiceBootstrapSequence
            Invoke-HarnessDirectReinstallSequence
            Invoke-HarnessFirstActivationFailureSequence
        }
        finally {
            Microsoft.PowerShell.Management\Set-Item `
                -LiteralPath (
                    'Function:script:Invoke-DefenseClawGatewayCommand'
                ) `
                -Value $script:HarnessRealGatewayCommand
            Microsoft.PowerShell.Management\Set-Item `
                -LiteralPath (
                    'Function:script:' +
                    'Assert-DefenseClawTargetRuntimeCleanupScopeExclusive'
                ) `
                -Value $script:HarnessRealTargetRuntimeCleanupScope
        }

        # Exercise the authenticated pre-layout self-uninstall state machine
        # directly. These cases cover the rename/transaction crash windows
        # that cannot be represented by the in-process uninstall mocks above.
        $selfUninstallRecoveryResults =
            [Collections.Generic.List[object]]::new()
        $sharedDirectoryResults = [Collections.Generic.List[object]]::new()
        function script:Get-DefenseClawSelfUninstallReceipt {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [switch]$Required
            )
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.SelfUninstallReceiptPath `
                    -PathType Leaf)) {
                if ($Required) {
                    throw 'injected self-uninstall receipt is missing'
                }
                return $null
            }
            return $script:HarnessSelfState.receipt
        }
        function script:Move-DefenseClawRetiredInstallTreeBack {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessSelfState.events.Add('move-retired-back')
            [IO.Directory]::Move(
                [string]$Receipt.retired_install_root,
                [string]$Layout.InstallRoot
            )
        }
        function script:Remove-DefenseClawSelfUninstallEvidence {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessSelfState.events.Add('remove-evidence')
            foreach ($path in @(
                $Layout.SelfUninstallHelperPath,
                $Layout.SelfUninstallReceiptPath
            )) {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $path) {
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $path `
                        -Force
                }
            }
        }
        function script:Assert-DefenseClawManagedInstallTree {
            param([Parameter(Mandatory)][hashtable]$Layout)
            $script:HarnessSelfState.events.Add(
                'assert-canonical-install-tree'
            )
        }
        function script:Assert-DefenseClawSelfUninstallCommittedState {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName,
                [Parameter(Mandatory)]$Receipt,
                [switch]$AllowPurgedState
            )
            $script:HarnessSelfState.events.Add(
                'assert-committed-state'
            )
        }
        function script:Remove-DefenseClawCommittedManagedHooksTeardownJournal {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            $script:HarnessSelfState.events.Add('retire-hook-journal')
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManagedHooksTeardownJournalPath) {
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                    -Force
            }
            return $null
        }
        function script:Set-DefenseClawSelfUninstallReceiptCommitted {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.PendingPath) {
                throw 'receipt committed before transaction completion'
            }
            $script:HarnessSelfState.events.Add('commit-receipt')
            $script:HarnessSelfState.receipt.phase =
                'committed_install_retirement'
            return $script:HarnessSelfState.receipt
        }
        function script:Test-DefenseClawSelfUninstallCallerRunning {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            return [bool]$script:HarnessSelfState.caller_running
        }
        function script:Ensure-DefenseClawSelfUninstallHelper {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessSelfState.events.Add('ensure-helper')
            [IO.File]::WriteAllText(
                $Layout.SelfUninstallHelperPath,
                '# authenticated harness helper',
                [Text.UTF8Encoding]::new($false)
            )
            return $Layout.SelfUninstallHelperPath
        }
        function script:Start-DefenseClawSelfUninstallHelper {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessSelfState.events.Add('start-helper')
            return $true
        }
        function script:Remove-DefenseClawRetiredInstallTree {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            $script:HarnessSelfState.events.Add('remove-retired-tree')
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath ([string]$Receipt.retired_install_root) `
                -Recurse `
                -Force
        }
        function script:Get-DefenseClawLifecycleStatus {
            param(
                [Parameter(Mandatory)][string]$Action,
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)][string]$GatewayServiceName,
                [Parameter(Mandatory)][string]$GuardianServiceName
            )
            return [pscustomobject]@{
                schema_version = 1
                ok = $true
                action = $Action.ToLowerInvariant()
                installed = $false
            }
        }

        # A transaction that created the Codex shared directories must be able to
        # unwind them. Its own serialization lock outlives the policy files it
        # guards, so the emptiness gate has to look past that one path and no
        # further.
        function Invoke-HarnessSharedDirectoryRollbackCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [bool]$WithLock = $false,
                [string]$ForeignFile = '',
                [bool]$ExpectFailure = $false
            )
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label ('shared-rollback-' + $Name)
            $layout = New-HarnessLayout -Root $root
            foreach ($directory in @(
                $layout.CodexVendorDirectory,
                $layout.CodexMachinePolicyDirectory
            )) {
                Microsoft.PowerShell.Management\New-Item `
                    -ItemType Directory `
                    -Path $directory `
                    -Force | Microsoft.PowerShell.Core\Out-Null
            }
            if ($WithLock) {
                [IO.File]::WriteAllBytes(
                    $layout.CodexManagedHooksLockPath,
                    [byte[]]@()
                )
            }
            if (-not [string]::IsNullOrWhiteSpace($ForeignFile)) {
                [IO.File]::WriteAllText(
                    (
                        Microsoft.PowerShell.Management\Join-Path `
                            $layout.CodexMachinePolicyDirectory `
                            $ForeignFile
                    ),
                    'foreign'
                )
            }
            $snapshot = [pscustomobject]@{
                created_shared_directories = @(
                    $layout.CodexVendorDirectory,
                    $layout.CodexMachinePolicyDirectory
                )
            }
            $failure = ''
            try {
                Remove-DefenseClawTransactionCreatedSharedDirectories `
                    -Snapshot $snapshot `
                    -Layout $layout
            }
            catch {
                $failure = [string]$_.Exception.Message
            }
            if ($ExpectFailure -and [string]::IsNullOrWhiteSpace($failure)) {
                throw "shared directory rollback case $Name removed a directory holding foreign content"
            }
            if (-not $ExpectFailure -and -not [string]::IsNullOrWhiteSpace($failure)) {
                throw "shared directory rollback case $Name failed: $failure"
            }
            $vendorRemains = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $layout.CodexVendorDirectory
            $policyRemains = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $layout.CodexMachinePolicyDirectory
            if (-not $ExpectFailure -and ($vendorRemains -or $policyRemains)) {
                throw "shared directory rollback case $Name left a transaction-created directory behind"
            }
            if ($ExpectFailure -and -not $policyRemains) {
                throw "shared directory rollback case $Name removed a directory it refused to clear"
            }
            $sharedDirectoryResults.Add([ordered]@{
                    name = $Name
                    lock_present = $WithLock
                    foreign_content = (
                        -not [string]::IsNullOrWhiteSpace($ForeignFile)
                    )
                    removed = (-not $vendorRemains -and -not $policyRemains)
                    failure = $failure
                }) | Microsoft.PowerShell.Core\Out-Null
        }

        function Invoke-HarnessSelfUninstallRecoveryCase {
            param(
                [Parameter(Mandatory)][string]$Name,
                [ValidateSet(
                    'prepared_install_retirement',
                    'committed_install_retirement'
                )]
                [string]$Phase,
                [ValidateSet(
                    'canonical-only',
                    'retired-only',
                    'both',
                    'neither'
                )]
                [string]$RootState,
                [bool]$Pending = $false,
                [bool]$CallerRunning = $false,
                [bool]$Purge = $false,
                [bool]$RemoveState = $false,
                [ValidateSet(
                    'Install',
                    'Upgrade',
                    'Repair',
                    'Uninstall',
                    'Status'
                )]
                [string]$Action = 'Uninstall',
                [bool]$ExpectFailure = $false,
                [bool]$ExpectHandled = $false,
                [bool]$ExpectCanonical = $false,
                [bool]$ExpectRetired = $false,
                [bool]$ExpectEvidence = $false,
                [string[]]$ExpectedEventOrder = @()
            )
            $root = New-HarnessCaseRoot `
                -Parent $TestRoot `
                -Label ('self-recovery-' + $Name)
            $layout = New-HarnessLayout -Root $root
            $retiredRoot = "$($layout.InstallRoot).retired-$(
                [Guid]::NewGuid().ToString('N')
            )"
            switch ($RootState) {
                'retired-only' {
                    [IO.Directory]::Move(
                        [string]$layout.InstallRoot,
                        $retiredRoot
                    )
                }
                'both' {
                    Microsoft.PowerShell.Management\New-Item `
                        -ItemType Directory `
                        -Path $retiredRoot `
                        -Force | Microsoft.PowerShell.Core\Out-Null
                }
                'neither' {
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $layout.InstallRoot `
                        -Recurse `
                        -Force
                }
            }
            if ($Pending) {
                [IO.File]::WriteAllText(
                    $layout.PendingPath,
                    '{"schema_version":1}',
                    [Text.UTF8Encoding]::new($false)
                )
            }
            if ($RemoveState) {
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $layout.StateRoot `
                    -Recurse `
                    -Force
            }
            $receipt = [pscustomobject][ordered]@{
                schema_version = 1
                phase = $Phase
                retired_install_root = $retiredRoot
                gateway_service = 'DefenseClawGateway'
                guardian_service = 'DefenseClawHookGuardian'
                purge_requested = $Purge
                helper_sha256 = ''
                tombstone_sha256 = ('a' * 64)
            }
            [IO.File]::WriteAllText(
                $layout.SelfUninstallReceiptPath,
                '{"authenticated":"harness"}',
                [Text.UTF8Encoding]::new($false)
            )
            $events = [Collections.Generic.List[string]]::new()
            $script:HarnessSelfState = @{
                layout = $layout
                receipt = $receipt
                caller_running = $CallerRunning
                events = $events
            }
            $failed = $false
            $recovery = $null
            try {
                $recovery = Invoke-DefenseClawSelfUninstallRecovery `
                    -Action $Action `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName 'DefenseClawHookGuardian' `
                    -Purge:$Purge
            }
            catch {
                $failed = $true
                if (-not $ExpectFailure) {
                    throw
                }
            }
            Assert-Harness `
                -Condition ($failed -eq $ExpectFailure) `
                -Message "$Name failure result did not match expectation"
            if (-not $failed) {
                Assert-Harness `
                    -Condition (
                        [bool]$recovery.handled -eq $ExpectHandled
                    ) `
                    -Message "$Name handled result did not match expectation"
            }
            $canonicalExists =
                Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.InstallRoot `
                    -PathType Container
            $retiredExists =
                Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $retiredRoot `
                    -PathType Container
            $evidenceExists =
                Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.SelfUninstallReceiptPath `
                    -PathType Leaf
            Assert-Harness `
                -Condition (
                    $canonicalExists -eq $ExpectCanonical -and
                    $retiredExists -eq $ExpectRetired -and
                    $evidenceExists -eq $ExpectEvidence
                ) `
                -Message "$Name did not preserve the expected root/evidence state"
            $lastEventIndex = -1
            foreach ($expectedEvent in $ExpectedEventOrder) {
                $eventIndex = $events.IndexOf($expectedEvent)
                Assert-Harness `
                    -Condition (
                        $eventIndex -gt $lastEventIndex
                    ) `
                    -Message (
                        "$Name did not preserve event order at " +
                        $expectedEvent
                    )
                $lastEventIndex = $eventIndex
            }
            if (-not $failed -and $ExpectHandled -and
                $CallerRunning) {
                Assert-Harness `
                    -Condition (
                        [bool]$recovery.result.
                            self_uninstall_cleanup_pending -and
                        [bool]$recovery.result.
                            canonical_install_root_absent -and
                        [bool]$recovery.result.
                            cached_enterprise_clients_require_reload
                    ) `
                    -Message "$Name omitted the installed-CLI handoff contract"
            }
            if (-not $failed -and $ExpectHandled -and
                $Purge -and $RemoveState) {
                Assert-Harness `
                    -Condition (
                        [bool]$recovery.result.purged -and
                        [bool]$recovery.result.
                            cached_enterprise_clients_require_reload
                    ) `
                    -Message "$Name omitted committed purge recovery fields"
            }
            $selfUninstallRecoveryResults.Add([pscustomobject]@{
                name = $Name
                failed_closed = $failed
                handled = $(if ($failed) {
                    $false
                } else {
                    [bool]$recovery.handled
                })
                events = @($events)
            })
        }

        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'prepared-pending-retired-rolls-back' `
            -Phase 'prepared_install_retirement' `
            -RootState 'retired-only' `
            -Pending:$true `
            -ExpectCanonical:$true `
            -ExpectRetired:$false `
            -ExpectEvidence:$false `
            -ExpectedEventOrder @(
                'move-retired-back',
                'remove-evidence'
            )
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'prepared-no-pending-promotes-commit' `
            -Phase 'prepared_install_retirement' `
            -RootState 'retired-only' `
            -ExpectCanonical:$false `
            -ExpectRetired:$false `
            -ExpectEvidence:$false `
            -ExpectedEventOrder @(
                'assert-committed-state',
                'retire-hook-journal',
                'commit-receipt',
                'remove-retired-tree',
                'remove-evidence'
            )
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'committed-running-helper-pending' `
            -Phase 'committed_install_retirement' `
            -RootState 'retired-only' `
            -CallerRunning:$true `
            -ExpectHandled:$true `
            -ExpectCanonical:$false `
            -ExpectRetired:$true `
            -ExpectEvidence:$true `
            -ExpectedEventOrder @(
                'assert-committed-state',
                'ensure-helper',
                'start-helper'
            )
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'committed-running-new-install-blocked' `
            -Phase 'committed_install_retirement' `
            -RootState 'retired-only' `
            -CallerRunning:$true `
            -Action 'Install' `
            -ExpectFailure:$true `
            -ExpectCanonical:$false `
            -ExpectRetired:$true `
            -ExpectEvidence:$true `
            -ExpectedEventOrder @(
                'assert-committed-state',
                'ensure-helper',
                'start-helper'
            )
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'both-roots-fail-closed' `
            -Phase 'committed_install_retirement' `
            -RootState 'both' `
            -ExpectFailure:$true `
            -ExpectCanonical:$true `
            -ExpectRetired:$true `
            -ExpectEvidence:$true
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'committed-dead-partial-subset-cleanup' `
            -Phase 'committed_install_retirement' `
            -RootState 'retired-only' `
            -ExpectCanonical:$false `
            -ExpectRetired:$false `
            -ExpectEvidence:$false `
            -ExpectedEventOrder @(
                'assert-committed-state',
                'remove-retired-tree',
                'remove-evidence'
            )
        Invoke-HarnessSelfUninstallRecoveryCase `
            -Name 'committed-purge-state-absent' `
            -Phase 'committed_install_retirement' `
            -RootState 'retired-only' `
            -Purge:$true `
            -RemoveState:$true `
            -ExpectHandled:$true `
            -ExpectCanonical:$false `
            -ExpectRetired:$false `
            -ExpectEvidence:$false `
            -ExpectedEventOrder @(
                'assert-committed-state',
                'remove-retired-tree',
                'remove-evidence'
            )

        Invoke-HarnessSharedDirectoryRollbackCase -Name 'empty'
        Invoke-HarnessSharedDirectoryRollbackCase `
            -Name 'serialization-lock-only' `
            -WithLock:$true
        Invoke-HarnessSharedDirectoryRollbackCase `
            -Name 'foreign-content-retained' `
            -WithLock:$true `
            -ForeignFile 'requirements.toml' `
            -ExpectFailure:$true

        # Blockers 039/040/043: exercise the crash-boundary decisions behind
        # the external fresh-install receipt and shared target-root rollback.
        # Native create/delete coverage remains in the focused Windows package;
        # these cases keep the lifecycle ordering and fail-closed transitions
        # visible in the complete PS 5.1/7 uninstall matrix.
        $installRollbackContractResults =
            [Collections.Generic.List[object]]::new()

        $replacementProbe = Microsoft.PowerShell.Management\Join-Path `
            $TestRoot `
            'manifest-replacement-probe.yaml'
        $samePathIsReplacement = [bool](
            & $script:HarnessRealSourceReplacementDecision `
                -Source @{path = $replacementProbe} `
                -Destination $replacementProbe
        )
        $distinctPathIsReplacement = [bool](
            & $script:HarnessRealSourceReplacementDecision `
                -Source @{path = $replacementProbe} `
                -Destination (Microsoft.PowerShell.Management\Join-Path `
                    $TestRoot `
                    'manifest-replacement-target.yaml')
        )
        Assert-Harness `
            -Condition (
                -not $samePathIsReplacement -and
                $distinctPathIsReplacement
            ) `
            -Message 'same-path manifest source can bypass validation-only ACL drift checks'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'same-path-manifest-remains-validation-only'
            same_path_replacement = $samePathIsReplacement
            distinct_path_replacement = $distinctPathIsReplacement
        })

        $legacyTimestampIntent = (
            [ordered]@{phase = 'rollback'} |
                Microsoft.PowerShell.Utility\ConvertTo-Json -Compress |
                Microsoft.PowerShell.Utility\ConvertFrom-Json
        )
        $legacyTimestampIntent =
            Assert-DefenseClawInstallRollbackIntentCommitTimestamp `
                -Intent $legacyTimestampIntent
        Assert-Harness `
            -Condition (
                $null -ne $legacyTimestampIntent.PSObject.Properties[
                    'committed_at'
                ] -and
                [string]$legacyTimestampIntent.committed_at -ceq ''
            ) `
            -Message 'legacy uncommitted receipt did not migrate committed_at'
        $invalidCommitTimestampsRejected = 0
        foreach ($invalidCommitIntent in @(
            [pscustomobject]@{phase = 'committed'},
            [pscustomobject]@{phase = 'committed'; committed_at = ''},
            [pscustomobject]@{
                phase = 'committed'
                committed_at = 'not-a-timestamp'
            },
            [pscustomobject]@{
                phase = 'preparing_layout'
                committed_at = ' '
            }
        )) {
            try {
                $null =
                    Assert-DefenseClawInstallRollbackIntentCommitTimestamp `
                        -Intent $invalidCommitIntent
            }
            catch {
                $invalidCommitTimestampsRejected++
            }
        }
        Assert-Harness `
            -Condition ($invalidCommitTimestampsRejected -eq 4) `
            -Message 'install receipt accepted an invalid phase/timestamp shape'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'legacy-v2-commit-timestamp-migration'
            missing_precommit_field_migrated = $true
            invalid_committed_shapes_rejected =
                $invalidCommitTimestampsRejected
        })

        $canonicalRootAcl = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $true `
            -Kind AdminDirectory `
            -GatewayServiceSID $script:AdministratorsSID
        $canonicalRootSnapshot = [pscustomobject]@{
            SecurityDescriptor =
                $canonicalRootAcl.GetSecurityDescriptorBinaryForm()
        }
        function script:Assert-DefenseClawManagedRootStagingAcl {
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$MarkerSID
            )
            $null = $Path
            $null = $MarkerSID
            if ([bool]$script:HarnessAcceptRootStagingDescriptor) {
                return [pscustomobject]@{
                    Identity = '00000001:0000000000000001'
                }
            }
            throw 'injected crash after canonical ACL publication'
        }
        $script:HarnessAcceptRootStagingDescriptor = $false
        $rollbackGatewaySID = 'S-1-5-80-1-2-3-4-5'
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'post-canonical-crash') `
            -Current $canonicalRootSnapshot `
            -CreationState staged `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind AdminDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        $unsafeRootAcl = [Security.AccessControl.DirectorySecurity]::new()
        $unsafeRootAcl.SetSecurityDescriptorSddlForm(
            'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)',
            [Security.AccessControl.AccessControlSections]::All
        )
        $unsafeCrashRejected = $false
        try {
            Assert-DefenseClawInstallRollbackRootDescriptor `
                -Path (Microsoft.PowerShell.Management\Join-Path `
                    $TestRoot `
                    'post-unsafe-crash') `
                -Current ([pscustomobject]@{
                    SecurityDescriptor =
                        $unsafeRootAcl.GetSecurityDescriptorBinaryForm()
                }) `
                -CreationState staged `
                -MarkerSID 'S-1-5-21-1-2-3-4' `
                -ExpectedKind AdminDirectory `
                -GatewayServiceSID $rollbackGatewaySID
        }
        catch {
            $unsafeCrashRejected = $true
        }
        Assert-Harness `
            -Condition $unsafeCrashRejected `
            -Message 'staged receipt accepted a noncanonical post-publication DACL'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'staged-to-canonical-crash-window'
            canonical_inode_accepted = $true
            noncanonical_inode_rejected = $unsafeCrashRejected
        })

        function Test-HarnessRollbackRootDescriptorRejected {
            param(
                [Parameter(Mandatory)]$Current,
                [Parameter(Mandatory)][string]$CreationState,
                [Parameter(Mandatory)][string]$ExpectedKind,
                [Parameter(Mandatory)][string]$GatewayServiceSID,
                [switch]$AllowPostManagedAcl
            )
            try {
                Assert-DefenseClawInstallRollbackRootDescriptor `
                    -Path (Microsoft.PowerShell.Management\Join-Path `
                        $TestRoot `
                        'descriptor-matrix') `
                    -Current $Current `
                    -CreationState $CreationState `
                    -MarkerSID 'S-1-5-21-1-2-3-4' `
                    -ExpectedKind $ExpectedKind `
                    -GatewayServiceSID $GatewayServiceSID `
                    -AllowPostManagedAcl:$AllowPostManagedAcl
                return $false
            }
            catch {
                return $true
            }
        }

        $installLiveAcl = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $true `
            -Kind ServiceInstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        $installLiveSnapshot = [pscustomobject]@{
            SecurityDescriptor =
                $installLiveAcl.GetSecurityDescriptorBinaryForm()
        }
        $stateLiveAcl = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $true `
            -Kind StateDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        $stateLiveSnapshot = [pscustomobject]@{
            SecurityDescriptor = $stateLiveAcl.GetSecurityDescriptorBinaryForm()
        }
        $foreignLiveAcl = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $true `
            -Kind ServiceInstallDirectory `
            -GatewayServiceSID 'S-1-5-80-6-7-8-9-10'
        $foreignLiveSnapshot = [pscustomobject]@{
            SecurityDescriptor =
                $foreignLiveAcl.GetSecurityDescriptorBinaryForm()
        }

        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'install-live') `
            -Current $installLiveSnapshot `
            -CreationState canonical `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind InstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID `
            -AllowPostManagedAcl
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'state-live') `
            -Current $stateLiveSnapshot `
            -CreationState canonical `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind AdminDirectory `
            -GatewayServiceSID $rollbackGatewaySID `
            -AllowPostManagedAcl
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'install-quarantined') `
            -Current $canonicalRootSnapshot `
            -CreationState quarantined `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind InstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'install-staged-quarantine-crash') `
            -Current $canonicalRootSnapshot `
            -CreationState staged `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind InstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'install-canonical-quarantine-crash') `
            -Current $canonicalRootSnapshot `
            -CreationState canonical `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind InstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID

        $script:HarnessAcceptRootStagingDescriptor = $true
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path (Microsoft.PowerShell.Management\Join-Path `
                $TestRoot `
                'planned-staging') `
            -Current $canonicalRootSnapshot `
            -CreationState planned `
            -MarkerSID 'S-1-5-21-1-2-3-4' `
            -ExpectedKind InstallDirectory `
            -GatewayServiceSID $rollbackGatewaySID
        $script:HarnessAcceptRootStagingDescriptor = $false

        $plannedBootstrapRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $canonicalRootSnapshot `
                -CreationState planned `
                -ExpectedKind AdminDirectory `
                -GatewayServiceSID $rollbackGatewaySID
        $stagedLiveRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $installLiveSnapshot `
                -CreationState staged `
                -ExpectedKind InstallDirectory `
                -GatewayServiceSID $rollbackGatewaySID
        $unboundLiveRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $installLiveSnapshot `
                -CreationState canonical `
                -ExpectedKind InstallDirectory `
                -GatewayServiceSID $rollbackGatewaySID
        $foreignSIDRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $foreignLiveSnapshot `
                -CreationState canonical `
                -ExpectedKind InstallDirectory `
                -GatewayServiceSID $rollbackGatewaySID `
                -AllowPostManagedAcl
        $swappedKindRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $installLiveSnapshot `
                -CreationState canonical `
                -ExpectedKind AdminDirectory `
                -GatewayServiceSID $rollbackGatewaySID `
                -AllowPostManagedAcl
        $quarantinedLiveRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current $installLiveSnapshot `
                -CreationState quarantined `
                -ExpectedKind InstallDirectory `
                -GatewayServiceSID $rollbackGatewaySID
        $inheritedAcl = [Security.AccessControl.DirectorySecurity]::new()
        $inheritedAcl.SetSecurityDescriptorSddlForm(
            'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',
            [Security.AccessControl.AccessControlSections]::All
        )
        $inheritedAclRejected =
            Test-HarnessRollbackRootDescriptorRejected `
                -Current ([pscustomobject]@{
                    SecurityDescriptor =
                        $inheritedAcl.GetSecurityDescriptorBinaryForm()
                }) `
                -CreationState canonical `
                -ExpectedKind AdminDirectory `
                -GatewayServiceSID $rollbackGatewaySID `
                -AllowPostManagedAcl
        Assert-Harness `
            -Condition (
                $plannedBootstrapRejected -and
                $stagedLiveRejected -and
                $unboundLiveRejected -and
                $foreignSIDRejected -and
                $swappedKindRejected -and
                $quarantinedLiveRejected -and
                $inheritedAclRejected
            ) `
            -Message 'rollback root descriptor phase/SID allowlist accepted drift'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'phase-bound-live-root-descriptor-matrix'
            planned_staging_only = $plannedBootstrapRejected
            staged_live_rejected = $stagedLiveRejected
            canonical_live_exact = $true
            unbound_live_rejected = $unboundLiveRejected
            wrong_sid_rejected = $foreignSIDRejected
            swapped_kind_rejected = $swappedKindRejected
            staged_quarantine_reentry_exact = $true
            canonical_quarantine_reentry_exact = $true
            quarantined_live_rejected = $quarantinedLiveRejected
            inherited_acl_rejected = $inheritedAclRejected
        })

        $productionState = Microsoft.PowerShell.Management\Join-Path `
            $TestRoot `
            'production-state'
        $productionIPC = Microsoft.PowerShell.Management\Join-Path `
            $productionState `
            'ipc'
        Assert-DefenseClawTargetRuntimeProductionChildrenExclusive `
            -ProductionState $productionState `
            -Children @([pscustomobject]@{FullName = $productionIPC})
        $productionChildRejected = $false
        try {
            Assert-DefenseClawTargetRuntimeProductionChildrenExclusive `
                -ProductionState $productionState `
                -Children @(
                    [pscustomobject]@{FullName = $productionIPC},
                    [pscustomobject]@{
                        FullName = (
                            Microsoft.PowerShell.Management\Join-Path `
                                $productionState `
                                'install'
                        )
                    }
                )
        }
        catch {
            $productionChildRejected = $true
        }
        Assert-Harness `
            -Condition $productionChildRejected `
            -Message 'shared target cleanup accepted non-IPC production state'
        $allCanonicalPlan = [pscustomobject]@{
            roots = @([pscustomobject]@{baseline = 'canonical'})
        }
        $absentPlan = [pscustomobject]@{
            roots = @([pscustomobject]@{baseline = 'absent'})
        }
        Assert-Harness `
            -Condition (
                -not (Test-DefenseClawTargetRuntimePlanRequiresExclusiveCleanup `
                    -Plan $allCanonicalPlan) -and
                (Test-DefenseClawTargetRuntimePlanRequiresExclusiveCleanup `
                    -Plan $absentPlan)
            ) `
            -Message 'target runtime cleanup coexistence gate ignored baseline ownership'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'production-root-coexistence-gate'
            ipc_only_allowed = $true
            foreign_child_rejected = $productionChildRejected
            canonical_only_plan_is_validation_only = $true
        })

        $targetPreparationModes = [ordered]@{
            Install = 'prepare'
            Upgrade = 'validate'
            Repair = 'validate'
        }
        foreach ($installLikeAction in $targetPreparationModes.Keys) {
            $actualPreparationMode =
                Get-DefenseClawTargetRuntimePreparationMode `
                    -Action $installLikeAction `
                    -ManifestPresent $true
            Assert-Harness `
                -Condition (
                    $actualPreparationMode -ceq
                        [string]$targetPreparationModes[$installLikeAction]
                ) `
                -Message (
                    "$installLikeAction target runtime mode was " +
                    "$actualPreparationMode, expected " +
                    [string]$targetPreparationModes[$installLikeAction]
                )
        }
        $lowercaseInstallPreparationMode =
            Get-DefenseClawTargetRuntimePreparationMode `
                -Action install `
                -ManifestPresent $true
        Assert-Harness `
            -Condition ($lowercaseInstallPreparationMode -ceq 'prepare') `
            -Message 'lowercase Install action skipped target preparation'
        $missingManifestRejected = $false
        try {
            $null = Get-DefenseClawTargetRuntimePreparationMode `
                -Action Install `
                -ManifestPresent $false
        }
        catch {
            $missingManifestRejected = [bool](
                $_.Exception.Message -like
                    '*requires an authenticated installed targets.yaml*'
            )
        }
        Assert-Harness `
            -Condition $missingManifestRejected `
            -Message 'manifest-free Install skipped target preparation'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'bounded-install-like-target-preparation'
            install = 'prepare'
            upgrade = 'validate'
            repair = 'validate'
            lowercase_install = 'prepare'
            missing_manifest = 'rejected'
        })

        $targetRuntimeDiagnostic =
            Get-DefenseClawTargetRuntimeProbeFailureMessage `
                -Phase planning `
                -Probe ([pscustomobject]@{
                    exit_code = 1
                    output = @(
                        'manifest ACL rejected token=diagnostic-secret ' +
                        [Environment]::NewLine +
                        '{"client_secret":"json-secret"} ' +
                        ('x' * 5000)
                    )
                })
        Assert-Harness `
            -Condition (
                $targetRuntimeDiagnostic -like
                    '*manifest ACL rejected token=<redacted>*' -and
                $targetRuntimeDiagnostic -notlike '*diagnostic-secret*' -and
                $targetRuntimeDiagnostic -notlike '*json-secret*' -and
                $targetRuntimeDiagnostic -notmatch '[\r\n]' -and
                $targetRuntimeDiagnostic.Length -le 2150
            ) `
            -Message 'target runtime failure diagnostic was hidden, unbounded, or unsafe'
        $emptyTargetRuntimeDiagnostic =
            Get-DefenseClawTargetRuntimeProbeFailureMessage `
                -Phase finalization `
                -Probe ([pscustomobject]@{
                    exit_code = 7
                    output = @()
                })
        Assert-Harness `
            -Condition ($emptyTargetRuntimeDiagnostic -ceq
                'target runtime finalization failed with exit 7: unavailable') `
            -Message 'empty target runtime output did not produce a safe diagnostic'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'bounded-redacted-target-runtime-diagnostic'
            captured_error_visible = $true
            credential_redacted = $true
            bounded = $true
        })

        # ConvertFrom-Json yields a fixed PSCustomObject shape on both Windows
        # PowerShell 5.1 and PowerShell 7. Model a legacy/restored transaction
        # that predates created_target_runtime_roots, then exercise both the
        # first live-claim publication and terminal cleanup replacement.
        $legacySchemaRoot = New-HarnessCaseRoot `
            -Parent $TestRoot `
            -Label 'legacy-target-runtime-schema'
        $legacySchemaLayout = New-HarnessLayout -Root $legacySchemaRoot
        Assert-Harness `
            -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $legacySchemaLayout.InstallRollbackIntentPath)) `
            -Message 'legacy schema fixture unexpectedly has rollback intent'
        $legacySchemaSnapshot = Microsoft.PowerShell.Management\Join-Path `
            $legacySchemaLayout.StateRoot `
            'legacy-target-runtime-snapshot.json'
        [IO.File]::WriteAllText(
            $legacySchemaSnapshot,
            (
                [ordered]@{
                    schema_version = 1
                    gateway_service = 'DefenseClawGateway'
                    guardian_service = 'DefenseClawHookGuardian'
                    created_shared_directories = @()
                } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json `
                        -Depth 6 `
                        -Compress
            ),
            [Text.UTF8Encoding]::new($false)
        )
        $legacyOriginal = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $legacySchemaSnapshot `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        Assert-Harness `
            -Condition (
                $null -eq $legacyOriginal.PSObject.Properties[
                    'created_target_runtime_roots'
                ]
            ) `
            -Message 'legacy transaction fixture unexpectedly has runtime claims'
        $legacyLiveClaim = [pscustomobject]@{
            user_home = 'C:\Users\Alice'
            data_dir = 'C:\Users\Alice\.defenseclaw'
            sid = 'S-1-5-21-111-222-333-1001'
            identity = '00000001:0000000000000001'
            created = $true
            state = 'staged'
        }
        $legacyStageReport = Assert-DefenseClawTargetRuntimeReport `
            -Report ([pscustomobject]@{
                schema_version = 1
                action = 'stage'
                ok = $true
                claims = @($legacyLiveClaim)
            }) `
            -Action stage `
            -JournalProjection
        [void](Set-DefenseClawTargetRuntimeTransactionState `
            -SnapshotPath $legacySchemaSnapshot `
            -Layout $legacySchemaLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -StageReport $legacyStageReport)
        $legacyStaged = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $legacySchemaSnapshot `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $legacyClaimsProperty = $legacyStaged.PSObject.Properties[
            'created_target_runtime_roots'
        ]
        Assert-Harness `
            -Condition ($null -ne $legacyClaimsProperty) `
            -Message 'legacy transaction did not add its runtime-claim property'
        $legacyClaims = @($legacyClaimsProperty.Value)
        Assert-Harness `
            -Condition (
                $legacyClaims.Count -eq 1 -and
                [string]$legacyClaims[0].state -ceq 'staged'
            ) `
            -Message 'legacy transaction could not add its first runtime claim'
        $legacyCleanupReport = Assert-DefenseClawTargetRuntimeReport `
            -Report ([pscustomobject]@{
                schema_version = 1
                action = 'cleanup'
                ok = $true
                claims = @([pscustomobject]@{
                    user_home = 'C:\Users\Alice'
                    data_dir = 'C:\Users\Alice\.defenseclaw'
                    sid = 'S-1-5-21-111-222-333-1001'
                    created = $false
                    state = 'absent'
                })
            }) `
            -Action cleanup
        [void](Set-DefenseClawTargetRuntimeTransactionState `
            -SnapshotPath $legacySchemaSnapshot `
            -Layout $legacySchemaLayout `
            -GatewayServiceName 'DefenseClawGateway' `
            -GuardianServiceName 'DefenseClawHookGuardian' `
            -CleanupReport $legacyCleanupReport)
        $legacyCleaned = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $legacySchemaSnapshot `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $legacyCleanedProperty = $legacyCleaned.PSObject.Properties[
            'created_target_runtime_roots'
        ]
        Assert-Harness `
            -Condition ($null -ne $legacyCleanedProperty) `
            -Message 'cleanup removed the runtime-claim property'
        Assert-Harness `
            -Condition (@($legacyCleanedProperty.Value).Count -eq 0) `
            -Message 'legacy transaction retained claims after exact cleanup'
        Assert-Harness `
            -Condition (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $legacySchemaLayout.InstallRollbackIntentPath)) `
            -Message 'schema upsert accidentally published rollback intent'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'legacy-restored-target-runtime-schema-upsert'
            missing_property_added = $true
            live_claim_replaced_by_cleanup = $true
            json_round_trip = $true
        })

        $twoRootPlan = [pscustomobject]@{
            roots = @(
                [pscustomobject]@{baseline = 'absent'},
                [pscustomobject]@{baseline = 'absent'}
            )
        }
        $partialCleanup = [pscustomobject]@{
            ok = $false
            claims = @([pscustomobject]@{state = 'absent'})
        }
        $completeCleanup = [pscustomobject]@{
            ok = $true
            claims = @(
                [pscustomobject]@{state = 'absent'},
                [pscustomobject]@{state = 'absent'}
            )
        }
        Assert-Harness `
            -Condition (
                -not (Test-DefenseClawTargetRuntimeReportComplete `
                    -Plan $twoRootPlan `
                    -Report $partialCleanup) -and
                (Test-DefenseClawTargetRuntimeReportComplete `
                    -Plan $twoRootPlan `
                    -Report $completeCleanup)
            ) `
            -Message 'partial target cleanup became terminal before successful retry'
        $cleanupSource = [string](
            Microsoft.PowerShell.Core\Get-Command `
                -Name Invoke-DefenseClawTargetRuntimeRollbackCleanup `
                -CommandType Function
        ).ScriptBlock
        $cleanupFailureGate = $cleanupSource.IndexOf(
            'target runtime rollback cleanup failed',
            [StringComparison]::Ordinal
        )
        $cleanupJournalUpdate = $cleanupSource.IndexOf(
            'Set-DefenseClawTargetRuntimeTransactionState',
            [StringComparison]::Ordinal
        )
        Assert-Harness `
            -Condition (
                $cleanupFailureGate -ge 0 -and
                $cleanupJournalUpdate -gt $cleanupFailureGate
            ) `
            -Message 'partial target cleanup can replace live rollback claims'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'multi-root-cleanup-failure-retries'
            partial_report_terminal = $false
            full_retry_terminal = $true
            prior_live_claims_retained = $true
        })

        function script:Test-DefenseClawServiceExists {
            param([Parameter(Mandatory)][string]$Name)
            throw "injected SCM access failure for $Name"
        }
        $noFreshCleanupSnapshot = [pscustomobject]@{
            gateway_service = 'DefenseClawGateway'
            guardian_service = 'DefenseClawHookGuardian'
            install_root_created = $false
            install_root_identity = '00000001:0000000000000001'
            state_root_created = $false
            state_root_identity = '00000002:0000000000000002'
            created_target_runtime_roots = @()
        }
        $noFreshCleanupIntent = Publish-DefenseClawInstallRollbackIntent `
            -Snapshot $noFreshCleanupSnapshot `
            -Layout $legacySchemaLayout
        Assert-Harness `
            -Condition (
                $null -eq $noFreshCleanupIntent -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $legacySchemaLayout.InstallRollbackIntentPath)
            ) `
            -Message (
                'Repair/Upgrade rollback queried restored services without ' +
                'fresh-install cleanup authority'
            )
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'existing-deployment-rollback-skips-fresh-root-absence-gate'
            fresh_cleanup_authority = $false
            service_absence_queried = $false
            receipt_published = $false
        })

        $freshCleanupSnapshot = [pscustomobject]@{
            gateway_service = 'DefenseClawGateway'
            guardian_service = 'DefenseClawHookGuardian'
            install_root_created = $true
            install_root_identity = '00000001:0000000000000001'
            state_root_created = $false
            state_root_identity = '00000002:0000000000000002'
            created_target_runtime_roots = @()
        }
        $freshCleanupServiceGateClosed = $false
        try {
            $null = Publish-DefenseClawInstallRollbackIntent `
                -Snapshot $freshCleanupSnapshot `
                -Layout $legacySchemaLayout
        }
        catch {
            $freshCleanupServiceGateClosed = [bool](
                $_.Exception.Message -like '*injected SCM access failure*'
            )
        }
        Assert-Harness `
            -Condition (
                $freshCleanupServiceGateClosed -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $legacySchemaLayout.InstallRollbackIntentPath)
            ) `
            -Message 'fresh-install cleanup authority bypassed the service-absence gate'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'fresh-root-authority-still-requires-service-absence'
            fresh_cleanup_authority = $true
            service_query_failure_propagated = $freshCleanupServiceGateClosed
            receipt_published = $false
        })

        $scmFailureClosed = $false
        try {
            Assert-DefenseClawServicesAbsentChecked `
                -Names @('DefenseClawGateway') `
                -Operation 'injected destructive cleanup'
        }
        catch {
            $scmFailureClosed = $true
        }
        $rootCleanupSource = [string](
            Microsoft.PowerShell.Core\Get-Command `
                -Name Complete-DefenseClawInstallRollbackIntent `
                -CommandType Function
        ).ScriptBlock
        $checkedAbsenceIndex = $rootCleanupSource.IndexOf(
            'Assert-DefenseClawServicesAbsentChecked',
            [StringComparison]::Ordinal
        )
        $quarantineIndex = $rootCleanupSource.IndexOf(
            'SetDirectoryDaclNoFollow',
            [StringComparison]::Ordinal
        )
        $rootMutationIndex = $rootCleanupSource.IndexOf(
            'Remove-DefenseClawManagedTree',
            [StringComparison]::Ordinal
        )
        Assert-Harness `
            -Condition (
                $scmFailureClosed -and
                $checkedAbsenceIndex -ge 0 -and
                $quarantineIndex -gt $checkedAbsenceIndex -and
                $rootMutationIndex -gt $quarantineIndex
            ) `
            -Message 'SCM query failure can reach destructive root cleanup'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'scm-query-failure-before-root-mutation'
            query_failure_propagated = $scmFailureClosed
            root_mutation_reached = $false
        })

        $preLayoutSource = [string](
            Microsoft.PowerShell.Core\Get-Command `
                -Name Invoke-DefenseClawPreLayoutRecovery `
                -CommandType Function
        ).ScriptBlock
        $enterpriseSource = [string](
            Microsoft.PowerShell.Core\Get-Command `
                -Name Invoke-DefenseClawEnterpriseLifecycle `
                -CommandType Function
        ).ScriptBlock
        $pendingMarker = $preLayoutSource.IndexOf(
            'Repair and Upgrade transactions predate',
            [StringComparison]::Ordinal
        )
        $pendingRecoveryIndex = if ($pendingMarker -ge 0) {
            $preLayoutSource.IndexOf(
                'Recover-DefenseClawPendingTransaction',
                $pendingMarker,
                [StringComparison]::Ordinal
            )
        }
        else {
            -1
        }
        $preLayoutIndex = $enterpriseSource.IndexOf(
            'Invoke-DefenseClawPreLayoutRecovery',
            [StringComparison]::Ordinal
        )
        $newReceiptIndex = $enterpriseSource.IndexOf(
            'New-DefenseClawInstallPreparationIntent',
            [StringComparison]::Ordinal
        )
        Assert-Harness `
            -Condition (
                $pendingMarker -ge 0 -and
                $pendingRecoveryIndex -gt $pendingMarker -and
                $preLayoutIndex -ge 0 -and
                $newReceiptIndex -gt $preLayoutIndex
            ) `
            -Message 'old pending transaction is not recovered before new Install authority'
        foreach ($priorAction in @('Repair', 'Upgrade')) {
            $installRollbackContractResults.Add([pscustomobject]@{
                name = ($priorAction.ToLowerInvariant() + '-crash-then-install')
                old_pending_recovered_before_new_receipt = $true
            })
        }

        $deferredModuleGate = $enterpriseSource.IndexOf(
            '-DeferredConfig is temporarily unavailable',
            [StringComparison]::Ordinal
        )
        $deferredModuleInvocationRejected = $false
        try {
            $null = Invoke-DefenseClawEnterpriseLifecycle `
                -Action Install `
                -DeferredConfig
        }
        catch {
            $deferredModuleInvocationRejected = [bool](
                $_.Exception.Message -like
                    '*-DeferredConfig is temporarily unavailable*'
            )
        }
        Assert-Harness `
            -Condition $deferredModuleInvocationRejected `
            -Message 'module invocation did not reject deferred config at entry'
        $moduleLayoutResolution = $enterpriseSource.IndexOf(
            'Resolve-DefenseClawCertificationCodexHome',
            [StringComparison]::Ordinal
        )
        $bootstrapInstallerSource = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $InstallerPath `
            -Raw
        $deferredBootstrapGate = $bootstrapInstallerSource.IndexOf(
            '-DeferredConfig is temporarily unavailable',
            [StringComparison]::Ordinal
        )
        $bootstrapEnvironmentCreation = $bootstrapInstallerSource.IndexOf(
            '$bootstrapEnvironment = New-DefenseClawBootstrapEnvironment',
            [StringComparison]::Ordinal
        )
        Assert-Harness `
            -Condition (
                $deferredModuleGate -ge 0 -and
                $moduleLayoutResolution -gt $deferredModuleGate -and
                $deferredBootstrapGate -ge 0 -and
                $bootstrapEnvironmentCreation -gt $deferredBootstrapGate
            ) `
            -Message 'deferred config can reach layout or bootstrap mutation'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'deferred-config-rejected-before-mutation'
            bootstrap_gate_precedes_environment = $true
            module_gate_precedes_layout = $true
            module_invocation_rejected = $deferredModuleInvocationRejected
        })

        $boundedFixtureRoot = Microsoft.PowerShell.Management\Join-Path `
            $TestRoot `
            'c999'
        $boundedLayout = New-HarnessLayout -Root $boundedFixtureRoot
        # Keep every Windows component below 255 characters. PowerShell 7 can
        # validate a nested long-path payload large enough to prove the raised
        # receipt bound; Windows PowerShell 5.1 uses one identical valid
        # component so its legacy MAX_PATH implementation can run the same
        # schema/uniqueness assertions authoritatively.
        $longProfileStem = ('a' * 180) -join ''
        $longPathComponentCount = if (
            $PSVersionTable.PSVersion.Major -ge 7
        ) {
            5
        }
        else {
            1
        }
        $boundedRoots = [Collections.Generic.List[object]]::new()
        $boundedClaims = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt 128; $index++) {
            $suffix = '{0:d3}' -f $index
            $profileComponents = [Collections.Generic.List[string]]::new()
            for (
                $componentIndex = 0;
                $componentIndex -lt $longPathComponentCount;
                $componentIndex++
            ) {
                $componentPrefix = if ($componentIndex -eq 0) {
                    'u' + $suffix + '-'
                }
                else {
                    'p' + $componentIndex + '-'
                }
                $profileComponents.Add(
                    $componentPrefix + $longProfileStem
                )
            }
            $home = 'C:\Users\' + ($profileComponents -join '\')
            $data = $home + '\.defenseclaw'
            $sid = 'S-1-5-21-100-200-300-' + (1000 + $index)
            $boundedRoots.Add([ordered]@{
                user_home = $home
                data_dir = $data
                sid = $sid
                baseline = 'absent'
                staging_leaf =
                    '.defenseclaw.setup-' + ('{0:x32}' -f ($index + 1))
                marker_sid = 'S-1-5-21-1-2-3-4-5-6-7-' + (10 + $index)
            })
            $boundedClaims.Add([ordered]@{
                user_home = $home
                data_dir = $data
                sid = $sid
                identity = ('00000001:{0:x16}' -f ($index + 1))
                created = $true
                state = 'canonical'
            })
        }
        $boundedPlan = [ordered]@{
            schema_version = 1
            manifest_path = [string]$boundedLayout.ManifestPath
            manifest_sha256 = (('a' * 64) -join '')
            roots = @($boundedRoots)
        }
        $boundedReport = [ordered]@{
            schema_version = 1
            action = 'finalize'
            ok = $true
            claims = @($boundedClaims)
        }
        $boundedPlan = (
            $boundedPlan |
                Microsoft.PowerShell.Utility\ConvertTo-Json `
                    -Depth 12 `
                    -Compress |
                Microsoft.PowerShell.Utility\ConvertFrom-Json
        )
        $boundedReport = (
            $boundedReport |
                Microsoft.PowerShell.Utility\ConvertTo-Json `
                    -Depth 12 `
                    -Compress |
                Microsoft.PowerShell.Utility\ConvertFrom-Json
        )
        $boundedPlan = Assert-DefenseClawTargetRuntimePlan `
            -Plan $boundedPlan `
            -Layout $boundedLayout
        $boundedReport = Assert-DefenseClawTargetRuntimeReport `
            -Report $boundedReport `
            -Action finalize `
            -Plan $boundedPlan `
            -JournalProjection
        $planBytes = [Text.Encoding]::UTF8.GetByteCount(
            ($boundedPlan |
                Microsoft.PowerShell.Utility\ConvertTo-Json `
                    -Depth 12 `
                    -Compress)
        )
        $reportBytes = [Text.Encoding]::UTF8.GetByteCount(
            ($boundedReport |
                Microsoft.PowerShell.Utility\ConvertTo-Json `
                    -Depth 12 `
                    -Compress)
        )
        Assert-Harness `
            -Condition ($planBytes -le 1048576 -and $reportBytes -le 1048576) `
            -Message 'max-root long-path fixture exceeds CLI exchange bounds'
        $boundedIntent = [ordered]@{
            schema_version = 2
            phase = 'preparing_layout'
            target_runtime_plan = $boundedPlan
            created_target_runtime_roots = @($boundedReport.claims)
        }
        $boundedIntentJson = ConvertTo-DefenseClawInstallRollbackIntentJson `
            -Intent $boundedIntent
        $roundTrippedIntent = $boundedIntentJson |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
        $boundedIntentBytes =
            [Text.Encoding]::UTF8.GetByteCount($boundedIntentJson)
        $expandedBoundExercised = [bool](
            $PSVersionTable.PSVersion.Major -lt 7 -or
            $boundedIntentBytes -gt 262144
        )
        Assert-Harness `
            -Condition (
                $boundedIntentBytes -le 3145728 -and
                $expandedBoundExercised -and
                @($roundTrippedIntent.target_runtime_plan.roots).Count -eq
                    128 -and
                @($roundTrippedIntent.created_target_runtime_roots).Count -eq
                    128
            ) `
            -Message 'bounded max-root install receipt does not round-trip'
        $installRollbackContractResults.Add([pscustomobject]@{
            name = 'max-root-long-path-receipt-roundtrip'
            roots = 128
            path_components = $longPathComponentCount
            plan_bytes = $planBytes
            report_bytes = $reportBytes
            receipt_bytes = $boundedIntentBytes
            expanded_bound_exercised = $expandedBoundExercised
        })

        $coverageStartedAfter = [DateTime]::UtcNow.AddMinutes(-1)
        $coverageGeneration = [DateTime]::UtcNow.ToString('o')
        $coverageDigest = ('a' * 64) -join ''
        $coveragePriorID = ('b' * 32) -join ''
        $coverageFreshID = ('c' * 32) -join ''
        $coveragePriorStateIdentity = '00000001:0000000000000001'
        $coverageFreshStateIdentity = '00000001:0000000000000002'
        $coverageState = [pscustomobject][ordered]@{
            version = 1
            updated_at = $coverageGeneration
        }
        $coverageAuthorization = [pscustomobject][ordered]@{
            version = 1
            updated_at = $coverageGeneration
        }
        $coverageActivation = [pscustomobject][ordered]@{
            version = 1
            updated_at = $coverageGeneration
            reconcile_id = $coverageFreshID
            manifest_sha256 = $coverageDigest
        }
        $coverageReport = [pscustomobject][ordered]@{
            ok = $true
            state = $coverageState
            authorization = $coverageAuthorization
            activation = $coverageActivation
            errors = @()
        }
        $acceptedCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $coverageReport `
            -PriorReconcileID $coveragePriorID `
            -ExpectedManifestSHA256 $coverageDigest `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition ([bool]$acceptedCoverage.ok) `
            -Message 'fresh exact Guardian coverage was rejected'

        $coverageReport.activation.reconcile_id = $coveragePriorID
        $staleCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $coverageReport `
            -PriorReconcileID $coveragePriorID `
            -ExpectedManifestSHA256 $coverageDigest `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition (-not [bool]$staleCoverage.ok) `
            -Message 'stale Guardian reconcile ID was accepted'

        $coverageReport.activation.reconcile_id = $coverageFreshID
        $wrongDigestCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $coverageReport `
            -PriorReconcileID $coveragePriorID `
            -ExpectedManifestSHA256 (('d' * 64) -join '') `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition (-not [bool]$wrongDigestCoverage.ok) `
            -Message 'wrong Guardian manifest digest was accepted'

        $missingActivationReport = [pscustomobject][ordered]@{
            ok = $true
            state = $coverageState
            authorization = $coverageAuthorization
            errors = @()
        }
        $missingActivationCoverage =
            Test-DefenseClawGuardianCoverageReport `
                -Report $missingActivationReport `
                -PriorReconcileID $coveragePriorID `
                -ExpectedManifestSHA256 $coverageDigest `
                -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition (-not [bool]$missingActivationCoverage.ok) `
            -Message 'missing exact Guardian activation was accepted'

        $legacyReport = [pscustomobject][ordered]@{
            ok = $true
            state = $coverageState
            authorization = $coverageAuthorization
            errors = @()
        }
        $legacyCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $legacyReport `
            -PriorGeneration ([DateTime]::UtcNow.AddMinutes(-2).ToString('o')) `
            -PriorStateIdentity $coveragePriorStateIdentity `
            -CurrentStateIdentity $coverageFreshStateIdentity `
            -ExpectedManifestSHA256 '' `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition ([bool]$legacyCoverage.ok) `
            -Message 'rollback-compatible fresh v1 Guardian coverage was rejected'
        $staleLegacyCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $legacyReport `
            -PriorGeneration $coverageGeneration `
            -PriorStateIdentity $coveragePriorStateIdentity `
            -CurrentStateIdentity $coverageFreshStateIdentity `
            -ExpectedManifestSHA256 '' `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition (-not [bool]$staleLegacyCoverage.ok) `
            -Message 'stale rollback-compatible v1 Guardian coverage was accepted'
        $sameInodeLegacyCoverage = Test-DefenseClawGuardianCoverageReport `
            -Report $legacyReport `
            -PriorGeneration ([DateTime]::UtcNow.AddMinutes(-2).ToString('o')) `
            -PriorStateIdentity $coveragePriorStateIdentity `
            -CurrentStateIdentity $coveragePriorStateIdentity `
            -ExpectedManifestSHA256 '' `
            -StartedAfter $coverageStartedAfter
        Assert-Harness `
            -Condition (-not [bool]$sameInodeLegacyCoverage.ok) `
            -Message 'same-inode rollback-compatible v1 Guardian coverage was accepted'

        return [pscustomobject]@{
            schema_version = 1
            ok = $true
            shared_directory_cases = @($sharedDirectoryResults)
            recovery_cases = @($recoveryResults)
            quiescing_cases = @($quiescingResults)
            uninstall_cases = @($uninstallResults)
            purge_cases = @($purgeResults)
            self_uninstall_recovery_cases = @(
                $selfUninstallRecoveryResults
            )
            install_rollback_contract_cases = @(
                $installRollbackContractResults
            )
        }
    } $testRoot $installerPath

    $resultItems = @($result)
    if ($resultItems.Count -ne 1) {
        throw (
            'uninstall transaction smoke emitted ' +
            "$($resultItems.Count) report objects, expected exactly one"
        )
    }
    $resultItems[0] |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress
}
finally {
    Microsoft.PowerShell.Core\Remove-Module `
        -Name DefenseClawEnterprise `
        -Force `
        -ErrorAction SilentlyContinue
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $testRoot) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $testRoot `
            -Recurse `
            -Force
    }
}
