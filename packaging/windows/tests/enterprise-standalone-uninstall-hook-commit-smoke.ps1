# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# A standalone uninstall keeps every managed hook registered while the
# lifecycle transaction is pending, even if its Setup process tree or CLI
# caller disappears. The committed tombstone permits teardown on retry.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath(),
    [switch]$ChildHold
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = [IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
if ($ChildHold) {
    [void][IO.Directory]::CreateDirectory($ScratchRoot)
    $pending = [IO.Path]::Combine($ScratchRoot, 'pending.json')
    $registered = [IO.Path]::Combine($ScratchRoot, 'hook-registration.txt')
    [IO.File]::WriteAllText($pending, 'pending')
    [IO.File]::WriteAllText($registered, 'registered')
    try {
        & $module {
            param([string]$Pending)
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout @{ PendingPath = $Pending } `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian)
        } $pending
        exit 2
    }
    catch {
        if ($_.Exception.Message -notlike '*committed transaction*') { exit 3 }
    }
    [IO.File]::WriteAllText([IO.Path]::Combine($ScratchRoot, 'ready'), 'ready')
    Microsoft.PowerShell.Utility\Start-Sleep -Seconds 30
    exit 4
}
$root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), 'dc-hook-commit-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [string]$ModulePath)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $layout = @{
                StateRoot = $Root
                InstallRoot = [IO.Path]::Combine($Root, 'payload')
                PendingPath = [IO.Path]::Combine($Root, 'pending.json')
                ManagedHooksTeardownJournalPath = [IO.Path]::Combine($Root, 'managed-hooks-teardown-journal.json')
                CodexTargetEnabled = $false
            }
            $script:HookCommitEvents = [Collections.Generic.List[string]]::new()
            $script:HookCommitPhase = ''
            $script:HookCommitCapable = $true
            $realProbe = ${function:Test-DefenseClawManagedHooksCommittedTeardownSupported}
            $realTeardownCommand = ${function:Invoke-DefenseClawManagedHooksTeardownCommand}
            function script:Test-DefenseClawManagedHooksCommittedTeardownSupported {
                param($Layout, $GatewayServiceName)
                $script:HookCommitEvents.Add('capabilities')
                return $script:HookCommitCapable
            }
            function script:Invoke-DefenseClawCodexRequirementsCommand {
                param($Layout, $GatewayServiceName, $Action)
                $script:HookCommitEvents.Add("codex:$Action")
                return [pscustomobject]@{ ok = $true }
            }
            function script:Complete-DefenseClawCodexRequirementsRemoval {
                param($Layout, $GatewayServiceName, $Report)
            }
            function script:Get-DefenseClawDeploymentMetadata {
                param($Layout, [switch]$Required)
                return [pscustomobject]@{ installed = $false }
            }
            function script:Assert-DefenseClawMetadataIdentity {
                param($Metadata, $GatewayServiceName, $GuardianServiceName)
            }
            function script:Test-DefenseClawMetadataInstalled {
                param($Metadata)
                return [bool]$Metadata.installed
            }
            function script:Get-DefenseClawManagedServiceNames {
                param($GatewayServiceName, $GuardianServiceName)
                return @($GatewayServiceName, $GuardianServiceName)
            }
            function script:Test-DefenseClawServiceExists { param($Name) return $false }
            function script:Assert-DefenseClawRecordedArtifactHashes {
                param($Metadata, $Layout, $Action)
                $script:HookCommitEvents.Add('artifact-proof')
            }
            function script:Assert-DefenseClawInstallTreeRetirementState {
                param($Layout, [switch]$NativeSealed, [switch]$AllowUnretiredAcls)
                $script:HookCommitEvents.Add($(if ($AllowUnretiredAcls) { 'shape-proof' } else { 'retirement-acl-proof' }))
            }
            function script:Get-DefenseClawManagedHooksTeardownJournalPhase {
                param($Layout, $Metadata, $GatewayServiceName, [switch]$AllowLegacyInactive)
                return $script:HookCommitPhase
            }
            function script:Invoke-DefenseClawManagedHooksTeardownCommand {
                param($Layout, $GatewayServiceName, $GuardianServiceName,
                    [string]$Action, [switch]$PurgeContractLocks)
                if ([IO.File]::Exists($Layout.PendingPath)) {
                    throw "hook $Action ran with pending.json still present"
                }
                $script:HookCommitEvents.Add("hooks:$Action")
                if ($Action -ceq 'prepare') {
                    [IO.File]::WriteAllText($Layout.ManagedHooksTeardownJournalPath, 'prepared')
                    $script:HookCommitPhase = 'prepared'
                }
                elseif ($Action -ceq 'finalize') {
                    $script:HookCommitPhase = 'finalized'
                }
                return [pscustomobject]@{ ok = $true }
            }
            function script:Remove-DefenseClawStandaloneOpenCodeManagedPlugin {
                param($Layout)
                $script:HookCommitEvents.Add('opencode-removed')
            }
            function script:Set-DefenseClawInstallTreeRetirementAcls {
                param($Layout, [switch]$Committed)
                if (-not $Committed) { throw 'standalone InstallRoot was locked before commit' }
                $script:HookCommitEvents.Add('install-tree-locked')
            }
            function script:Get-DefenseClawManagedHookContractCleanupReceipt {
                param($Layout, $GatewayServiceName, $GuardianServiceName, $Metadata, [switch]$Required)
                return [pscustomobject]@{ phase = 'prepared' }
            }

            [IO.File]::WriteAllText($layout.PendingPath, 'pending')
            try {
                [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                    -Layout $layout `
                    -GatewayServiceName DefenseClawGateway `
                    -GuardianServiceName DefenseClawHookGuardian)
                $failures.Add('a pending transaction removed managed hook registrations')
            }
            catch {
                if ($_.Exception.Message -notlike '*committed transaction*') {
                    $failures.Add("pending refusal: $($_.Exception.Message)")
                }
            }
            if ($script:HookCommitEvents.Count -ne 0) {
                $failures.Add('pending refusal touched managed state')
            }
            [IO.File]::Delete($layout.PendingPath)
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian)
            $expected = 'artifact-proof,shape-proof,capabilities,hooks:prepare,hooks:verify,opencode-removed,install-tree-locked,retirement-acl-proof,artifact-proof,hooks:finalize'
            $observed = $script:HookCommitEvents -join ','
            if ($observed -cne $expected) {
                $failures.Add("committed cleanup order: $observed")
            }
            if ($script:HookCommitPhase -cne 'finalized') {
                $failures.Add('committed cleanup did not finish the journal')
            }

            # A helper that prepares against the tombstone also removes the
            # Codex requirements after the commit.
            $layout.CodexTargetEnabled = $true
            $script:HookCommitEvents.Clear()
            $script:HookCommitPhase = ''
            [IO.File]::Delete($layout.ManagedHooksTeardownJournalPath)
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian)
            $expected = 'artifact-proof,shape-proof,capabilities,hooks:prepare,hooks:verify,codex:remove,opencode-removed,install-tree-locked,retirement-acl-proof,artifact-proof,hooks:finalize'
            $observed = $script:HookCommitEvents -join ','
            if ($observed -cne $expected) {
                $failures.Add("committed cleanup order with Codex: $observed")
            }

            # GAP-1443, GAP-1447: the helper of an older deployment (1.0.0 to
            # 1.0.3, an earlier 1.0.4 build) cannot prepare against the
            # tombstone. Its uninstall prepared the removal, and removed the
            # Codex requirements, before the commit: only the finalize is
            # left, and nothing asks the old helper to prepare or to remove
            # the Codex requirements again.
            $script:HookCommitCapable = $false
            $script:HookCommitEvents.Clear()
            $script:HookCommitPhase = 'prepared'
            [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, 'prepared')
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian)
            $expected = 'artifact-proof,shape-proof,capabilities,opencode-removed,install-tree-locked,retirement-acl-proof,artifact-proof,hooks:finalize'
            $observed = $script:HookCommitEvents -join ','
            if ($observed -cne $expected) {
                $failures.Add("committed cleanup order with an older helper: $observed")
            }
            if ($script:HookCommitPhase -cne 'finalized') {
                $failures.Add('committed cleanup with an older helper did not finish the journal')
            }
            # A finalized journal of an older helper is complete: the helper
            # is not asked again.
            $script:HookCommitEvents.Clear()
            [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                -Layout $layout `
                -GatewayServiceName DefenseClawGateway `
                -GuardianServiceName DefenseClawHookGuardian)
            if (@($script:HookCommitEvents | Microsoft.PowerShell.Core\Where-Object { $_ -like 'hooks:*' -or $_ -ceq 'capabilities' }).Count -ne 0) {
                $failures.Add("a finalized journal asked the older helper again: $($script:HookCommitEvents -join ',')")
            }
            # GAP-1443, GAP-1447: an earlier 1.0.4 Setup committed a tombstone
            # over an older deployment without preparing the removal (no
            # journal) or the removal rolled back. The older helper is never
            # asked to prepare against the tombstone (it refuses): the legacy
            # recovery runs it against the reactivated record instead, and
            # the finalize follows. Any other phase is still refused.
            $realLegacy = ${function:Invoke-DefenseClawLegacyHelperTombstoneHookTeardown}
            function script:Invoke-DefenseClawLegacyHelperTombstoneHookTeardown {
                param($Layout, $GatewayServiceName, $GuardianServiceName)
                $script:HookCommitEvents.Add('legacy-recovery')
                [IO.File]::WriteAllText($Layout.ManagedHooksTeardownJournalPath, 'prepared')
                $script:HookCommitPhase = 'prepared'
            }
            foreach ($phase in @('', 'rolled_back')) {
                $script:HookCommitEvents.Clear()
                $script:HookCommitPhase = $phase
                if ($phase -ceq '') {
                    [IO.File]::Delete($layout.ManagedHooksTeardownJournalPath)
                }
                else {
                    [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, $phase)
                }
                [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                    -Layout $layout `
                    -GatewayServiceName DefenseClawGateway `
                    -GuardianServiceName DefenseClawHookGuardian)
                $expected = 'artifact-proof,shape-proof,capabilities,legacy-recovery,opencode-removed,install-tree-locked,retirement-acl-proof,artifact-proof,hooks:finalize'
                $observed = $script:HookCommitEvents -join ','
                if ($observed -cne $expected) {
                    $failures.Add("legacy tombstone recovery order (phase '$phase'): $observed")
                }
            }
            $script:HookCommitEvents.Clear()
            $script:HookCommitPhase = 'captured'
            [IO.File]::WriteAllText($layout.ManagedHooksTeardownJournalPath, 'captured')
            try {
                [void](Complete-DefenseClawCommittedManagedHooksFinalization `
                    -Layout $layout `
                    -GatewayServiceName DefenseClawGateway `
                    -GuardianServiceName DefenseClawHookGuardian)
                $failures.Add('a captured older-helper journal finished without its rollback')
            }
            catch {
                if ($_.Exception.Message -notlike '*cannot remove its managed hooks after an uninstall committed*') {
                    $failures.Add("older helper refusal: $($_.Exception.Message)")
                }
            }
            if (@($script:HookCommitEvents | Microsoft.PowerShell.Core\Where-Object { $_ -like 'hooks:*' -or $_ -like 'codex:*' -or $_ -ceq 'legacy-recovery' }).Count -ne 0) {
                $failures.Add("the older helper was asked to act on a captured journal: $($script:HookCommitEvents -join ',')")
            }
            Microsoft.PowerShell.Management\Set-Item -Path function:script:Invoke-DefenseClawLegacyHelperTombstoneHookTeardown -Value $realLegacy

            # The legacy recovery itself: the helper sees installed=true for
            # prepare and verify only; the byte-exact tombstone is back
            # afterwards, also when the helper fails, and the Codex
            # requirements access list is restored when its backup exists.
            $metadataPath = [IO.Path]::Combine($Root, 'deployment.json')
            $aclBackup = [IO.Path]::Combine($Root, 'codex-requirements-acl-backup.json')
            $tombstoneText = "{`r`n    ""schema_version"":  1,`r`n    ""installed"":  false,`r`n    ""product_version"":  ""1.0.2""`r`n}"
            $tombstoneBytes = [Text.UTF8Encoding]::new($false).GetBytes($tombstoneText)
            $legacyLayout = @{
                MetadataPath = $metadataPath
                CodexRequirementsAclBackupPath = $aclBackup
                ManagedHooksTeardownJournalPath = $layout.ManagedHooksTeardownJournalPath
            }
            function script:Set-DefenseClawPathAcl {
                param($Path, $Kind, $GatewayServiceSID)
                if ($Kind -cne 'AdminFile') { throw "unexpected ACL kind $Kind" }
                $script:HookCommitEvents.Add('acl:AdminFile')
            }
            $script:LegacyFail = ''
            function script:Invoke-DefenseClawManagedHooksTeardownCommand {
                param($Layout, $GatewayServiceName, $GuardianServiceName,
                    [string]$Action, [switch]$PurgeContractLocks)
                $seen = [IO.File]::ReadAllText($Layout.MetadataPath)
                if ($seen -notmatch '"installed":\s*true' -or $seen -match '"installed":\s*false') {
                    throw "legacy helper $Action saw an inactive record"
                }
                $script:HookCommitEvents.Add("hooks:$Action")
                if ($script:LegacyFail -ceq $Action) { throw "helper $Action failed" }
                return [pscustomobject]@{ ok = $true }
            }
            foreach ($case in @(
                @{ name = 'with Codex backup'; backup = $true; fail = ''; want = 'acl:AdminFile,hooks:prepare,hooks:verify,codex:remove,acl:AdminFile' },
                @{ name = 'without Codex backup'; backup = $false; fail = ''; want = 'acl:AdminFile,hooks:prepare,hooks:verify,acl:AdminFile' },
                @{ name = 'prepare fails'; backup = $true; fail = 'prepare'; want = 'acl:AdminFile,hooks:prepare,acl:AdminFile' }
            )) {
                [IO.File]::WriteAllBytes($metadataPath, $tombstoneBytes)
                if ($case.backup) { [IO.File]::WriteAllText($aclBackup, '{}') } else { [IO.File]::Delete($aclBackup) }
                $script:LegacyFail = $case.fail
                $script:HookCommitEvents.Clear()
                try {
                    Invoke-DefenseClawLegacyHelperTombstoneHookTeardown `
                        -Layout $legacyLayout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                    if ($case.fail -cne '') { $failures.Add("legacy recovery, $($case.name): a failed helper was not reported") }
                }
                catch {
                    if ($case.fail -ceq '' -or $_.Exception.Message -notlike "*helper $($case.fail) failed*") {
                        $failures.Add("legacy recovery, $($case.name): $($_.Exception.Message)")
                    }
                }
                $observed = $script:HookCommitEvents -join ','
                if ($observed -cne $case.want) {
                    $failures.Add("legacy recovery, $($case.name): $observed")
                }
                $after = [IO.File]::ReadAllBytes($metadataPath)
                if ([Convert]::ToBase64String($after) -cne [Convert]::ToBase64String($tombstoneBytes)) {
                    $failures.Add("legacy recovery, $($case.name): the tombstone was not restored byte for byte")
                }
                if (@([IO.Directory]::GetFiles($Root, 'deployment.json.new.*')).Count -ne 0) {
                    $failures.Add("legacy recovery, $($case.name): a metadata temporary was left")
                }
            }
            # An active record or a record with two flags is never rewritten.
            foreach ($bad in @(
                "{""installed"":  true}",
                "{""installed"":  false, ""x"": {""installed"": false}}"
            )) {
                [IO.File]::WriteAllText($metadataPath, $bad)
                $script:HookCommitEvents.Clear()
                try {
                    Invoke-DefenseClawLegacyHelperTombstoneHookTeardown `
                        -Layout $legacyLayout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                    $failures.Add("legacy recovery accepted $bad")
                }
                catch {
                    if ($_.Exception.Message -notlike '*exactly one inactive installed flag*') {
                        $failures.Add("legacy recovery refusal for ${bad}: $($_.Exception.Message)")
                    }
                }
                if ($script:HookCommitEvents.Count -ne 0 -or [IO.File]::ReadAllText($metadataPath) -cne $bad) {
                    $failures.Add("legacy recovery changed state for $bad")
                }
            }
            $layout.CodexTargetEnabled = $false
            $script:HookCommitCapable = $true

            # The capability report: only one well-formed report that says
            # so counts. A 1.0.2 or 1.0.3 helper answers an unknown command
            # with an error or with help text.
            $script:ProbeAnswer = $null
            Microsoft.PowerShell.Management\Set-Item -Path function:script:Test-DefenseClawManagedHooksCommittedTeardownSupported -Value $realProbe
            function script:Invoke-DefenseClawGatewayCommand {
                param($Layout, $GatewayServiceName, [string[]]$Arguments, [switch]$Capture,
                    [switch]$AllowFailure, [int]$TimeoutSeconds)
                if (($Arguments -join ' ') -cne 'enterprise windows teardown-managed-hooks capabilities --json') {
                    throw "unexpected helper call: $($Arguments -join ' ')"
                }
                return $script:ProbeAnswer
            }
            $good = '{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true}'
            foreach ($case in @(
                @{ name = 'this helper'; code = 0; output = @($good); want = $true },
                @{ name = 'this helper with a log line'; code = 0; output = @('note: x', $good); want = $true },
                @{ name = 'unknown flag (1.0.2)'; code = 1; output = @('Error: unknown flag: --json'); want = $false },
                @{ name = 'help text'; code = 0; output = @('Transactionally revoke managed hook machine wiring', 'Usage:'); want = $false },
                @{ name = 'failed run with a report'; code = 1; output = @($good); want = $false },
                @{ name = 'two reports'; code = 0; output = @($good, $good); want = $false },
                @{ name = 'malformed report'; code = 0; output = @('{"committed_standalone_prepare":tru'); want = $false },
                @{ name = 'says no'; code = 0; output = @('{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":false}'); want = $false },
                @{ name = 'string true'; code = 0; output = @('{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":"true"}'); want = $false },
                @{ name = 'another action'; code = 0; output = @('{"schema_version":4,"action":"prepare","ok":true,"committed_standalone_prepare":true}'); want = $false },
                @{ name = 'not ok'; code = 0; output = @('{"schema_version":4,"action":"capabilities","ok":false,"committed_standalone_prepare":true}'); want = $false },
                @{ name = 'no output'; code = 0; output = @(); want = $false }
            )) {
                $script:ProbeAnswer = [pscustomobject]@{ exit_code = $case.code; output = $case.output }
                $got = Test-DefenseClawManagedHooksCommittedTeardownSupported -Layout $layout -GatewayServiceName DefenseClawGateway
                if ($got -isnot [bool] -or $got -ne $case.want) {
                    $failures.Add("capability probe, $($case.name): $got, want $($case.want)")
                }
            }
            # GAP-0571: the wrapper accepts the helper's real check report
            # (verified installed, binary not released) and nothing that
            # claims more. Before the fix a good check report fell into the
            # finalize rules and refused every healthy uninstall.
            Microsoft.PowerShell.Management\Set-Item -Path function:script:Invoke-DefenseClawManagedHooksTeardownCommand -Value $realTeardownCommand
            function script:Invoke-DefenseClawGatewayCommand {
                param($Layout, $GatewayServiceName, [string[]]$Arguments, [switch]$Capture,
                    [switch]$AllowFailure, [int]$TimeoutSeconds)
                if (($Arguments -join ' ') -cne 'enterprise windows teardown-managed-hooks check --json') {
                    throw "unexpected helper call: $($Arguments -join ' ')"
                }
                return $script:ProbeAnswer
            }
            $checkLayout = @{
                ManifestPath = 'C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml'
                ManagedHooksTeardownJournalPath = 'C:\ProgramData\DefenseClaw\install\managed-hooks-teardown.json'
                ManagedHookContractCleanupReceiptPath = 'C:\ProgramData\DefenseClaw\install\contract-cleanup.json'
                PurgeScopeSHA256 = ('a' * 64)
            }
            $checkReport = {
                param([bool]$SafeToRemove, [int]$VerifiedInstalled)
                [ordered]@{
                    schema_version = 4; action = 'check'; ok = $true
                    manifest_path = $checkLayout.ManifestPath
                    journal_path = $checkLayout.ManagedHooksTeardownJournalPath
                    target_count = 1; enrollment_target_count = 0; succeeded_count = 1
                    verified_clean_count = 0; verified_installed_count = $VerifiedInstalled; failed_count = 0
                    surviving_owned_path_references = 0; collected_generation_count = 0
                    rollback_ready = $false; safe_to_remove_binary = $SafeToRemove
                    results = @(@{ connector = 'codex'; sid = 'S-1-5-21-111-222-333-1001'; ok = $true })
                } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -Depth 4
            }
            foreach ($case in @(
                @{ name = 'a healthy deployment'; report = (& $checkReport $false 1); want = $true },
                @{ name = 'a check that releases the binary'; report = (& $checkReport $true 1); want = $false },
                @{ name = 'a check that verified no target'; report = (& $checkReport $false 0); want = $false }
            )) {
                $script:ProbeAnswer = [pscustomobject]@{ exit_code = 0; output = @($case.report) }
                $accepted = $true
                try {
                    [void](Invoke-DefenseClawManagedHooksTeardownCommand -Layout $checkLayout `
                        -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian -Action check)
                }
                catch {
                    $accepted = $false
                    $checkError = $_.Exception.Message
                }
                if ($accepted -ne $case.want) {
                    $failures.Add("check report, $($case.name): accepted=$accepted, want $($case.want) ($checkError)")
                }
            }
            function script:Invoke-DefenseClawGatewayCommand {
                param($Layout, $GatewayServiceName, [string[]]$Arguments, [switch]$Capture,
                    [switch]$AllowFailure, [int]$TimeoutSeconds)
                if (($Arguments -join ' ') -cne 'enterprise windows teardown-managed-hooks capabilities --json') {
                    throw "unexpected helper call: $($Arguments -join ' ')"
                }
                return $script:ProbeAnswer
            }
            # GAP-0571: the precommit_check capability, same rules. A helper
            # without it (every helper before this fix) gets no check.
            $goodCheck = '{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true,"precommit_check":true}'
            foreach ($case in @(
                @{ name = 'this helper'; code = 0; output = @($goodCheck); want = $true },
                @{ name = 'an earlier helper'; code = 0; output = @($good); want = $false },
                @{ name = 'says no'; code = 0; output = @('{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true,"precommit_check":false}'); want = $false },
                @{ name = 'string true'; code = 0; output = @('{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true,"precommit_check":"true"}'); want = $false },
                @{ name = 'failed run'; code = 1; output = @($goodCheck); want = $false },
                @{ name = 'unknown flag (1.0.2)'; code = 1; output = @('Error: unknown flag: --json'); want = $false }
            )) {
                $script:ProbeAnswer = [pscustomobject]@{ exit_code = $case.code; output = $case.output }
                $got = Test-DefenseClawManagedHooksCommittedTeardownSupported -Layout $layout -GatewayServiceName DefenseClawGateway -Capability precommit_check
                if ($got -isnot [bool] -or $got -ne $case.want) {
                    $failures.Add("precommit check probe, $($case.name): $got, want $($case.want)")
                }
            }

            # The common lifecycle module is used by Setup and by
            # `enterprise windows uninstall`. Its precommit branch must not
            # call the removal helpers for standalone installations.
            $tokens = $null
            $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
            if (@($parseErrors).Count -gt 0) {
                $failures.Add('enterprise module did not parse')
            }
            $uninstall = $ast.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Invoke-DefenseClawUninstallLifecycle'
            }, $true)
            foreach ($name in @(
                'Invoke-DefenseClawManagedHooksTeardownCommand',
                'Invoke-DefenseClawCodexRequirementsCommand',
                'Remove-DefenseClawStandaloneOpenCodeManagedPlugin',
                'Set-DefenseClawInstallTreeRetirementAcls'
            )) {
                foreach ($call in @($uninstall.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -ceq $name
                }, $true))) {
                    # GAP-0571: the read-only check (no write) is asked
                    # before the commit on purpose; it is pinned below.
                    if ($name -ceq 'Invoke-DefenseClawManagedHooksTeardownCommand' -and
                        $call.Extent.Text -cmatch '-Action\s+check\s*$') {
                        continue
                    }
                    $guarded = $false
                    for ($parent = $call.Parent; $null -ne $parent; $parent = $parent.Parent) {
                        if ($parent -is [Management.Automation.Language.IfStatementAst]) {
                            foreach ($clause in $parent.Clauses) {
                                if ($clause.Item1.Extent.Text -match '-not\s*(\(Test-DefenseClawStandaloneProfile\)|\$postCommitHookTeardown)') {
                                    $guarded = $true
                                    break
                                }
                            }
                            if ($guarded) { break }
                        }
                    }
                    if (-not $guarded) {
                        $failures.Add("$name can remove standalone hook state before commit")
                    }
                }
            }
            # The precommit removal runs only for Secure Client and for an
            # older helper (GAP-1443): the switch is the standalone profile
            # and this helper's report, decided before the transaction.
            $decision = @($uninstall.FindAll({
                param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -ceq '$postCommitHookTeardown'
            }, $true))
            if ($decision.Count -ne 1 -or
                $decision[0].Right.Extent.Text -notmatch 'Test-DefenseClawStandaloneProfile' -or
                $decision[0].Right.Extent.Text -notmatch 'Test-DefenseClawManagedHooksCommittedTeardownSupported') {
                $failures.Add('the uninstall does not decide the hook removal order from the profile and the helper')
            }
            else {
                $transaction = $uninstall.Find({
                    param($node)
                    $node -is [Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -ceq 'New-DefenseClawTransaction'
                }, $true)
                if ($null -eq $transaction -or $decision[0].Extent.StartOffset -gt $transaction.Extent.StartOffset) {
                    $failures.Add('the hook removal order is decided after the uninstall transaction started')
                }
                # GAP-0571: a standalone uninstall asks the helper's
                # read-only check after that decision and before the
                # transaction, so a deployment the post-commit prepare
                # would refuse is never committed.
                $checks = @($uninstall.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -ceq 'Invoke-DefenseClawManagedHooksTeardownCommand' -and
                        $node.Extent.Text -cmatch '-Action\s+check\s*$'
                }, $true))
                if ($checks.Count -ne 1 -or $null -eq $transaction -or
                    $checks[0].Extent.StartOffset -lt $decision[0].Extent.StartOffset -or
                    $checks[0].Extent.StartOffset -gt $transaction.Extent.StartOffset) {
                    $failures.Add('the uninstall does not run the read-only hook check between the order decision and the transaction')
                }
                else {
                    $checkGuarded = $false
                    for ($parent = $checks[0].Parent; $null -ne $parent; $parent = $parent.Parent) {
                        if ($parent -is [Management.Automation.Language.IfStatementAst] -and
                            $parent.Clauses[0].Item1.Extent.Text -match '^\$postCommitHookTeardown\s+-and' -and
                            $parent.Clauses[0].Item1.Extent.Text -match 'precommit_check') {
                            $checkGuarded = $true
                            break
                        }
                    }
                    if (-not $checkGuarded) {
                        $failures.Add('the read-only hook check is not limited to a post-commit removal with a helper that offers it')
                    }
                }
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return $failures.ToArray()
    } $root $modulePath
    if (@($failures).Count -gt 0) {
        foreach ($failure in $failures) { [Console]::Error.WriteLine("FAIL: $failure") }
        exit 1
    }
    # The Setup watchdog is a child process and taskkill /T can remove the
    # whole tree. The pending contract is durable without that process: the
    # installed hook registration remains after the tree is killed.
    $killRoot = [IO.Path]::Combine($root, 'process-tree')
    [void][IO.Directory]::CreateDirectory($killRoot)
    $engine = [IO.Path]::Combine($PSHOME, $(if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }))
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ScratchRoot "{1}" -ChildHold' -f $PSCommandPath, $killRoot
    $child = Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList $arguments -PassThru -WindowStyle Hidden
    try {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while (-not [IO.File]::Exists([IO.Path]::Combine($killRoot, 'ready'))) {
            if ($child.HasExited -or $clock.ElapsedMilliseconds -gt 15000) {
                throw 'the pending uninstall child did not reach its hold point'
            }
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
        }
        $taskkill = [IO.Path]::Combine($env:SystemRoot, 'System32', 'taskkill.exe')
        & $taskkill /F /T /PID $child.Id | Microsoft.PowerShell.Core\Out-Null
        if ($LASTEXITCODE -ne 0 -or -not $child.WaitForExit(10000)) {
            throw 'taskkill did not stop the pending uninstall process tree'
        }
        if (-not [IO.File]::Exists([IO.Path]::Combine($killRoot, 'pending.json')) -or
            -not [IO.File]::Exists([IO.Path]::Combine($killRoot, 'hook-registration.txt'))) {
            throw 'a killed uninstall process tree lost its pending hook registration'
        }
    }
    finally {
        if (-not $child.HasExited) { $child.Kill() }
        $child.Dispose()
    }
    [Console]::WriteLine('enterprise-standalone-uninstall-hook-commit-smoke: OK')
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
