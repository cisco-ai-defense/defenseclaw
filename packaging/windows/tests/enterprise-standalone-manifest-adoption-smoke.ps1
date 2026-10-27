# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for standalone manifest adoption. The hook
# enumerator service republishes targets.yaml on every enrollment change (a
# new user or agent, an agent update, a deferred row) after the last
# lifecycle transaction bound the deployment's managed-hook activation
# evidence to the manifest it activated. Before this fix every later verify,
# repair, upgrade and uninstall refused with "deployment managed-hook
# activation evidence does not bind installed targets.yaml", and a failed
# uninstall could not roll back, leaving the services disabled. The lifecycle
# now adopts a republished manifest once the guardian's protected activation
# record binds it exactly, and rebinds the committed evidence before a
# servicing transaction. Everything runs inside a disposable scratch
# directory; ACL helpers and the guardian status probe are stubbed.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-standalone-manifest-adoption-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [string]$ModulePath)

        function New-DefenseClawCanonicalPathAcl {
            param([switch]$IsDirectory, $Kind, $GatewayServiceSID)
            return $null
        }
        function Assert-DefenseClawCanonicalPathAcl {
            param($Path, $Expected, [switch]$AllowSelfHeal)
        }
        $script:TestAclWrites = [Collections.Generic.List[string]]::new()
        function Set-DefenseClawPathAcl {
            param($Path, $Kind, $GatewayServiceSID)
            $script:TestAclWrites.Add("$Kind|$GatewayServiceSID")
        }
        $script:TestGuardianReport = $null
        $script:TestGuardianProbes = 0
        $script:TestGuardianCatchUp = $null
        $script:TestGuardianSources = [Collections.Generic.List[object]]::new()
        function Get-DefenseClawGuardianStatusReport {
            param($Layout, $GatewayServiceName, $GatewaySource)
            $script:TestGuardianProbes++
            $script:TestGuardianSources.Add($GatewaySource)
            if ($null -ne $script:TestGuardianCatchUp -and $script:TestGuardianProbes -ge 2) {
                return $script:TestGuardianCatchUp
            }
            return $script:TestGuardianReport
        }
        $script:ManifestCatchUpPollMilliseconds = 0

        $originalProfile = Get-DefenseClawEnterpriseProfile
        $failures = [Collections.Generic.List[string]]::new()
        $canRewrite = $PSVersionTable.PSVersion.Major -ge 7
        try {
            $installRoot = [IO.Path]::Combine($Root, 'Program Files', 'DefenseClaw')
            $stateRoot = [IO.Path]::Combine($Root, 'ProgramData', 'DefenseClaw')
            $installState = [IO.Path]::Combine($stateRoot, 'install')
            $guardian = [IO.Path]::Combine($stateRoot, 'hook-guardian')
            foreach ($directory in @($installRoot, $installState, $guardian)) {
                [void][IO.Directory]::CreateDirectory($directory)
            }
            $layout = @{
                InstallRoot = $installRoot
                StateRoot = $stateRoot
                BrokerEnabled = $false
                MetadataPath = [IO.Path]::Combine($installState, 'deployment.json')
                PendingPath = [IO.Path]::Combine($installState, 'pending.json')
                ManifestPath = [IO.Path]::Combine($guardian, 'targets.yaml')
                CodexMachinePolicyPath = [IO.Path]::Combine($Root, 'codex', 'requirements.toml')
                CodexManagedHooksDirectory = [IO.Path]::Combine($Root, 'codex', 'hooks')
                CodexManagedHooksStatePath = [IO.Path]::Combine($installState, 'codex-hooks.json')
                CodexRequirementsOwnershipPath = [IO.Path]::Combine($installState, 'codex-requirements-ownership.json')
                CodexRequirementsAclBackupPath = [IO.Path]::Combine($installState, 'codex-requirements-acl-backup.json')
                AgentApplicationControlAttestationPath = [IO.Path]::Combine($installState, 'agent-application-control-attestation.json')
                ManagedHooksTeardownJournalPath = [IO.Path]::Combine($installState, 'managed-hooks-teardown.json')
                CertificationCodexHome = ''
                CoreHardeningCertification = $false
                ClaudeTargetEnabled = $false
                CodexTargetEnabled = $false
                CursorTargetEnabled = $false
            }
            $utf8 = [Text.UTF8Encoding]::new($false)
            $generation = '0123456789abcdef0123456789abcdef'

            function Get-TestSha256([string]$Path) {
                return (
                    Microsoft.PowerShell.Utility\Get-FileHash `
                        -LiteralPath $Path `
                        -Algorithm SHA256
                ).Hash.ToLowerInvariant()
            }
            function Set-TestManifest([string]$Body) {
                [IO.File]::WriteAllText($layout.ManifestPath, $Body, $utf8)
                return (Get-TestSha256 $layout.ManifestPath)
            }
            function Set-TestMetadata([string]$ManifestSHA256, [string]$State, [int64]$TargetCount, [string]$GatewayHash = '') {
                $value = [ordered]@{
                    schema_version = 1
                    installed = $true
                    install_root = $installRoot
                    state_root = $stateRoot
                    updated_at = '2026-09-27T02:56:38.1234567Z'
                    gateway_service = 'DefenseClawGateway'
                    guardian_service = 'DefenseClawHookGuardian'
                    managed_hooks_activation = [ordered]@{
                        schema_version = 1
                        deployment_generation_id = $generation
                        state = $State
                        manifest_sha256 = $ManifestSHA256
                        target_count = $TargetCount
                    }
                }
                if (-not [bool]$layout.BrokerEnabled) {
                    $value['profile'] = 'standalone'
                }
                if (-not [string]::IsNullOrEmpty($GatewayHash)) {
                    $value['hashes'] = [ordered]@{ gateway = $GatewayHash }
                }
                [IO.File]::WriteAllText(
                    $layout.MetadataPath,
                    ($value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6),
                    $utf8
                )
            }
            function Set-TestGuardian([bool]$Ok, [string]$ManifestSHA256, [int64]$TargetCount, [int64]$Failures = 0, [string]$StateStamp = '', [switch]$NoAuthorization, [switch]$Stale, [object[]]$Results = @(), [int64]$RemovedAccountFailures = 0, [int64]$AwaitingSignInFailures = 0) {
                $stamp = '2026-09-27T15:55:44Z'
                if ([string]::IsNullOrEmpty($StateStamp)) {
                    $StateStamp = $stamp
                }
                $record = {
                    param([string]$Updated)
                    return [pscustomobject][ordered]@{
                        version = 1
                        updated_at = $Updated
                        ok = ($Failures -eq 0)
                        target_count = $TargetCount
                        success_count = ($TargetCount - $Failures)
                        failure_count = $Failures
                    }
                }
                $activation = & $record $stamp
                $activation | Microsoft.PowerShell.Utility\Add-Member -NotePropertyName manifest_sha256 -NotePropertyValue $ManifestSHA256
                $errors = @()
                if ($Stale) {
                    $errors += "hook guardian state is not fresh: updated_at $stamp is stale (older than 5m0s)"
                }
                if ($Failures -ne 0) {
                    $errors += 'last guardian reconcile failed for alice/codex: marker'
                }
                $state = & $record $StateStamp
                $state | Microsoft.PowerShell.Utility\Add-Member -NotePropertyName results -NotePropertyValue $Results
                $report = [ordered]@{
                    ok = $Ok
                    errors = $errors
                    activation = $activation
                    state = $state
                }
                if (-not $NoAuthorization) {
                    $report['authorization'] = (& $record $stamp)
                }
                if ($RemovedAccountFailures -gt 0) {
                    $report['removed_account_failures'] = $RemovedAccountFailures
                }
                if ($AwaitingSignInFailures -gt 0) {
                    $report['awaiting_sign_in_failures'] = $AwaitingSignInFailures
                }
                $script:TestGuardianReport = [pscustomobject]$report
            }
            function Get-TestMetadataText {
                return [IO.File]::ReadAllText($layout.MetadataPath)
            }
            function Invoke-TestSync {
                return Sync-DefenseClawStandaloneManagedHooksActivationBinding `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway'
            }
            function Assert-TestSyncRefuses([string]$Label, [string]$Needle) {
                $before = Get-TestMetadataText
                try {
                    [void](Invoke-TestSync)
                    $failures.Add("${Label}: expected a refusal")
                }
                catch {
                    $message = $_.Exception.Message
                    if (-not $message.Contains('does not bind installed targets.yaml') -or
                        -not $message.Contains($Needle)) {
                        $failures.Add("${Label}: unexpected refusal: $message")
                    }
                }
                if ((Get-TestMetadataText) -cne $before) {
                    $failures.Add("${Label}: a refused rebind changed deployment.json")
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $activatedSHA256 = Set-TestManifest "version: 1`ntargets:`n  - sid: S-1-5-21-1-2-3-1017`n    connector: codex`n"
            Set-TestMetadata $activatedSHA256 'activated' 1
            Set-TestGuardian $true $activatedSHA256 1
            if ($canRewrite -and (Invoke-TestSync)) {
                $failures.Add('an exactly bound deployment was rebound')
            }
            if ($script:TestGuardianProbes -ne 0) {
                $failures.Add('an exactly bound deployment probed the guardian')
            }

            # The enumerator adds a row and the guardian activates it.
            $republishedSHA256 = Set-TestManifest "version: 1`ntargets:`n  - sid: S-1-5-21-1-2-3-1017`n    connector: codex`n  - sid: S-1-5-21-1-2-3-1018`n    connector: codex`n"
            Set-TestGuardian $true $republishedSHA256 2
            $activation = (Get-DefenseClawDeploymentMetadata -Layout $layout -Required).managed_hooks_activation
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or [int64]$adoption.target_count -ne 2) {
                $failures.Add("guardian-activated republication was not adoptable: $($adoption.reason)")
            }

            # A stopped guardian (quiesced or recovering transaction) still
            # proves what it last activated: staleness alone does not refuse.
            Set-TestGuardian $false $republishedSHA256 2 -Stale
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok) {
                $failures.Add("a stale but exact guardian activation was refused: $($adoption.reason)")
            }

            # Verify came in between the enumerator's republication and the
            # guardian's activation of it, seconds later: it waits for that.
            Set-TestGuardian $true $republishedSHA256 2
            $script:TestGuardianCatchUp = $script:TestGuardianReport
            Set-TestGuardian $true $activatedSHA256 1
            $script:TestGuardianProbes = 0
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or $script:TestGuardianProbes -ne 2) {
                $failures.Add("verify did not wait for the guardian to activate a fresh republication: $($adoption.reason)")
            }
            $script:TestGuardianCatchUp = $null

            # The guardian has not activated the republished manifest yet, or
            # its records do not describe one failure-free reconcile of it.
            [IO.File]::SetLastWriteTimeUtc($layout.ManifestPath, [DateTime]::UtcNow.AddMinutes(-10))
            Set-TestGuardian $true $activatedSHA256 1
            Assert-TestSyncRefuses 'guardian still on the old manifest' 'guardian'
            Set-TestGuardian $false $republishedSHA256 2 1
            Assert-TestSyncRefuses 'guardian reconcile failed' 'marker'
            # A failure that lasts until a signed-out account signs in names
            # that account instead of asking for a retry.
            $signedOut = [pscustomobject]@{
                user = 'alice'; sid = 'S-1-5-21-1-2-3-1018'; connector = 'codex'; ok = $false
                error = 'enterprise hooks: protected target requires repair but its exact active Windows session is unavailable'
            }
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @([pscustomobject]@{ sid = 'S-1-5-21-1-2-3-1017'; connector = 'codex'; ok = $true }, $signedOut)
            Assert-TestSyncRefuses 'signed-out account' 'sign in, or remove it with its profile, then run this command again: alice (S-1-5-21-1-2-3-1018). The guardian repairs their DefenseClaw hooks only in their own Windows session)'
            # GAP-1657: a deleted account the guardian reports through the
            # session wait (its home no longer exists) is accepted as a
            # removed account, not named as a signed-out one to remove again.
            $removedRow = [pscustomobject]@{
                user = 'gone'; sid = 'S-1-5-21-1-2-3-1018'; connector = 'codex'; ok = $false
                error = 'enterprise hooks: protected target requires repair but its exact active Windows session is unavailable (verification: enterprise hooks: user home C:\Users\gone no longer exists: the account was deleted or its profile folder removed; run Setup /ensure again (file does not exist))'
            }
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @([pscustomobject]@{ sid = 'S-1-5-21-1-2-3-1017'; connector = 'codex'; ok = $true }, $removedRow)
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok) {
                $failures.Add("a deleted account reported through the session wait refused the adoption: $($adoption.reason)")
            }
            # A deleted account whose profile folder was removed fails every
            # reconcile until the enumerator's next pass drops its rows; the
            # guardian status counts exactly those failures, and the adoption
            # accepts them, as verify and status do.
            Set-TestGuardian $true $republishedSHA256 2 1 -RemovedAccountFailures 1
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or [int64]$adoption.target_count -ne 2) {
                $failures.Add("a deleted account's failing rows refused the adoption: $($adoption.reason)")
            }
            # GAP-0644: a target an earlier release protected waits for its
            # signed-out account's next sign-in; status counts it, and the
            # adoption accepts it, as verify and status do.
            Set-TestGuardian $true $republishedSHA256 2 1 -AwaitingSignInFailures 1
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or [int64]$adoption.target_count -ne 2) {
                $failures.Add("a row waiting for its account's next sign-in refused the adoption: $($adoption.reason)")
            }
            # #1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade with a signed-out
            # account whose hooks folder had one extra permission entry
            # returned 1603 twice. Only that failure of the account's own
            # DefenseClaw folder, while it is signed out, waits for its next
            # sign-in: the adoption goes on and names the folder.
            $unavailable = 'enterprise hooks: protected target requires repair but its exact active Windows session is unavailable (verification: '
            $hookCheck = 'enterprise hooks: managed hook directory verification failed: '
            $folderError = $unavailable + $hookCheck + 'enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7)'
            $healthy = [pscustomobject]@{ sid = 'S-1-5-21-1-2-3-1017'; user_home = 'C:\Users\alice'; connector = 'codex'; ok = $true }
            $newFolderRow = {
                param([string]$Message, [string]$UserHome = 'C:\Users\r103gb13-u1')
                return [pscustomobject]@{
                    user = 'DCFC\r103gb13-u1'; sid = 'S-1-5-21-1-2-3-1123'; user_home = $UserHome
                    connector = 'claudecode'; ok = $false; error = $Message
                }
            }
            $folderEntry = 'DCFC\r103gb13-u1 (S-1-5-21-1-2-3-1123): C:\Users\r103gb13-u1\.defenseclaw\hooks'
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @($healthy, (& $newFolderRow $folderError))
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or [int64]$adoption.target_count -ne 2 -or
                @($adoption.untrusted_folders).Count -ne 1 -or
                [string]@($adoption.untrusted_folders)[0] -cne $folderEntry) {
                $failures.Add("a signed-out account's untrusted DefenseClaw folder refused the adoption: $($adoption.reason) [$(@($adoption.untrusted_folders) -join '; ')]")
            }
            # It stays excused next to a row waiting for its sign-in.
            $waitingRow = [pscustomobject]@{
                sid = 'S-1-5-21-1-2-3-1124'; user_home = 'C:\Users\bob'; connector = 'codex'; ok = $false
                error = "enterprise hooks: protected target waits for its account's next sign-in: DefenseClaw 1.0.2 protected it, and this release's hooks install only in the account's own Windows session; its exact active Windows session is unavailable, so the guardian repairs it at the account's next sign-in (verification: drift)"
            }
            Set-TestGuardian $false $republishedSHA256 3 2 -Results @($healthy, (& $newFolderRow $folderError), $waitingRow)
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if (-not [bool]$adoption.ok -or [int64]$adoption.target_count -ne 3) {
                $failures.Add("an untrusted folder next to a waiting row refused the adoption: $($adoption.reason)")
            }
            # No other failure is excused: another account's folder, a
            # junction, a connected account, any other failed row, or a row
            # only the gateway could excuse.
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @($healthy, (& $newFolderRow $folderError 'C:\Users\other'))
            Assert-TestSyncRefuses 'untrusted folder of another account' 'sign in, or remove it with its profile, then run this command again: DCFC\r103gb13-u1 (S-1-5-21-1-2-3-1123)'
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @($healthy, (& $newFolderRow ($unavailable + $hookCheck + 'enterprise hooks: symlinks, junctions, and reparse points are not allowed: C:\Users\r103gb13-u1\.defenseclaw\hooks)')))
            Assert-TestSyncRefuses 'signed-out junction' 'sign in, or remove it with its profile'
            Set-TestGuardian $false $republishedSHA256 2 1 -Results @($healthy, (& $newFolderRow ($hookCheck + 'enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7')))
            Assert-TestSyncRefuses 'connected account with an untrusted folder' 'failure-free reconcile'
            $otherRow = [pscustomobject]@{
                sid = 'S-1-5-21-1-2-3-1124'; user_home = 'C:\Users\bob'; connector = 'codex'; ok = $false
                error = 'enterprise hooks: write managed Claude Code hook runtime: access is denied'
            }
            Set-TestGuardian $false $republishedSHA256 3 2 -Results @($healthy, (& $newFolderRow $folderError), $otherRow)
            Assert-TestSyncRefuses 'untrusted folder next to another failure' 'failure-free reconcile'
            $removedRow = [pscustomobject]@{
                sid = 'S-1-5-21-1-2-3-1125'; user_home = 'C:\Users\gone'; connector = 'codex'; ok = $false
                error = 'enterprise hooks: inspect profile: the system cannot find the path specified'
            }
            Set-TestGuardian $false $republishedSHA256 3 2 -Results @($healthy, (& $newFolderRow $folderError), $removedRow) -RemovedAccountFailures 1
            Assert-TestSyncRefuses 'untrusted folder next to a removed account' 'failure-free reconcile'
            if ($canRewrite) {
                # The rebind before a servicing transaction keeps the folder
                # for the result (signed_out_untrusted_folders).
                $script:DefenseClawSignedOutUntrustedFolders = @()
                Set-TestGuardian $false $republishedSHA256 2 1 -Results @($healthy, (& $newFolderRow $folderError))
                if (-not (Invoke-TestSync) -or
                    @($script:DefenseClawSignedOutUntrustedFolders).Count -ne 1 -or
                    [string]@($script:DefenseClawSignedOutUntrustedFolders)[0] -cne $folderEntry) {
                    $failures.Add("the rebind did not keep the signed-out untrusted folder: $(@($script:DefenseClawSignedOutUntrustedFolders) -join '; ')")
                }
                $script:DefenseClawSignedOutUntrustedFolders = @()
                Set-TestMetadata $activatedSHA256 'activated' 1
            }

            Set-TestGuardian $true $republishedSHA256 2 0 '2026-09-27T15:50:44Z'
            Assert-TestSyncRefuses 'guardian records from two reconciles' 'state record'
            Set-TestGuardian $true $republishedSHA256 2 -NoAuthorization
            Assert-TestSyncRefuses 'guardian authorization missing' 'authorization'

            # A never-activated (no-start) deployment has no guardian proof.
            Set-TestMetadata $activatedSHA256 'never_activated' 1
            Set-TestGuardian $true $republishedSHA256 2
            Assert-TestSyncRefuses 'never activated' 'never activated'

            # A pending transaction is recovered first; the rebind never runs over it.
            Set-TestMetadata $activatedSHA256 'activated' 1
            [IO.File]::WriteAllText($layout.PendingPath, '{}', $utf8)
            $before = Get-TestMetadataText
            if ((Invoke-TestSync) -or (Get-TestMetadataText) -cne $before) {
                $failures.Add('rebind ran over a pending transaction')
            }
            [IO.File]::Delete($layout.PendingPath)

            if ($canRewrite) {
                $script:TestAclWrites.Clear()
                if (-not (Invoke-TestSync)) {
                    $failures.Add('guardian-activated republication was not rebound')
                }
                $rebound = Get-DefenseClawDeploymentMetadata -Layout $layout -Required
                $record = $rebound.managed_hooks_activation
                if ([string]$record.manifest_sha256 -cne $republishedSHA256 -or
                    [int64]$record.target_count -ne 2 -or
                    [string]$record.state -cne 'activated' -or
                    [string]$record.deployment_generation_id -cne $generation) {
                    $failures.Add('rebind did not bind exactly the republished manifest')
                }
                if (-not (Get-TestMetadataText).Contains('"updated_at": "2026-09-27T02:56:38.1234567Z"') -or
                    [string]$rebound.gateway_service -cne 'DefenseClawGateway' -or
                    -not [bool]$rebound.installed) {
                    $failures.Add('rebind changed metadata fields other than the binding')
                }
                if ($script:TestAclWrites.Count -lt 2 -or
                    @($script:TestAclWrites | Microsoft.PowerShell.Core\Where-Object {
                        $_ -cne "AdminFile|$script:AdministratorsSID"
                    }).Count -ne 0) {
                    $failures.Add('rebound metadata did not get the administrator-only ACL')
                }
                if (@([IO.Directory]::GetFiles($installState, 'deployment.json.new.*')).Count -ne 0) {
                    $failures.Add('rebind left a temporary metadata file')
                }
                $after = Get-TestMetadataText
                if ((Invoke-TestSync) -or (Get-TestMetadataText) -cne $after) {
                    $failures.Add('a second rebind was not a no-op')
                }
            }

            # GAP-1417: Repair and Upgrade install their authenticated
            # gateway inside the transaction. Before it, a missing or
            # replaced installed gateway cannot prove the guardian's records,
            # so the staged replacement reads them; a recorded installed
            # gateway still does, and a call without a replacement (Verify,
            # Reconcile, Uninstall) keeps the installed one.
            if ($canRewrite) {
                $layout.GatewayPath = [IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe')
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($layout.GatewayPath))
                $recordedGateway = [IO.Path]::Combine($Root, 'recorded-gateway.bin')
                [IO.File]::WriteAllText($recordedGateway, 'recorded gateway', $utf8)
                $recordedGatewayHash = Get-TestSha256 $recordedGateway
                $replacement = @{ path = [IO.Path]::Combine($Root, 'staged-gateway.exe'); sha256 = 'staged' }
                foreach ($case in @(
                    @{ label = 'missing installed gateway'; bytes = $null; source = $replacement; want = 'replacement' },
                    @{ label = 'replaced installed gateway'; bytes = 'tampered gateway'; source = $replacement; want = 'replacement' },
                    @{ label = 'recorded installed gateway'; bytes = 'recorded gateway'; source = $replacement; want = 'installed' },
                    @{ label = 'missing gateway without a replacement'; bytes = $null; source = $null; want = 'installed' }
                )) {
                    if ($null -eq $case.bytes) {
                        if ([IO.File]::Exists($layout.GatewayPath)) {
                            [IO.File]::Delete($layout.GatewayPath)
                        }
                    }
                    else {
                        [IO.File]::WriteAllText($layout.GatewayPath, [string]$case.bytes, $utf8)
                    }
                    Set-TestMetadata $activatedSHA256 'activated' 1 $recordedGatewayHash
                    Set-TestGuardian $true $republishedSHA256 2
                    $script:TestGuardianSources.Clear()
                    try {
                        if (-not (Sync-DefenseClawStandaloneManagedHooksActivationBinding `
                                -Layout $layout `
                                -GatewayServiceName 'DefenseClawGateway' `
                                -GatewaySource $case.source)) {
                            $failures.Add("$($case.label): the republished manifest was not rebound")
                        }
                    }
                    catch {
                        $failures.Add("$($case.label): the rebind refused: $($_.Exception.Message)")
                    }
                    $usedReplacement = $script:TestGuardianSources.Count -gt 0 -and
                        @($script:TestGuardianSources | Microsoft.PowerShell.Core\Where-Object {
                            -not [object]::ReferenceEquals($_, $replacement)
                        }).Count -eq 0
                    $usedInstalled = $script:TestGuardianSources.Count -gt 0 -and
                        @($script:TestGuardianSources | Microsoft.PowerShell.Core\Where-Object {
                            $null -ne $_
                        }).Count -eq 0
                    if (($case.want -ceq 'replacement' -and -not $usedReplacement) -or
                        ($case.want -ceq 'installed' -and -not $usedInstalled)) {
                        $failures.Add("$($case.label): the guardian records were not read with the $($case.want) gateway")
                    }
                }
                $layout.Remove('GatewayPath')
                Set-TestMetadata $activatedSHA256 'activated' 1
            }

            # Secure Client never adopts, and its message is unchanged.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $layout.BrokerEnabled = $true
            Set-TestMetadata $activatedSHA256 'activated' 1
            Set-TestGuardian $true $republishedSHA256 2
            $script:TestGuardianProbes = 0
            $before = Get-TestMetadataText
            if ((Invoke-TestSync) -or (Get-TestMetadataText) -cne $before) {
                $failures.Add('Secure Client rebound a republished manifest')
            }
            $activation = (Get-DefenseClawDeploymentMetadata -Layout $layout -Required).managed_hooks_activation
            $adoption = Get-DefenseClawStandaloneManifestAdoption `
                -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -Activation $activation `
                -InstalledManifestSHA256 $republishedSHA256
            if ([bool]$adoption.ok -or -not [string]::IsNullOrEmpty([string]$adoption.reason) -or
                $script:TestGuardianProbes -ne 0) {
                $failures.Add('Secure Client adoption is not a silent refusal')
            }

            # Wiring: verify/servicing assertions adopt, and the dispatcher
            # rebinds before Upgrade, Repair, Reconcile and Uninstall.
            $tokens = $null
            $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
            $functions = @{}
            foreach ($definition in $ast.FindAll({
                param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
            }, $true)) {
                $functions[$definition.Name] = $definition.Body.Extent.Text
            }
            if (-not $functions['Assert-DefenseClawEnterpriseDeployment'].Contains('Get-DefenseClawStandaloneManifestAdoption')) {
                $failures.Add('the deployment assertion does not adopt a guardian-activated manifest')
            }
            foreach ($name in @('Assert-DefenseClawEnterpriseDeployment', 'Sync-DefenseClawStandaloneManagedHooksActivationBinding')) {
                if (-not $functions[$name].Contains('Add-DefenseClawSignedOutUntrustedFolders -Adoption $adoption')) {
                    $failures.Add("$name does not keep the signed-out untrusted folders for the result")
                }
            }
            if (-not $functions['Get-DefenseClawLifecycleStatus'].Contains("`$status['signed_out_untrusted_folders']")) {
                $failures.Add('the result does not report the signed-out untrusted folders')
            }
            $dispatcher = $functions['Invoke-DefenseClawEnterpriseLifecycle']
            $syncCalls = ([regex]::Matches($dispatcher, 'Sync-DefenseClawStandaloneManagedHooksActivationBinding')).Count
            if (-not $dispatcher.Contains("`$Action -in @('Upgrade', 'Repair') -and `$sources.ContainsKey('gateway')") -or
                -not $dispatcher.Contains('-GatewaySource $bindingGatewaySource')) {
                $failures.Add('Upgrade and Repair do not let their replacement gateway prove the guardian records (GAP-1417)')
            }
            if ($syncCalls -ne 2 -or
                $dispatcher.IndexOf('Sync-DefenseClawStandaloneManagedHooksActivationBinding') -gt
                    $dispatcher.IndexOf('return Invoke-DefenseClawReconcileLifecycle') -or
                $dispatcher.LastIndexOf('Sync-DefenseClawStandaloneManagedHooksActivationBinding') -gt
                    $dispatcher.IndexOf('return Invoke-DefenseClawUninstallLifecycle')) {
                $failures.Add('the lifecycle does not rebind before Reconcile and Uninstall/Upgrade/Repair')
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root $modulePath
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-manifest-adoption-smoke: OK'
