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
            param($Path, $Expected)
        }
        $script:TestAclWrites = [Collections.Generic.List[string]]::new()
        function Set-DefenseClawPathAcl {
            param($Path, $Kind, $GatewayServiceSID)
            $script:TestAclWrites.Add("$Kind|$GatewayServiceSID")
        }
        $script:TestGuardianReport = $null
        $script:TestGuardianProbes = 0
        function Get-DefenseClawGuardianStatusReport {
            param($Layout, $GatewayServiceName)
            $script:TestGuardianProbes++
            return $script:TestGuardianReport
        }

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
            function Set-TestMetadata([string]$ManifestSHA256, [string]$State, [int64]$TargetCount) {
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
                [IO.File]::WriteAllText(
                    $layout.MetadataPath,
                    ($value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6),
                    $utf8
                )
            }
            function Set-TestGuardian([bool]$Ok, [string]$ManifestSHA256, [int64]$TargetCount, [int64]$Failures = 0, [string]$StateStamp = '', [switch]$NoAuthorization, [switch]$Stale) {
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
                $report = [ordered]@{
                    ok = $Ok
                    errors = $errors
                    activation = $activation
                    state = (& $record $StateStamp)
                }
                if (-not $NoAuthorization) {
                    $report['authorization'] = (& $record $stamp)
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

            # The guardian has not activated the republished manifest yet, or
            # its records do not describe one failure-free reconcile of it.
            Set-TestGuardian $true $activatedSHA256 1
            Assert-TestSyncRefuses 'guardian still on the old manifest' 'guardian'
            Set-TestGuardian $false $republishedSHA256 2 1
            Assert-TestSyncRefuses 'guardian reconcile failed' 'marker'
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
            $dispatcher = $functions['Invoke-DefenseClawEnterpriseLifecycle']
            $syncCalls = ([regex]::Matches($dispatcher, 'Sync-DefenseClawStandaloneManagedHooksActivationBinding')).Count
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
