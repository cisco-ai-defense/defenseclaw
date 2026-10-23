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
            $expected = 'artifact-proof,shape-proof,hooks:prepare,hooks:verify,opencode-removed,install-tree-locked,retirement-acl-proof,artifact-proof,hooks:finalize'
            $observed = $script:HookCommitEvents -join ','
            if ($observed -cne $expected) {
                $failures.Add("committed cleanup order: $observed")
            }
            if ($script:HookCommitPhase -cne 'finalized') {
                $failures.Add('committed cleanup did not finish the journal')
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
                    $guarded = $false
                    for ($parent = $call.Parent; $null -ne $parent; $parent = $parent.Parent) {
                        if ($parent -is [Management.Automation.Language.IfStatementAst]) {
                            foreach ($clause in $parent.Clauses) {
                                if ($clause.Item1.Extent.Text -match '-not\s*\(Test-DefenseClawStandaloneProfile\)') {
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
