# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0977: a program that holds one of the hook guardian's state files open
# without delete sharing keeps the guardian from publishing, so the fresh
# coverage the transaction waits for can never come. The standalone profile
# finds the holder before anything is stopped (guardian_state_held, retryable,
# nothing changed), a rollback that meets it leaves the file as it is and
# defers the guardian's coverage proof (so the restored services start), and
# Secure Client sees nothing of it. Same account, one process, scratch folders.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-guardian-held-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)

try {
    & $module {
        param($Scratch)
        $authorization = [IO.Path]::Combine($Scratch, 'hook-guardian-state')
        $runtime = [IO.Path]::Combine($Scratch, 'runtime')
        $enumerator = [IO.Path]::Combine($Scratch, 'hook-guardian')
        foreach ($directory in @($authorization, $runtime, $enumerator)) { [void][IO.Directory]::CreateDirectory($directory) }
        $layout = @{
            AuthorizationDirectory = $authorization
            RuntimeDirectory       = $runtime
            ManifestPath           = [IO.Path]::Combine($enumerator, 'targets.yaml')
            GuardianLogPath        = [IO.Path]::Combine($Scratch, 'guardian.log')
        }
        $class = @(
            [IO.Path]::Combine($authorization, 'protected_targets.json'),
            [IO.Path]::Combine($authorization, 'activation.json'),
            [IO.Path]::Combine($authorization, 'removed-connectors.json'),
            [IO.Path]::Combine($authorization, 'user-cleanup.json'),
            [IO.Path]::Combine($authorization, 'unprotected-agents.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_state.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_startup.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_notices.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_restores.json'),
            [IO.Path]::Combine($enumerator, 'targets.yaml'),
            [IO.Path]::Combine($enumerator, 'unprotected-agents.json'),
            [IO.Path]::Combine($enumerator, '.enrollment-groups.json'),
            [IO.Path]::Combine($enumerator, '.inventory-grants.json'),
            [IO.Path]::Combine($enumerator, 'opencode-service-ports.json')
        )
        foreach ($path in $class) { [IO.File]::WriteAllText($path, '{}') }
        # Held open on purpose, and not the guardian's: audit data in the runtime folder.
        [IO.File]::WriteAllText([IO.Path]::Combine($enumerator, 'opencode-service-ports.lock'), 'x')
        [IO.File]::WriteAllText([IO.Path]::Combine($enumerator, '.state'), 'x')
        [IO.File]::WriteAllText([IO.Path]::Combine($runtime, 'audit.db'), 'x')

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $listed = @(Get-DefenseClawGuardianStateFiles -Layout $layout | Microsoft.PowerShell.Core\ForEach-Object { [IO.Path]::GetFileName($_) } | Microsoft.PowerShell.Utility\Sort-Object)
            $expected = @($class | Microsoft.PowerShell.Core\ForEach-Object { [IO.Path]::GetFileName($_) } | Microsoft.PowerShell.Utility\Sort-Object)
            if (($listed -join '|') -ne ($expected -join '|')) {
                throw "the class is '$($listed -join ', ')', want '$($expected -join ', ')'"
            }
            if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw 'nothing is held but a hold was reported' }

            foreach ($path in $class) {
                $name = [IO.Path]::GetFileName($path)
                # A reader that shares delete is not a hold.
                $sharing = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                try { if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw "a reader that shares delete counted as a hold on $name" } }
                finally { $sharing.Dispose() }
                # A holder that does not share delete is.
                $holder = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    $held = Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2
                    if ($held -ne $path) { throw "a Read holder on $name was reported as '$held'" }
                    # The pre-stop gate refuses with the stable code first, retryably, naming the file.
                    $gate = ''
                    try { Assert-DefenseClawGuardianStateNotHeld -Layout $layout -TimeoutSeconds 1 } catch { $gate = $_.Exception.Message }
                    if (-not $gate.StartsWith('guardian_state_held: ') -or -not $gate.Contains($path) -or -not $gate.Contains('changed nothing')) {
                        throw "the gate on $name said '$gate'"
                    }
                    if (-not (Test-DefenseClawRollbackHeldMessage -Message $gate)) { throw 'the held code is not a rollback-held message' }
                    # A rollback defers the guardian proof and ends held, pending.
                    Clear-DefenseClawRollbackDeferredHolds
                    Set-DefenseClawRollbackGuardianStateDeferral -Layout $layout
                    if (-not (Test-DefenseClawRollbackCoverageDeferred)) { throw "a rollback on $name did not defer the guardian proof" }
                    $ended = ''
                    try { Assert-DefenseClawRollbackHoldsResolved } catch { $ended = $_.Exception.Message }
                    if (-not $ended.StartsWith('guardian_state_held: ') -or -not $ended.Contains($path) -or -not $ended.Contains('still pending')) {
                        throw "the rollback on $name ended '$ended'"
                    }
                    if (Test-DefenseClawRollbackCoverageDeferred) { throw 'the deferral outlived the rollback' }
                }
                finally { $holder.Dispose() }
                $gate = ''
                try { Assert-DefenseClawGuardianStateNotHeld -Layout $layout -TimeoutSeconds 1 } catch { $gate = $_.Exception.Message }
                if ($gate -ne '') { throw "the gate refused after $name was released: $gate" }
                Clear-DefenseClawRollbackDeferredHolds
                Set-DefenseClawRollbackGuardianStateDeferral -Layout $layout
                if (Test-DefenseClawRollbackCoverageDeferred) { throw "a rollback deferred with nothing held (after $name)" }
            }
            # Files outside the class do not count; a lock the enumerator holds on purpose neither.
            $auditHold = [IO.FileStream]::new([IO.Path]::Combine($runtime, 'audit.db'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
            $lockHold = [IO.FileStream]::new([IO.Path]::Combine($enumerator, 'opencode-service-ports.lock'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
            try { if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw 'a file outside the class, or a lock, counted as a hold' } }
            finally { $auditHold.Dispose(); $lockHold.Dispose() }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }

        # Secure Client: no hold is looked for, nothing is deferred.
        $secureHolder = [IO.FileStream]::new($class[0], [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw 'Secure Client looked for a guardian state hold' }
            Clear-DefenseClawRollbackDeferredHolds
            Set-DefenseClawRollbackGuardianStateDeferral -Layout $layout
            if ((Test-DefenseClawRollbackCoverageDeferred) -or $script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw 'Secure Client deferred over a guardian state hold' }
        }
        finally { $secureHolder.Dispose() }
    } $scratch
    'enterprise-standalone-guardian-state-held-smoke: OK'
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
