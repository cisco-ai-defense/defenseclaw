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
        $markers = [IO.Path]::Combine($Scratch, 'hook-runtime')
        foreach ($directory in @($authorization, $runtime, $enumerator, $markers)) { [void][IO.Directory]::CreateDirectory($directory) }
        $layout = @{
            AuthorizationDirectory = $authorization
            RuntimeDirectory       = $runtime
            ManifestPath           = [IO.Path]::Combine($enumerator, 'targets.yaml')
            GuardianLogPath        = [IO.Path]::Combine($Scratch, 'guardian.log')
        }
        $class = @(
            [IO.Path]::Combine($authorization, 'protected_targets.json'),
            [IO.Path]::Combine($authorization, 'activation.json'),
            [IO.Path]::Combine($authorization, 'user-cleanup.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_state.json')
        )
        # Published too, but a hold on them did not stop a repair, or a standard
        # account can open them: not gated.
        $notGated = @(
            [IO.Path]::Combine($authorization, 'removed-connectors.json'),
            [IO.Path]::Combine($authorization, 'unprotected-agents.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_startup.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_notices.json'),
            [IO.Path]::Combine($runtime, 'hook_guardian_restores.json'),
            [IO.Path]::Combine($enumerator, 'targets.yaml'),
            [IO.Path]::Combine($enumerator, 'unprotected-agents.json'),
            [IO.Path]::Combine($enumerator, '.enrollment-groups.json'),
            [IO.Path]::Combine($markers, '.defenseclaw-connector-off-roster-claudecode')
        )
        foreach ($path in @($class + $notGated)) { [IO.File]::WriteAllText($path, '{}') }
        # Held open on purpose, and not the guardian: audit data in the runtime folder.
        [IO.File]::WriteAllText([IO.Path]::Combine($enumerator, 'opencode-service-ports.lock'), 'x')
        [IO.File]::WriteAllText([IO.Path]::Combine($runtime, 'audit.db'), 'x')
        # What the guardian publishes is for administrators; the scratch folder
        # inherits the profile access list, so make it so. Only SYSTEM and
        # Administrators (the smoke runs elevated): no named user, or the files
        # would not be gated (N2).
        foreach ($path in @($class + $notGated)) {
            & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        }

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
            # A published file that is not critical is not gated, held or not.
            foreach ($path in $notGated) {
                $other = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try { if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw "a hold on the non-critical $([IO.Path]::GetFileName($path)) was gated" } }
                finally { $other.Dispose() }
            }
            # N2: a critical file a standard account can read is not gated either:
            # that account could hold it and block every ensure and repair.
            $ledger = $class[0]
            & icacls.exe $ledger /grant '*S-1-5-32-545:R' | Out-Null
            $reader = [IO.FileStream]::new($ledger, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -contains $ledger) { throw 'a user-readable ledger stayed in the class' }
                if ($null -ne (Get-DefenseClawGuardianStateHold -Layout $layout -Probes 2)) { throw 'a user-readable file held by a reader was reported as a hold' }
                $gate = ''
                try { Assert-DefenseClawGuardianStateNotHeld -Layout $layout -TimeoutSeconds 1 } catch { $gate = $_.Exception.Message }
                if ($gate -ne '') { throw "the gate refused over a user-readable file: $gate" }
            }
            finally { $reader.Dispose(); & icacls.exe $ledger /remove:g '*S-1-5-32-545' | Out-Null }
            # N2 tighten: any access for any other principal, not only read: a
            # write-only Users entry, and a user SID named directly.
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $openers = [ordered]@{ 'a write-only Users entry' = '*S-1-5-32-545:W' }
            if ($currentUser -ne 'S-1-5-18') { $openers['a named user SID'] = "*${currentUser}:R" }
            foreach ($label in $openers.Keys) {
                $grant = $openers[$label]
                & icacls.exe $ledger /grant $grant | Out-Null
                try {
                    if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -contains $ledger) { throw "$label stayed in the class" }
                }
                finally { & icacls.exe $ledger /remove:g ($grant -replace ':.*$', '') | Out-Null }
                if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -notcontains $ledger) { throw "the ledger stayed out of the class after $label was removed" }
            }
            # GAP-0989: an inherit-only Users entry applies to what a folder holds, not to
            # the file that carries it, so the ledger stays in the class; the same entry
            # without the flag takes it out.
            & icacls.exe $ledger /grant '*S-1-5-32-545:(OI)(CI)(IO)R' | Out-Null
            try {
                if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -notcontains $ledger) { throw 'an inherit-only Users entry took the ledger out of the class' }
            }
            finally { & icacls.exe $ledger /remove:g '*S-1-5-32-545' | Out-Null }
            & icacls.exe $ledger /grant '*S-1-5-32-545:(OI)(CI)R' | Out-Null
            try {
                if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -contains $ledger) { throw 'a Users entry on the file itself left the ledger in the class' }
            }
            finally { & icacls.exe $ledger /remove:g '*S-1-5-32-545' | Out-Null }
            if (@(Get-DefenseClawGuardianStateFiles -Layout $layout) -notcontains $ledger) { throw 'the ledger stayed out of the class after the inheritable entry was removed' }
            # S-I1: a hold that fails after it stopped the guardian starts it again
            # and puts its start mode back; the services a held run left Running
            # are Running at the end. The service calls are replaced in the module.
            Add-Type -AssemblyName System.ServiceProcess
            $replaced = @('Test-DefenseClawServiceExists', 'Get-DefenseClawServiceStartMode', 'Get-DefenseClawServiceDelayedAutoStart', 'Set-DefenseClawServiceDelayedAutoStart', 'Get-DefenseClawServiceChecked', 'Set-DefenseClawServiceStartMode', 'Stop-DefenseClawService', 'Start-DefenseClawService', 'Install-DefenseClawFileAtomic')
            $original = @{}
            foreach ($name in $replaced) { $original[$name] = (Get-Item -LiteralPath "function:$name").ScriptBlock }
            $transaction = [IO.Path]::Combine($scratch, 'txn')
            [void][IO.Directory]::CreateDirectory($transaction)
            $guardPath = [IO.Path]::Combine($transaction, 'early-hook-closed.exe')
            [IO.File]::WriteAllText($guardPath, 'closed hook guard')
            $guardSha = (Get-FileHash -LiteralPath $guardPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $holdLayout = @{ HookPath = [IO.Path]::Combine($scratch, 'defenseclaw-hook.exe') }
            $script:SmokeServiceCalls = [Collections.Generic.List[string]]::new()
            $script:SmokeInstallFails = $true
            $script:SmokeStartFails = $false
            # GAP-0989: the guardian's delayed-auto flag. SmokeDelayed is the flag the
            # mocked service holds; SmokeModeClearsDelayed models a mode change that
            # takes the flag with it (the real service answers natively, in the lane).
            $script:SmokeDelayed = $false
            $script:SmokeModeClearsDelayed = $false
            try {
                Set-Item -LiteralPath 'function:script:Test-DefenseClawServiceExists' -Value { $true }
                Set-Item -LiteralPath 'function:script:Get-DefenseClawServiceStartMode' -Value { 2 }
                Set-Item -LiteralPath 'function:script:Get-DefenseClawServiceChecked' -Value { [pscustomobject]@{ Status = [ServiceProcess.ServiceControllerStatus]::Running } }
                Set-Item -LiteralPath 'function:script:Get-DefenseClawServiceDelayedAutoStart' -Value { $script:SmokeDelayed }
                Set-Item -LiteralPath 'function:script:Set-DefenseClawServiceDelayedAutoStart' -Value { $script:SmokeServiceCalls.Add("delayed $($args[3])"); $script:SmokeDelayed = [bool]$args[3] }
                Set-Item -LiteralPath 'function:script:Set-DefenseClawServiceStartMode' -Value { $script:SmokeServiceCalls.Add("mode $($args[3])"); if ($script:SmokeModeClearsDelayed) { $script:SmokeDelayed = $false } }
                Set-Item -LiteralPath 'function:script:Stop-DefenseClawService' -Value { $script:SmokeServiceCalls.Add('stop') }
                Set-Item -LiteralPath 'function:script:Start-DefenseClawService' -Value { if ($script:SmokeStartFails) { throw 'start refused' }; $script:SmokeServiceCalls.Add('start') }
                Set-Item -LiteralPath 'function:script:Install-DefenseClawFileAtomic' -Value { if ($script:SmokeInstallFails) { throw 'injected failure after the stop' }; Copy-Item -LiteralPath $guardPath -Destination $holdLayout.HookPath -Force }
                $hold = { param($Failure) Hold-DefenseClawEarlyHookGuard -Layout $holdLayout -TransactionDirectory $transaction -GuardCopy $guardPath -GuardSHA256 $guardSha -GuardianServiceName 'DcSmokeGuardian' }
                $caught = ''
                try { [void](& $hold) } catch { $caught = $_.Exception.Message }
                if ($caught -ne 'injected failure after the stop') { throw "the failed hold said '$caught'" }
                if (($script:SmokeServiceCalls -join '|') -ne 'mode 4|stop|mode 2|start') { throw "a failed hold left '$($script:SmokeServiceCalls -join '|')', want the guardian stopped, then its start mode and start restored" }
                # GAP-0989: a delayed-auto guardian comes back delayed-auto, whether the mode
                # change took the flag with it (it is set again) or left it (no extra call), and
                # a plain automatic guardian is not made delayed.
                $script:SmokeServiceCalls.Clear(); $script:SmokeDelayed = $true; $script:SmokeModeClearsDelayed = $true; $caught = ''
                try { [void](& $hold) } catch { $caught = $_.Exception.Message }
                if ($caught -ne 'injected failure after the stop') { throw "the delayed-auto hold said '$caught'" }
                if (($script:SmokeServiceCalls -join '|') -ne 'mode 4|stop|mode 2|delayed True|start') { throw "a failed hold of a delayed-auto guardian left '$($script:SmokeServiceCalls -join '|')', want the mode, then the delayed flag, then start" }
                if (-not $script:SmokeDelayed) { throw 'the delayed-auto guardian came back plain automatic' }
                $script:SmokeServiceCalls.Clear(); $script:SmokeDelayed = $true; $script:SmokeModeClearsDelayed = $false; $caught = ''
                try { [void](& $hold) } catch { $caught = $_.Exception.Message }
                if (($script:SmokeServiceCalls -join '|') -ne 'mode 4|stop|mode 2|start') { throw "a failed hold that kept the delayed flag left '$($script:SmokeServiceCalls -join '|')'" }
                $script:SmokeServiceCalls.Clear(); $script:SmokeDelayed = $false; $script:SmokeModeClearsDelayed = $false; $caught = ''
                try { [void](& $hold) } catch { $caught = $_.Exception.Message }
                if (($script:SmokeServiceCalls -join '|') -ne 'mode 4|stop|mode 2|start' -or $script:SmokeDelayed) { throw "a failed hold of a plain automatic guardian left '$($script:SmokeServiceCalls -join '|')' delayed=$($script:SmokeDelayed)" }
                # The guardian cannot be started again: the failure says so, with the first cause.
                $script:SmokeServiceCalls.Clear()
                $script:SmokeServiceCalls.Clear(); $script:SmokeStartFails = $true; $caught = ''
                try { [void](& $hold) } catch { $caught = $_.Exception.Message }
                if (-not $caught.StartsWith('injected failure after the stop') -or -not $caught.Contains('could not be started again') -or -not $caught.Contains('start refused')) { throw "the failed restart said '$caught'" }
                # A hold that works leaves the guardian stopped for the rollback that follows.
                $script:SmokeServiceCalls.Clear(); $script:SmokeStartFails = $false; $script:SmokeInstallFails = $false
                if ((& $hold) -ne $guardSha) { throw 'a working hold did not return the guard digest' }
                if (($script:SmokeServiceCalls -join '|') -ne 'mode 4|stop') { throw "a working hold left '$($script:SmokeServiceCalls -join '|')'" }
            }
            finally { foreach ($name in $replaced) { Set-Item -LiteralPath "function:script:$name" -Value $original[$name] } }
            # S-H3: a holder that arrives during the rollback proof (after the check
            # before it) is resolved: the proof is deferred and the run continues.
            $late = [IO.FileStream]::new($class[1], [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                Clear-DefenseClawRollbackDeferredHolds
                $failure = $null
                try { throw ('guardian_state_held: x has ' + $class[1] + ' open without delete sharing, so the hook guardian could not publish fresh required coverage') } catch { $failure = $_ }
                # The service name does not exist: the best-effort start fails and is logged, as on a guardian that does not stay up.
                if (-not (Resolve-DefenseClawRollbackLateGuardianHold -Layout $layout -Failure $failure -GuardianServiceName 'DcSmokeNoSuchGuardian')) { throw 'a late holder was not resolved' }
                if (-not (Test-DefenseClawRollbackCoverageDeferred)) { throw 'the late holder did not defer the proof' }
                $ended = ''
                try { Assert-DefenseClawRollbackHoldsResolved } catch { $ended = $_.Exception.Message }
                if (-not $ended.StartsWith('guardian_state_held: ') -or -not $ended.Contains($class[1])) { throw "the late holder ended '$ended'" }
                # Another failure is not resolved, and neither is a holder that has gone.
                $other = $null
                try { throw 'some other failure' } catch { $other = $_ }
                if (Resolve-DefenseClawRollbackLateGuardianHold -Layout $layout -Failure $other -GuardianServiceName 'DcSmokeNoSuchGuardian') { throw 'another failure was resolved as a late holder' }
            }
            finally { $late.Dispose() }
            Clear-DefenseClawRollbackDeferredHolds
            if (Resolve-DefenseClawRollbackLateGuardianHold -Layout $layout -Failure $failure -GuardianServiceName 'DcSmokeNoSuchGuardian') { throw 'a holder that has gone was resolved' }
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
