# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0999: a Codex writer that keeps its transaction open (the writer lock
# counter odd) is named by process id, defers the guardian proof of a rollback
# the way a held file does, and ends the rollback with the retryable
# codex_state_unsettled; a settled writer defers nothing; Secure Client has no
# writer lock and defers nothing. The writer is a second process of this
# engine that holds the lock with an odd size. Same account, no service.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-codex-writer-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)
$engine = (Microsoft.PowerShell.Management\Get-Process -Id $PID).Path
$children = [Collections.Generic.List[object]]::new()

try {
    & $module {
        param($Scratch, $Engine, $Children)
        $state = [IO.Path]::Combine($Scratch, '.defenseclaw-managed-hooks.state')
        $lock = [IO.Path]::Combine($Scratch, '.defenseclaw-managed-hooks.writer.lock')
        $layout = @{ CodexManagedHooksStatePath = $state; InstallRoot = $Scratch; StateRoot = $Scratch }
        $childScript = [IO.Path]::Combine($Scratch, 'writer.ps1')
        [IO.File]::WriteAllText($childScript, @'
param([string]$Lock, [string]$Stop, [string]$Ready, [int]$Size, [int]$EndSize)
$fs = [IO.File]::Open($Lock, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
$fs.SetLength($Size)
[IO.File]::WriteAllText($Ready, [string]$PID)
while (-not (Test-Path -LiteralPath $Stop)) { Start-Sleep -Milliseconds 100 }
$fs.SetLength($EndSize)
$fs.Dispose()
'@)
        function Start-Writer([int]$Size, [int]$EndSize) {
            $stop = [IO.Path]::Combine($Scratch, 'writer.stop'); $ready = [IO.Path]::Combine($Scratch, 'writer.ready')
            Remove-Item -LiteralPath $stop, $ready -Force -ErrorAction SilentlyContinue
            $arguments = @('-NoLogo', '-NoProfile', '-File', $childScript, '-Lock', $lock, '-Stop', $stop, '-Ready', $ready, '-Size', $Size, '-EndSize', $EndSize)
            $start = @{ FilePath = $Engine; ArgumentList = $arguments; PassThru = $true; WindowStyle = 'Hidden' }
            $process = Start-Process @start
            $Children.Add($process)
            for ($i = 0; $i -lt 100 -and -not (Test-Path -LiteralPath $ready); $i++) { Start-Sleep -Milliseconds 100 }
            if (-not (Test-Path -LiteralPath $ready)) { throw 'the writer fixture did not start' }
            return $process
        }
        function Stop-Writer($Process) {
            New-Item -ItemType File -Path ([IO.Path]::Combine($Scratch, 'writer.stop')) -Force | Out-Null
            [void]$Process.WaitForExit(15000)
            if (-not $Process.HasExited) { Stop-Process -Id $Process.Id -Force }
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            Clear-DefenseClawRollbackDeferredHolds
            # No program has the lock open: the text says so (no process named).
            [IO.File]::WriteAllBytes($lock, [byte[]]::new(19))
            $none = Get-DefenseClawCodexWriterHolderText -Path $state
            if (-not $none.Contains('no program this account can name has the writer lock open')) { throw "holder text without a holder: '$none'" }

            $writer = Start-Writer 19 18
            try {
                $named = Get-DefenseClawCodexWriterHolderText -Path $state
                if (-not $named.StartsWith('the writer is ') -or -not $named.Contains(('pid {0}' -f $writer.Id))) { throw "holder text: the writer was not named by its process id: '$named'" }

                # The wait refuses by name, and the refusal carries the writer.
                $refusal = ''
                try { [void](Wait-DefenseClawCodexManagedHooksStateSettled -Path $state -TimeoutSeconds 2) } catch { $refusal = $_.Exception.Message }
                if (-not $refusal.StartsWith('codex_state_unsettled: ') -or -not $refusal.Contains('stayed at 19 (odd: a transaction is open)') -or
                    -not $refusal.Contains(('pid {0}' -f $writer.Id)) -or -not $refusal.Contains('/repair') -or $refusal -match 'FORCE') {
                    throw "unsettled refusal: not named: '$refusal'"
                }
                if (Test-DefenseClawRollbackHeldMessage -Message $refusal) { throw 'the refusal of a forward run was read as a rollback deferral' }

                # The guardian proof of a rollback is deferred for the stuck writer.
                if (-not (Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)) { throw 'a stuck writer did not defer the guardian proof' }
                if ($script:DefenseClawRollbackDeferredHolds.Count -ne 1 -or -not (Test-DefenseClawRollbackCoverageDeferred)) { throw 'the deferral was not recorded' }
                [void](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
                if ($script:DefenseClawRollbackDeferredHolds.Count -ne 1) { throw 'the writer was listed twice' }
                $ended = ''
                try { Assert-DefenseClawRollbackHoldsResolved } catch { $ended = $_.Exception.Message }
                if (-not (Test-DefenseClawRollbackHeldMessage -Message $ended) -or -not $ended.Contains(('pid {0}' -f $writer.Id)) -or
                    -not $ended.Contains('the transaction is still pending') -or -not $ended.Contains('/repair') -or $ended -match 'FORCE|uninstall' -or
                    -not $ended.Contains("The guardian's coverage was not proven by this rollback")) {
                    throw "the rollback did not end retryable and named: '$ended'"
                }
                if ($script:DefenseClawRollbackDeferredHolds.Count -ne 0 -or (Test-DefenseClawRollbackCoverageDeferred)) { throw 'the deferral outlived the rollback' }
                # The recovery that started the services keeps only this deferral.
                [void](Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)
                Add-DefenseClawRollbackDeferredHold -Message 'hook_in_use: x has C:\h.exe, the installed hook, open'
                $kept = Get-DefenseClawRollbackCodexWriterHolds
                Clear-DefenseClawRollbackDeferredHolds
                Restore-DefenseClawRollbackCodexWriterHolds -Kept $kept
                if ($script:DefenseClawRollbackDeferredHolds.Count -ne 1 -or -not $script:DefenseClawRollbackDeferredHolds[0].StartsWith('codex_state_unsettled: ')) { throw 'KeepCodexWriter kept the wrong holds' }
                Clear-DefenseClawRollbackDeferredHolds
            }
            finally { Stop-Writer $writer }

            # A program holds the lock with the counter EVEN (an antivirus scanner, a backup
            # program): it is a named holder, so the proof is deferred the same way.
            $holder = Start-Writer 18 18
            try {
                if (-not (Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout)) { throw 'a named holder with an even counter did not defer the guardian proof' }
                $even = [string]$script:DefenseClawRollbackDeferredHolds[0]
                if (-not $even.Contains('stayed at 18 (even, but a writer holds the lock') -or -not $even.Contains(('pid {0}' -f $holder.Id))) { throw "the even-counter deferral did not name the holder: '$even'" }
                Clear-DefenseClawRollbackDeferredHolds
            }
            finally { Stop-Writer $holder }

            # The writer ended its transaction (the size is even again): nothing is deferred.
            if ((Get-DefenseClawCodexManagedHooksWriterCounter -Path $state) % 2 -ne 0) { throw 'the writer fixture did not end its transaction' }
            if (Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout) { throw 'a settled writer deferred the guardian proof' }
            if ($script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw 'a settled writer left a hold' }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }

        # Secure Client pin: no writer lock, nothing is deferred, whatever the size says.
        [IO.File]::WriteAllBytes($lock, [byte[]]::new(19))
        Clear-DefenseClawRollbackDeferredHolds
        if (Test-DefenseClawGuardianProofDeferredByCodexWriter -Layout $layout) { throw 'Secure Client: the guardian proof was deferred' }
        if ($script:DefenseClawRollbackDeferredHolds.Count -ne 0 -or (Test-DefenseClawRollbackCoverageDeferred)) { throw 'Secure Client: a hold was recorded' }
        if ((Resolve-DefenseClawCodexManagedHooksStateCopySettled -Strict -Path $state) -ne ($state + '.20')) { throw 'Secure Client: the settled resolver waited or refused' }
    } $scratch $engine $children
    'enterprise-standalone-codex-writer-stuck-smoke: OK'
}
finally {
    foreach ($child in $children) {
        if (-not $child.HasExited) { Microsoft.PowerShell.Management\Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
