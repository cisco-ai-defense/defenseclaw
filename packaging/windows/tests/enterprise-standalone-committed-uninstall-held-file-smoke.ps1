# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-1042: a standalone uninstall that already committed and then meets a file
# a program holds open (the Codex writer lock, requirements.toml, the hook)
# waits the settle bound for the holder, then ends with the retryable held code
# (exit 1618 in the CLI) that names the file and the holder, says the uninstall
# is committed and nothing is rolled back, and points at the same uninstall
# (PURGE=1 when it asked for it), never FORCE. A failure of an uninstall that
# did not commit, an unrelated failure, and Secure Client are left as they
# were. The holders are second processes of this engine (same account, no
# service); nothing outside the scratch folder is touched.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-committed-held-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)
$engine = (Microsoft.PowerShell.Management\Get-Process -Id $PID).Path
$children = [Collections.Generic.List[object]]::new()

try {
    & $module {
        param($Scratch, $Engine, $Children)
        $codex = [IO.Path]::Combine($Scratch, 'codex')
        [void][IO.Directory]::CreateDirectory($codex)
        $lock = [IO.Path]::Combine($codex, '.defenseclaw-managed-hooks.writer.lock')
        $requirements = [IO.Path]::Combine($codex, 'requirements.toml')
        $hook = [IO.Path]::Combine($Scratch, 'hook.exe')
        $layout = @{
            CodexManagedHooksLockPath = $lock
            CodexManagedHooksStatePath = [IO.Path]::Combine($codex, '.defenseclaw-managed-hooks.state')
            CodexMachinePolicyPath = $requirements
            HookPath = $hook
            InstallRoot = [IO.Path]::Combine($Scratch, 'install')
            StateRoot = [IO.Path]::Combine($Scratch, 'state')
            PendingPath = [IO.Path]::Combine($Scratch, 'state', 'pending.json')
        }
        [IO.File]::WriteAllBytes($lock, [byte[]]::new(18))
        [IO.File]::WriteAllText($requirements, 'allow_managed_hooks_only = true')
        [IO.File]::WriteAllBytes($hook, [byte[]]::new(4))

        # A holder: a second process that opens the file sharing read and write
        # but not delete (a writer, a scanner) until the stop file appears or
        # the hold ends by itself.
        $childScript = [IO.Path]::Combine($Scratch, 'holder.ps1')
        [IO.File]::WriteAllText($childScript, @'
param([string]$Path, [string]$Stop, [string]$Ready, [int]$HoldSeconds)
$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
[IO.File]::WriteAllText($Ready, [string]$PID)
$end = [DateTime]::UtcNow.AddSeconds($HoldSeconds)
while (-not (Test-Path -LiteralPath $Stop) -and [DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 100 }
$fs.Dispose()
'@)
        function Start-Holder([string]$Path, [int]$HoldSeconds = 120) {
            $stop = [IO.Path]::Combine($Scratch, 'holder.stop'); $ready = [IO.Path]::Combine($Scratch, 'holder.ready')
            Remove-Item -LiteralPath $stop, $ready -Force -ErrorAction SilentlyContinue
            $arguments = @('-NoLogo', '-NoProfile', '-File', $childScript, '-Path', $Path, '-Stop', $stop, '-Ready', $ready, '-HoldSeconds', $HoldSeconds)
            $start = @{ FilePath = $Engine; ArgumentList = $arguments; PassThru = $true; WindowStyle = 'Hidden' }
            $process = Start-Process @start
            $Children.Add($process)
            for ($i = 0; $i -lt 100 -and -not (Test-Path -LiteralPath $ready); $i++) { Start-Sleep -Milliseconds 100 }
            if (-not (Test-Path -LiteralPath $ready)) { throw 'the holder fixture did not start' }
            return $process
        }
        function Stop-Holder($Process) {
            New-Item -ItemType File -Path ([IO.Path]::Combine($Scratch, 'holder.stop')) -Force | Out-Null
            [void]$Process.WaitForExit(15000)
            if (-not $Process.HasExited) { Stop-Process -Id $Process.Id -Force }
        }

        # The committed state the classifier reads: a tombstone, no pending record.
        $script:smokeInstalled = $false
        function script:Get-DefenseClawDeploymentMetadata { param([hashtable]$Layout) return [pscustomobject]@{ installed = $script:smokeInstalled } }
        function script:Test-DefenseClawMetadataInstalled { param($Metadata) return [bool]$Metadata.installed }
        $script:CodexStateSettleSeconds = 2
        $script:DefenseClawCommittedUninstallHeldWaits = $true

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $script:DefenseClawUninstallPurgeUserState = $false

            # Nobody holds anything: nothing is found, the wait returns at once.
            if ($null -ne (Get-DefenseClawCommittedUninstallHeldFile -Layout $layout)) { throw 'a file nobody holds was reported held' }
            $timer = [Diagnostics.Stopwatch]::StartNew()
            Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock
            if ($timer.Elapsed.TotalSeconds -gt 1.5) { throw 'the wait for a free file took time' }
            # A file that is not there is not held either.
            Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path ([IO.Path]::Combine($codex, '.defenseclaw-managed-hooks.lock'))

            # The Codex writer lock held (the counter plays no part in the wait): the wait gives up at
            # the bound and names the file, the holder, the committed state and the rerun; no FORCE.
            [IO.File]::WriteAllBytes($lock, [byte[]]::new(19))
            $holder = Start-Holder $lock
            try {
                $held = Get-DefenseClawCommittedUninstallHeldFile -Layout $layout
                if ($null -eq $held -or $held.Code -cne 'codex_state_held') { throw 'the held writer lock was not found' }
                $text = ''
                $timer = [Diagnostics.Stopwatch]::StartNew()
                try { Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock } catch { $text = $_.Exception.Message }
                if ($timer.Elapsed.TotalSeconds -lt 1.5 -or $timer.Elapsed.TotalSeconds -gt 30) { throw "the wait was not the settle bound ($($timer.Elapsed.TotalSeconds) s)" }
                if (-not $text.StartsWith('codex_state_held: ') -or -not $text.Contains(('process id {0}' -f $holder.Id)) -or -not $text.Contains($lock) -or
                    -not $text.Contains('The uninstall is already committed') -or -not $text.Contains('/uninstall') -or $text.Contains('PURGE=1') -or $text -match 'FORCE|/repair') {
                    throw "the held message is wrong: '$text'"
                }
                if (-not (Test-DefenseClawFileDeleteBlocked -Path $lock)) { throw 'the fixture does not hold the lock' }
                # The same uninstall after PURGE=1 says so.
                $script:DefenseClawUninstallPurgeUserState = $true
                $text = ''
                $script:CodexStateSettleSeconds = 1
                try { Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock } catch { $text = $_.Exception.Message }
                $script:CodexStateSettleSeconds = 2
                $script:DefenseClawUninstallPurgeUserState = $false
                if (-not $text.Contains('/uninstall PURGE=1')) { throw "the purge rerun is not named: '$text'" }
            }
            finally { Stop-Holder $holder }

            # A recovery (not the foreground Uninstall) does not wait and does not read the file: the call
            # returns at once and the delete that follows is the one it always was. The detached recovery
            # Setup starts behind every uninstall is then over before the next run starts.
            $script:DefenseClawCommittedUninstallHeldWaits = $false
            $holder = Start-Holder $lock
            try {
                $text = ''
                $timer = [Diagnostics.Stopwatch]::StartNew()
                try { Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock } catch { $text = $_.Exception.Message }
                if ($timer.Elapsed.TotalSeconds -gt 1.5) { throw "a recovery waited for the holder ($($timer.Elapsed.TotalSeconds) s)" }
                if ($text -ne '') { throw "a recovery threw: '$text'" }
                if (-not (Test-DefenseClawFileDeleteBlocked -Path $lock)) { throw 'the fixture no longer holds the lock' }
            }
            finally { Stop-Holder $holder; $script:DefenseClawCommittedUninstallHeldWaits = $true }

            # A holder that lets go inside the bound: the wait ends without an error.
            $holder = Start-Holder $lock 1
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $script:CodexStateSettleSeconds = 20
            try { Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock } finally { $script:CodexStateSettleSeconds = 2 }
            if ($timer.Elapsed.TotalSeconds -gt 15) { throw 'the wait outlived the holder' }
            Stop-Holder $holder
            if ($null -ne (Get-DefenseClawCommittedUninstallHeldFile -Layout $layout)) { throw 'the released lock is still reported held' }

            # The classifier: a failure of the committed uninstall that names a held file.
            $io = "The process cannot access the file '{0}' because it is being used by another process."
            $holder = Start-Holder $lock
            try {
                $text = [string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $lock))
                if (-not $text.StartsWith('codex_state_held: ') -or -not $text.Contains(('process id {0}' -f $holder.Id)) -or -not $text.Contains($lock) -or $text -match 'FORCE') { throw "classifier, IOException: '$text'" }
                $wrapped = 'Uninstall committed, but managed runtime finalization or binary retirement failed; retry Uninstall to finish cleanup: ' + ($io -f $lock)
                if (-not ([string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message $wrapped)).StartsWith('codex_state_held: ')) { throw 'classifier: the wrapped failure was not read' }
                # The gateway's own timeout text, with no file named.
                $gateway = 'Codex requirements remove failed: timed out waiting 10s for Codex machine policy lock'
                if (-not ([string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message $gateway)).StartsWith('codex_state_held: ')) { throw 'classifier: the gateway writer-lock timeout was not read' }
                # The forward refusal the Codex command throws for a busy writer.
                if (-not ([string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message 'codex_state_unsettled: a Codex writer holds the writer lock')).StartsWith('codex_state_held: ')) { throw 'classifier: codex_state_unsettled was not read' }
                # Already honest: not read twice.
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message $text)) { throw 'classifier: a held message was wrapped again' }
                # A failure that quotes another file than the one held now is not read as this one.
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f (Join-Path $Scratch 'other.txt')))) { throw 'classifier: a failure on another file was read as the held lock' }
                # An unrelated failure stays as it was.
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message 'committed-uninstall cleanup requires an uninstall tombstone')) { throw 'classifier: an unrelated failure was read' }
                # A sharing failure with no file held now (and no Codex writer): left as it was.
            }
            finally { Stop-Holder $holder }
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $lock))) { throw 'classifier: named a file nobody holds' }

            # The gateway's writer-lock timeout with nobody holding the lock now (a writer that stopped
            # in the middle of its transaction): still the held code, with the original failure kept.
            $text = [string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message 'managed-hook teardown prepare failed: timed out waiting 10s for a Codex machine policy transaction to finish')
            if (-not $text.StartsWith('codex_state_held: ') -or -not $text.Contains('The failure was: managed-hook teardown prepare failed: timed out waiting 10s') -or $text -match 'FORCE') { throw "classifier, writer stopped mid-transaction: '$text'" }

            # The lock of 1.0.8 and earlier is waited for too.
            $legacy = [IO.Path]::Combine($codex, '.defenseclaw-managed-hooks.lock')
            [IO.File]::WriteAllBytes($legacy, [byte[]]::new(2))
            $holder = Start-Holder $legacy
            try {
                $text = ''
                try { Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $legacy } catch { $text = $_.Exception.Message }
                if (-not $text.StartsWith('codex_state_held: ') -or -not $text.Contains($legacy)) { throw "the legacy lock was not named: '$text'" }
            }
            finally { Stop-Holder $holder }
            [IO.File]::Delete($legacy)

            # A teardown journal that cannot be trusted for this deployment: the refusal names the file and the next step.
            $layout['ManagedHooksTeardownJournalPath'] = [IO.Path]::Combine($Scratch, 'state', 'managed-hooks-teardown-journal.json')
            $untrusted = 'schema-6 managed-hook teardown journal activation binding is invalid'
            $text = [string](ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message $untrusted)
            if (-not $text.StartsWith($untrusted) -or -not $text.Contains($layout['ManagedHooksTeardownJournalPath']) -or -not $text.Contains('/verify') -or
                -not $text.Contains('Setup deleted nothing') -or $text -match 'FORCE') { throw "journal refusal: '$text'" }
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message $text)) { throw 'journal refusal: a named refusal was named again' }
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message 'managed-hook teardown journal is missing or is not a regular file')) { throw 'journal refusal: a missing journal was refused' }
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message 'some other failure')) { throw 'journal refusal: an unrelated failure was read' }
            foreach ($transient in @('managed-hook teardown journal identity changed while it was read', 'managed-hook teardown journal was replaced while it was read', 'refusing to retire the managed-hook teardown journal before uninstall is durably committed', 'managed-hook teardown journal changed during publication')) {
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message $transient)) { throw "journal refusal: a transient failure was named as an untrusted record: $transient" }
            }
            $script:smokeInstalled = $true
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message $untrusted)) { throw 'journal refusal: an uninstall that is not committed was read' }
            $script:smokeInstalled = $false

            # requirements.toml and the hook get their own held codes.
            $holder = Start-Holder $requirements
            try {
                $text = [string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $requirements))
                if (-not $text.StartsWith('codex_requirements_held: ') -or -not $text.Contains($requirements) -or -not $text.Contains(('process id {0}' -f $holder.Id))) { throw "classifier, requirements.toml: '$text'" }
            }
            finally { Stop-Holder $holder }
            $holder = Start-Holder $hook
            try {
                $text = [string](ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $hook))
                if (-not $text.StartsWith('hook_in_use: ') -or -not $text.Contains($hook)) { throw "classifier, hook: '$text'" }

                # An uninstall that did not commit is not read: still installed, or a pending transaction.
                $script:smokeInstalled = $true
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $hook))) { throw 'classifier: an uninstall that is not committed was read' }
                $script:smokeInstalled = $false
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($layout.PendingPath))
                [IO.File]::WriteAllText($layout.PendingPath, '{}')
                if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ($io -f $hook))) { throw 'classifier: a pending transaction was read' }
                [IO.File]::Delete($layout.PendingPath)
            }
            finally { Stop-Holder $holder }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }

        # Secure Client keeps its text: nothing waits and nothing is read.
        if ($null -ne (ConvertTo-DefenseClawCommittedUninstallJournalMessage -Layout $layout -Message 'schema-6 managed-hook teardown journal activation binding is invalid')) { throw 'Secure Client: a journal refusal was rewritten' }
        $holder = Start-Holder $lock
        try {
            $timer = [Diagnostics.Stopwatch]::StartNew()
            Wait-DefenseClawCommittedUninstallFileReleased -Layout $layout -Path $lock
            if ($timer.Elapsed.TotalSeconds -gt 1.5) { throw 'Secure Client: the wait took time' }
            if ($null -ne (ConvertTo-DefenseClawCommittedUninstallHeldMessage -Layout $layout -Message ("The process cannot access the file '$lock' because it is being used by another process."))) { throw 'Secure Client: a failure was read' }
        }
        finally { Stop-Holder $holder }
    } $scratch $engine $children
    'enterprise-standalone-committed-uninstall-held-file-smoke: OK'
}
finally {
    foreach ($child in $children) {
        if (-not $child.HasExited) { Microsoft.PowerShell.Management\Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
