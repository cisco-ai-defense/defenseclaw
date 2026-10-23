# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-0136: a standalone purge with another program holding a file under
# StateRoot open. A read-only reader of runtime\audit.db (a SIEM forwarder or
# a log tail) made the purge fail 1603 after it had removed the binaries and
# the Claude Code hook wiring. Now the data-file check refuses before the
# purge changes anything, with uninstall_in_use naming the program, its pid,
# account and the file, a holder seen only once does not block, and the
# deletion after the services stopped retries a file in use and then refuses
# with uninstall_in_use, so running the purge again finishes it. The readers
# are real child processes that open the file with FileShare.Read, found
# through the Windows Restart Manager. Runs elevated in a disposable
# directory under Windows PowerShell 5.1 and PowerShell 7; no service or
# machine root is touched.

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
    ('dcsf-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
$readers = [Collections.Generic.List[Diagnostics.Process]]::new()
try {
    $failures = & $module {
        param([string]$Root, $Readers)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $savedProgramData = $script:ProgramData
        $savedRecheck = $script:InstallTreeUseRecheckMilliseconds
        $savedRetry = $script:StateRootRemovalRetryMilliseconds
        $engine = [IO.Path]::Combine($PSHOME, $(if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }))
        $engineName = [IO.Path]::GetFileName($engine)
        $readerScript = [IO.Path]::Combine($Root, 'reader.ps1')
        [IO.File]::WriteAllText($readerScript, @'
param([string]$Path, [string]$Ready, [int]$HoldMilliseconds)
$stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Milliseconds $HoldMilliseconds
$stream.Dispose()
'@)
        try {
            function Start-TestReader([string]$Path, [int]$HoldMilliseconds) {
                $ready = [IO.Path]::Combine($Root, 'ready-' + [Guid]::NewGuid().ToString('N'))
                $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Path "{1}" -Ready "{2}" -HoldMilliseconds {3}' -f $readerScript, $Path, $ready, $HoldMilliseconds
                $process = Microsoft.PowerShell.Management\Start-Process `
                    -FilePath $engine `
                    -ArgumentList $arguments `
                    -WindowStyle Hidden `
                    -PassThru
                $Readers.Add($process)
                $clock = [Diagnostics.Stopwatch]::StartNew()
                while (-not [IO.File]::Exists($ready)) {
                    if ($process.HasExited -or $clock.ElapsedMilliseconds -gt 60000) {
                        throw "test reader of $Path did not open it"
                    }
                    Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
                }
                return $process
            }
            function Stop-TestReader($Process) {
                if (-not $Process.HasExited) {
                    $Process.Kill()
                }
                $Process.WaitForExit()
            }
            function New-TestState([string]$Name) {
                $state = [IO.Path]::Combine($Root, $Name, 'PD', 'Cisco', 'DefenseClaw')
                $runtime = [IO.Path]::Combine($state, 'runtime')
                $install = [IO.Path]::Combine($Root, $Name, 'PF', 'Cisco', 'DefenseClaw')
                foreach ($directory in @($runtime, [IO.Path]::Combine($state, 'logs', 'gateway'), [IO.Path]::Combine($state, 'install'), [IO.Path]::Combine($install, 'bin'))) {
                    [void][IO.Directory]::CreateDirectory($directory)
                }
                foreach ($file in @(
                        [IO.Path]::Combine($runtime, 'audit.db'),
                        [IO.Path]::Combine($runtime, 'audit.db-wal'),
                        [IO.Path]::Combine($runtime, 'audit.db-shm'),
                        [IO.Path]::Combine($state, 'logs', 'gateway', 'gateway.log'),
                        [IO.Path]::Combine($state, 'install', 'deployment.json')
                    )) {
                    [IO.File]::WriteAllText($file, 'state')
                }
                [IO.File]::WriteAllText([IO.Path]::Combine($install, 'bin', 'defenseclaw-hook.exe'), 'installed')
                return @{
                    InstallRoot = $install
                    BinDirectory = [IO.Path]::Combine($install, 'bin')
                    StateRoot = $state
                    RuntimeDirectory = $runtime
                }
            }
            function Invoke-Preflight([hashtable]$Layout, [int]$CallerPID = 0) {
                Assert-DefenseClawStandaloneStateFilesNotInUse `
                    -Layout $Layout `
                    -GatewayServiceName DefenseClawGateway `
                    -GuardianServiceName DefenseClawHookGuardian `
                    -SelfUninstallCallerPID $CallerPID
            }
            function Test-Refused([string]$Label, [scriptblock]$Action, [string]$Pattern) {
                try {
                    & $Action
                    $failures.Add("${Label}: expected a refusal")
                }
                catch {
                    if ($_.Exception.Message -notmatch $Pattern) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                }
            }
            function Test-Accepted([string]$Label, [scriptblock]$Action) {
                try {
                    & $Action
                }
                catch {
                    $failures.Add("${Label} was refused: $($_.Exception.Message)")
                }
            }
            function Test-StateIntact([string]$Label, [hashtable]$Layout) {
                foreach ($leaf in @('runtime\audit.db', 'runtime\audit.db-wal', 'runtime\audit.db-shm', 'logs\gateway\gateway.log', 'install\deployment.json')) {
                    $file = [IO.Path]::Combine([string]$Layout.StateRoot, $leaf)
                    if (-not [IO.File]::Exists($file) -or [IO.File]::ReadAllText($file) -cne 'state') {
                        $failures.Add("${Label}: $leaf changed")
                    }
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

            # The audit database and its companions come first in the walk.
            $layout = New-TestState 'order'
            $files = Get-DefenseClawStateRootFiles -Layout $layout
            $expectedFirst = @('audit.db', 'audit.db-wal', 'audit.db-shm')
            if ($files.Count -ne 5 -or
                (@($files[0..2] | Microsoft.PowerShell.Core\ForEach-Object { [IO.Path]::GetFileName($_) }) -join ',') -cne ($expectedFirst -join ',')) {
                $failures.Add("state files are not audit database first: $($files -join ', ')")
            }

            # No other program has a file open: the purge goes ahead at once.
            $script:InstallTreeUseRecheckMilliseconds = 5000
            $clock = [Diagnostics.Stopwatch]::StartNew()
            Test-Accepted 'purge with no reader' { Invoke-Preflight $layout }
            if ($clock.ElapsedMilliseconds -ge 5000) {
                $failures.Add("purge with no reader waited for a recheck ($($clock.ElapsedMilliseconds) ms)")
            }

            # This lifecycle's own handle does not count.
            $own = [IO.File]::Open([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db'), 'Open', 'Read', 'ReadWrite')
            try {
                $clock = [Diagnostics.Stopwatch]::StartNew()
                Test-Accepted 'purge with this lifecycle holding audit.db' { Invoke-Preflight $layout }
                if ($clock.ElapsedMilliseconds -ge 5000) {
                    $failures.Add('this lifecycle holding audit.db was counted as a holder')
                }
            }
            finally {
                $own.Dispose()
            }

            # A reader seen only once (here it closes the file after 2.5 s,
            # before the recheck 6 s later) does not block, and the check did
            # see it (it waited for the recheck).
            $script:InstallTreeUseRecheckMilliseconds = 6000
            $layout = New-TestState 'transient'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 2500
            $clock = [Diagnostics.Stopwatch]::StartNew()
            Test-Accepted 'purge with a reader seen once' { Invoke-Preflight $layout }
            if ($clock.ElapsedMilliseconds -lt 6000) {
                $failures.Add("the check did not see the short-lived reader ($($clock.ElapsedMilliseconds) ms)")
            }
            Stop-TestReader $reader

            # A lasting reader of audit.db refuses the purge before it changes
            # anything and names the program, pid, account and file.
            $script:InstallTreeUseRecheckMilliseconds = 500
            $layout = New-TestState 'reader'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 120000
            Test-Refused 'purge with an audit.db reader' { Invoke-Preflight $layout } (
                '^uninstall_in_use: ' + [regex]::Escape($engineName) + ' \(pid ' + $reader.Id +
                ', account [^,)]+(, started by [^)]+)?\) has runtime\\audit\.db open in ' +
                [regex]::Escape([string]$layout.StateRoot) + ', which the purge deletes.*nothing was changed\. ' +
                'Close it first: stop the program \(for example a SIEM forwarder or a log tail that reads runtime\\audit\.db\)')
            Test-StateIntact 'refused purge' $layout

            # The self-uninstall caller and programs run from the install
            # folder (the install-folder check names those) do not count.
            Test-Accepted 'purge whose self-uninstall caller holds audit.db' { Invoke-Preflight $layout $reader.Id }
            $installHolder = $layout.Clone()
            $installHolder.InstallRoot = [IO.Path]::GetDirectoryName($engine)
            Test-Accepted 'purge with a reader run from the install folder' { Invoke-Preflight $installHolder }

            # Once the reader closes, the purge goes ahead.
            Stop-TestReader $reader
            Test-Accepted 'purge after the reader closed' { Invoke-Preflight $layout }

            # GAP-0752: an outside program may hold an installed executable
            # without running its image from InstallRoot. Refuse before the
            # hook wiring or services are touched.
            $layout = New-TestState 'install-holder'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.BinDirectory, 'defenseclaw-hook.exe')) 120000
            Test-Refused 'installed binary is held open' {
                Assert-DefenseClawStandaloneInstallTreeNotInUse `
                    -Layout $layout `
                    -GatewayServiceName DefenseClawGateway `
                    -GuardianServiceName DefenseClawHookGuardian
            } ('^uninstall_in_use: .*' + [regex]::Escape($engineName) + ' \(pid ' + $reader.Id +
                '.* holds a file in ' + [regex]::Escape([string]$layout.InstallRoot) +
                '; nothing was changed\. Close the program and run the uninstall again$')
            Test-StateIntact 'install-root holder refusal' $layout
            Stop-TestReader $reader

            # Two short hook invocations on a busy host can be seen on
            # different passes. Neither PID survived the recheck.
            $savedInstallRootHolders = ${function:Get-DefenseClawInstallRootHolders}
            try {
                $script:HolderPass = 0
                function Get-DefenseClawInstallRootHolders {
                    param($InstallRoot, $SelfUninstallCallerPID, $ExcludedProcessIds,
                        [switch]$FailOnQueryError, [switch]$IncludeProcessId)
                    $script:HolderPass++
                    $holderId = 200000 + $script:HolderPass
                    return [pscustomobject]@{
                        Id = $holderId
                        Description = "defenseclaw-hook.exe (pid $holderId)"
                    }
                }
                Test-Accepted 'different short hook holders across recheck' {
                    Assert-DefenseClawStandaloneInstallTreeNotInUse `
                        -Layout $layout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                }
                if ($script:HolderPass -ne 2) {
                    $failures.Add("install holder check ran $script:HolderPass passes, expected two")
                }
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item `
                    -Path function:Get-DefenseClawInstallRootHolders `
                    -Value $savedInstallRootHolders
            }

            # A Restart Manager query that fails refuses the purge before it
            # changes anything: the check did not run, and the purge must not
            # start blind.
            if (-not ('DcsfFailingRestartManager' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class DcsfFailingRestartManager { public static object[] GetFileHolders(string[] paths) { throw new System.ComponentModel.Win32Exception(5, "Restart Manager session start failed"); } }'
            }
            $savedNative = ${function:Initialize-DefenseClawNativeSecurity}
            try {
                function script:Initialize-DefenseClawNativeSecurity { return [DcsfFailingRestartManager] }
                Test-Refused 'purge whose Restart Manager query fails' { Invoke-Preflight $layout } (
                    '^uninstall_in_use: Restart Manager could not list the programs that hold DefenseClaw data files \(.*Restart Manager session start failed.*\); ' +
                    'nothing was changed; run the uninstall again$')
                Test-StateIntact 'purge refused after a failed Restart Manager query' $layout
                # GAP-0735: the install-root query has the same precommit
                # guard. An error here used to be taken for no holder and
                # the uninstall only failed after removing the services.
                Test-Refused 'install-root Restart Manager query fails' {
                    Assert-DefenseClawStandaloneInstallTreeNotInUse `
                        -Layout $layout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                } '^uninstall_in_use: Restart Manager could not list the programs that hold DefenseClaw install files \(.*Restart Manager session start failed.*\); nothing was changed; run the uninstall again$'
                Test-StateIntact 'install-root query refusal' $layout
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item -Path function:script:Initialize-DefenseClawNativeSecurity -Value $savedNative
            }

            # The Secure Client profile has no data-file check.
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 120000
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            Test-Accepted 'Secure Client purge with a reader' { Invoke-Preflight $layout }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            Stop-TestReader $reader

            # After the services stopped: the deletion of StateRoot. The
            # tree removal is replaced by the plain recursive delete it ends
            # with, because its trusted-root checks refuse a scratch tree.
            function script:Remove-DefenseClawManagedTree {
                param([string]$Path, [string]$RequiredBase, [string]$Label, [string]$AllowAFUnixSocketAt)
                if ([IO.File]::Exists([IO.Path]::Combine($Path, 'refuse'))) {
                    throw "refusing $Label reparse point: $Path"
                }
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            }
            $script:StateRootRemovalRetryMilliseconds = 15000

            # A real sharing violation is recognised.
            $layout = New-TestState 'classify'
            $blocked = [IO.File]::Open([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db'), 'Open', 'Read', 'Read')
            try {
                try {
                    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $layout.StateRoot -Recurse -Force -ErrorAction Stop
                    $failures.Add('deleting a held audit.db succeeded')
                }
                catch {
                    if (-not (Test-DefenseClawFileInUseError -ErrorRecord $_)) {
                        $failures.Add("a sharing violation was not recognised: $($_.Exception.GetType().FullName) $($_.Exception.HResult) $($_.Exception.Message)")
                    }
                }
            }
            finally {
                $blocked.Dispose()
            }

            # A reader that closes within the retry window: the deletion
            # finishes.
            $layout = New-TestState 'retry'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 3000
            $clock = [Diagnostics.Stopwatch]::StartNew()
            Test-Accepted 'deletion with a reader that closes within 15 s' { Remove-DefenseClawPurgedStateRoot -Layout $layout }
            if ([IO.Directory]::Exists($layout.StateRoot)) {
                $failures.Add('StateRoot survived the retried deletion')
            }
            if ($clock.ElapsedMilliseconds -lt 1000) {
                $failures.Add("the deletion did not meet the reader ($($clock.ElapsedMilliseconds) ms)")
            }
            Stop-TestReader $reader

            # A reader that stays: uninstall_in_use names it and the file,
            # the rest stays for the next run, and that run finishes.
            $script:StateRootRemovalRetryMilliseconds = 2000
            $layout = New-TestState 'lasting'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db-wal')) 120000
            Test-Refused 'deletion with a lasting reader' { Remove-DefenseClawPurgedStateRoot -Layout $layout } (
                '^uninstall_in_use: ' + [regex]::Escape($engineName) + ' \(pid ' + $reader.Id +
                ', account [^,)]+(, started by [^)]+)?\) has runtime\\audit\.db-wal open in ' +
                [regex]::Escape([string]$layout.StateRoot) + ', so the purge could not delete that folder within 2 seconds\. ' +
                'DefenseClaw is already uninstalled and only this data folder is left\..*run the uninstall with PURGE=1 again to finish$')
            if (-not [IO.File]::Exists([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db-wal'))) {
                $failures.Add('the held file was deleted')
            }
            Stop-TestReader $reader
            Test-Accepted 'deletion run again after the reader closed' { Remove-DefenseClawPurgedStateRoot -Layout $layout }
            if ([IO.Directory]::Exists($layout.StateRoot)) {
                $failures.Add('StateRoot survived the deletion run again')
            }

            # Any other deletion failure is not retried and keeps its message.
            $layout = New-TestState 'other'
            [IO.File]::WriteAllText([IO.Path]::Combine($layout.StateRoot, 'refuse'), 'x')
            $clock = [Diagnostics.Stopwatch]::StartNew()
            Test-Refused 'deletion that fails for another reason' { Remove-DefenseClawPurgedStateRoot -Layout $layout } '^refusing StateRoot reparse point: '
            if ($clock.ElapsedMilliseconds -ge 1500) {
                $failures.Add("a failure that is not a file in use was retried ($($clock.ElapsedMilliseconds) ms)")
            }

            # The Secure Client profile keeps the single deletion.
            $layout = New-TestState 'secure-client'
            $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 120000
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $clock = [Diagnostics.Stopwatch]::StartNew()
            try {
                Remove-DefenseClawPurgedStateRoot -Layout $layout
                $failures.Add('Secure Client deletion of a held audit.db succeeded')
            }
            catch {
                if ($_.Exception.Message -match '^uninstall_in_use' -or $clock.ElapsedMilliseconds -ge 1500) {
                    $failures.Add("Secure Client deletion was retried or reworded: $($_.Exception.Message)")
                }
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            Stop-TestReader $reader
        }
        finally {
            $script:ProgramData = $savedProgramData
            $script:InstallTreeUseRecheckMilliseconds = $savedRecheck
            $script:StateRootRemovalRetryMilliseconds = $savedRetry
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root $readers
}
finally {
    foreach ($reader in $readers) {
        if (-not $reader.HasExited) {
            $reader.Kill()
            $reader.WaitForExit()
        }
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-state-files-in-use-smoke: OK'
