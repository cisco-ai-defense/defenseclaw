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
$leftBehind = $false
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
param([string]$Path, [string]$Ready, [int]$HoldMilliseconds, [string]$Share = 'Read')
$stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]$Share)
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Milliseconds $HoldMilliseconds
$stream.Dispose()
'@)
        # Holds a file open the way an elevated program with backup rights
        # can: ordinary read sharing (no delete sharing), whatever the access
        # list says. It is how a CI runner holds a SYSTEM-only file.
        if (-not ('DcsfPrivileges' -as [type])) {
            Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class DcsfPrivileges {
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Lo; public int Hi; }
  [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Luid; public uint Attr; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValueW(string s, string n, out LUID l);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, uint l, IntPtr p, IntPtr r);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static void Set(string privilege, bool enabled) { IntPtr t; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out t)) return; LUID l; if (LookupPrivilegeValueW(null, privilege, out l)) { TP n = new TP(); n.Count = 1; n.Luid = l; n.Attr = enabled ? 2u : 0u; AdjustTokenPrivileges(t, false, ref n, 0, IntPtr.Zero, IntPtr.Zero); } CloseHandle(t); }
}
'@
        }
        # Backup, restore and take-ownership of this process, as "Name=State".
        function Get-TestPrivilegeState {
            return (@(& "$env:SystemRoot\System32\whoami.exe" /priv | Microsoft.PowerShell.Core\ForEach-Object {
                        if ($_ -match '^(SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege)\s.*\s(Enabled|Disabled)\s*$') { '{0}={1}' -f $Matches[1], $Matches[2] }
                    }) -join ';')
        }
        $backupReaderScript = [IO.Path]::Combine($Root, 'reader-backup.ps1')
        [IO.File]::WriteAllText($backupReaderScript, @'
param([string]$Path, [string]$Ready, [int]$HoldMilliseconds, [string]$Share = 'Read')
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class DcsfBackupOpen {
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Lo; public int Hi; }
  [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Luid; public uint Attr; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValueW(string s, string n, out LUID l);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, uint l, IntPtr p, IntPtr r);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  public static void Enable(string privilege) { IntPtr t; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out t)) return; LUID l; if (LookupPrivilegeValueW(null, privilege, out l)) { TP n = new TP(); n.Count = 1; n.Luid = l; n.Attr = 2u; AdjustTokenPrivileges(t, false, ref n, 0, IntPtr.Zero, IntPtr.Zero); } CloseHandle(t); }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static IntPtr Open(string p) { IntPtr h = CreateFileW(p, 0x80000000u, 1u, IntPtr.Zero, 3u, 0x02000000u, IntPtr.Zero); if (h == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); return h; }
  public static void Close(IntPtr h) { CloseHandle(h); }
}
"@
[DcsfBackupOpen]::Enable('SeBackupPrivilege')
[DcsfBackupOpen]::Enable('SeRestorePrivilege')
$handle = [DcsfBackupOpen]::Open($Path)
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Milliseconds $HoldMilliseconds
[DcsfBackupOpen]::Close($handle)
'@)
        try {
            function Start-TestReader([string]$Path, [int]$HoldMilliseconds, [string]$Share = 'Read', [string]$ScriptPath = $readerScript) {
                $ready = [IO.Path]::Combine($Root, 'ready-' + [Guid]::NewGuid().ToString('N'))
                $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Path "{1}" -Ready "{2}" -HoldMilliseconds {3} -Share "{4}"' -f $ScriptPath, $Path, $ready, $HoldMilliseconds, $Share
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

            # GAP-0789: before an upgrade or repair swaps the hook, only a
            # holder whose handle does not share delete defers the run. A
            # well-behaved scanner (FileShare ReadWrite and Delete) deferred
            # every repair with hook_in_use; the swap works under its handle
            # and leaves nothing beside the hook.
            $layout = New-TestState 'hook-shares-delete'
            $layout.HookPath = [IO.Path]::Combine($layout.BinDirectory, 'defenseclaw-hook.exe')
            $reader = Start-TestReader $layout.HookPath 120000 'ReadWrite, Delete'
            $clock = [Diagnostics.Stopwatch]::StartNew()
            Test-Accepted 'hook held with delete sharing' { Assert-DefenseClawHookNotHeld -Layout $layout -TimeoutSeconds 3 }
            if ($clock.ElapsedMilliseconds -ge 3000) {
                $failures.Add("a hook holder that shares delete was waited for ($($clock.ElapsedMilliseconds) ms)")
            }
            $replacement = [IO.Path]::Combine($Root, 'hook-shares-delete', 'replacement.exe')
            [IO.File]::WriteAllText($replacement, 'replaced')
            Test-Accepted 'swap of a hook held with delete sharing' { Install-DefenseClawFileAtomic -Source $replacement -Destination $layout.HookPath }
            if (-not [IO.File]::Exists($layout.HookPath) -or [IO.File]::ReadAllText($layout.HookPath) -cne 'replaced') {
                $failures.Add('the hook held with delete sharing was not replaced')
            }
            $left = @([IO.Directory]::GetFileSystemEntries($layout.BinDirectory) | Microsoft.PowerShell.Core\Where-Object {
                    [IO.Path]::GetFileName($_) -cne 'defenseclaw-hook.exe' })
            if ($left.Count -gt 0) {
                $failures.Add("the swap of a hook held with delete sharing left $($left -join ', ')")
            }
            if ($reader.HasExited) {
                $failures.Add('the hook holder that shares delete was ended')
            }
            Stop-TestReader $reader

            # A holder without delete sharing still defers the run, named,
            # with the hook unchanged.
            $layout = New-TestState 'hook-held'
            $layout.HookPath = [IO.Path]::Combine($layout.BinDirectory, 'defenseclaw-hook.exe')
            $reader = Start-TestReader $layout.HookPath 120000 'Read'
            Test-Refused 'hook held without delete sharing' { Assert-DefenseClawHookNotHeld -Layout $layout -TimeoutSeconds 2 } (
                '^hook_in_use: ' + [regex]::Escape($engineName) + ' \(process id ' + $reader.Id + '[,)].* has ' +
                [regex]::Escape([string]$layout.HookPath) + ' open, so Setup could not replace it; this run stopped and replaced nothing\.')
            if ([IO.File]::ReadAllText($layout.HookPath) -cne 'installed') {
                $failures.Add('the hook held without delete sharing changed')
            }
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

            # GAP-2265: a holder Restart Manager reported that has exited
            # by the time the process list is read holds nothing. Under
            # agent load the hook's own short-lived processes were named
            # "a program" or "DefenseClaw Agent Hook" that way and deferred
            # every upgrade with hook_in_use; a running holder outside the
            # install folder is still named.
            if (-not ('DcsfListedRestartManager' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
public class DcsfListedHolder { public int ProcessId { get; set; } public string ServiceName { get; set; } public string AppName { get; set; } public long StartFileTime { get; set; } }
public static class DcsfListedRestartManager {
    public static int[] Ids = new int[0];
    public static object[] GetFileHolders(string[] paths) {
        object[] found = new object[Ids.Length];
        for (int i = 0; i < Ids.Length; i++) { found[i] = new DcsfListedHolder { ProcessId = Ids[i], ServiceName = "", AppName = "DefenseClaw Agent Hook", StartFileTime = i }; }
        return found;
    }
}
'@
            }
            $exited = Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList @('-NoProfile', '-Command', 'exit 0') -WindowStyle Hidden -PassThru
            [void]$exited.WaitForExit(60000)
            $running = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 120000
            $savedNative = ${function:Initialize-DefenseClawNativeSecurity}
            try {
                function script:Initialize-DefenseClawNativeSecurity { return [DcsfListedRestartManager] }
                $self = [Collections.Generic.HashSet[int]]::new()
                [void]$self.Add([int]$PID)
                [DcsfListedRestartManager]::Ids = @([int]$exited.Id)
                $seen = Get-DefenseClawStateFileHolders -Layout $layout -Paths @([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) -Excluded $self
                if ($seen.Count -ne 0) {
                    $failures.Add("an exited holder (pid $($exited.Id)) still counted: $(@($seen.Values | Microsoft.PowerShell.Core\ForEach-Object { $_.Name }) -join ', ')")
                }
                [DcsfListedRestartManager]::Ids = @([int]$exited.Id, [int]$running.Id)
                $seen = Get-DefenseClawStateFileHolders -Layout $layout -Paths @([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) -Excluded $self
                $named = @($seen.Values | Microsoft.PowerShell.Core\Where-Object { $_.Id -eq [int]$running.Id })
                if ($seen.Count -ne 1 -or $named.Count -ne 1 -or $named[0].Name -ne $engineName) {
                    $failures.Add("a running holder beside an exited one was not named alone: $(@($seen.Values | Microsoft.PowerShell.Core\ForEach-Object { '{0}={1}' -f $_.Id, $_.Name }) -join ', ')")
                }
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item -Path function:script:Initialize-DefenseClawNativeSecurity -Value $savedNative
                Stop-TestReader $running
            }

            # GAP-0878: a DefenseClaw file this account cannot open (its
            # access list names only SYSTEM, as hook-guardian\opencode-service-ports.json
            # does) made Restart Manager fail the holder list of every file
            # with access denied, so an administrator's uninstall was refused
            # although nothing held a file. Real Restart Manager, real files:
            # such a file no longer fails the check, nobody holding it is no
            # holder, and a real reader of another file is still named.
            $layout = New-TestState 'restricted'
            $guardianDirectory = [IO.Path]::Combine($layout.StateRoot, 'hook-guardian')
            [void][IO.Directory]::CreateDirectory($guardianDirectory)
            $restricted = [IO.Path]::Combine($guardianDirectory, 'opencode-service-ports.json')
            [IO.File]::WriteAllText($restricted, 'state')
            & "$env:SystemRoot\System32\icacls.exe" $restricted /inheritance:r /grant:r '*S-1-5-18:F' | Out-Null
            # The privileges that would let this account open the file anyway are
            # disabled for the rest of this smoke, so the rows below behave the
            # same on a CI runner, in an elevated prompt and over ssh.
            foreach ($privilegeName in 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege') {
                [DcsfPrivileges]::Set($privilegeName, $false)
            }
            $privilegeState = Get-TestPrivilegeState
            if ($privilegeState -match '=Enabled') {
                $failures.Add("the test privileges could not be disabled: $privilegeState")
            }
            $canOpenRestricted = $true
            try {
                [IO.File]::Open($restricted, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite).Dispose()
            }
            catch [UnauthorizedAccessException] {
                $canOpenRestricted = $false
            }
            if ($canOpenRestricted) {
                # SYSTEM can open its own file, so the case cannot be set up.
                # The skip is said on stdout, and a CI runner (an elevated
                # administrator) must never skip: that would hide a regression.
                $reason = 'SKIP restricted-file rows: this account (' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ') can open a file whose access list names only SYSTEM'
                [Console]::Out.WriteLine($reason)
                if ($env:GITHUB_ACTIONS -eq 'true' -or $env:CI -eq 'true') {
                    $failures.Add($reason + ' on CI; run this smoke as an elevated administrator')
                }
            }
            else {
                $script:InstallTreeUseRecheckMilliseconds = 500
                Test-Accepted 'purge with a SYSTEM-only file and no holder' { Invoke-Preflight $layout }
                $reader = Start-TestReader ([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) 120000
                Test-Refused 'purge with a SYSTEM-only file and an audit.db reader' { Invoke-Preflight $layout } (
                    '^uninstall_in_use: ' + [regex]::Escape($engineName) + ' \(pid ' + $reader.Id +
                    ', account [^,)]+(, started by [^)]+)?\) has runtime\\audit\.db open in ')
                Stop-TestReader $reader
                Test-Accepted 'purge after the reader closed, SYSTEM-only file still there' { Invoke-Preflight $layout }
                Test-Accepted 'install-root check with a SYSTEM-only file in the install folder' {
                    $restrictedInstall = [IO.Path]::Combine($layout.BinDirectory, 'restricted.bin')
                    [IO.File]::WriteAllText($restrictedInstall, 'state')
                    & "$env:SystemRoot\System32\icacls.exe" $restrictedInstall /inheritance:r /grant:r '*S-1-5-18:F' | Out-Null
                    Assert-DefenseClawStandaloneInstallTreeNotInUse `
                        -Layout $layout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                }
                # The SYSTEM-only file itself held by a program (a backup-rights
                # open, read sharing): refused, the file named, the hint said.
                $holder = Start-TestReader $restricted 120000 'Read' $backupReaderScript
                Test-Refused 'purge with the SYSTEM-only file held open' { Invoke-Preflight $layout } (
                    '^uninstall_in_use: a program has hook-guardian\\opencode-service-ports\.json open \(it is probably running as SYSTEM.*Associated Handles.*\) in ' +
                    [regex]::Escape([string]$layout.StateRoot) + ', which the purge deletes.*nothing was changed\. ')
                Test-StateIntact 'refused purge with the SYSTEM-only file held' $layout
                Stop-TestReader $holder
                Test-Accepted 'purge after the SYSTEM-only file holder closed' { Invoke-Preflight $layout }
                if (-not [IO.File]::Exists($restricted)) {
                    $failures.Add('the check removed the SYSTEM-only file')
                }
                # GAP-0890: everything above ran with the backup and restore
                # privileges disabled in this process (the state of an elevated
                # Administrator and of a CI runner), whatever token the host
                # gave. The probe enabled them for its own opens only: the
                # process token is unchanged, and this thread is no longer
                # impersonating a privileged token (a backup-semantics DELETE
                # open of the SYSTEM-only file is denied again).
                $nativeForProbe = Initialize-DefenseClawNativeSecurity
                $afterState = Get-TestPrivilegeState
                if ($afterState -cne $privilegeState) {
                    $failures.Add("the privilege state of the process changed: before '$privilegeState', after '$afterState'")
                }
                if ([int]$nativeForProbe::GetDirectoryOpenError($restricted, [uint32]0x10000) -ne 5) {
                    $failures.Add('the probe left its privileged thread token in place: a backup-semantics DELETE open of the SYSTEM-only file succeeded afterwards')
                }
                # Review S4 (Secure Client pin): the unreadable-file handling is
                # standalone only. Under the Secure Client profile the native
                # query asks Restart Manager about every path exactly as before,
                # so the SYSTEM-only file still fails the batch there, while the
                # standalone profile answers.
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                $nativeSecureClient = Initialize-DefenseClawNativeSecurity
                try {
                    [void]$nativeSecureClient::GetFileHolders([string[]]@($restricted))
                    $failures.Add('the Secure Client profile used the standalone unreadable-file handling')
                }
                catch {
                    if ($_.Exception.Message -notmatch 'Restart Manager holder list failed') {
                        $failures.Add("the Secure Client profile did not get the original Restart Manager failure: $($_.Exception.Message)")
                    }
                }
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                $nativeStandalone = Initialize-DefenseClawNativeSecurity
                try {
                    [void]$nativeStandalone::GetFileHolders([string[]]@($restricted))
                }
                catch {
                    $failures.Add("the standalone profile did not handle the SYSTEM-only file: $($_.Exception.Message)")
                }
                # Review S1: when the privileged thread token cannot be taken
                # off the thread, the process stops at once with a named reason
                # instead of throwing where a caller might swallow it. The
                # revert failure is injected in a child process.
                $moduleFile = [string](Microsoft.PowerShell.Core\Get-Module -Name DefenseClawEnterprise).Path
                $childScript = [IO.Path]::Combine($Root, 'revert-failure-child.ps1')
                [IO.File]::WriteAllText($childScript, @"
`$ErrorActionPreference = 'Stop'
`$module = Import-Module -Name '$($moduleFile.Replace("'", "''"))' -Force -PassThru
& `$module {
    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
    `$native = Initialize-DefenseClawNativeSecurity
    `$native.GetField('failRevertForTest', [Reflection.BindingFlags]'NonPublic,Static').SetValue(`$null, `$true)
    [void]`$native::GetFileHolders([string[]]@('$($restricted.Replace("'", "''"))'))
}
'THE-PROCESS-SURVIVED'
"@)
                $childStdout = [IO.Path]::Combine($Root, 'revert-failure-child.out')
                $childStderr = [IO.Path]::Combine($Root, 'revert-failure-child.err')
                $childProcess = Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $childScript) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $childStdout -RedirectStandardError $childStderr
                $childExit = $childProcess.ExitCode
                $childOutput = [IO.File]::ReadAllText($childStdout) + [IO.File]::ReadAllText($childStderr)
                if ($childExit -eq 0 -or $childOutput -match 'THE-PROCESS-SURVIVED') {
                    $failures.Add("a failed token revert did not stop the process (exit $childExit)")
                }
                if ($childOutput -notmatch 'privilege_revert_failed') {
                    $failures.Add("a failed token revert did not name its reason: $childOutput")
                }
                # The access list is unchanged.
                $restrictedAcl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $restricted).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
                    Microsoft.PowerShell.Core\ForEach-Object { $_.IdentityReference.Value }
                if (@($restrictedAcl).Count -ne 1 -or @($restrictedAcl)[0] -cne 'S-1-5-18') {
                    $failures.Add("the SYSTEM-only file's access list changed: $(@($restrictedAcl) -join ', ')")
                }
            }

            # The holder of a file this account cannot query has no process
            # id: it is refused and named without one, and neither the
            # excluded process ids (a stopped service is process id 0) nor the
            # service names remove it. The native answer is replaced here
            # because holding a SYSTEM-only file needs SYSTEM (the native
            # cell holds a real one).
            if (-not ('DcsfUnnamedRestartManager' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
public class DcsfUnnamedHolder { public uint ProcessId { get; set; } public string ServiceName { get; set; } public string AppName { get; set; } public long StartFileTime { get; set; } public bool Unnamed { get; set; } }
public static class DcsfUnnamedRestartManager {
    public static object[] GetFileHolders(string[] paths) {
        return new object[] { new DcsfUnnamedHolder { ProcessId = 0, ServiceName = "", AppName = "a program", StartFileTime = 0, Unnamed = true } };
    }
}
'@
            }
            $layout = New-TestState 'unnamed'
            $script:InstallTreeUseRecheckMilliseconds = 200
            $savedNative = ${function:Initialize-DefenseClawNativeSecurity}
            try {
                function script:Initialize-DefenseClawNativeSecurity { return [DcsfUnnamedRestartManager] }
                Test-Refused 'purge with a holder that has no process id' { Invoke-Preflight $layout } (
                    '^uninstall_in_use: a program has runtime\\audit\.db open \(it is probably running as SYSTEM.*Associated Handles.*\) in ' + [regex]::Escape([string]$layout.StateRoot) +
                    ', which the purge deletes.*nothing was changed\. ')
                $stopped = [Collections.Generic.HashSet[int]]::new()
                [void]$stopped.Add(0)
                $seen = Get-DefenseClawStateFileHolders -Layout $layout -Paths @([IO.Path]::Combine($layout.RuntimeDirectory, 'audit.db')) -Excluded $stopped -ServiceNames @('DefenseClawGateway')
                if ($seen.Count -ne 1) {
                    $failures.Add("a holder with no process id was removed by process id 0 in the excluded set: $($seen.Count) holders")
                }
                Test-Refused 'install-root check with a holder that has no process id' {
                    Assert-DefenseClawStandaloneInstallTreeNotInUse `
                        -Layout $layout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                } '^uninstall_in_use: a program \(it is probably running as SYSTEM.*Associated Handles.*\) holds a file in '
                Test-StateIntact 'refusals for a holder with no process id' $layout
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item -Path function:script:Initialize-DefenseClawNativeSecurity -Value $savedNative
            }

            # GAP-0878: how the answer of the DELETE open of a file Restart
            # Manager could not open is read (the real classifier). Deletable
            # (0) and gone (2, 3: the guardian renames its staging file between
            # the walk and the probe) are no holder; a sharing violation (32)
            # is one; every other answer throws, and a caller that fails closed
            # then refuses.
            $nativeType = Initialize-DefenseClawNativeSecurity
            foreach ($answer in 0, 2, 3) {
                try {
                    if ($nativeType::DeleteProbeFindsHolder($answer, 'x', '') -ne $false) {
                        $failures.Add("a DELETE answer of $answer was taken for a holder")
                    }
                }
                catch {
                    $failures.Add("a DELETE answer of $answer threw instead of meaning no holder: $($_.Exception.Message)")
                }
            }
            if ($nativeType::DeleteProbeFindsHolder(32, 'x', '') -ne $true) {
                $failures.Add('a sharing violation was not taken for a holder')
            }
            foreach ($answer in 1, 5, 19, 87) {
                try {
                    [void]$nativeType::DeleteProbeFindsHolder($answer, 'C:\scratch\sample.json', '')
                    $failures.Add("a DELETE answer of $answer did not throw")
                }
                catch {
                    if ($_.Exception.Message -notmatch ('cannot read, and this account cannot delete, C:\\scratch\\sample\.json \(Win32 error ' + $answer + '\)')) {
                        $failures.Add("a DELETE answer of ${answer} threw an unexpected message: $($_.Exception.Message)")
                    }
                }
            }
            # A token that holds neither privilege (not an administrator, or a
            # user-rights policy removed them) is refused with the privileges
            # named, never taken for "no holder".
            try {
                [void]$nativeType::DeleteProbeFindsHolder(5, 'C:\scratch\sample.json', ' (SeBackupPrivilege, SeRestorePrivilege missing)')
                $failures.Add('an access-denied probe answer with missing privileges did not throw')
            }
            catch {
                if ($_.Exception.Message -notmatch '\(Win32 error 5\) \(SeBackupPrivilege, SeRestorePrivilege missing\)') {
                    $failures.Add("the missing privileges were not named: $($_.Exception.Message)")
                }
            }
            # The throw reaches a fail-closed caller as a refusal, with the
            # state untouched.
            if (-not ('DcsfCannotDeleteRestartManager' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class DcsfCannotDeleteRestartManager { public static object[] GetFileHolders(string[] paths) { throw new System.ComponentModel.Win32Exception(5, "Restart Manager cannot read, and this account cannot delete, " + paths[0]); } }'
            }
            # A token that lacks the privileges is told to run as SYSTEM, and
            # the refusal is not the retryable uninstall_in_use (GAP-0890 r2).
            if (-not ('DcsfMissingPrivilegeRestartManager' -as [type])) {
                Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class DcsfMissingPrivilegeRestartManager { public static object[] GetFileHolders(string[] paths) { throw new System.ComponentModel.Win32Exception(5, "Restart Manager cannot read, and this account cannot delete, " + paths[0] + " (Win32 error 5) (SeBackupPrivilege, SeRestorePrivilege missing)"); } }'
            }
            $layout = New-TestState 'missing-privileges'
            $savedNative = ${function:Initialize-DefenseClawNativeSecurity}
            try {
                function script:Initialize-DefenseClawNativeSecurity { return [DcsfMissingPrivilegeRestartManager] }
                Test-Refused 'purge by a token without backup and restore' { Invoke-Preflight $layout } (
                    '^privileges_required: .*\(SeBackupPrivilege, SeRestorePrivilege missing\).*nothing was changed and the services are still running\. Run the same uninstall as SYSTEM ')
                Test-Refused 'install-root check by a token without backup and restore' {
                    Assert-DefenseClawStandaloneInstallTreeNotInUse `
                        -Layout $layout `
                        -GatewayServiceName DefenseClawGateway `
                        -GuardianServiceName DefenseClawHookGuardian
                } '^privileges_required: .*Run the same uninstall as SYSTEM '
                Test-StateIntact 'refusal for a token without backup and restore' $layout
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item -Path function:script:Initialize-DefenseClawNativeSecurity -Value $savedNative
            }
            $layout = New-TestState 'cannot-delete'
            $savedNative = ${function:Initialize-DefenseClawNativeSecurity}
            try {
                function script:Initialize-DefenseClawNativeSecurity { return [DcsfCannotDeleteRestartManager] }
                Test-Refused 'purge with a file that can be neither queried nor deleted' { Invoke-Preflight $layout } (
                    '^uninstall_in_use: Restart Manager could not list the programs that hold DefenseClaw data files \(.*cannot read, and this account cannot delete, .*\); ' +
                    'nothing was changed; run the uninstall again$')
                Test-StateIntact 'refusal for a file that can be neither queried nor deleted' $layout
            }
            finally {
                Microsoft.PowerShell.Management\Set-Item -Path function:script:Initialize-DefenseClawNativeSecurity -Value $savedNative
            }

            # GAP-0890: the privileged deletion of DefenseClaw's own tree after
            # an access-denied failure. It acts for the standalone profile on
            # the exact StateRoot and InstallRoot only, removes a link as the
            # link without entering it, rewrites no access list, and logs
            # every path it deleted. The process privileges stay disabled.
            if (-not $canOpenRestricted) {
                $savedProgramFiles = $script:ProgramFiles
                $savedWindowsDirectory = $script:WindowsDirectory
                try {
                    $script:WindowsDirectory = [IO.Path]::Combine($Root, 'privdel', 'WIN')
                    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($script:WindowsDirectory, 'Logs', 'DefenseClaw'))
                    $privLayout = New-TestState 'privdel'
                    $script:ProgramData = [IO.Path]::Combine($Root, 'privdel', 'PD')
                    $script:ProgramFiles = [IO.Path]::Combine($Root, 'privdel', 'PF')
                    $denied = [Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Access to the path is denied.'), 'denied', [Management.Automation.ErrorCategory]::PermissionDenied, $null)
                    $inUseError = [Management.Automation.ErrorRecord]::new([IO.IOException]::new('The process cannot access the file.'), 'inuse', [Management.Automation.ErrorCategory]::WriteError, $null)
                    $guardianFolder = [IO.Path]::Combine($privLayout.StateRoot, 'hook-guardian')
                    [void][IO.Directory]::CreateDirectory($guardianFolder)
                    $secret = [IO.Path]::Combine($guardianFolder, 'opencode-service-ports.json')
                    [IO.File]::WriteAllText($secret, 'state')
                    & "$env:SystemRoot\System32\icacls.exe" $secret /inheritance:r /grant:r '*S-1-5-18:F' | Out-Null
                    # A junction and a directory symbolic link inside StateRoot
                    # that point at a folder outside it, with a decoy there.
                    $outside = [IO.Path]::Combine($Root, 'privdel', 'outside')
                    [void][IO.Directory]::CreateDirectory($outside)
                    $decoy = [IO.Path]::Combine($outside, 'decoy.txt')
                    [IO.File]::WriteAllText($decoy, 'decoy')
                    $decoyHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $decoy -Algorithm SHA256).Hash
                    $junction = [IO.Path]::Combine($privLayout.StateRoot, 'junction')
                    $symlink = [IO.Path]::Combine($privLayout.StateRoot, 'symlink')
                    & "$env:SystemRoot\System32\cmd.exe" /c mklink /J "$junction" "$outside" | Out-Null
                    & "$env:SystemRoot\System32\cmd.exe" /c mklink /D "$symlink" "$outside" 2>&1 | Out-Null
                    $symlinkMade = [bool](Microsoft.PowerShell.Management\Get-Item -LiteralPath $symlink -Force -ErrorAction SilentlyContinue)
                    $refusals = @(
                        @{ Name = 'a label that is not StateRoot or InstallRoot'; Label = 'Other'; Error = $denied; Root = $privLayout.StateRoot },
                        @{ Name = 'an error that is not access denied'; Label = 'StateRoot'; Error = $inUseError; Root = $privLayout.StateRoot },
                        @{ Name = 'a folder that is not the exact StateRoot'; Label = 'StateRoot'; Error = $denied; Root = $guardianFolder },
                        @{ Name = 'a vendor folder'; Label = 'StateRoot'; Error = $denied; Root = [IO.Path]::Combine($script:ProgramData, 'OpenAI', 'Codex') },
                        @{ Name = 'a target that is not the checked root'; Label = 'StateRoot'; Error = $denied; Root = $privLayout.StateRoot; Target = $guardianFolder }
                    )
                    foreach ($case in $refusals) {
                        $caseTarget = if ($case.ContainsKey('Target')) { $case.Target } else { $case.Root }
                        if (Remove-DefenseClawStateTreePrivileged -Root $case.Root -Target $caseTarget -Label $case.Label -ErrorRecord $case.Error) {
                            $failures.Add("the privileged deletion acted on $($case.Name)")
                        }
                    }
                    if (-not [IO.File]::Exists($secret)) {
                        $failures.Add('a refused privileged deletion removed the SYSTEM-only file')
                    }
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                    if (Remove-DefenseClawStateTreePrivileged -Root $privLayout.StateRoot -Target $privLayout.StateRoot -Label StateRoot -ErrorRecord $denied) {
                        $failures.Add('the privileged deletion acted for the Secure Client profile')
                    }
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                    if (-not [IO.File]::Exists($secret)) {
                        $failures.Add('the Secure Client profile lost the SYSTEM-only file')
                    }
                    $privilegesBefore = Get-TestPrivilegeState
                    $done = Remove-DefenseClawStateTreePrivileged -Root $privLayout.StateRoot -Target $privLayout.StateRoot -Label StateRoot -ErrorRecord $denied
                    if (-not $done -or [IO.Directory]::Exists($privLayout.StateRoot)) {
                        $failures.Add('the privileged deletion did not remove the StateRoot with the SYSTEM-only file and the links')
                    }
                    if ((Get-TestPrivilegeState) -cne $privilegesBefore) {
                        $failures.Add('the privileged deletion left the process privileges changed')
                    }
                    if (-not [IO.File]::Exists($decoy) -or (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $decoy -Algorithm SHA256).Hash -cne $decoyHash) {
                        $failures.Add('the privileged deletion followed a link and changed the folder it points to')
                    }
                    $lifecycleLog = [IO.Path]::Combine($script:WindowsDirectory, 'Logs', 'DefenseClaw', 'enterprise-lifecycle.log')
                    $logged = if ([IO.File]::Exists($lifecycleLog)) { [IO.File]::ReadAllText($lifecycleLog) } else { '' }
                    foreach ($expected in @('opencode-service-ports.json', 'junction (link, not followed)')) {
                        if ($logged -notmatch ('defenseclaw_repair path=[^"]*' + [regex]::Escape($expected).Replace('\\', '\\\\'))) {
                            $failures.Add("the lifecycle log has no defenseclaw_repair line for $expected")
                        }
                    }
                    $events = @(Get-DefenseClawResilienceEvents)
                    $expectedLines = @('opencode-service-ports.json', 'junction (link, not followed)')
                    if ($symlinkMade) {
                        $expectedLines += 'symlink (link, not followed)'
                    }
                    foreach ($expected in $expectedLines) {
                        if (@($events | Microsoft.PowerShell.Core\Where-Object { $_ -like "*defenseclaw_repair*$expected*" }).Count -lt 1) {
                            $failures.Add("the privileged deletion logged no defenseclaw_repair line for $expected")
                        }
                    }
                    # Review S5: with no lifecycle log folder the deletion
                    # still leaves a record (the warnings, and one that says the
                    # log could not be written).
                    $noLogLayout = New-TestState 'privdel2'
                    $script:ProgramData = [IO.Path]::Combine($Root, 'privdel2', 'PD')
                    $script:ProgramFiles = [IO.Path]::Combine($Root, 'privdel2', 'PF')
                    $script:WindowsDirectory = [IO.Path]::Combine($Root, 'privdel2', 'WIN')
                    [void][IO.Directory]::CreateDirectory($script:WindowsDirectory)
                    $guardian2 = [IO.Path]::Combine($noLogLayout.StateRoot, 'hook-guardian')
                    [void][IO.Directory]::CreateDirectory($guardian2)
                    $secret2 = [IO.Path]::Combine($guardian2, 'opencode-service-ports.json')
                    [IO.File]::WriteAllText($secret2, 'state')
                    & "$env:SystemRoot\System32\icacls.exe" $secret2 /inheritance:r /grant:r '*S-1-5-18:F' | Out-Null
                    $denied2 = [Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Access to the path is denied.'), 'denied', [Management.Automation.ErrorCategory]::PermissionDenied, $null)
                    $done2 = Remove-DefenseClawStateTreePrivileged -Root $noLogLayout.StateRoot -Target $noLogLayout.StateRoot -Label StateRoot -ErrorRecord $denied2 -WarningVariable noLogWarnings -WarningAction SilentlyContinue
                    if (-not $done2 -or [IO.Directory]::Exists($noLogLayout.StateRoot)) {
                        $failures.Add('the privileged deletion without a lifecycle log folder did not remove the StateRoot')
                    }
                    if (@($noLogWarnings | Microsoft.PowerShell.Core\Where-Object { "$_" -like '*lifecycle log could not be written*' }).Count -ne 1) {
                        $failures.Add('the privileged deletion without a lifecycle log folder left no record that the log was not written')
                    }
                    if (@($noLogWarnings | Microsoft.PowerShell.Core\Where-Object { "$_" -like '*defenseclaw_repair*opencode-service-ports.json*' }).Count -lt 1) {
                        $failures.Add('the privileged deletion without a lifecycle log folder named no path in the warnings')
                    }
                }
                finally {
                    $script:ProgramFiles = $savedProgramFiles
                    $script:WindowsDirectory = $savedWindowsDirectory
                    $script:ProgramData = $savedProgramData
                }
            }

            # GAP-0890 r2: a default-token Administrator (backup and restore
            # present but disabled) could not even list a SYSTEM-only folder in
            # StateRoot (the IB22 forced fixture), so the purge failed at its
            # first walk, long before the delete the earlier fallback guards.
            # The walks now retry once with backup and restore enabled for that
            # walk only, on the exact StateRoot of the standalone profile.
            if (-not $canOpenRestricted) {
                $savedProgramFiles4 = $script:ProgramFiles
                $savedWindows4 = $script:WindowsDirectory
                try {
                    $walkLayout = New-TestState 'walk'
                    $script:ProgramData = [IO.Path]::Combine($Root, 'walk', 'PD')
                    $script:ProgramFiles = [IO.Path]::Combine($Root, 'walk', 'PF')
                    $script:WindowsDirectory = [IO.Path]::Combine($Root, 'walk', 'WIN')
                    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($script:WindowsDirectory, 'Logs', 'DefenseClaw'))
                    $forcedFolder = [IO.Path]::Combine($walkLayout.StateRoot, 'r109ib22-forced')
                    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($forcedFolder, 'nested'))
                    [IO.File]::WriteAllText([IO.Path]::Combine($forcedFolder, 'nested', 'file.txt'), 'forced')
                    # SYSTEM only, leaf first: the creator-owner entry that the
                    # parent gives the creating Administrator is removed too, as a
                    # folder created by SYSTEM never has it.
                    foreach ($forcedPart in @([IO.Path]::Combine($forcedFolder, 'nested', 'file.txt'), [IO.Path]::Combine($forcedFolder, 'nested'), $forcedFolder)) {
                        & "$env:SystemRoot\System32\icacls.exe" $forcedPart /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' /remove:g '*S-1-5-32-544' | Out-Null
                    }
                    $listable = $true
                    try { [void][IO.Directory]::GetFileSystemEntries($forcedFolder) } catch [UnauthorizedAccessException] { $listable = $false }
                    if ($listable) {
                        $failures.Add('the forced SYSTEM-only folder could be listed with the privileges disabled; the fixture is wrong')
                    }
                    $walkOutside = [IO.Path]::Combine($Root, 'walk', 'outside')
                    [void][IO.Directory]::CreateDirectory($walkOutside)
                    $walkDecoy = [IO.Path]::Combine($walkOutside, 'decoy.txt')
                    [IO.File]::WriteAllText($walkDecoy, 'decoy')
                    $walkDecoyHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $walkDecoy -Algorithm SHA256).Hash
                    $walkJunction = [IO.Path]::Combine($walkLayout.StateRoot, 'r109ib22-link')
                    & "$env:SystemRoot\System32\cmd.exe" /c mklink /J "$walkJunction" "$walkOutside" | Out-Null
                    $walkPrivileges = Get-TestPrivilegeState
                    # The plain walk is denied; the retried walk lists the tree,
                    # removes the junction as a link and leaves the decoy alone.
                    try {
                        Remove-DefenseClawUninstallStateTreeLinks -Layout @{ StateRoot = $walkLayout.StateRoot } 3>$null
                    }
                    catch {
                        $failures.Add("the link walk over a tree with a SYSTEM-only folder was refused: $($_.Exception.Message)")
                    }
                    if (Microsoft.PowerShell.Management\Get-Item -LiteralPath $walkJunction -Force -ErrorAction SilentlyContinue) {
                        $failures.Add('the link walk left the junction in place')
                    }
                    if (-not [IO.File]::Exists($walkDecoy) -or (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $walkDecoy -Algorithm SHA256).Hash -cne $walkDecoyHash) {
                        $failures.Add('the link walk changed the folder the junction pointed to')
                    }
                    if ((Get-TestPrivilegeState) -cne $walkPrivileges) {
                        $failures.Add('the privileged walk left the process privileges changed')
                    }
                    $walkLog = [IO.Path]::Combine($script:WindowsDirectory, 'Logs', 'DefenseClaw', 'enterprise-lifecycle.log')
                    if (-not [IO.File]::Exists($walkLog) -or [IO.File]::ReadAllText($walkLog) -notmatch 'listed after access denied, with backup and restore privileges enabled for this walk only') {
                        $failures.Add('the privileged walk left no lifecycle log line')
                    }
                    # The rows below call Invoke-DefenseClawStateRootWalk directly. The
                    # link walk above is the entry point of the purge, so a module
                    # without the wrapper (the release before GAP-0890 r2) already
                    # failed it with the access denied of the first walk; the missing
                    # wrapper is said once and the direct rows are not run.
                    if (-not (Microsoft.PowerShell.Core\Get-Command -Name Invoke-DefenseClawStateRootWalk -ErrorAction SilentlyContinue)) {
                        $failures.Add('Invoke-DefenseClawStateRootWalk is missing')
                    }
                    else {
                    $walkValue = Invoke-DefenseClawStateRootWalk -WalkRoot $walkLayout.StateRoot -WalkLabel StateRoot -Walk {
                        @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $walkLayout.StateRoot -Recurse -Force) | Microsoft.PowerShell.Core\Out-Null
                        return 'walked'
                    }
                    if ($walkValue -cne 'walked') {
                        $failures.Add("the recursive walk of a tree with a SYSTEM-only folder returned '$walkValue'")
                    }
                    # Anything but the exact StateRoot, or any other profile,
                    # keeps the original refusal.
                    $deniedWalk = { Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $forcedFolder -Force | Microsoft.PowerShell.Core\Out-Null }
                    foreach ($case in @(
                            @{ Name = 'the folder above StateRoot'; Root = [IO.Path]::GetDirectoryName($walkLayout.StateRoot); Label = 'StateRoot' },
                            @{ Name = 'a label that is not StateRoot or InstallRoot'; Root = $walkLayout.StateRoot; Label = 'Other' })) {
                        $refused = $false
                        try { Invoke-DefenseClawStateRootWalk -WalkRoot $case.Root -WalkLabel $case.Label -Walk $deniedWalk }
                        catch { $refused = ($_.Exception.Message -match 'Access to the path') -and ($_.Exception.Message -notmatch 'privileges_required') }
                        if (-not $refused) {
                            $failures.Add("the privileged walk acted on $($case.Name)")
                        }
                    }
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                    $refused = $false
                    try { Invoke-DefenseClawStateRootWalk -WalkRoot $walkLayout.StateRoot -WalkLabel StateRoot -Walk $deniedWalk }
                    catch { $refused = ($_.Exception.Message -match 'Access to the path') -and ($_.Exception.Message -notmatch 'privileges_required') }
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                    if (-not $refused) {
                        $failures.Add('the privileged walk acted for the Secure Client profile')
                    }
                    # Review R1: a file inside the forced SYSTEM-only folder is
                    # holder-checked before anything changes. The preflight walks
                    # the folder under the call-scoped privileges, so a program
                    # that holds the nested file without delete sharing refuses the
                    # purge, names the file and changes nothing; with no holder the
                    # preflight passes.
                    $nestedFile = [IO.Path]::Combine($forcedFolder, 'nested', 'file.txt')
                    $walkLayout.GatewayServiceName = 'DefenseClawGateway'
                    $script:InstallTreeUseRecheckMilliseconds = 300
                    Test-Accepted 'purge preflight with a SYSTEM-only folder and no holder' { Invoke-Preflight $walkLayout }
                    $nestedHolder = Start-TestReader $nestedFile 120000 'Read' $backupReaderScript
                    Test-Refused 'purge with a file inside the SYSTEM-only folder held open' { Invoke-Preflight $walkLayout } (
                        '^uninstall_in_use: a program has r109ib22-forced\\nested\\file\.txt open \(it is probably running as SYSTEM.*\) in ' +
                        [regex]::Escape([string]$walkLayout.StateRoot) + ', which the purge deletes.*nothing was changed\. ')
                    if (-not [IO.Directory]::Exists($walkLayout.StateRoot) -or -not [IO.Directory]::Exists($walkOutside)) {
                        $failures.Add('the refused preflight changed the tree')
                    }
                    Stop-TestReader $nestedHolder
                    Test-Accepted 'purge preflight after the nested holder closed' { Invoke-Preflight $walkLayout }
                    # A token that does not hold the privileges at all (they are
                    # removed from the token of a child process, as a user-rights
                    # policy does) is refused with the reason and the way out,
                    # and nothing changes.
                    & "$env:SystemRoot\System32\cmd.exe" /c mklink /J "$walkJunction" "$walkOutside" | Out-Null
                    $moduleFile4 = [string](Microsoft.PowerShell.Core\Get-Module -Name DefenseClawEnterprise).Path
                    $childScript4 = [IO.Path]::Combine($Root, 'no-privileges-child.ps1')
                    [IO.File]::WriteAllText($childScript4, @"
`$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class DcsfRemove {
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Lo; public int Hi; }
  [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Luid; public uint Attr; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValueW(string s, string n, out LUID l);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, uint l, IntPtr p, IntPtr r);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  public static void Remove(string privilege) { IntPtr t; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out t)) return; LUID l; if (LookupPrivilegeValueW(null, privilege, out l)) { TP n = new TP(); n.Count = 1; n.Luid = l; n.Attr = 4u; AdjustTokenPrivileges(t, false, ref n, 0, IntPtr.Zero, IntPtr.Zero); } }
}
'@
[DcsfRemove]::Remove('SeBackupPrivilege'); [DcsfRemove]::Remove('SeRestorePrivilege')
`$module = Import-Module -Name '$($moduleFile4.Replace("'", "''"))' -Force -PassThru
& `$module {
    `$script:ProgramData = '$($script:ProgramData.Replace("'", "''"))'
    `$script:ProgramFiles = '$($script:ProgramFiles.Replace("'", "''"))'
    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
    try { Remove-DefenseClawUninstallStateTreeLinks -Layout @{ StateRoot = '$($walkLayout.StateRoot.Replace("'", "''"))' }; 'NO-ERROR' } catch { 'ERROR: ' + `$_.Exception.Message }
}
"@)
                    $child4Stdout = [IO.Path]::Combine($Root, 'no-privileges-child.out')
                    $child4Stderr = [IO.Path]::Combine($Root, 'no-privileges-child.err')
                    [void](Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $childScript4) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $child4Stdout -RedirectStandardError $child4Stderr)
                    $child4Output = [IO.File]::ReadAllText($child4Stdout) + [IO.File]::ReadAllText($child4Stderr)
                    if ($child4Output -notmatch 'ERROR: privileges_required: ' -or $child4Output -notmatch 'does not hold SeBackupPrivilege and SeRestorePrivilege' -or
                        $child4Output -notmatch 'nothing was changed and the services are still running' -or $child4Output -notmatch 'Run the same uninstall as SYSTEM') {
                        $failures.Add("a token without backup and restore was not refused with the reason and the way out: $child4Output")
                    }
                    if (-not (Microsoft.PowerShell.Management\Get-Item -LiteralPath $walkJunction -Force -ErrorAction SilentlyContinue)) {
                        $failures.Add('the refused walk changed the tree')
                    }
                    }
                    # Give the scratch cleanup the forced folder back (its owner may).
                    & "$env:SystemRoot\System32\icacls.exe" $forcedFolder /grant '*S-1-5-32-544:(OI)(CI)F' /C /Q 2>&1 | Out-Null
                }
                finally {
                    $script:ProgramFiles = $savedProgramFiles4
                    $script:WindowsDirectory = $savedWindows4
                    $script:ProgramData = $savedProgramData
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                }
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
    # The SYSTEM-only files this smoke made cannot be deleted by an account
    # whose backup and restore privileges are disabled (the smoke disables them
    # in its own process), and a harness that cleans the scratch folder after
    # it would fail on them. The owner of a file may always rewrite its access
    # list, so give Administrators the tree back first; no privilege is needed.
    & "$env:SystemRoot\System32\icacls.exe" $root /grant '*S-1-5-32-544:F' /T /C /Q 2>&1 | Out-Null
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $root) {
        $leftBehind = $true
    }
}

if ($leftBehind) {
    Microsoft.PowerShell.Utility\Write-Output "FAIL: the scratch folder $root could not be removed"
    exit 1
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-state-files-in-use-smoke: OK'
