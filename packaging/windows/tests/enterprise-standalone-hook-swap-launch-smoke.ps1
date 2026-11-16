# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-0240: agents start bin\defenseclaw-hook.exe for every tool call, also
# while Setup /ensure, upgrade, repair or rollback replaces it. File.Replace
# moved the old file aside and held the new one open for writing, so a start
# in that moment failed with a sharing violation, "Access is denied" or "file
# not found", and the agent ran the tool call with no DefenseClaw decision.
# This smoke starts a copy of a system program over and over from several
# threads, as agents start the hook, while Install-DefenseClawFileAtomic
# replaces it with another build many times: every start must succeed, the
# last build must be in place, and the swap must leave no staging copy. A
# backup of a build a started process still runs may stay (Windows deletes it
# at the next restart). On a file with the protected InstallFile DACL the swap
# leaves the same owner, group and DACL as File.Replace. Runs elevated in a disposable directory under Windows
# PowerShell 5.1 and PowerShell 7; no service or machine root is touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath(),
    [ValidateRange(4, 400)][int]$Swaps = 24,
    [ValidateRange(1, 16)][int]$Starters = 6
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

if (-not ('DcHookSwapStarter' -as [type])) {
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

public sealed class DcHookSwapStarter
{
    private readonly string path;
    private readonly List<Thread> threads = new List<Thread>();
    private volatile bool stopping;
    private int starts;
    public readonly List<string> Failures = new List<string>();

    public DcHookSwapStarter(string path, int count)
    {
        this.path = path;
        for (int i = 0; i < count; i++)
        {
            int index = i;
            Thread thread = new Thread(() => Run(index));
            thread.IsBackground = true;
            threads.Add(thread);
        }
    }

    public int Starts { get { return Interlocked.CompareExchange(ref starts, 0, 0); } }

    public void Start()
    {
        foreach (Thread thread in threads)
            thread.Start();
    }

    public void Stop()
    {
        stopping = true;
        foreach (Thread thread in threads)
            thread.Join(60000);
    }

    private void Run(int index)
    {
        // Short and one-second runs, so swaps meet starting and running images.
        string arguments = index % 2 == 0 ? "-n 1 -w 50 127.0.0.1" : "-n 2 -w 50 127.0.0.1";
        while (!stopping)
        {
            ProcessStartInfo info = new ProcessStartInfo(path, arguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            Interlocked.Increment(ref starts);
            try
            {
                using (Process process = Process.Start(info))
                {
                    process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                }
            }
            catch (Exception error)
            {
                lock (Failures)
                    Failures.Add(DateTime.UtcNow.ToString("HH:mm:ss.fff") + " " + error.GetType().Name + ": " + error.Message);
            }
        }
    }
}
'@
}

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dchs-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
$starter = $null
try {
    $result = & $module {
        param([string]$Root, [int]$Swaps, [int]$Starters)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $starter = $null
        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $bin = [IO.Path]::Combine($Root, 'bin')
            [void][IO.Directory]::CreateDirectory($bin)
            $program = [IO.Path]::Combine([Environment]::SystemDirectory, 'PING.EXE')
            $builds = @(
                [IO.Path]::Combine($Root, 'build-a.exe'),
                [IO.Path]::Combine($Root, 'build-b.exe')
            )
            [IO.File]::Copy($program, $builds[0])
            $bytes = [IO.File]::ReadAllBytes($program)
            # A second build: the same program with an overlay after the image.
            [IO.File]::WriteAllBytes($builds[1], [byte[]]($bytes + [Text.Encoding]::ASCII.GetBytes('defenseclaw-hook-swap-smoke')))
            $hook = [IO.Path]::Combine($bin, 'defenseclaw-hook.exe')
            [IO.File]::Copy($builds[0], $hook)
            # The access entries must stay; the auto-inherited control flag
            # Windows sets when it writes the list (D:AI) is not compared.
            $daclBefore = [regex]::Replace(
                (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $hook).GetSecurityDescriptorSddlForm('Access'),
                '^D:(P?)(AI)?', 'D:$1')

            $starter = [DcHookSwapStarter]::new($hook, $Starters)
            $starter.Start()
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 500
            for ($i = 0; $i -lt $Swaps; $i++) {
                $build = $builds[($i + 1) % 2]
                $want = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $build -Algorithm SHA256).Hash
                Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want
                $have = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $hook -Algorithm SHA256).Hash
                if ($have -cne $want) {
                    $failures.Add("swap $i left $have at the hook, not $want")
                }
                Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 150
            }
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 500
            $starter.Stop()
            if ($starter.Starts -lt $Swaps) {
                $failures.Add("only $($starter.Starts) starts ran beside $Swaps swaps")
            }
            foreach ($failure in @($starter.Failures)) {
                $failures.Add("a start of the hook failed during a swap: $failure")
            }
            $daclAfter = [regex]::Replace(
                (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $hook).GetSecurityDescriptorSddlForm('Access'),
                '^D:(P?)(AI)?', 'D:$1')
            if ($daclAfter -cne $daclBefore) {
                $failures.Add("the swap changed the hook access list from $daclBefore to $daclAfter")
            }
            $staging = @([IO.Directory]::GetFiles($bin) | Microsoft.PowerShell.Core\Where-Object {
                    [IO.Path]::GetFileName($_) -like 'defenseclaw-hook.exe.new.*' })
            if ($staging.Count -gt 0) {
                $failures.Add("the swaps left staging copies: $($staging -join ', ')")
            }
            $other = @([IO.Directory]::GetFiles($bin) | Microsoft.PowerShell.Core\Where-Object {
                    $name = [IO.Path]::GetFileName($_)
                    $name -cne 'defenseclaw-hook.exe' -and
                    -not (Test-DefenseClawReplacementBackupName -Name $name -Leaf 'defenseclaw-hook.exe') })
            if ($other.Count -gt 0) {
                $failures.Add("the swaps left unexpected files: $($other -join ', ')")
            }
            # Every backup can go once no started process runs it.
            foreach ($left in @(Remove-DefenseClawStaleReplacementBackups -Destination $hook)) {
                $failures.Add("a backup no process runs could not be removed: $left")
            }
            # Installed bin programs carry a protected DACL (InstallFile).
            # The swap must leave the same owner, group and DACL as the
            # File.Replace it replaces would, on a protected file too.
            $protectedBin = [IO.Path]::Combine($Root, 'bin-protected')
            [void][IO.Directory]::CreateDirectory($protectedBin)
            $installFileSddl = 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
            $swappedHook = [IO.Path]::Combine($protectedBin, 'defenseclaw-hook.exe')
            $replacedHook = [IO.Path]::Combine($protectedBin, 'replaced-hook.exe')
            foreach ($path in @($swappedHook, $replacedHook)) {
                [IO.File]::Copy($builds[0], $path)
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm($installFileSddl)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $path -AclObject $security
            }
            $sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
            $want = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $builds[1] -Algorithm SHA256).Hash
            Install-DefenseClawFileAtomic -Source $builds[1] -Destination $swappedHook -ExpectedSHA256 $want
            $replacement = [IO.Path]::Combine($protectedBin, 'replaced-hook.exe.new')
            $replacedBackup = [IO.Path]::Combine($protectedBin, 'replaced-hook.exe.old')
            [IO.File]::Copy($builds[1], $replacement)
            [IO.File]::Replace($replacement, $replacedHook, $replacedBackup, $true)
            [IO.File]::Delete($replacedBackup)
            $swappedSddl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $swappedHook).GetSecurityDescriptorSddlForm($sections)
            $replacedSddl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $replacedHook).GetSecurityDescriptorSddlForm($sections)
            if ($swappedSddl -cne $replacedSddl) {
                $failures.Add("on a protected file the swap left $swappedSddl, File.Replace $replacedSddl")
            }
            $swappedDacl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $swappedHook).GetSecurityDescriptorSddlForm('Access')
            if ($swappedDacl -cne 'D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)') {
                $failures.Add("the swap changed the protected DACL to $swappedDacl")
            }
            if ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $swappedHook -Algorithm SHA256).Hash -cne $want) {
                $failures.Add('the protected swap did not publish the new build')
            }
            Microsoft.PowerShell.Utility\Write-Output ("protected: swap {0} File.Replace {1}" -f $swappedSddl, $replacedSddl)
            Microsoft.PowerShell.Utility\Write-Output ("starts={0} swaps={1}" -f $starter.Starts, $Swaps)
        }
        finally {
            if ($null -ne $starter) {
                $starter.Stop()
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root $Swaps $Starters
    $failures = $result[-1]
    foreach ($line in @($result | Microsoft.PowerShell.Utility\Select-Object -SkipLast 1)) {
        Microsoft.PowerShell.Utility\Write-Output $line
    }
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-hook-swap-launch-smoke: OK'
