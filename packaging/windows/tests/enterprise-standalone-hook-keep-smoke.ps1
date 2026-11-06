# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-0656: a standalone repair or config-restart ensure keeps a hook binary
# that already has the release's bytes, so it renames nothing onto the name
# agents start (a start in that instant could fail, and the agent ran the
# tool call unchecked). This smoke runs the real Install-DefenseClawFileAtomic
# -SkipIfContentMatches on a copy of a system program and reads the NTFS file
# ID before and after:
#   - a healthy object (one name, protected DACL, trusted owner, readers and a
#     running start only) keeps its file ID (GAP-0656 review S2);
#   - each drifted shape gets a fresh object (review M2, the g582 trust class:
#     a kept object is never re-stamped in place): a second hard link, a
#     foreign owner, an access entry that lets Users write, and a handle open
#     for writing that shares read and delete. While that handle is open every
#     start fails with a sharing violation; after the swap starts succeed.
# The fresh object is the release's bytes with one name and a trusted owner
# and access list. Runs elevated in a disposable directory under Windows
# PowerShell 5.1 and PowerShell 7; no service or machine root is touched.

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
    ('dchk-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $result = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $lines = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $native = Initialize-DefenseClawNativeSecurity
        $installFileSddl = 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
        $build = [IO.Path]::Combine($Root, 'build.exe')
        [IO.File]::Copy([IO.Path]::Combine([Environment]::SystemDirectory, 'PING.EXE'), $build)
        $want = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $build -Algorithm SHA256).Hash
        $handles = [Collections.Generic.List[IDisposable]]::new()
        $extraLinks = [Collections.Generic.List[string]]::new()

        function New-SmokeHook {
            param([string]$Name, [string]$Sddl = $installFileSddl)
            $dir = [IO.Path]::Combine($Root, $Name, 'bin')
            [void][IO.Directory]::CreateDirectory($dir)
            $path = [IO.Path]::Combine($dir, 'defenseclaw-hook.exe')
            [IO.File]::Copy($build, $path)
            [void]$native::SetPathSecurityDescriptorPrivilegedNoFollow($path, $Sddl, $false)
            return $path
        }
        function Test-SmokeStart {
            param([string]$Path)
            try {
                $info = [Diagnostics.ProcessStartInfo]::new($Path, '-n 1 -w 10 127.0.0.1')
                $info.UseShellExecute = $false
                $info.CreateNoWindow = $true
                $info.RedirectStandardOutput = $true
                $process = [Diagnostics.Process]::Start($info)
                [void]$process.StandardOutput.ReadToEnd()
                $process.WaitForExit()
                $process.Dispose()
                return ''
            }
            catch {
                return $_.Exception.Message
            }
        }
        function Assert-SmokeFreshObject {
            param([string]$Case, [string]$Path, [string]$Before)
            $after = $native::GetFileIdentity($Path)
            if ($after -ceq $Before) {
                $failures.Add("${Case}: the drifted hook object was kept (file ID $after)")
            }
            $have = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            if ($have -cne $want) {
                $failures.Add("${Case}: the hook has $have, not the release's $want")
            }
            $drift = Get-DefenseClawKeptFileDrift -Path $Path
            if (-not [string]::IsNullOrEmpty($drift)) {
                $failures.Add("${Case}: the fresh hook object is not healthy: $drift")
            }
            $start = Test-SmokeStart -Path $Path
            if ($start -ne '') {
                $failures.Add("${Case}: a start of the fresh hook failed: $start")
            }
            $staging = @([IO.Directory]::GetFiles([IO.Path]::GetDirectoryName($Path), 'defenseclaw-hook.exe.new.*'))
            if ($staging.Count -gt 0) {
                $failures.Add("${Case}: staging copies left: $($staging -join ', ')")
            }
            $lines.Add("${Case}: file ID $Before -> $after")
        }

        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

            # Healthy: the same object stays, also while a start runs it and
            # a reader that shares read and delete has it open.
            $hook = New-SmokeHook -Name 'healthy'
            $before = $native::GetFileIdentity($hook)
            $drift = Get-DefenseClawKeptFileDrift -Path $hook
            if (-not [string]::IsNullOrEmpty($drift)) {
                $failures.Add("healthy: reported as drifted: $drift")
            }
            $running = [Diagnostics.Process]::Start(
                [Diagnostics.ProcessStartInfo]@{ FileName = $hook; Arguments = '-n 30 127.0.0.1'; UseShellExecute = $false; CreateNoWindow = $true })
            $reader = [IO.File]::Open($hook, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'Read, Delete')
            try {
                foreach ($run in 1..2) {
                    Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
                }
            }
            finally {
                $reader.Dispose()
                if (-not $running.HasExited) { $running.Kill() }
                $running.WaitForExit()
                $running.Dispose()
            }
            $after = $native::GetFileIdentity($hook)
            if ($after -cne $before) {
                $failures.Add("healthy: the hook object was replaced (file ID $before -> $after)")
            }
            if (@([IO.Directory]::GetFiles([IO.Path]::GetDirectoryName($hook))).Count -ne 1) {
                $failures.Add('healthy: the skip left files beside the hook')
            }
            $lines.Add("healthy: file ID $before -> $after (kept)")

            # A second hard link.
            $hook = New-SmokeHook -Name 'link'
            $link = [IO.Path]::Combine($Root, 'link', 'other-name.exe')
            $extraLinks.Add($link)
            Microsoft.PowerShell.Management\New-Item -ItemType HardLink -Path $link -Value $hook | Microsoft.PowerShell.Core\Out-Null
            $before = $native::GetFileIdentity($hook)
            if ((Get-DefenseClawKeptFileDrift -Path $hook) -notlike '*2 names*') {
                $failures.Add('link: the second name was not reported')
            }
            Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
            Assert-SmokeFreshObject -Case 'link' -Path $hook -Before $before

            # A foreign owner (Users).
            $hook = New-SmokeHook -Name 'owner' -Sddl 'O:BUG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
            $before = $native::GetFileIdentity($hook)
            if ((Get-DefenseClawKeptFileDrift -Path $hook) -notlike '*owner S-1-5-32-545*') {
                $failures.Add('owner: the foreign owner was not reported')
            }
            Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
            Assert-SmokeFreshObject -Case 'owner' -Path $hook -Before $before

            # An access entry that lets Users modify the hook.
            $hook = New-SmokeHook -Name 'writer' -Sddl 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)'
            $before = $native::GetFileIdentity($hook)
            if ((Get-DefenseClawKeptFileDrift -Path $hook) -notlike '*S-1-5-32-545 can change it*') {
                $failures.Add('writer: the Users write entry was not reported')
            }
            Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
            Assert-SmokeFreshObject -Case 'writer' -Path $hook -Before $before
            $dacl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $hook).GetSecurityDescriptorSddlForm('Access')
            if ($dacl -like '*0x1301bf;;;BU*') {
                $failures.Add("writer: the fresh object took over the old object's Users write entry: $dacl")
            }

            # A handle open for writing that shares read and delete: every
            # start fails until the name moves to a fresh object.
            $hook = New-SmokeHook -Name 'handle'
            $before = $native::GetFileIdentity($hook)
            $writer = [IO.File]::Open($hook, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]'Read, Delete')
            $handles.Add($writer)
            $blocked = Test-SmokeStart -Path $hook
            if ($blocked -eq '') {
                $failures.Add('handle: a start succeeded although a writer held the hook')
            }
            if ((Get-DefenseClawKeptFileDrift -Path $hook) -notlike '*error 32*') {
                $failures.Add('handle: the writer handle was not reported')
            }
            Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
            Assert-SmokeFreshObject -Case 'handle' -Path $hook -Before $before
            $lines.Add("handle: a start while the writer held the hook failed: $blocked")
        }
        finally {
            foreach ($handle in $handles) { $handle.Dispose() }
            foreach ($link in $extraLinks) {
                if ([IO.File]::Exists($link)) { [IO.File]::Delete($link) }
            }
            foreach ($dir in @([IO.Directory]::GetDirectories($Root))) {
                $hookPath = [IO.Path]::Combine($dir, 'bin', 'defenseclaw-hook.exe')
                if ([IO.File]::Exists($hookPath)) {
                    foreach ($left in @(Remove-DefenseClawStaleReplacementBackups -Destination $hookPath)) {
                        $failures.Add("a backup no process runs could not be removed: $left")
                    }
                }
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        foreach ($line in $lines) { Microsoft.PowerShell.Utility\Write-Output $line }
        return , $failures
    } $root
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-hook-keep-smoke: OK'
