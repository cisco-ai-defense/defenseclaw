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
#   - Setup's own account may own a kept file but not write it (review L4);
#   - a healthy install keeps every payload file a repair rewrites with
#     -SkipIfContentMatches, with no "is not kept" notice (review S7);
#   - the hold check Setup runs before the swap blocks no hook start (the
#     upgrade window, GAP-0656);
#   - the rollback copy of the installed hook has the digest the deployment
#     records, or is the guardian's protected copy with it, or the run throws
#     before anything stops (review M3).
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
        # The scratch folder is protected like the install folder, so a fresh
        # object inherits SYSTEM, Administrators and Users read only. Under a
        # profile's temporary folder it would inherit the elevated account's
        # own full-control entry, which is a writer outside the trusted set
        # (review L4) and has nothing to do with a real install.
        [void]$native::SetPathSecurityDescriptorPrivilegedNoFollow(
            $Root, 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)', $true)
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

            # Review L4: the account Setup runs as owns a kept file, as in
            # Assert-DefenseClawStandaloneContentTrusted (GAP-0603), but is
            # not a trusted writer. A foreign account stays refused.
            $setupSid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if ($setupSid -in @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
                $lines.Add("setup account: skipped ($setupSid is a trusted writer)")
            }
            else {
                $hook = New-SmokeHook -Name 'setup-owner' -Sddl "O:${setupSid}G:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
                $drift = Get-DefenseClawKeptFileDrift -Path $hook
                if (-not [string]::IsNullOrEmpty($drift)) {
                    $failures.Add("setup-owner: Setup's own account as owner was reported: $drift")
                }
                $hook = New-SmokeHook -Name 'setup-writer' -Sddl "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;${setupSid})"
                $before = $native::GetFileIdentity($hook)
                if ((Get-DefenseClawKeptFileDrift -Path $hook) -notlike "*${setupSid} can change it*") {
                    $failures.Add("setup-writer: Setup's account with a write entry was not reported")
                }
                Install-DefenseClawFileAtomic -Source $build -Destination $hook -ExpectedSHA256 $want -SkipIfContentMatches
                Assert-SmokeFreshObject -Case 'setup-writer' -Path $hook -Before $before
            }

            # Review S7: a healthy standalone install keeps every payload
            # file a repair or an ensure writes with -SkipIfContentMatches
            # (the payload loop, the config and manifest restores, the
            # Cowork files), whatever access list its own stamp gives it: no
            # "is not kept" notice and the same object. The stamps are the
            # product's (Set-DefenseClawPathAcl, the kinds Set-DefenseClawManagedAcls
            # gives each file).
            $script:SmokePhases = [Collections.Generic.List[string]]::new()
            function script:Write-DefenseClawLifecyclePhase { param([string]$Stage) $script:SmokePhases.Add($Stage) }
            $gatewaySid = try {
                Get-DefenseClawDeterministicServiceSID -ServiceName 'DefenseClawGateway'
            }
            catch {
                'S-1-5-19'
            }
            $payloadDir = [IO.Path]::Combine($Root, 'payload', 'bin')
            [void][IO.Directory]::CreateDirectory($payloadDir)
            $payload = [ordered]@{
                'defenseclaw-gateway.exe'     = 'ServiceInstallFile'
                'defenseclaw-acp.exe'         = 'InstallFile'
                'defenseclaw-hook.exe'        = 'InstallFile'
                'defenseclaw-sensor-helper.exe' = 'InstallFile'
                'defenseclaw.exe'             = 'InstallFile'
                'defenseclaw-installer.exe'   = 'InstallFile'
                'DefenseClawEnterprise.psm1'  = 'InstallFile'
                'config.yaml'                 = 'ConfigFile'
                'targets.yaml'                = 'AdminFile'
            }
            $identities = @{}
            foreach ($name in $payload.Keys) {
                $path = [IO.Path]::Combine($payloadDir, $name)
                Install-DefenseClawFileAtomic -Source $build -Destination $path -ExpectedSHA256 $want
                Set-DefenseClawPathAcl -Path $path -Kind $payload[$name] -GatewayServiceSID $gatewaySid
                $identities[$name] = $native::GetFileIdentity($path)
            }
            foreach ($run in 1..2) {
                foreach ($name in $payload.Keys) {
                    $path = [IO.Path]::Combine($payloadDir, $name)
                    Install-DefenseClawFileAtomic -Source $build -Destination $path -ExpectedSHA256 $want -SkipIfContentMatches
                    Set-DefenseClawPathAcl -Path $path -Kind $payload[$name] -GatewayServiceSID $gatewaySid
                }
            }
            foreach ($name in $payload.Keys) {
                $after = $native::GetFileIdentity([IO.Path]::Combine($payloadDir, $name))
                if ($after -cne $identities[$name]) {
                    $failures.Add("payload ${name}: the healthy file was replaced by a repair (file ID $($identities[$name]) -> $after)")
                }
            }
            $notKept = @($script:SmokePhases | Where-Object { $_ -like '*is not kept*' })
            if ($notKept.Count -gt 0) {
                $failures.Add("payload: a healthy install got 'is not kept' notices: $($notKept -join ' | ')")
            }
            if (@([IO.Directory]::GetFiles($payloadDir)).Count -ne $payload.Count) {
                $failures.Add('payload: a repair left files beside the payload')
            }
            $lines.Add("payload: $($payload.Count) healthy files kept twice, $($notKept.Count) not-kept notices")

            # Review M3 (the g582 trust class): the rollback copy of the
            # installed hook has the digest the deployment records, or it is
            # the guardian's protected copy with that digest, or the run
            # throws before anything is stopped. The drifted hook is made as
            # Administrator by writing other bytes into the file.
            $script:SmokeRecorded = ''
            function script:Get-DefenseClawRecordedHookSHA256 { param($Layout) return [string]$script:SmokeRecorded }
            $recordedBytes = [Text.Encoding]::ASCII.GetBytes('recorded-hook-release-bytes')
            $driftedBytes = [Text.Encoding]::ASCII.GetBytes('bytes-a-user-wrote-into-the-hook')
            $recordedHash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($recordedBytes)) -replace '-', '').ToLowerInvariant()
            function New-PreimageCase {
                param([string]$Name, [byte[]]$HookBytes, [byte[]]$GuardianBytes)
                $dir = [IO.Path]::Combine($Root, $Name)
                $hookPath = [IO.Path]::Combine($dir, 'bin', 'defenseclaw-hook.exe')
                $guardianDir = [IO.Path]::Combine($dir, 'hook-guardian')
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($hookPath))
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($guardianDir, 'payload'))
                [IO.File]::WriteAllBytes($hookPath, $HookBytes)
                if ($null -ne $GuardianBytes) {
                    [IO.File]::WriteAllBytes([IO.Path]::Combine($guardianDir, 'payload', 'defenseclaw-hook.exe'), $GuardianBytes)
                }
                return @{
                    Dir = $dir
                    Hook = $hookPath
                    Preimage = [IO.Path]::Combine($dir, 'early-hook.bak')
                    Layout = @{ HookPath = $hookPath; GuardianDirectory = $guardianDir }
                }
            }
            function Test-SmokeRefused {
                param([scriptblock]$Action)
                try { & $Action; return '' } catch { return $_.Exception.Message }
            }
            $script:SmokeRecorded = $recordedHash

            # The installed hook has the recorded digest: it is the copy.
            $case = New-PreimageCase -Name 'm3-match' -HookBytes $recordedBytes -GuardianBytes $recordedBytes
            $script:SmokePhases.Clear()
            $digest = Copy-DefenseClawRecordedHookPreimage -Layout $case.Layout -Destination $case.Preimage
            if ($digest -cne $recordedHash -or
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($case.Preimage)) -cne [Convert]::ToBase64String($recordedBytes)) {
                $failures.Add('m3-match: the preimage is not the recorded hook')
            }
            if (@($script:SmokePhases | Where-Object { $_ -like '*guardian*' }).Count -ne 0) {
                $failures.Add('m3-match: the guardian copy was used for a matching hook')
            }
            Assert-DefenseClawHookPreimageAvailable -Layout $case.Layout -Source @{ path = $build } -PriorDeploymentActive

            # Other bytes in the hook: refused as the preimage; the guardian
            # copy is used, and the recorded digest is returned, not the
            # digest of the other bytes.
            $case = New-PreimageCase -Name 'm3-drift' -HookBytes $driftedBytes -GuardianBytes $recordedBytes
            $script:SmokePhases.Clear()
            $digest = Copy-DefenseClawRecordedHookPreimage -Layout $case.Layout -Destination $case.Preimage
            if ($digest -cne $recordedHash) { $failures.Add("m3-drift: returned $digest, not the recorded $recordedHash") }
            if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($case.Preimage)) -cne [Convert]::ToBase64String($recordedBytes)) {
                $failures.Add('m3-drift: the preimage is not the guardian copy of the recorded hook')
            }
            if (@($script:SmokePhases | Where-Object { $_ -like "*protected copy*" }).Count -ne 1) {
                $failures.Add('m3-drift: no notice that the guardian copy was used')
            }
            if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($case.Hook)) -cne [Convert]::ToBase64String($driftedBytes)) {
                $failures.Add('m3-drift: the installed hook was changed')
            }

            # A writer holds the hook and has written other bytes into it: the
            # tolerant read copies them, and the digest check refuses them.
            $case = New-PreimageCase -Name 'm3-writer' -HookBytes $recordedBytes -GuardianBytes $recordedBytes
            $writer = [IO.File]::Open($case.Hook, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]'Read, Delete')
            $handles.Add($writer)
            $writer.Write($driftedBytes, 0, $driftedBytes.Length)
            $writer.Flush($true)
            $digest = Copy-DefenseClawRecordedHookPreimage -Layout $case.Layout -Destination $case.Preimage
            if ($digest -cne $recordedHash -or
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($case.Preimage)) -cne [Convert]::ToBase64String($recordedBytes)) {
                $failures.Add('m3-writer: the bytes a writer put into the hook became the preimage')
            }

            # No guardian copy, or one that is not the recorded release, or no
            # recorded digest: refused, nothing written, and the check that
            # runs before any service stops refuses too.
            foreach ($shape in @(
                    @{ Name = 'm3-noguardian'; Guardian = $null; Recorded = $recordedHash },
                    @{ Name = 'm3-badguardian'; Guardian = $driftedBytes; Recorded = $recordedHash },
                    @{ Name = 'm3-norecord'; Guardian = $recordedBytes; Recorded = '' })) {
                $case = New-PreimageCase -Name $shape.Name -HookBytes $driftedBytes -GuardianBytes $shape.Guardian
                $script:SmokeRecorded = $shape.Recorded
                $message = Test-SmokeRefused { Copy-DefenseClawRecordedHookPreimage -Layout $case.Layout -Destination $case.Preimage }
                if ($message -notlike 'refusing to replace the installed hook*') {
                    $failures.Add("$($shape.Name): the drifted hook was accepted as a preimage ($message)")
                }
                if ([IO.File]::Exists($case.Preimage)) {
                    $failures.Add("$($shape.Name): a preimage file was left")
                }
                $message = Test-SmokeRefused { Assert-DefenseClawHookPreimageAvailable -Layout $case.Layout -Source @{ path = $build } -PriorDeploymentActive }
                if ($message -notlike 'refusing to replace the installed hook*') {
                    $failures.Add("$($shape.Name): the check before the services stop did not refuse ($message)")
                }
                if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($case.Hook)) -cne [Convert]::ToBase64String($driftedBytes)) {
                    $failures.Add("$($shape.Name): the installed hook was changed")
                }
            }
            $lines.Add('m3: matching hook copied; drifted hook refused, guardian copy used; neither: refused before anything stops')

            # GAP-0656 (upgrade window): the hold check Setup runs about 5 s before
            # it swaps the hook must not block a hook start. Restart Manager,
            # asked about the hook, opens it with no sharing for about 23 ms the
            # first time (80 us after that), and every hook start in that moment
            # failed with a sharing violation (4 starts of one native upgrade).
            # A sampler opens the hook as a program start does, as fast as it
            # can, while the check runs; it must never see error 32.
            $hook = New-SmokeHook -Name 'holdcheck'
            $state = [hashtable]::Synchronized(@{ stop = $false; samples = 0; refused = 0 })
            $sampler = [powershell]::Create()
            [void]$sampler.AddScript({
                    param($path, $state, $native)
                    while (-not $state.stop) {
                        $error32 = $native::GetReadOpenWithoutWriteSharingError($path)
                        $state.samples = $state.samples + 1
                        if ($error32 -ne 0) { $state.refused = $state.refused + 1 }
                    }
                }).AddArgument($hook).AddArgument($state).AddArgument($native)
            $sampling = $sampler.BeginInvoke()
            # The runspace can take seconds to start on a loaded runner, so wait
            # for the sampler to prove it is running (its first 1000 opens, bounded
            # at 10 s) instead of a fixed sleep. The checks below run only beside a
            # running sampler; the assertions after them are unchanged.
            $samplerWait = [Diagnostics.Stopwatch]::StartNew()
            while ($state.samples -lt 1000 -and -not $sampling.IsCompleted -and $samplerWait.Elapsed.TotalSeconds -lt 10) {
                Start-Sleep -Milliseconds 20
            }
            $samplerReady = $state.samples -ge 1000
            if (-not $samplerReady) {
                $samplerErrors = @($sampler.Streams.Error | ForEach-Object { "$_" }) -join "; "
                $failures.Add("holdcheck: the sampler had made $($state.samples) opens after $([int]$samplerWait.Elapsed.TotalSeconds) s (finished: $($sampling.IsCompleted)); its errors: [$samplerErrors]")
            }
            $holdLayout = @{ HookPath = $hook; InstallRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($hook)) }
            try {
                if ($samplerReady) {
                    foreach ($check in 1..5) {
                        Assert-DefenseClawHookNotHeld -Layout $holdLayout -TimeoutSeconds 5
                    }
                }
            }
            finally {
                Start-Sleep -Milliseconds 100
                $state.stop = $true
                [void]$sampler.EndInvoke($sampling)
                $sampler.Dispose()
            }
            if ($state.refused -gt 0) {
                $failures.Add("holdcheck: the hold check made $($state.refused) of $($state.samples) program-start style opens of the hook fail")
            }
            if ($state.samples -lt 1000) {
                $failures.Add("holdcheck: the sampler made only $($state.samples) opens")
            }
            $lines.Add("holdcheck: 5 hold checks beside $($state.samples) start-style opens of the hook, $($state.refused) refused")
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
