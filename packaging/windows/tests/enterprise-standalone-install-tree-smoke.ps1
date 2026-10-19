# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Standalone uninstall and the two directories a standalone install adds under
# InstallRoot: <InstallRoot>\ipc\ (the sensor helper's AF_UNIX socket, a
# reparse file on Windows) and <InstallRoot>\share\opencode\defenseclaw.js
# (the managed OpenCode plugin the guardian installs from the payload). The
# install-tree walk must accept exactly those directories and their expected
# leaves, removal after the services are gone must delete only them (refusing
# links and anything else, and deleting nothing when it refuses), and the
# Secure Client allow-list must stay unchanged. Runs elevated in a short
# disposable directory (AF_UNIX paths are limited to 108 characters) under
# Windows PowerShell 5.1 and PowerShell 7; the live socket leaf needs .NET's
# AF_UNIX support, so only PowerShell 7 binds one. No service or real machine
# root is touched.

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
    ('dcit-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [bool]$BindSocket)
        $failures = [Collections.Generic.List[string]]::new()
        $openSockets = [Collections.Generic.List[object]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        try {
            function New-TestLayout([string]$Name) {
                $install = [IO.Path]::Combine($Root, $Name, 'DefenseClaw')
                $bin = [IO.Path]::Combine($install, 'bin')
                $libexec = [IO.Path]::Combine($install, 'libexec')
                $compilerLib = [IO.Path]::Combine($install, 'lib')
                $compilerDir = [IO.Path]::Combine($compilerLib, 'defenseclaw')
                [void][IO.Directory]::CreateDirectory($bin)
                [void][IO.Directory]::CreateDirectory($libexec)
                $gateway = [IO.Path]::Combine($bin, 'defenseclaw-gateway.exe')
                [IO.File]::WriteAllText($gateway, 'stand-in')
                return @{
                    InstallRoot = $install
                    BinDirectory = $bin
                    LibexecDirectory = $libexec
                    CompilerLibDirectory = $compilerLib
                    CompilerDirectory = $compilerDir
                    CompilerPath = [IO.Path]::Combine($compilerDir, 'policy_compiler.py')
                    ManagedIPCDirectory = [IO.Path]::Combine($install, 'ipc')
                    GatewayPath = $gateway
                    BrokerPath = ''
                    ACPPath = ''
                    HookPath = ''
                    SensorHelperPath = ''
                    CLIPath = ''
                    InstallerPath = ''
                    ModulePath = ''
                }
            }
            function New-Plugin([hashtable]$Layout) {
                $directory = [IO.Path]::Combine($Layout.InstallRoot, 'share', 'opencode')
                [void][IO.Directory]::CreateDirectory($directory)
                $plugin = [IO.Path]::Combine($directory, 'defenseclaw.js')
                [IO.File]::WriteAllText($plugin, '// defenseclaw-managed-opencode-plugin v1')
                return $plugin
            }
            function New-TestLink([string]$Path, [string]$Target) {
                try {
                    [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path $Path -Target $Target)
                    return $true
                }
                catch {
                    $failures.Add('could not create a symbolic link (the smoke must run elevated)')
                    return $false
                }
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
            function Test-SecureClientTreeDrift([string]$Label, [hashtable]$Layout, [string]$Pattern) {
                $prior = [Environment]::GetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', 'Process')
                try {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', '1', 'Process')
                    Test-Refused "$Label (strict)" { Assert-DefenseClawManagedInstallTree -Layout $Layout } $Pattern
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $null, 'Process')
                    try {
                        Assert-DefenseClawManagedInstallTree -Layout $Layout 3>$null
                    }
                    catch {
                        $failures.Add("${Label}: bulldoze posture refused: $($_.Exception.Message)")
                    }
                }
                finally {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $prior, 'Process')
                }
            }
            function Test-Accepted([string]$Label, [hashtable]$Layout) {
                try {
                    Assert-DefenseClawManagedInstallTree -Layout $Layout
                }
                catch {
                    $failures.Add("${Label} was refused: $($_.Exception.Message)")
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

            # The ipc directory: its socket leaf is accepted and removed with it.
            $layout = New-TestLayout 'ipc'
            [void][IO.Directory]::CreateDirectory($layout.ManagedIPCDirectory)
            if ($BindSocket) {
                # Keep the socket open: .NET unlinks the socket file when a
                # bound socket is disposed, and the test needs the file the
                # way a crashed service leaves it.
                $socketPath = [IO.Path]::Combine($layout.ManagedIPCDirectory, 'sensor-helper.sock')
                $socket = [Net.Sockets.Socket]::new(
                    [Net.Sockets.AddressFamily]::Unix,
                    [Net.Sockets.SocketType]::Stream,
                    [Net.Sockets.ProtocolType]::Unspecified
                )
                $openSockets.Add($socket)
                $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new($socketPath))
                if (([IO.File]::GetAttributes($socketPath) -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                    $failures.Add('stand-in socket is not a reparse file; the test would not exercise the AF_UNIX case')
                }
            }
            Test-Accepted 'standalone tree with ipc' $layout
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout
            if ([IO.Directory]::Exists($layout.ManagedIPCDirectory)) {
                $failures.Add('standalone ipc directory survived removal')
            }
            Test-Accepted 'tree without ipc' $layout
            # Removal with no ipc directory is a no-op.
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout

            # The managed OpenCode plugin: accepted and removed with its two
            # directories, leaving the rest of the tree.
            $layout = New-TestLayout 'plugin'
            $paths = Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $layout
            $plugin = New-Plugin $layout
            if (-not [string]::Equals([string]$paths.PluginPath, [IO.Path]::GetFullPath($plugin), [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add("plugin path $($paths.PluginPath), want $plugin")
            }
            Test-Accepted 'standalone tree with the managed OpenCode plugin' $layout
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout
            foreach ($gone in @($plugin, [string]$paths.PluginDirectory, [string]$paths.ShareDirectory)) {
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $gone) {
                    $failures.Add("$gone survived removal")
                }
            }
            if (-not [IO.Directory]::Exists($layout.BinDirectory)) {
                $failures.Add('removal touched the bin directory')
            }
            Test-Accepted 'tree without the plugin' $layout
            # Removal with nothing installed is a no-op.
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout

            # The Fleet compiler is the only Python source admitted under
            # the protected lib tree. A sibling or link still aborts uninstall.
            $layout = New-TestLayout 'compiler'
            [void][IO.Directory]::CreateDirectory($layout.CompilerDirectory)
            [IO.File]::WriteAllText($layout.CompilerPath, 'print("compiler")')
            Test-Accepted 'standalone tree with Fleet compiler' $layout
            $unexpectedCompiler = [IO.Path]::Combine($layout.CompilerDirectory, 'other.py')
            [IO.File]::WriteAllText($unexpectedCompiler, 'print("unexpected")')
            Test-Refused 'unexpected compiler sibling' {
                Assert-DefenseClawManagedInstallTree -Layout $layout
            } 'unexpected file'
            [IO.File]::Delete($unexpectedCompiler)
            $linkedCompiler = New-TestLayout 'linked-compiler'
            [void][IO.Directory]::CreateDirectory($linkedCompiler.CompilerDirectory)
            $compilerTarget = [IO.Path]::Combine($Root, 'outside-compiler.py')
            [IO.File]::WriteAllText($compilerTarget, 'print("outside")')
            if (New-TestLink $linkedCompiler.CompilerPath $compilerTarget) {
                Test-Refused 'compiler reparse point' {
                    Assert-DefenseClawManagedInstallTree -Layout $linkedCompiler
                } 'reparse point'
            }

            # Anything other than the exact leaves stays refused, and a
            # refused removal deletes nothing.
            $extra = New-TestLayout 'extra-ipc'
            [void][IO.Directory]::CreateDirectory($extra.ManagedIPCDirectory)
            $plantedIPC = [IO.Path]::Combine($extra.ManagedIPCDirectory, 'planted.txt')
            [IO.File]::WriteAllText($plantedIPC, 'x')
            Test-Refused 'unexpected ipc file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected ipc file (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $extra } 'unexpected managed IPC content'
            $extra = New-TestLayout 'extra-plugin'
            $extraPlugin = New-Plugin $extra
            $plantedPlugin = [IO.Path]::Combine([IO.Path]::GetDirectoryName($extraPlugin), 'planted.js')
            [IO.File]::WriteAllText($plantedPlugin, 'x')
            Test-Refused 'unexpected plugin file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected plugin file (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $extra } 'unexpected managed OpenCode content'
            foreach ($kept in @($plantedIPC, $plantedPlugin, $extraPlugin)) {
                if (-not [IO.File]::Exists($kept)) {
                    $failures.Add("refused removal still deleted content: $kept")
                }
            }

            # GAP-0743, GAP-0772: Windows renames but does not delete a
            # program that is running, so the copy File.Replace keeps of a
            # running defenseclaw-acp.exe stays. The upgrade still succeeds,
            # the copy is deleted at the next restart, and the uninstall
            # sweep removes what an earlier upgrade left.
            $restartDeletes = [Collections.Generic.List[string]]::new()
            function Request-DefenseClawDeleteAtRestart {
                param([string]$Path)
                $restartDeletes.Add($Path)
            }
            $busy = New-TestLayout 'busy'
            $guard = [IO.Path]::Combine($busy.BinDirectory, 'defenseclaw-acp.exe')
            [IO.File]::Copy([IO.Path]::Combine([Environment]::SystemDirectory, 'PING.EXE'), $guard)
            $busy.ACPPath = $guard
            $newer = [IO.Path]::Combine($Root, 'newer-guard.exe')
            [IO.File]::WriteAllText($newer, 'newer guard')
            $running = Microsoft.PowerShell.Management\Start-Process `
                -FilePath $guard `
                -ArgumentList @('-n', '120', '127.0.0.1') `
                -WindowStyle Hidden `
                -PassThru
            try {
                Install-DefenseClawFileAtomic -Source $newer -Destination $guard
            }
            catch {
                $failures.Add("replacing a running program failed: $($_.Exception.Message)")
            }
            finally {
                Microsoft.PowerShell.Management\Stop-Process -Id $running.Id -Force
                $running.WaitForExit()
            }
            if ([IO.File]::ReadAllText($guard) -cne 'newer guard') {
                $failures.Add('the running program was not replaced')
            }
            $copies = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $busy.BinDirectory -Force -Filter 'defenseclaw-acp.exe.backup.*')
            if ($copies.Count -ne 1 -or $restartDeletes.Count -ne 1 -or $restartDeletes[0] -ne $copies[0].FullName) {
                $failures.Add("the running program's copy was not left for deletion at restart: $($copies.Count) copies, $($restartDeletes -join ', ')")
            }
            Test-Refused 'tree with an earlier upgrade copy (walk)' { Assert-DefenseClawManagedInstallTree -Layout $busy } 'unexpected file'

            # GAP-0852: a handle that shares only read access (as an antivirus
            # scan holds a file) failed the replacement with a raw sharing
            # violation. The refusal names the held file and the retry step,
            # and the file keeps its bytes.
            $held = New-TestLayout 'held'
            $heldTarget = [IO.Path]::Combine($held.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::WriteAllText($heldTarget, 'old hook')
            $heldSource = [IO.Path]::Combine($Root, 'newer-hook.exe')
            [IO.File]::WriteAllText($heldSource, 'newer hook')
            $handle = [IO.File]::Open($heldTarget, 'Open', 'Read', 'Read')
            try {
                Test-Refused 'replacement of a file another program holds open' {
                    Install-DefenseClawFileAtomic -Source $heldSource -Destination $heldTarget
                } ([regex]::Escape("another program holds $heldTarget open") + '.*run Setup again')
            }
            finally {
                $handle.Dispose()
            }
            if ([IO.File]::ReadAllText($heldTarget) -cne 'old hook') {
                $failures.Add('a refused replacement changed the held file')
            }
            Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $busy
            if (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $busy.BinDirectory -Force -Filter 'defenseclaw-acp.exe.backup.*').Count -ne 0) {
                $failures.Add('the uninstall sweep left the earlier upgrade copy')
            }
            Test-Accepted 'tree after the uninstall sweep' $busy

            # GAP-1190: a file DefenseClaw did not install (an administrator's
            # renamed copy of the hook) stops the standalone uninstall before
            # it changes anything, and the refusal names the file and the step.
            $renamed = New-TestLayout 'renamed'
            $away = [IO.Path]::Combine($renamed.BinDirectory, 'defenseclaw-hook.exe.away')
            [IO.File]::WriteAllText($away, 'renamed hook')
            Test-Refused 'uninstall with a renamed hook copy' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $renamed
            } ('unexpected file from managed install root: .*\\defenseclaw-hook\.exe\.away\. ' +
                'The uninstall stopped before it changed anything\..* move it out of .*DefenseClaw, ' +
                'then run the uninstall again$')
            if (-not [IO.File]::Exists($away)) {
                $failures.Add('the refused uninstall removed the renamed copy')
            }

            $sibling = New-TestLayout 'sibling'
            [void](New-Plugin $sibling)
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($sibling.InstallRoot, 'share', 'policies'))
            Test-Refused 'unexpected share directory (walk)' { Assert-DefenseClawManagedInstallTree -Layout $sibling } 'unexpected directory'
            Test-Refused 'unexpected share directory (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $sibling } 'unexpected managed OpenCode content'

            $nested = New-TestLayout 'nested'
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.ManagedIPCDirectory, 'sensor-helper.sock'))
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.InstallRoot, 'share', 'opencode', 'defenseclaw.js'))
            Test-Refused 'directory named like the socket' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $nested } 'unexpected managed IPC content'
            Test-Refused 'directory named like the plugin' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $nested } 'not a plain file'

            $target = [IO.Path]::Combine($Root, 'outside.txt')
            [IO.File]::WriteAllText($target, 'keep')
            $linkedIPC = New-TestLayout 'linked-ipc'
            [void][IO.Directory]::CreateDirectory($linkedIPC.ManagedIPCDirectory)
            if (New-TestLink ([IO.Path]::Combine($linkedIPC.ManagedIPCDirectory, 'sensor-helper.sock')) $target) {
                Test-Refused 'symbolic link named like the socket (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linkedIPC } 'reparse point'
                Test-Refused 'symbolic link named like the socket (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $linkedIPC } 'unexpected managed IPC content'
            }
            $linkedPlugin = New-TestLayout 'linked-plugin'
            $linkedDirectory = [IO.Path]::Combine($linkedPlugin.InstallRoot, 'share', 'opencode')
            [void][IO.Directory]::CreateDirectory($linkedDirectory)
            if (New-TestLink ([IO.Path]::Combine($linkedDirectory, 'defenseclaw.js')) $target) {
                Test-Refused 'symbolic link named like the plugin (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linkedPlugin } 'reparse point'
                Test-Refused 'symbolic link named like the plugin (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $linkedPlugin } 'not a plain file'
            }
            if (-not [IO.File]::Exists($target)) {
                $failures.Add('link target outside the tree was removed')
            }

            # GAP-0942: an editor's ACP thread that runs defenseclaw-acp.exe
            # from the install folder refuses the uninstall before it changes
            # anything and names the program, account and parent; a process
            # seen only once (a hook call) and this lifecycle do not block.
            $inUse = New-TestLayout 'in-use'
            $script:SmokeProcessPasses = 0
            $acp = [IO.Path]::Combine($inUse.BinDirectory, 'defenseclaw-acp.exe')
            $hook = [IO.Path]::Combine($inUse.BinDirectory, 'defenseclaw-hook.exe')
            function script:Get-DefenseClawProcessImages {
                $script:SmokeProcessPasses++
                [pscustomobject]@{ Id = 4242; Path = $acp; UserName = 'HOST\dcw-w3a1'; Parent = 'zed' }
                [pscustomobject]@{ Id = [int]$PID; Path = $acp; UserName = ''; Parent = '' }
                if ($script:SmokeProcessPasses -eq 1) {
                    [pscustomobject]@{ Id = 4343; Path = $hook; UserName = 'HOST\dcw-w3a2'; Parent = 'claude' }
                }
            }
            $script:InstallTreeUseRecheckMilliseconds = 0
            Test-Refused 'uninstall with an open ACP thread' {
                Assert-DefenseClawStandaloneInstallTreeNotInUse -Layout $inUse -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian
            } '^uninstall_in_use: defenseclaw-acp\.exe \(pid 4242, account HOST\\dcw-w3a1, started by zed\) runs from .*nothing was changed'

            # Secure Client: the AVC IPC directory lives under InstallRoot
            # (path parity with the Go IPC resolver) and a graceful stop leaves it empty,
            # so the uninstall inventory accepts that exact directory (release
            # 26.8.4, #839) but nothing inside it beyond the layout's socket.
            # share is not accepted, and the standalone removal helpers are
            # no-ops.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            Assert-DefenseClawStandaloneInstallTreeNotInUse -Layout $inUse -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian
            $secureClient = New-TestLayout 'secure-client-ipc'
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            Test-Accepted 'Secure Client empty ipc directory' $secureClient
            $secureClientStray = [IO.Path]::Combine($secureClient.ManagedIPCDirectory, 'stray.txt')
            [IO.File]::WriteAllText($secureClientStray, 'x')
            # Release 26.8.4 (#1068) bulldozes Secure Client install-tree
            # drift: an unexpected item is reported and removed with the tree
            # unless the strict trust pin is set, which restores the refusal.
            Test-SecureClientTreeDrift 'Secure Client allow-list (ipc content)' $secureClient 'unexpected file'
            [IO.File]::Delete($secureClientStray)
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $secureClient
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed by the standalone helper')
            }
            # A Secure Client layout with the sensor helper admits its exact
            # socket leaf. Uninstall removes only that leaf after the service
            # is gone and leaves the ipc directory for the tree removal; a
            # link at the socket path is still refused.
            $secureClient = New-TestLayout 'scsock'
            $secureClient.SensorHelperPath = [IO.Path]::Combine($secureClient.BinDirectory, 'defenseclaw-sensor-helper.exe')
            [IO.File]::WriteAllText($secureClient.SensorHelperPath, 'stand-in')
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            $sensorSocket = [IO.Path]::Combine($secureClient.ManagedIPCDirectory, 'sensor-helper.sock')
            if ($BindSocket) {
                $socket = [Net.Sockets.Socket]::new(
                    [Net.Sockets.AddressFamily]::Unix,
                    [Net.Sockets.SocketType]::Stream,
                    [Net.Sockets.ProtocolType]::Unspecified
                )
                $openSockets.Add($socket)
                $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new($sensorSocket))
            }
            else {
                # Windows PowerShell 5.1, which Setup runs, has no AF_UNIX
                # endpoint. A PowerShell 7 child binds the socket and exits
                # without closing it, leaving the reparse file a crashed
                # service leaves; without pwsh a plain file stands in.
                $pwsh = Microsoft.PowerShell.Core\Get-Command pwsh -ErrorAction SilentlyContinue
                if ($null -ne $pwsh) {
                    & $pwsh.Source -NoProfile -NonInteractive -Command (
                        "`$s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::Unix,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Unspecified); " +
                        "`$s.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new('$sensorSocket')); [Environment]::Exit(0)"
                    )
                }
                if (-not [IO.File]::Exists($sensorSocket)) {
                    [IO.File]::WriteAllText($sensorSocket, '')
                }
            }
            Test-Accepted 'Secure Client tree with the sensor helper socket' $secureClient
            Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
            if ([IO.File]::Exists($sensorSocket)) {
                $failures.Add('Secure Client sensor helper socket survived removal')
            }
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed with the sensor helper socket')
            }
            # Removal with no socket is a no-op.
            Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
            $socketTarget = [IO.Path]::Combine($Root, 'outside-socket.txt')
            [IO.File]::WriteAllText($socketTarget, 'outside')
            if (New-TestLink $sensorSocket $socketTarget) {
                Test-Refused 'Secure Client sensor helper socket link' {
                    Assert-DefenseClawManagedInstallTree -Layout $secureClient
                } 'reparse point'
                Test-Refused 'Secure Client sensor helper socket link removal' {
                    Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
                } 'unexpected managed IPC content'
                if (-not [IO.File]::Exists($socketTarget)) {
                    $failures.Add('Secure Client socket link removal touched its target')
                }
                [IO.File]::Delete($sensorSocket)
            }
            if (@(Get-DefenseClawSecureClientSensorHelperSocketLeaves -Layout (New-TestLayout 'scnosock')).Count -ne 0) {
                $failures.Add('Secure Client layout without the sensor helper reported a socket leaf')
            }
            $secureClient = New-TestLayout 'secure-client-share'
            $secureClientPlugin = New-Plugin $secureClient
            Test-SecureClientTreeDrift 'Secure Client allow-list (share)' $secureClient 'unexpected directory'
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $secureClient
            if (-not [IO.File]::Exists($secureClientPlugin)) {
                $failures.Add('Secure Client share content was removed by the standalone helper')
            }
            if ($null -ne (Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $secureClient)) {
                $failures.Add('Secure Client reported managed OpenCode plugin paths')
            }
        }
        finally {
            foreach ($open in $openSockets) {
                $open.Dispose()
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root ($PSVersionTable.PSVersion.Major -ge 7)
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-install-tree-smoke: OK'
