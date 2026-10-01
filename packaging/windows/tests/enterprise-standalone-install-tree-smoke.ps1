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
                [void][IO.Directory]::CreateDirectory($bin)
                [void][IO.Directory]::CreateDirectory($libexec)
                $gateway = [IO.Path]::Combine($bin, 'defenseclaw-gateway.exe')
                [IO.File]::WriteAllText($gateway, 'stand-in')
                return @{
                    InstallRoot = $install
                    BinDirectory = $bin
                    LibexecDirectory = $libexec
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

            # Secure Client keeps its original allow-list: neither ipc nor share
            # is accepted, and removal is a no-op.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $secureClient = New-TestLayout 'secure-client-ipc'
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            Test-Refused 'Secure Client allow-list (ipc)' { Assert-DefenseClawManagedInstallTree -Layout $secureClient } 'unexpected directory'
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $secureClient
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed by the standalone helper')
            }
            $secureClient = New-TestLayout 'secure-client-share'
            $secureClientPlugin = New-Plugin $secureClient
            Test-Refused 'Secure Client allow-list (share)' { Assert-DefenseClawManagedInstallTree -Layout $secureClient } 'unexpected directory'
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
