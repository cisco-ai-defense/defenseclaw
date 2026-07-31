# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Advisory packaged OmniGent native-Windows degraded-mode contract.

.DESCRIPTION
    Installs the official OmniGent 0.7.0 client with its documented uv-tool
    path, installs the packaged DefenseClaw distribution, registers the
    in-process policy, starts the real OmniGent server, and verifies live,
    fail-closed, and teardown behavior. No WSL, shell compatibility layer,
    terminal wrapper, container, or sandbox-parity assertion is involved.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$StateRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or [Environment]::Is64BitOperatingSystem -ne $true) {
    throw 'OmniGent native contract requires Windows x64'
}

$state = [IO.Path]::GetFullPath($StateRoot)
$artifacts = [IO.Path]::GetFullPath($ArtifactRoot)
if (-not (Test-Path -LiteralPath $artifacts -PathType Container)) {
    throw "packaged artifact directory is missing: $artifacts"
}
[IO.Directory]::CreateDirectory($state) | Out-Null

$env:OMNIGENT_CONFIG_HOME = Join-Path $state 'omnigent-config'
$env:OMNIGENT_DATA_DIR = Join-Path $state 'omnigent-data'
$env:UV_TOOL_DIR = Join-Path $state 'uv-tools'
$env:UV_TOOL_BIN_DIR = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin'
$env:UV_CACHE_DIR = Join-Path $state 'uv-cache'
$env:OMNIGENT_ACCOUNTS_AUTO_OPEN = '0'
$env:PATH = $env:UV_TOOL_BIN_DIR + ';' + $env:PATH
foreach ($directory in @(
    $env:OMNIGENT_CONFIG_HOME,
    $env:OMNIGENT_DATA_DIR,
    $env:UV_TOOL_DIR,
    $env:UV_TOOL_BIN_DIR
)) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 120,
        [int[]]$AcceptedExitCodes = @(0)
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [IO.Path]::GetFullPath($FilePath)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        if (-not $process.Start()) {
            throw "native process did not start: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $remaining = [Math]::Max(
            1,
            [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        )
        if (-not $process.WaitForExit($remaining)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) {
                throw "native process tree did not exit within 10 seconds after termination: $FilePath"
            }
            throw "native process timed out after $TimeoutSeconds seconds: $FilePath"
        }
        $remaining = [Math]::Max(
            1,
            [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        )
        $outputTasks = [Threading.Tasks.Task]::WhenAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
        )
        if (-not $outputTasks.Wait($remaining)) {
            throw "native process output did not close before the $TimeoutSeconds second deadline: $FilePath"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stderr) {
            [Console]::Error.Write($stderr)
        }
        if ($process.ExitCode -notin $AcceptedExitCodes) {
            throw "native process failed with exit code $($process.ExitCode)`: $FilePath"
        }
        return $stdout
    } finally {
        $process.Dispose()
    }
}

$uv = (Get-Command uv.exe -CommandType Application -ErrorAction Stop).Source
Invoke-NativeChecked $uv @(
    'tool', 'install', '--python', '3.12', '--force', 'omnigent==0.7.0'
) -TimeoutSeconds 600
$omnigent = Join-Path $env:UV_TOOL_BIN_DIR 'omnigent.exe'
$omnigentPython = Join-Path $env:UV_TOOL_DIR 'omnigent\Scripts\python.exe'
foreach ($required in @($omnigent, $omnigentPython)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "official OmniGent uv-tool installation is incomplete: $required"
    }
}
$version = (Invoke-NativeChecked $omnigent @('--version') -TimeoutSeconds 30).Trim()
if ($version -notmatch '\b0\.7\.0\b') {
    throw "official OmniGent version probe was not 0.7.0: $version"
}

$defenseclawData = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.defenseclaw'
$nativeInstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\DefenseClaw'
if ((Test-Path -LiteralPath $nativeInstallRoot) -or
    (Test-Path -LiteralPath (Join-Path $defenseclawData 'active_connector.json'))) {
    throw 'OmniGent advisory Setup lifecycle requires a clean disposable Windows user'
}
$config = Join-Path $env:OMNIGENT_CONFIG_HOME 'config.yaml'
$module = Join-Path $defenseclawData 'hooks\defenseclaw_omnigent_policy.py'
$pth = Join-Path $env:UV_TOOL_DIR 'omnigent\Lib\site-packages\defenseclaw_omnigent.pth'
foreach ($parent in @(
    (Split-Path -Parent $config),
    (Split-Path -Parent $module),
    (Split-Path -Parent $pth)
)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($config, "policy_modules: []`npolicies: []`n", $utf8)
[IO.File]::WriteAllText($module, "# operator-owned preexisting module`n", $utf8)
[IO.File]::WriteAllText($pth, "C:\operator-owned-python-path`n", $utf8)
$originalHashes = @{}
foreach ($path in @($config, $module, $pth)) {
    $originalHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

$install = Join-Path $PSScriptRoot 'install.ps1'
$pwsh = (Get-Process -Id $PID).Path
Invoke-NativeChecked $pwsh @(
    '-NoLogo', '-NoProfile', '-File', $install,
    '-Local', $artifacts, '-Connector', 'omnigent', '-Yes',
    '-Quickstart', '-QuickstartMode', 'action'
)

$defenseclaw = Join-Path $nativeInstallRoot 'bin\defenseclaw.exe'
$gateway = Join-Path $nativeInstallRoot 'bin\defenseclaw-gateway.exe'
$installStatePath = Join-Path $nativeInstallRoot 'installer\install-state.json'
foreach ($required in @($defenseclaw, $gateway, $installStatePath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "packaged DefenseClaw installation is incomplete: $required"
    }
}
$installState = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
if ([string]$installState.connector -cne 'omnigent' -or
    [IO.Path]::GetFullPath([string]$installState.omnigent_config_home) -cne
        [IO.Path]::GetFullPath($env:OMNIGENT_CONFIG_HOME)) {
    throw 'native Setup did not persist the OmniGent connector and exact config-home custody'
}
$setup = [string]$installState.maintenance_path
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "native Setup maintenance executable is missing: $setup"
}

Invoke-NativeChecked $defenseclaw @(
    'setup', 'omnigent', '--yes', '--mode', 'action',
    '--fail-mode', 'closed', '--restart'
)

foreach ($required in @($config, $module, $pth)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "OmniGent policy setup did not create required state: $required"
    }
}
Invoke-NativeChecked $setup @('/repair', '/quiet', '/norestart')
Invoke-NativeChecked $setup @('/upgrade', '/quiet', '/norestart')
$preservedState = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
if ([string]$preservedState.connector -cne 'omnigent' -or
    [IO.Path]::GetFullPath([string]$preservedState.omnigent_config_home) -cne
        [IO.Path]::GetFullPath($env:OMNIGENT_CONFIG_HOME)) {
    throw 'native Setup repair/upgrade did not preserve the OmniGent custody ledger'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$serverOut = Join-Path $state 'omnigent-server.stdout.log'
$serverErr = Join-Path $state 'omnigent-server.stderr.log'
$server = Start-Process -FilePath $omnigent -ArgumentList @(
    'server', '--host', '127.0.0.1', '--port', [string]$port,
    '--config', $config, '--no-open'
) -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($server.HasExited) {
            throw "official OmniGent server exited before readiness with code $($server.ExitCode)"
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $port)
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        } finally {
            $client.Dispose()
        }
    }
    if (-not $ready) {
        throw 'official OmniGent server did not bind its native loopback listener'
    }

    $policyProbe = @'
import json
import defenseclaw_omnigent_policy as policy
print(json.dumps(policy.defenseclaw_policy({
    "type": "tool_call",
    "target": "read_file",
    "data": {"name": "read_file", "arguments": {"path": "README.md"}},
    "context": {"actor": {"client_id": "windows-native-contract"}},
})))
'@
    $liveVerdict = (Invoke-NativeChecked $omnigentPython @('-I', '-c', $policyProbe) -TimeoutSeconds 30).Trim() | ConvertFrom-Json
    if ([string]$liveVerdict.result -notin @('ALLOW', 'ASK', 'DENY')) {
        throw 'official OmniGent Python environment did not execute the managed policy'
    }

    Invoke-NativeChecked $gateway @('stop')
    $closedVerdict = (Invoke-NativeChecked $omnigentPython @('-I', '-c', $policyProbe) -TimeoutSeconds 30).Trim() | ConvertFrom-Json
    if ([string]$closedVerdict.result -cne 'DENY') {
        throw 'OmniGent managed policy did not fail closed after the gateway stopped'
    }

} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        $server.WaitForExit(10000)
    }
    $server.Dispose()
}

Invoke-NativeChecked $setup @('/uninstall', '/quiet', '/norestart') `
    -TimeoutSeconds 300 -AcceptedExitCodes @(0, 3010)
foreach ($path in @($config, $module, $pth)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "native Setup uninstall did not restore the preexisting OmniGent file: $path"
    }
    $restoredHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($restoredHash -cne $originalHashes[$path]) {
        throw "native Setup uninstall did not restore exact OmniGent bytes: $path"
    }
}

Write-Host 'OmniGent 0.7.0 packaged native-Windows degraded Setup lifecycle contract passed.'
