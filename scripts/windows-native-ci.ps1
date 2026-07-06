# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Native Windows x64 CI build, packaged-install, lifecycle, and cleanup harness.

.DESCRIPTION
    Keeps every mutable profile/cache/temp path below StateRoot. The harness is
    intentionally PowerShell-native and never requires WSL, MSYS, or Git Bash.
#>

[CmdletBinding()]
param(
    [ValidateSet('stage-package-data', 'build-artifacts', 'acceptance', 'contract', 'capture', 'cleanup', 'self-test')]
    [string]$Operation = 'self-test',
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) 'defenseclaw-windows-native-ci'),
    [string]$ArtifactRoot = '',
    [string]$DiagnosticsRoot = '',
    [ValidateSet('codex', 'claudecode')][string]$Connector = 'codex',
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RedactionValues {
    $names = @(
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AZURE_OPENAI_API_KEY',
        'AWS_BEARER_TOKEN_BEDROCK', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN', 'LLM_API_KEY', 'GH_TOKEN', 'GITHUB_TOKEN',
        'DEFENSECLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_TOKEN', 'DC_E2E_TEST_SECRET'
    )
    return @($names | ForEach-Object { [Environment]::GetEnvironmentVariable($_) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_.Length -ge 8 } |
        Sort-Object -Unique)
}

function Protect-WindowsNativeText([AllowNull()][string]$Text) {
    if ($null -eq $Text) { return '' }
    $safe = $Text
    foreach ($value in Get-RedactionValues) { $safe = $safe.Replace($value, '***REDACTED***') }
    return $safe -replace '(?im)(api[_-]?key|access[_-]?token|secret[_-]?key|authorization)\s*[:=]\s*\S+', '$1=***REDACTED***'
}

function Assert-NativeWindowsX64 {
    if (-not $IsWindows) { throw 'Windows Native CI requires native Windows PowerShell' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
        throw 'Windows Native CI certifies only native Windows x64'
    }
}

function Test-PathWithin([string]$Path, [string]$Root) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $candidate.StartsWith($parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafeStateRoot([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowedRoots = @(
        [Environment]::GetEnvironmentVariable('RUNNER_TEMP'),
        [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT'),
        [IO.Path]::GetTempPath()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (-not ($allowedRoots | Where-Object {
        $full.Equals([IO.Path]::GetFullPath($_).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
        (Test-PathWithin $full $_)
    } | Select-Object -First 1)) {
        throw "StateRoot must be a child of RUNNER_TEMP or the system temp directory: $full"
    }
    foreach ($protected in @($WorkspaceRoot, $env:USERPROFILE, [IO.Path]::GetTempPath())) {
        if (-not [string]::IsNullOrWhiteSpace($protected) -and
            $full.Equals([IO.Path]::GetFullPath($protected).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "StateRoot must not equal a workspace, profile, or temp root: $full"
        }
    }
    return $full
}

function Write-BoundedText([string]$Path, [AllowNull()][string]$Text, [int]$MaxBytes = 1048576) {
    $safe = Protect-WindowsNativeText $Text
    $bytes = [Text.Encoding]::UTF8.GetBytes($safe)
    if ($bytes.Length -gt $MaxBytes) {
        $safe = [Text.Encoding]::UTF8.GetString($bytes, 0, $MaxBytes) + "`n[truncated]`n"
    }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    [IO.File]::WriteAllText($Path, $safe, [Text.UTF8Encoding]::new($false))
}

function Invoke-WindowsNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 600,
        [string]$LogPath = '',
        [string]$WorkingDirectory = ''
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($WorkingDirectory) { $start.WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory) }
    foreach ($argument in $ArgumentList) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "failed to start $FilePath" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $process.Kill($true) } catch { Write-Warning (Protect-WindowsNativeText $_.Exception.Message) }
        $process.WaitForExit()
    }
    $stdout = Protect-WindowsNativeText $stdoutTask.GetAwaiter().GetResult()
    $stderr = Protect-WindowsNativeText $stderrTask.GetAwaiter().GetResult()
    $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
    $combined = @($stdout, $stderr | Where-Object { $_ }) -join [Environment]::NewLine
    if ($combined) { Write-Host $combined }
    if ($LogPath) { Write-BoundedText -Path $LogPath -Text $combined }
    $result = [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $stdout
        StdErr = $stderr
        TimedOut = $timedOut
        ProcessId = $process.Id
    }
    if ($exitCode -notin $AllowedExitCodes) {
        $reason = if ($timedOut) { "timed out after ${TimeoutSeconds}s" } else { "exited $exitCode" }
        throw "$FilePath $reason`n$combined"
    }
    return $result
}

function Get-RequiredCommand([string]$Name) {
    $command = Get-Command $Name -ErrorAction Stop
    return $command.Source
}

function Copy-Tree([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { throw "missing source directory: $Source" }
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Destination)) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Copy-MatchedFiles([string]$Pattern, [string]$Destination, [string]$Exclude = '') {
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $items = @(Get-ChildItem -Path $Pattern -File)
    if ($Exclude) { $items = @($items | Where-Object { $_.Name -notlike $Exclude }) }
    foreach ($item in $items) { Copy-Item -LiteralPath $item.FullName -Destination $Destination -Force }
}

function Stage-PackageData([string]$PackageRoot) {
    $data = Join-Path $PackageRoot '_data'
    if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }
    Copy-MatchedFiles (Join-Path $WorkspaceRoot 'policies\rego\*.rego') (Join-Path $data 'policies\rego') '*_test.rego'
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'policies\rego\data.json') -Destination (Join-Path $data 'policies\rego') -Force
    Copy-MatchedFiles (Join-Path $WorkspaceRoot 'policies\*.yaml') (Join-Path $data 'policies')
    Copy-Tree (Join-Path $WorkspaceRoot 'policies\openshell') (Join-Path $data 'policies\openshell')
    foreach ($name in @('default', 'strict', 'permissive')) {
        Copy-Tree (Join-Path $WorkspaceRoot "policies\guardrail\$name") (Join-Path $data "policies\guardrail\$name")
    }
    [IO.Directory]::CreateDirectory((Join-Path $data 'envvars')) | Out-Null
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'internal\envvars\registry.json') -Destination (Join-Path $data 'envvars') -Force
    [IO.Directory]::CreateDirectory((Join-Path $data 'scripts')) | Out-Null
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'scripts\install-openshell-sandbox.sh') -Destination (Join-Path $data 'scripts') -Force
    Copy-Tree (Join-Path $WorkspaceRoot 'skills\codeguard') (Join-Path $data 'skills\codeguard')
    [IO.Directory]::CreateDirectory((Join-Path $data 'llm')) | Out-Null
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'bundles\llm\model_catalog.json') -Destination (Join-Path $data 'llm') -Force
    foreach ($name in @('splunk_local_bridge', 'local_observability_stack', 'splunk_o11y_dashboards')) {
        Copy-Tree (Join-Path $WorkspaceRoot "bundles\$name") (Join-Path $data $name)
    }
}

function Invoke-BuildArtifacts {
    Assert-NativeWindowsX64
    $root = Assert-SafeStateRoot $StateRoot
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for build-artifacts' }
    $dist = [IO.Path]::GetFullPath($ArtifactRoot)
    [IO.Directory]::CreateDirectory($root) | Out-Null
    if (Test-Path -LiteralPath $dist) { Remove-Item -LiteralPath $dist -Recurse -Force }
    [IO.Directory]::CreateDirectory($dist) | Out-Null
    $go = Get-RequiredCommand 'go.exe'
    $uv = Get-RequiredCommand 'uv.exe'
    $stage = Join-Path $root 'gateway-stage'
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $previousCgo = $env:CGO_ENABLED
    try {
        $env:CGO_ENABLED = '0'
        Invoke-WindowsNativeProcess $go @('build', '-ldflags', '-s -w -X main.version=0.0.0-windows-native', '-o', (Join-Path $stage 'defenseclaw.exe'), './cmd/defenseclaw') -TimeoutSeconds 900 | Out-Null
        Invoke-WindowsNativeProcess $go @('build', '-ldflags', '-s -w -H=windowsgui -X main.version=0.0.0-windows-native', '-o', (Join-Path $stage 'defenseclaw-hook.exe'), './cmd/defenseclaw-hook') -TimeoutSeconds 900 | Out-Null
    } finally {
        if ($null -eq $previousCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
        else { $env:CGO_ENABLED = $previousCgo }
    }
    Compress-Archive -LiteralPath (Join-Path $stage 'defenseclaw.exe'), (Join-Path $stage 'defenseclaw-hook.exe') `
        -DestinationPath (Join-Path $dist 'defenseclaw_0.0.0-windows-native_windows_amd64.zip') -Force

    $packageStage = Join-Path $root 'package-source'
    [IO.Directory]::CreateDirectory($packageStage) | Out-Null
    foreach ($file in @('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', 'MANIFEST.in')) {
        Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) -Destination $packageStage -Force
    }
    [IO.Directory]::CreateDirectory((Join-Path $packageStage 'cli')) | Out-Null
    Copy-Tree (Join-Path $WorkspaceRoot 'cli\defenseclaw') (Join-Path $packageStage 'cli\defenseclaw')
    Stage-PackageData (Join-Path $packageStage 'cli\defenseclaw')
    Invoke-WindowsNativeProcess $uv @('build', '--wheel', '--out-dir', $dist) -TimeoutSeconds 900 -WorkingDirectory $packageStage | Out-Null
    $wheel = Get-ChildItem -LiteralPath $dist -Filter 'defenseclaw-*.whl' -File | Select-Object -First 1
    if (-not $wheel) {
        throw 'wheel build did not produce a DefenseClaw wheel'
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($wheel.FullName)
    try {
        $entries = @($archive.Entries.FullName)
        foreach ($required in @(
            'defenseclaw/_data/envvars/registry.json',
            'defenseclaw/_data/skills/codeguard/SKILL.md',
            'defenseclaw/_data/llm/model_catalog.json'
        )) {
            if ($required -notin $entries) { throw "wheel is missing packaged runtime data: $required" }
        }
    } finally { $archive.Dispose() }
    Remove-Item -LiteralPath (Join-Path $dist '.gitignore') -Force -ErrorAction SilentlyContinue
}

function Initialize-IsolatedProfile([string]$Root) {
    $safeRoot = Assert-SafeStateRoot $Root
    [IO.Directory]::CreateDirectory($safeRoot) | Out-Null
    $originalProfile = $env:USERPROFILE
    $profile = Join-Path $safeRoot 'profile'
    $temp = Join-Path $safeRoot 'temp'
    $tools = Join-Path $safeRoot 'tools'
    foreach ($path in @($profile, $temp, $tools, (Join-Path $profile 'AppData\Roaming'), (Join-Path $profile 'AppData\Local'))) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
    $uvSource = Get-RequiredCommand 'uv.exe'
    $uvIsolated = Join-Path $tools 'uv.exe'
    if (-not ([IO.Path]::GetFullPath($uvSource).Equals(
        [IO.Path]::GetFullPath($uvIsolated), [StringComparison]::OrdinalIgnoreCase))) {
        Copy-Item -LiteralPath $uvSource -Destination $uvIsolated -Force
    }

    $env:USERPROFILE = $profile
    $env:HOME = $profile
    $driveRoot = [IO.Path]::GetPathRoot($profile)
    $env:HOMEDRIVE = $driveRoot.TrimEnd('\')
    $env:HOMEPATH = $profile.Substring($driveRoot.Length - 1)
    $env:APPDATA = Join-Path $profile 'AppData\Roaming'
    $env:LOCALAPPDATA = Join-Path $profile 'AppData\Local'
    $env:TEMP = $temp
    $env:TMP = $temp
    $env:DEFENSECLAW_HOME = Join-Path $profile '.defenseclaw'
    $env:CODEX_HOME = Join-Path $profile '.codex'
    $env:CLAUDE_CONFIG_DIR = Join-Path $profile '.claude'
    $env:HERMES_HOME = Join-Path $profile '.hermes'
    $env:ZEPTOCLAW_HOME = Join-Path $profile '.zeptoclaw'
    $env:OPENCODE_CONFIG_DIR = Join-Path $profile '.config\opencode'
    $env:OMNIGENT_CONFIG_HOME = Join-Path $profile '.config\omnigent'
    $env:XDG_CONFIG_HOME = Join-Path $profile '.config'
    $env:UV_CACHE_DIR = Join-Path $safeRoot 'cache\uv'
    $env:PIP_CACHE_DIR = Join-Path $safeRoot 'cache\pip'
    $env:NPM_CONFIG_CACHE = Join-Path $safeRoot 'cache\npm'
    $env:GIT_CONFIG_GLOBAL = Join-Path $profile '.gitconfig'
    $bin = Join-Path $profile '.local\bin'
    $venvScripts = Join-Path $env:DEFENSECLAW_HOME '.venv\Scripts'
    $systemPaths = @(
        $bin, $venvScripts, $tools, $PSHOME,
        (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot,
        (Join-Path $env:SystemRoot 'System32\Wbem')
    ) | Select-Object -Unique
    $env:PATH = $systemPaths -join ';'
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
    Remove-Item Env:HERMES_GIT_BASH_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:DEFENSECLAW_GATEWAY_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:OPENCLAW_GATEWAY_TOKEN -ErrorAction SilentlyContinue

    if ($originalProfile) {
        foreach ($entry in ($env:PATH -split ';')) {
            if ($entry -and (Test-PathWithin $entry $originalProfile) -and -not (Test-PathWithin $entry $safeRoot)) {
                throw "isolated PATH retained an entry from the runner profile: $entry"
            }
        }
    }
    return [pscustomobject]@{ Root = $safeRoot; Profile = $profile; Bin = $bin; VenvScripts = $venvScripts }
}

function Install-PackagedArtifacts([string]$Root, [string]$Artifacts) {
    $profile = Initialize-IsolatedProfile $Root
    if (-not (Test-Path -LiteralPath $Artifacts -PathType Container)) { throw "artifact directory missing: $Artifacts" }
    $pwsh = (Get-Process -Id $PID).Path
    $install = Join-Path $WorkspaceRoot 'scripts\install.ps1'
    $userPathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')
    Invoke-WindowsNativeProcess $pwsh @(
        '-NoLogo', '-NoProfile', '-File', $install, '-Local', ([IO.Path]::GetFullPath($Artifacts)),
        '-Connector', 'none', '-Yes', '-NoPersistPath'
    ) -TimeoutSeconds 1800 -LogPath (Join-Path $Root 'logs\install.log') | Out-Null
    $userPathAfter = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not [string]::Equals($userPathBefore, $userPathAfter, [StringComparison]::Ordinal)) {
        throw 'packaged install mutated the runner user PATH despite -NoPersistPath'
    }
    foreach ($path in @(
        (Join-Path $profile.Bin 'defenseclaw.cmd'),
        (Join-Path $profile.Bin 'defenseclaw-gateway.exe'),
        (Join-Path $profile.Bin 'defenseclaw-hook.exe'),
        (Join-Path $profile.VenvScripts 'python.exe'),
        (Join-Path $profile.VenvScripts 'defenseclaw.exe')
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "packaged install missing: $path" }
    }
    return $profile
}

function Invoke-Installed([string]$Executable, [string[]]$Arguments, [int[]]$Allowed = @(0), [int]$Timeout = 300, [string]$Log = '') {
    $file = $Executable
    $args = $Arguments
    if ([IO.Path]::GetExtension($Executable).Equals('.cmd', [StringComparison]::OrdinalIgnoreCase)) {
        $file = $env:ComSpec
        $args = @('/d', '/c', $Executable) + $Arguments
    }
    return Invoke-WindowsNativeProcess -FilePath $file -ArgumentList $args -AllowedExitCodes $Allowed -TimeoutSeconds $Timeout -LogPath $Log
}

function Assert-ManagedImports([string]$Python, [string]$VenvRoot) {
    $code = @'
import importlib
import pathlib
import sys

venv = pathlib.Path(sys.argv[1]).resolve()
workspace = pathlib.Path(sys.argv[2]).resolve()
for name in ('defenseclaw', 'skill_scanner', 'mcpscanner'):
    module = importlib.import_module(name)
    location = pathlib.Path(module.__file__).resolve()
    if venv not in location.parents:
        raise SystemExit(f'{name} resolved outside managed venv: {location}')
    if workspace == location or workspace in location.parents:
        raise SystemExit(f'{name} resolved from source checkout: {location}')
print('managed imports:', ', '.join(('defenseclaw', 'skill_scanner', 'mcpscanner')))
'@
    Invoke-Installed $Python @('-I', '-c', $code, $VenvRoot, $WorkspaceRoot) -Timeout 120 | Out-Null
}

function Invoke-HeadlessTui([string]$Python) {
    $code = @'
import asyncio
from defenseclaw.tui.app import DefenseClawTUI

async def smoke():
    app = DefenseClawTUI()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()

asyncio.run(asyncio.wait_for(smoke(), timeout=20))
print('headless TUI started and stopped cleanly')
'@
    Invoke-Installed $Python @('-I', '-c', $code) -Timeout 30 | Out-Null
}

function Wait-PathsAbsent([string[]]$Paths, [int]$Attempts = 150) {
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $remaining = @($Paths | Where-Object { Test-Path -LiteralPath $_ })
        if ($remaining.Count -eq 0) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for removal: $($remaining -join ', ')"
}

function Invoke-Acceptance {
    Assert-NativeWindowsX64
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for acceptance' }
    $root = Assert-SafeStateRoot $StateRoot
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = $root
    $profile = Install-PackagedArtifacts $root ([IO.Path]::GetFullPath($ArtifactRoot))
    $cliShim = Join-Path $profile.Bin 'defenseclaw.cmd'
    $cli = Join-Path $profile.VenvScripts 'defenseclaw.exe'
    $gateway = Join-Path $profile.Bin 'defenseclaw-gateway.exe'
    $python = Join-Path $profile.VenvScripts 'python.exe'
    $venvRoot = Split-Path -Parent $profile.VenvScripts
    $uv = Join-Path $root 'tools\uv.exe'
    $logs = Join-Path $root 'logs'

    Invoke-Installed $cliShim @('--version') -Log (Join-Path $logs 'version.log') | Out-Null
    Invoke-Installed $uv @('pip', 'check', '--python', $python) -Timeout 300 -Log (Join-Path $logs 'uv-pip-check.log') | Out-Null
    Assert-ManagedImports $python $venvRoot
    Invoke-Installed $cli @(
        'init', '--skip-install', '--non-interactive', '--yes', '--connector', 'codex',
        '--profile', 'observe', '--no-start-gateway', '--no-verify'
    ) -Timeout 300 -Log (Join-Path $logs 'init.log') | Out-Null
    Invoke-Installed $gateway @('start') -Timeout 60 -Log (Join-Path $logs 'gateway-start.log') | Out-Null
    Invoke-Installed $gateway @('status') -Timeout 30 -Log (Join-Path $logs 'gateway-status.log') | Out-Null
    Invoke-Installed $cli @('doctor', '--json-output') -Timeout 300 -Log (Join-Path $logs 'doctor.json') | Out-Null

    $skill = Join-Path $root 'clean-skill'
    [IO.Directory]::CreateDirectory($skill) | Out-Null
    Write-BoundedText (Join-Path $skill 'SKILL.md') "---`nname: windows-native-smoke`ndescription: Prints a friendly greeting.`n---`n`nUse this skill to print a friendly greeting.`n"
    Write-BoundedText (Join-Path $skill 'skill.yaml') "name: windows-native-smoke`ndescription: Prints a friendly greeting.`nversion: 1.0.0`n"
    Invoke-Installed $cli @('skill', 'scan', $skill, '--no-use-llm', '--json') -Timeout 300 -Log (Join-Path $logs 'skill-scan.json') | Out-Null
    Invoke-Installed $cli @('mcp', 'scan', '--all', '--json') -Timeout 300 -Log (Join-Path $logs 'mcp-scan.json') | Out-Null
    Invoke-HeadlessTui $python

    Invoke-Installed $gateway @('restart') -Timeout 60 -Log (Join-Path $logs 'gateway-restart.log') | Out-Null
    Invoke-Installed $gateway @('status') -Timeout 30 | Out-Null
    Invoke-Installed $gateway @('stop') -Timeout 60 -Log (Join-Path $logs 'gateway-stop.log') | Out-Null
    $stopped = Invoke-Installed $gateway @('status') @(1) 30 (Join-Path $logs 'gateway-stopped-status.log')
    if ($stopped.ExitCode -eq 0) { throw 'gateway status returned success after stop' }

    Invoke-Installed $cli @('reset', '--yes') -Timeout 300 -Log (Join-Path $logs 'reset-first.log') | Out-Null
    Invoke-Installed $cli @('reset', '--yes') -Timeout 300 -Log (Join-Path $logs 'reset-second.log') | Out-Null

    $sentinel = Join-Path $profile.Bin 'unrelated.txt'
    Write-BoundedText $sentinel 'preserve'
    $uninstall = Invoke-Installed $cli @('uninstall', '--all', '--binaries', '--yes') @(0) 300 (Join-Path $logs 'uninstall.log')
    $resultMatch = [regex]::Match(($uninstall.StdOut + "`n" + $uninstall.StdErr), 'result:\s+([^\)]+\.json)')
    if (-not $resultMatch.Success) { throw 'full uninstall did not report its deferred result path' }
    $resultPath = $resultMatch.Groups[1].Value.Trim()
    Wait-PathsAbsent @(
        (Join-Path $profile.Bin 'defenseclaw.cmd'),
        (Join-Path $profile.Bin 'defenseclaw-gateway.exe'),
        (Join-Path $profile.Bin 'defenseclaw-hook.exe'),
        $env:DEFENSECLAW_HOME
    )
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) { throw "uninstall result missing: $resultPath" }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($result.status -ne 'succeeded') { throw "uninstall helper failed: $($result.detail)" }
    Remove-Item -LiteralPath $resultPath -Force
    if ((Get-Content -LiteralPath $sentinel -Raw).Trim() -ne 'preserve') { throw 'uninstall modified unrelated install-root content' }

    $profile = Install-PackagedArtifacts $root ([IO.Path]::GetFullPath($ArtifactRoot))
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw.cmd') @('--version') | Out-Null
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw-gateway.exe') @('--version') | Out-Null
}

function Invoke-Contract {
    Assert-NativeWindowsX64
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for contract' }
    foreach ($name in @(
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AZURE_OPENAI_API_KEY',
        'AWS_BEARER_TOKEN_BEDROCK', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN', 'LLM_API_KEY'
    )) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    $root = Assert-SafeStateRoot $StateRoot
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = $root
    $profile = Install-PackagedArtifacts (Join-Path $root 'install') ([IO.Path]::GetFullPath($ArtifactRoot))
    $contractRoot = $profile.Root
    $contractHome = $profile.Profile
    foreach ($path in @($contractHome, (Join-Path $contractHome 'AppData\Roaming'), (Join-Path $contractHome 'AppData\Local'), (Join-Path $contractRoot 'temp'))) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
    $env:USERPROFILE = $contractHome
    $env:HOME = $contractHome
    $env:APPDATA = Join-Path $contractHome 'AppData\Roaming'
    $env:LOCALAPPDATA = Join-Path $contractHome 'AppData\Local'
    $env:TEMP = Join-Path $contractRoot 'temp'
    $env:TMP = $env:TEMP
    $env:CODEX_HOME = Join-Path $contractHome '.codex'
    $env:CLAUDE_CONFIG_DIR = Join-Path $contractHome '.claude'
    $env:PATH = "$($profile.VenvScripts);$($profile.Bin);$env:PATH"
    $harness = Join-Path $WorkspaceRoot 'scripts\live-connector-e2e\run-windows.ps1'
    & $harness -Layer contract -Connector $Connector -WorkspaceRoot $WorkspaceRoot `
        -StateRoot $contractRoot -HomeRoot $contractHome -ResultsPath (Join-Path $root 'results.jsonl') `
        -ArtifactPath (Join-Path $root 'contract-diagnostics')
}

function Get-StateProcesses([string]$Root) {
    $full = [IO.Path]::GetFullPath($Root)
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and
        $_.CommandLine.IndexOf($full, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}

function Stop-StateProcesses([string]$Root) {
    $processes = @(Get-StateProcesses $Root)
    $ids = @($processes | ForEach-Object { [int]$_.ProcessId })
    foreach ($process in ($processes | Sort-Object CreationDate -Descending)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (-not ($ids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })) { return }
        Start-Sleep -Milliseconds 250
    }
    $remaining = @($ids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })
    if ($remaining.Count) { throw "isolated process cleanup timed out: $($remaining -join ', ')" }
}

function Invoke-Capture {
    $root = Assert-SafeStateRoot $StateRoot
    $destination = if ($DiagnosticsRoot) { [IO.Path]::GetFullPath($DiagnosticsRoot) } else { Join-Path $root 'diagnostics' }
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $processes = @(Get-StateProcesses $root | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json -Depth 3)
    Write-BoundedText (Join-Path $destination 'processes.json') $processes
    $pids = @(Get-StateProcesses $root | ForEach-Object { $_.ProcessId })
    $listeners = @()
    if ($pids.Count) {
        $netstat = Invoke-WindowsNativeProcess (Join-Path $env:SystemRoot 'System32\netstat.exe') @('-ano') @(0) 30
        $listeners = @($netstat.StdOut -split "`r?`n" | Where-Object {
            $columns = $_.Trim() -split '\s+'
            $columns.Count -ge 5 -and $columns[-1] -in $pids
        })
    }
    Write-BoundedText (Join-Path $destination 'listeners.txt') ($listeners -join [Environment]::NewLine)
    if (Test-Path -LiteralPath $root) {
        $interesting = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^(gateway|watchdog|results|doctor|.*\.log)' -and $_.Length -le 1048576
        } | Select-Object -First 30
        foreach ($file in $interesting) {
            $relative = [IO.Path]::GetRelativePath($root, $file.FullName) -replace '[\\/:*?"<>|]', '_'
            Write-BoundedText (Join-Path $destination $relative) ([IO.File]::ReadAllText($file.FullName))
        }
    }
}

function Invoke-Cleanup {
    $root = Assert-SafeStateRoot $StateRoot
    # This operation normally runs in a new workflow step, where process-level
    # profile variables from the acceptance step no longer exist. Never invoke
    # a discovered gateway with the runner's default profile; terminate only
    # processes whose command line proves they belong to this isolated root.
    Stop-StateProcesses $root
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
    if (@(Get-StateProcesses $root).Count -ne 0) { throw 'isolated processes remain after cleanup' }
}

function Invoke-SelfTest {
    Assert-NativeWindowsX64
    $root = Assert-SafeStateRoot $StateRoot
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = $root
    $originalProfile = $env:USERPROFILE
    $profile = Initialize-IsolatedProfile $root
    foreach ($name in @(
        'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
        'DEFENSECLAW_HOME', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'HERMES_HOME',
        'ZEPTOCLAW_HOME', 'OPENCODE_CONFIG_DIR', 'OMNIGENT_CONFIG_HOME',
        'XDG_CONFIG_HOME', 'UV_CACHE_DIR', 'PIP_CACHE_DIR', 'NPM_CONFIG_CACHE',
        'GIT_CONFIG_GLOBAL'
    )) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not $value -or -not (Test-PathWithin $value $root)) { throw "$name is not isolated below StateRoot: $value" }
    }
    $driveHome = [IO.Path]::GetFullPath("$env:HOMEDRIVE$env:HOMEPATH")
    if (-not $driveHome.Equals([IO.Path]::GetFullPath($profile.Profile), [StringComparison]::OrdinalIgnoreCase)) {
        throw "HOMEDRIVE/HOMEPATH do not resolve to the isolated profile: $driveHome"
    }
    if ($originalProfile) {
        foreach ($entry in ($env:PATH -split ';')) {
            if ($entry -and (Test-PathWithin $entry $originalProfile) -and -not (Test-PathWithin $entry $root)) {
                throw "isolated PATH contains the original runner profile: $entry"
            }
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'tools\uv.exe') -PathType Leaf)) { throw 'uv was not isolated' }
    Write-Host "Isolated profile self-test passed: $($profile.Profile)"
}

if (-not $NoRun) {
    switch ($Operation) {
        'stage-package-data' { Stage-PackageData (Join-Path $WorkspaceRoot 'cli\defenseclaw') }
        'build-artifacts' { Invoke-BuildArtifacts }
        'acceptance' { Invoke-Acceptance }
        'contract' { Invoke-Contract }
        'capture' { Invoke-Capture }
        'cleanup' { Invoke-Cleanup }
        'self-test' { Invoke-SelfTest }
    }
}
