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

function Assert-NoReparseAncestors([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $drive = [IO.Path]::GetPathRoot($full)
    $cursor = $drive
    foreach ($segment in $full.Substring($drive.Length).Split(
        [char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries
    )) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Disposable path traverses a reparse point: $cursor"
        }
    }
    return $full
}

function Assert-NoReparseTree([string]$Path) {
    $full = Assert-NoReparseAncestors $Path
    if (-not (Test-Path -LiteralPath $full)) { return $full }
    foreach ($item in @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Disposable tree contains a reparse point: $($item.FullName)"
        }
        if ($item.PSIsContainer) { $null = Assert-NoReparseTree $item.FullName }
    }
    return $full
}

function Remove-SafeDisposableTree([string]$Path, [string]$Root = $Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -and
        -not (Test-PathWithin $full $rootFull)) {
        throw "Disposable cleanup path escaped its verified root: $full"
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    if ($full.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -and
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Disposable cleanup root must not be a reparse point: $full"
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if ($item.PSIsContainer) { [IO.Directory]::Delete($full) }
        else { [IO.File]::Delete($full) }
        return
    }
    if (-not $item.PSIsContainer) {
        Remove-Item -LiteralPath $full -Force -ErrorAction Stop
        return
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop)) {
        Remove-SafeDisposableTree -Path $child.FullName -Root $rootFull
    }
    Remove-Item -LiteralPath $full -Force -ErrorAction Stop
}

function Assert-SafeStateRoot([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $explicitBase = [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT')
    $allowedRoots = @(
        [Environment]::GetEnvironmentVariable('RUNNER_TEMP'),
        $explicitBase,
        [IO.Path]::GetTempPath()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $equalsExplicitBase = -not [string]::IsNullOrWhiteSpace($explicitBase) -and
        $full.Equals(
            [IO.Path]::GetFullPath($explicitBase).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )
    if (-not $equalsExplicitBase -and
        -not ($allowedRoots | Where-Object { Test-PathWithin $full $_ } | Select-Object -First 1)) {
        throw "StateRoot must be a child of RUNNER_TEMP or the system temp directory: $full"
    }
    foreach ($protected in @($WorkspaceRoot, $env:USERPROFILE, [IO.Path]::GetTempPath())) {
        if (-not [string]::IsNullOrWhiteSpace($protected) -and
            $full.Equals([IO.Path]::GetFullPath($protected).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "StateRoot must not equal a workspace, profile, or temp root: $full"
        }
    }
    return Assert-NoReparseAncestors $full
}

function Limit-WindowsNativeText([AllowNull()][string]$Text, [int]$MaxBytes = 1048576) {
    $safe = Protect-WindowsNativeText $Text
    $bytes = [Text.Encoding]::UTF8.GetBytes($safe)
    if ($bytes.Length -le $MaxBytes) { return $safe }
    return [Text.Encoding]::UTF8.GetString($bytes, 0, $MaxBytes) + "`n[truncated]`n"
}

function Write-BoundedText([string]$Path, [AllowNull()][string]$Text, [int]$MaxBytes = 1048576) {
    $safe = Limit-WindowsNativeText $Text $MaxBytes
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
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
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
    $stdout = Limit-WindowsNativeText $stdoutTask.GetAwaiter().GetResult()
    $stderr = Limit-WindowsNativeText $stderrTask.GetAwaiter().GetResult()
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
    if (Test-Path -LiteralPath $Destination) {
        Remove-SafeDisposableTree -Path $Destination -Root $Destination
    }
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
    if (Test-Path -LiteralPath $data) {
        Remove-SafeDisposableTree -Path $data -Root $data
    }
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
    $dist = Assert-SafeStateRoot $ArtifactRoot
    [IO.Directory]::CreateDirectory($root) | Out-Null
    if (Test-Path -LiteralPath $dist) {
        Remove-SafeDisposableTree -Path $dist -Root $dist
    }
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
    if (Test-Path -LiteralPath $packageStage) {
        Remove-SafeDisposableTree -Path $packageStage -Root $root
    }
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
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $safeRoot 'cache\uv-python'
    $env:UV_TOOL_DIR = Join-Path $safeRoot 'cache\uv-tools'
    $env:UV_TOOL_BIN_DIR = Join-Path $safeRoot 'tools\uv-bin'
    $env:PIP_CACHE_DIR = Join-Path $safeRoot 'cache\pip'
    $env:NPM_CONFIG_CACHE = Join-Path $safeRoot 'cache\npm'
    $env:XDG_CACHE_HOME = Join-Path $safeRoot 'cache\xdg'
    $env:PYTHONPYCACHEPREFIX = Join-Path $safeRoot 'cache\pycache'
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
    return [pscustomobject]@{
        Root = $safeRoot
        Profile = $profile
        Bin = $bin
        VenvScripts = $venvScripts
        Temp = $temp
        Tools = $tools
    }
}

function Invoke-PackagedInstaller(
    [string]$Root,
    [string]$Artifacts,
    [int[]]$AllowedExitCodes = @(0),
    [string]$LogName = 'install.log'
) {
    $profile = Initialize-IsolatedProfile $Root
    if (-not (Test-Path -LiteralPath $Artifacts -PathType Container)) { throw "artifact directory missing: $Artifacts" }
    $pwsh = (Get-Process -Id $PID).Path
    $install = Join-Path $WorkspaceRoot 'scripts\install.ps1'
    $userPathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')
    $result = Invoke-WindowsNativeProcess $pwsh @(
        '-NoLogo', '-NoProfile', '-File', $install, '-Local', ([IO.Path]::GetFullPath($Artifacts)),
        '-Connector', 'none', '-Yes', '-NoPersistPath'
    ) -AllowedExitCodes $AllowedExitCodes -TimeoutSeconds 1800 `
        -LogPath (Join-Path $Root "logs\$LogName")
    $userPathAfter = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not [string]::Equals($userPathBefore, $userPathAfter, [StringComparison]::Ordinal)) {
        throw 'packaged install mutated the runner user PATH despite -NoPersistPath'
    }
    return [pscustomobject]@{ Profile = $profile; Result = $result }
}

function Install-PackagedArtifacts(
    [string]$Root,
    [string]$Artifacts,
    [string]$LogName = 'install.log'
) {
    $invocation = Invoke-PackagedInstaller -Root $Root -Artifacts $Artifacts -LogName $LogName
    $profile = $invocation.Profile
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

function Invoke-Installed(
    [string]$Executable,
    [string[]]$Arguments,
    [int[]]$Allowed = @(0),
    [int]$Timeout = 300,
    [string]$Log = '',
    [string]$WorkingDirectory = ''
) {
    $file = $Executable
    $args = $Arguments
    if ([IO.Path]::GetExtension($Executable).Equals('.cmd', [StringComparison]::OrdinalIgnoreCase)) {
        $file = $env:ComSpec
        $args = @('/d', '/c', $Executable) + $Arguments
    }
    return Invoke-WindowsNativeProcess -FilePath $file -ArgumentList $args `
        -AllowedExitCodes $Allowed -TimeoutSeconds $Timeout -LogPath $Log `
        -WorkingDirectory $WorkingDirectory
}

function Assert-ManagedImports([string]$Python, [string]$VenvRoot) {
    $code = @'
import importlib
import pathlib
import shutil
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
scripts = venv / 'Scripts'
for command in ('defenseclaw', 'skill-scanner', 'mcp-scanner'):
    resolved = shutil.which(command, path=str(scripts))
    if not resolved:
        raise SystemExit(f'missing managed console entry point: {command}')
    location = pathlib.Path(resolved).resolve()
    if scripts != location.parent:
        raise SystemExit(f'{command} resolved outside managed Scripts: {location}')
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

function Assert-PackagedDoctorSmoke([string]$CliShim, [string]$Logs) {
    # An initialized-but-stopped profile is intentionally unhealthy: doctor
    # reports the unavailable gateway and missing live hook with exit code 1.
    # The smoke contract is valid bounded JSON and truthful exit semantics,
    # not an artificially green result before lifecycle acceptance starts it.
    $doctor = Invoke-Installed $CliShim @('doctor', '--json-output') @(0, 1) 300 `
        (Join-Path $Logs 'doctor.json')
    try { $report = $doctor.StdOut | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "packaged doctor did not emit valid JSON: $($_.Exception.Message)" }
    if ($null -eq $report.checks -or @($report.checks).Count -eq 0) {
        throw 'packaged doctor emitted no health checks'
    }
    if (($doctor.ExitCode -eq 0) -ne ([int]$report.failed -eq 0)) {
        throw 'packaged doctor exit code disagrees with its failed-check count'
    }
}

function Get-GatewayIdentity([string]$DataDir) {
    $pidFile = Join-Path $DataDir 'gateway.pid'
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
        throw "managed gateway PID file is missing: $pidFile"
    }
    $record = Get-Content -LiteralPath $pidFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $processId = 0
    if (-not [int]::TryParse([string]$record.pid, [ref]$processId) -or $processId -le 0) {
        throw "managed gateway PID record is invalid: $pidFile"
    }
    if ($null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        throw "managed gateway process is not running: $processId"
    }
    return [pscustomobject]@{
        ProcessId = $processId
        StartIdentity = [string]$record.start_identity
        Executable = [IO.Path]::GetFullPath([string]$record.executable)
    }
}

function Test-GatewayIdentityChanged([object]$Before, [object]$After) {
    return $Before.ProcessId -ne $After.ProcessId -or
        $Before.StartIdentity -ne $After.StartIdentity
}

function Assert-ManagedDistributionIntegrity([string]$Python, [string]$VenvRoot) {
    $code = @'
import importlib.metadata as metadata
import pathlib
import re
import sys

site = pathlib.Path(sys.argv[1]).resolve() / 'Lib' / 'site-packages'
projects = {}
for distribution in metadata.distributions(path=[str(site)]):
    name = distribution.metadata.get('Name')
    if not name:
        raise SystemExit(f'distribution without Name metadata: {distribution.locate_file("")}')
    normalized = re.sub(r'[-_.]+', '-', name).lower()
    projects.setdefault(normalized, []).append(str(distribution.locate_file('')))
duplicates = {name: paths for name, paths in projects.items() if len(paths) != 1}
if duplicates:
    raise SystemExit(f'duplicate distributions remain: {duplicates}')
if len(projects.get('defenseclaw', ())) != 1:
    raise SystemExit('expected exactly one DefenseClaw distribution')
print(f'validated {len(projects)} unique managed distributions')
'@
    Invoke-Installed $Python @('-I', '-c', $code, $VenvRoot) -Timeout 120 | Out-Null
}

function Add-DamagedManagedEnvironmentFixture([object]$Profile) {
    $venvRoot = Split-Path -Parent $Profile.VenvScripts
    $sitePackages = Join-Path $venvRoot 'Lib\site-packages'
    $defenseClawMetadata = @(Get-ChildItem -LiteralPath $sitePackages `
        -Directory -Filter 'defenseclaw-*.dist-info')
    if ($defenseClawMetadata.Count -ne 1) {
        throw "expected one DefenseClaw metadata directory before corruption; found $($defenseClawMetadata.Count)"
    }
    $duplicate = Join-Path $sitePackages 'defenseclaw-duplicate.dist-info'
    Copy-Tree -Source $defenseClawMetadata[0].FullName -Destination $duplicate
    Remove-Item -LiteralPath (Join-Path $duplicate 'RECORD') -Force -ErrorAction Stop

    $certifiMetadata = @(Get-ChildItem -LiteralPath $sitePackages `
        -Directory -Filter 'certifi-*.dist-info')
    if ($certifiMetadata.Count -ne 1) {
        throw "expected one certifi metadata directory before corruption; found $($certifiMetadata.Count)"
    }
    Remove-Item -LiteralPath (Join-Path $certifiMetadata[0].FullName 'RECORD') `
        -Force -ErrorAction Stop
    Remove-Item -LiteralPath (Join-Path $sitePackages 'certifi\core.py') `
        -Force -ErrorAction Stop

    $python = Join-Path $Profile.VenvScripts 'python.exe'
    $broken = Invoke-Installed $python @('-I', '-c', 'from certifi import where; where()') @(1) 30
    if ($broken.ExitCode -eq 0) { throw 'damaged managed-environment fixture remained importable' }
}

function Assert-ResetAcceptance([object]$Profile, [string]$Root, [string]$Logs) {
    $cliShim = Join-Path $Profile.Bin 'defenseclaw.cmd'
    $python = Join-Path $Profile.VenvScripts 'python.exe'
    $runtimeHash = (Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash
    $savedIoEncoding = [Environment]::GetEnvironmentVariable('PYTHONIOENCODING')
    try {
        $env:PYTHONIOENCODING = 'cp1252'
        $reset = Invoke-Installed $cliShim @('reset', '--yes') @(0) 300 `
            (Join-Path $Logs 'reset-first.log') $WorkspaceRoot
    } finally {
        if ($null -eq $savedIoEncoding) { Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue }
        else { $env:PYTHONIOENCODING = $savedIoEncoding }
    }
    $resetText = $reset.StdOut + "`n" + $reset.StdErr
    if ($resetText -notmatch 'Reset complete' -or $resetText -notmatch '✓' -or
        $resetText.Contains([char]0xfffd)) {
        throw 'packaged reset did not emit intact UTF-8 success output'
    }
    if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
        (Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash -ne $runtimeHash) {
        throw 'packaged reset did not preserve the loaded managed runtime'
    }
    $remaining = @(Get-ChildItem -LiteralPath $env:DEFENSECLAW_HOME -Force | Select-Object -ExpandProperty Name)
    if ($remaining.Count -ne 1 -or $remaining[0] -ne '.venv') {
        throw "packaged reset left unexpected state: $($remaining -join ', ')"
    }
    Invoke-Installed $cliShim @('--version') -WorkingDirectory $WorkspaceRoot | Out-Null
    $status = Invoke-Installed $cliShim @('status') @(1) 60 (Join-Path $Logs 'reset-status.log')
    if ($status.ExitCode -eq 0) { throw 'status succeeded after reset removed configuration' }
    Invoke-Installed $cliShim @('reset', '--yes') @(0) 300 `
        (Join-Path $Logs 'reset-second.log') $WorkspaceRoot | Out-Null

    $fixtureRoot = Join-Path $Root 'fixtures\reset-reparse'
    $target = Join-Path $fixtureRoot 'target'
    $junction = Join-Path $fixtureRoot 'managed-home-junction'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    Write-BoundedText (Join-Path $target 'audit.db') 'preserve outside reset root'
    if (Test-Path -LiteralPath $junction) { throw "reset junction fixture already exists: $junction" }
    New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
    $savedHome = $env:DEFENSECLAW_HOME
    try {
        $env:DEFENSECLAW_HOME = $junction
        $failed = Invoke-Installed $cliShim @('reset', '--yes') @(1) 60 `
            (Join-Path $Logs 'reset-failure.log') $WorkspaceRoot
        $failedText = $failed.StdOut + "`n" + $failed.StdErr
        if ($failed.ExitCode -eq 0 -or $failedText -match 'Reset complete' -or
            $failedText.Contains([char]0xfffd)) {
            throw 'failed reset returned success, printed false completion, or emitted invalid UTF-8'
        }
    } finally {
        $env:DEFENSECLAW_HOME = $savedHome
        if (Test-Path -LiteralPath $junction) {
            Remove-SafeDisposableTree -Path $junction -Root $fixtureRoot
        }
    }
    if ((Get-Content -LiteralPath (Join-Path $target 'audit.db') -Raw).Trim() -ne
        'preserve outside reset root') {
        throw 'reset traversed a junction fixture'
    }
}

function Set-PermissiveFixtureDacl([string]$Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $owner, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $everyone, [Security.AccessControl.FileSystemRights]::Modify, $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-PackagedDaclAcceptance([string]$Python, [string]$Root) {
    $exportRoot = Join-Path $Root 'profile\Packaged DACL 雪'
    Set-PermissiveFixtureDacl $exportRoot
    $code = @'
import pathlib
import sys

from defenseclaw.file_permissions import windows_acl_write_error
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.tui_state import TUIState, TUIStateStore

root = pathlib.Path(sys.argv[1]).resolve()
before = windows_acl_write_error(root)
if before is None:
    raise SystemExit('DACL fixture was not permissive before packaged writes')
store = TUIStateStore(root)
if not store.save(TUIState(palette_mru=('doctor',))):
    raise SystemExit('packaged TUI state save failed')
app = DefenseClawTUI(data_dir=root)
audit = app._export_audit(pathlib.Path('packaged-audit-export.json'))
for path in (root, store.path, audit):
    problem = windows_acl_write_error(path)
    if problem is not None:
        raise SystemExit(f'unsafe packaged DACL for {path}: {problem}')
print('packaged TUI state and audit export DACLs are private')
'@
    Invoke-Installed $Python @('-I', '-c', $code, $exportRoot) -Timeout 120 | Out-Null
}

function Set-MinimalGatewayAcceptanceConfig([string]$Python) {
    # Installer lifecycle acceptance needs a real managed daemon, but it does
    # not need to wait for connector scanners or the guardrail proxy. Those
    # subsystems have their own required Windows suites and can make startup
    # depend on unrelated host inventory.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        $apiPort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
    $code = @'
import sys
from defenseclaw.config import load

cfg = load()
cfg.guardrail.enabled = False
cfg.gateway.watcher.enabled = False
cfg.gateway.api_port = int(sys.argv[1])
cfg.save()
print(f'packaged gateway fixture uses isolated API port {cfg.gateway.api_port}')
'@
    Invoke-Installed $Python @('-I', '-c', $code, $apiPort) -Timeout 60 | Out-Null
}

function Wait-PathsAbsent([string[]]$Paths, [int]$Attempts = 150) {
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $remaining = @($Paths | Where-Object { Test-Path -LiteralPath $_ })
        if ($remaining.Count -eq 0) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for removal: $($remaining -join ', ')"
}

function Wait-UninstallCompletion([string[]]$Paths, [string]$ResultPath, [int]$Attempts = 1800) {
    # A full managed venv can take longer than 20 seconds to remove on a busy
    # Windows filesystem. Keep this bounded, but allow the native deferred
    # helper enough time to finish before diagnosing a lifecycle failure.
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $remaining = @($Paths | Where-Object { Test-Path -LiteralPath $_ })
        if ($remaining.Count -eq 0 -and
            (Test-Path -LiteralPath $ResultPath -PathType Leaf)) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for deferred uninstall completion: $($remaining -join ', ')"
}

function New-RollbackArtifactFixture([string]$Artifacts, [string]$Root) {
    $fixtureRoot = Join-Path $Root 'fixtures\rollback-artifacts'
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-SafeDisposableTree -Path $fixtureRoot -Root $Root
    }
    Copy-Tree -Source $Artifacts -Destination $fixtureRoot
    $zip = @(Get-ChildItem -LiteralPath $fixtureRoot `
        -File -Filter 'defenseclaw_*_windows_amd64.zip')
    if ($zip.Count -ne 1) { throw "expected one Windows artifact zip; found $($zip.Count)" }
    $expanded = Join-Path $fixtureRoot 'expanded'
    Expand-Archive -LiteralPath $zip[0].FullName -DestinationPath $expanded
    $gateway = Join-Path $expanded 'defenseclaw.exe'
    $hook = Join-Path $expanded 'defenseclaw-hook.exe'
    $stream = [IO.File]::Open(
        $gateway, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read
    )
    try { $stream.WriteByte(10) } finally { $stream.Dispose() }
    $mutatedHash = (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    Invoke-WindowsNativeProcess $gateway @('--version') -TimeoutSeconds 30 | Out-Null
    Remove-Item -LiteralPath $zip[0].FullName -Force
    Compress-Archive -LiteralPath $gateway, $hook -DestinationPath $zip[0].FullName
    Remove-SafeDisposableTree -Path $expanded -Root $fixtureRoot
    return [pscustomobject]@{ Root = $fixtureRoot; MutatedGatewayHash = $mutatedHash }
}

function Assert-PackagedRepairAcceptance(
    [object]$Profile,
    [string]$Root,
    [string]$Artifacts,
    [string]$Logs
) {
    Add-DamagedManagedEnvironmentFixture $Profile
    $savedPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH')
    try {
        $env:PYTHONPATH = $WorkspaceRoot
        $Profile = Install-PackagedArtifacts $Root $Artifacts 'damaged-venv-repair-install.log'
    } finally {
        if ($null -eq $savedPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
        else { $env:PYTHONPATH = $savedPythonPath }
    }
    $python = Join-Path $Profile.VenvScripts 'python.exe'
    $venvRoot = Split-Path -Parent $Profile.VenvScripts
    $uv = Join-Path $Root 'tools\uv.exe'
    Invoke-Installed $uv @('pip', 'check', '--python', $python) -Timeout 300 `
        -Log (Join-Path $Logs 'damaged-venv-repair-pip-check.log') | Out-Null
    Assert-ManagedDistributionIntegrity $python $venvRoot
    Assert-ManagedImports $python $venvRoot
    return $Profile
}

function Assert-RunningReinstallAcceptance(
    [object]$Profile,
    [string]$Root,
    [string]$Artifacts,
    [string]$Logs
) {
    $gateway = Join-Path $Profile.Bin 'defenseclaw-gateway.exe'
    $before = Get-GatewayIdentity $env:DEFENSECLAW_HOME
    $Profile = Install-PackagedArtifacts $Root $Artifacts 'running-gateway-reinstall.log'
    $after = Get-GatewayIdentity $env:DEFENSECLAW_HOME
    if (-not (Test-GatewayIdentityChanged $before $after)) {
        throw 'running packaged reinstall did not replace the managed gateway process'
    }
    if (-not $after.Executable.Equals(
        [IO.Path]::GetFullPath($gateway), [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "restarted gateway uses an unexpected executable: $($after.Executable)"
    }
    Invoke-Installed $gateway @('status') -Timeout 30 `
        -Log (Join-Path $Logs 'running-reinstall-status.log') | Out-Null
    $python = Join-Path $Profile.VenvScripts 'python.exe'
    $venvRoot = Split-Path -Parent $Profile.VenvScripts
    $uv = Join-Path $Root 'tools\uv.exe'
    Invoke-Installed $uv @('pip', 'check', '--python', $python) -Timeout 300 `
        -Log (Join-Path $Logs 'running-reinstall-pip-check.log') | Out-Null
    Assert-ManagedDistributionIntegrity $python $venvRoot
    Assert-ManagedImports $python $venvRoot
    return $Profile
}

function Assert-TransactionalRollbackAcceptance(
    [object]$Profile,
    [string]$Root,
    [string]$Artifacts,
    [string]$Logs
) {
    $gateway = Join-Path $Profile.Bin 'defenseclaw-gateway.exe'
    $hook = Join-Path $Profile.Bin 'defenseclaw-hook.exe'
    $shim = Join-Path $Profile.Bin 'defenseclaw.cmd'
    $python = Join-Path $Profile.VenvScripts 'python.exe'
    $before = Get-GatewayIdentity $env:DEFENSECLAW_HOME
    $hashes = @{}
    foreach ($path in @($gateway, $hook, $shim, $python)) {
        $hashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    $fixture = New-RollbackArtifactFixture $Artifacts $Root
    if ($fixture.MutatedGatewayHash -eq $hashes[$gateway]) {
        throw 'rollback fixture did not change the staged gateway identity'
    }

    # Read sharing permits the transaction backup, while deliberately denying
    # the delete share required by MoveFileEx during paired hook replacement.
    $lock = [IO.File]::Open(
        $hook, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $failed = Invoke-PackagedInstaller -Root $Root -Artifacts $fixture.Root `
            -AllowedExitCodes @(1) -LogName 'rollback-install-failure.log'
    } finally {
        $lock.Dispose()
    }
    $failureText = $failed.Result.StdOut + "`n" + $failed.Result.StdErr
    if ($failed.Result.ExitCode -eq 0 -or
        $failureText -match 'DefenseClaw installed successfully') {
        throw 'failed paired replacement returned success or printed a false success banner'
    }
    foreach ($path in @($gateway, $hook, $shim, $python)) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hashes[$path]) {
            throw "paired replacement rollback did not restore: $path"
        }
    }
    $after = Get-GatewayIdentity $env:DEFENSECLAW_HOME
    if (-not (Test-GatewayIdentityChanged $before $after)) {
        throw 'rollback did not restart the prior managed gateway'
    }
    Invoke-Installed $gateway @('status') -Timeout 30 `
        -Log (Join-Path $Logs 'rollback-restarted-status.log') | Out-Null
    if (@(Get-ChildItem -LiteralPath $env:DEFENSECLAW_HOME `
        -Directory -Filter '.install-backup.*').Count -ne 0) {
        throw 'paired replacement rollback left a recovery backup behind'
    }
}

function Invoke-FullUninstallCycle(
    [object]$Profile,
    [string]$Root,
    [string]$Logs,
    [string]$Label
) {
    $cliShim = Join-Path $Profile.Bin 'defenseclaw.cmd'
    $sentinel = Join-Path $Profile.Bin 'unrelated.txt'
    Write-BoundedText $sentinel 'preserve'
    $uninstall = Invoke-Installed $cliShim @('uninstall', '--all', '--binaries', '--yes') `
        @(0) 300 (Join-Path $Logs "$Label-uninstall.log") $WorkspaceRoot
    $uninstallText = $uninstall.StdOut + "`n" + $uninstall.StdErr
    $resultMatch = [regex]::Match($uninstallText, 'result:\s+([^\)]+\.json)')
    if (-not $resultMatch.Success -or $uninstallText -notmatch 'deferred cleanup:\s+scheduled') {
        throw 'full uninstall did not report scheduled deferred cleanup and its result path'
    }
    $resultPath = [IO.Path]::GetFullPath($resultMatch.Groups[1].Value.Trim())
    if (-not (Test-PathWithin $resultPath $Root)) {
        throw "uninstall result escaped disposable state: $resultPath"
    }
    $removed = @(
        (Join-Path $Profile.Bin 'defenseclaw.cmd'),
        (Join-Path $Profile.Bin 'defenseclaw-gateway.exe'),
        (Join-Path $Profile.Bin 'defenseclaw-hook.exe'),
        $env:DEFENSECLAW_HOME
    )
    Wait-UninstallCompletion $removed $resultPath
    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($result.status -ne 'succeeded') { throw "uninstall helper failed: $($result.detail)" }
    Remove-Item -LiteralPath $resultPath -Force
    if ((Get-Content -LiteralPath $sentinel -Raw).Trim() -ne 'preserve') {
        throw 'uninstall modified unrelated install-root content'
    }
    if (@($removed | Where-Object { Test-Path -LiteralPath $_ }).Count -ne 0) {
        throw 'deferred uninstall left product-owned runtime artifacts'
    }
}

function Invoke-InstallerAcceptance([string]$Root, [string]$Artifacts) {
    $root = Assert-SafeStateRoot $Root
    $artifacts = [IO.Path]::GetFullPath($Artifacts)
    $seedProfile = Initialize-IsolatedProfile $root
    [IO.Directory]::CreateDirectory($seedProfile.Bin) | Out-Null
    Write-BoundedText (Join-Path $seedProfile.Bin 'defenseclaw.exe') `
        'stale source-checkout launcher; never execute'
    $profile = Install-PackagedArtifacts $root $artifacts 'fresh-install.log'
    $cliShim = Join-Path $profile.Bin 'defenseclaw.cmd'
    $gateway = Join-Path $profile.Bin 'defenseclaw-gateway.exe'
    $python = Join-Path $profile.VenvScripts 'python.exe'
    $venvRoot = Split-Path -Parent $profile.VenvScripts
    $uv = Join-Path $root 'tools\uv.exe'
    $logs = Join-Path $root 'logs'

    if (Test-Path -LiteralPath (Join-Path $profile.Bin 'defenseclaw.exe')) {
        throw 'packaged install did not remove a stale shadowing CLI executable'
    }
    $resolvedCli = @(Get-Command defenseclaw -CommandType Application -ErrorAction Stop)[0].Source
    if (-not [IO.Path]::GetFullPath($resolvedCli).Equals(
        [IO.Path]::GetFullPath($cliShim), [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "unqualified DefenseClaw command resolved outside the packaged shim: $resolvedCli"
    }
    $env:PYTHONPATH = $WorkspaceRoot
    try {
        Invoke-Installed $cliShim @('--version') -Log (Join-Path $logs 'version.log') `
            -WorkingDirectory $WorkspaceRoot | Out-Null
    } finally { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
    Invoke-Installed $uv @('pip', 'check', '--python', $python) -Timeout 300 -Log (Join-Path $logs 'uv-pip-check.log') | Out-Null
    Assert-ManagedImports $python $venvRoot
    Assert-ManagedDistributionIntegrity $python $venvRoot
    Assert-PackagedDaclAcceptance $python $root
    Invoke-Installed $cliShim @(
        'init', '--skip-install', '--non-interactive', '--yes', '--connector', 'codex',
        '--profile', 'observe', '--no-start-gateway', '--no-verify'
    ) -Timeout 300 -Log (Join-Path $logs 'init.log') | Out-Null
    Assert-PackagedDoctorSmoke $cliShim $logs

    $skill = Join-Path $root 'clean-skill'
    [IO.Directory]::CreateDirectory($skill) | Out-Null
    Write-BoundedText (Join-Path $skill 'SKILL.md') "---`nname: windows-native-smoke`ndescription: Prints a friendly greeting.`n---`n`nUse this skill to print a friendly greeting.`n"
    Write-BoundedText (Join-Path $skill 'skill.yaml') "name: windows-native-smoke`ndescription: Prints a friendly greeting.`nversion: 1.0.0`n"
    Invoke-Installed $cliShim @('skill', 'scan', $skill, '--no-use-llm', '--json') -Timeout 300 -Log (Join-Path $logs 'skill-scan.json') | Out-Null
    Invoke-Installed $cliShim @('mcp', 'scan', '--all', '--json') -Timeout 300 -Log (Join-Path $logs 'mcp-scan.json') | Out-Null
    Invoke-HeadlessTui $python

    Assert-ResetAcceptance $profile $root $logs
    $profile = Assert-PackagedRepairAcceptance $profile $root $artifacts $logs
    Invoke-FullUninstallCycle $profile $root $logs 'first'

    $profile = Install-PackagedArtifacts $root $artifacts 'first-reinstall.log'
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw.cmd') @('--version') | Out-Null
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw-gateway.exe') @('--version') | Out-Null
    Invoke-FullUninstallCycle $profile $root $logs 'second'

    $profile = Install-PackagedArtifacts $root $artifacts 'final-reinstall.log'
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw.cmd') @('--version') | Out-Null
    Invoke-Installed (Join-Path $profile.Bin 'defenseclaw-gateway.exe') @('--version') | Out-Null
    return $profile
}

function Invoke-GatewayLifecycleAcceptance(
    [object]$Profile,
    [string]$Root,
    [string]$Artifacts
) {
    $root = Assert-SafeStateRoot $Root
    $artifacts = [IO.Path]::GetFullPath($Artifacts)
    $logs = Join-Path $root 'logs'
    $cliShim = Join-Path $Profile.Bin 'defenseclaw.cmd'
    $gateway = Join-Path $Profile.Bin 'defenseclaw-gateway.exe'
    $python = Join-Path $Profile.VenvScripts 'python.exe'
    Invoke-Installed $cliShim @(
        'init', '--skip-install', '--non-interactive', '--yes', '--connector', 'codex',
        '--profile', 'observe', '--no-start-gateway', '--no-verify'
    ) -Timeout 300 -Log (Join-Path $logs 'gateway-lifecycle-init.log') | Out-Null
    Set-MinimalGatewayAcceptanceConfig $python
    Invoke-Installed $gateway @('start') -Timeout 90 `
        -Log (Join-Path $logs 'gateway-start.log') | Out-Null
    Invoke-Installed $gateway @('status') -Timeout 30 `
        -Log (Join-Path $logs 'gateway-status.log') | Out-Null

    $Profile = Assert-RunningReinstallAcceptance $Profile $root $artifacts $logs
    $gateway = Join-Path $Profile.Bin 'defenseclaw-gateway.exe'
    Assert-TransactionalRollbackAcceptance $Profile $root $artifacts $logs
    Invoke-Installed $gateway @('restart') -Timeout 90 `
        -Log (Join-Path $logs 'gateway-restart.log') | Out-Null
    Invoke-Installed $gateway @('status') -Timeout 30 | Out-Null
    Invoke-Installed $gateway @('stop') -Timeout 60 `
        -Log (Join-Path $logs 'gateway-stop.log') | Out-Null
    $stopped = Invoke-Installed $gateway @('status') @(1) 30 `
        (Join-Path $logs 'gateway-stopped-status.log')
    if ($stopped.ExitCode -eq 0) { throw 'gateway status returned success after stop' }
}

function Invoke-Acceptance {
    Assert-NativeWindowsX64
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for acceptance' }
    $root = Assert-SafeStateRoot $StateRoot
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = $root
    $artifacts = [IO.Path]::GetFullPath($ArtifactRoot)
    $profile = Invoke-InstallerAcceptance -Root $root -Artifacts $artifacts
    # Keep the adjacent lifecycle gate required and last: all installer-owned
    # regressions execute first, but a gateway readiness failure still fails
    # packaged acceptance instead of being skipped or treated as advisory.
    Invoke-GatewayLifecycleAcceptance -Profile $profile -Root $root -Artifacts $artifacts
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
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $excluded = [Collections.Generic.HashSet[int]]::new()
    $ancestorId = $PID
    while ($ancestorId -gt 0 -and $excluded.Add($ancestorId)) {
        $ancestor = Get-CimInstance Win32_Process -Filter "ProcessId=$ancestorId" `
            -ErrorAction SilentlyContinue
        if ($null -eq $ancestor) { break }
        $ancestorId = [int]$ancestor.ParentProcessId
    }
    $rootPattern = [regex]::Escape($full)
    $rootedCommandPattern = '(?i)(?:^|\s|")' + $rootPattern + '\\'
    $stateArgumentPattern = '(?i)-StateRoot\s+"?' + $rootPattern + '(?:\s|"|$)'
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        if ($excluded.Contains([int]$_.ProcessId)) { return $false }
        $executableInRoot = $_.ExecutablePath -and (Test-PathWithin $_.ExecutablePath $full)
        $rootedCommand = $_.CommandLine -and
            $_.CommandLine -match $rootedCommandPattern
        $explicitStateArgument = $_.CommandLine -and
            $_.CommandLine -match $stateArgumentPattern
        return $executableInRoot -or $rootedCommand -or $explicitStateArgument
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
    $destination = if ($DiagnosticsRoot) {
        Assert-SafeStateRoot $DiagnosticsRoot
    } else {
        Join-Path $root 'diagnostics'
    }
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
    if (Test-Path -LiteralPath $root) {
        $null = Assert-NoReparseAncestors $root
        Remove-SafeDisposableTree -Path $root -Root $root
    }
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
        'UV_PYTHON_INSTALL_DIR', 'UV_TOOL_DIR', 'UV_TOOL_BIN_DIR',
        'XDG_CACHE_HOME', 'PYTHONPYCACHEPREFIX', 'GIT_CONFIG_GLOBAL'
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

    $junctionTarget = Join-Path $root 'junction-target'
    $cleanupFixture = Join-Path $root 'cleanup-fixture'
    $junction = Join-Path $cleanupFixture 'junction'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    [IO.Directory]::CreateDirectory($cleanupFixture) | Out-Null
    Write-BoundedText (Join-Path $junctionTarget 'sentinel.txt') 'preserve'
    New-Item -ItemType Junction -Path $junction -Target $junctionTarget | Out-Null
    $reparseRejected = $false
    try { $null = Assert-NoReparseTree $root } catch { $reparseRejected = $true }
    if (-not $reparseRejected) { throw 'cleanup safety did not reject a disposable junction' }
    Remove-SafeDisposableTree -Path $cleanupFixture -Root $root
    if (Test-Path -LiteralPath $cleanupFixture) {
        throw 'safe disposable cleanup left its fixture tree behind'
    }
    if ((Get-Content -LiteralPath (Join-Path $junctionTarget 'sentinel.txt') -Raw).Trim() -ne 'preserve') {
        throw 'junction safety fixture traversed its target'
    }
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
