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
    [ValidateSet('stage-package-data', 'build-artifacts', 'build-installer', 'acceptance', 'setup-acceptance', 'contract', 'capture', 'cleanup', 'self-test')]
    [string]$Operation = 'self-test',
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) 'defenseclaw-windows-native-ci'),
    [string]$ArtifactRoot = '',
    [string]$DiagnosticsRoot = '',
    [ValidateSet('codex', 'claudecode')][string]$Connector = 'codex',
    [switch]$AllowCurrentUserSetupAcceptance,
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

function Set-CurrentUserAsDefaultOwner {
    # GitHub's elevated Windows runner token can use BUILTIN\Administrators as
    # its default owner even though processes run as the runner user. That
    # makes ordinary child-created test paths look foreign to the production
    # ownership checks. Normalize only this disposable CI process token; child
    # processes inherit it and create objects owned by the actual runner user.
    if ($null -eq ('DefenseClaw.WindowsNative.TokenOwner' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace DefenseClaw.WindowsNative {
    public static class TokenOwner {
        private const uint TokenQuery = 0x0008;
        private const uint TokenAdjustDefault = 0x0080;
        private const int TokenOwnerClass = 4;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(
            IntPtr token,
            int informationClass,
            IntPtr information,
            int informationLength
        );

        public static void SetCurrentUser() {
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            if (user == null) {
                throw new InvalidOperationException("Current Windows identity has no user SID");
            }
            byte[] sid = new byte[user.BinaryLength];
            user.GetBinaryForm(sid, 0);
            GCHandle pinnedSid = GCHandle.Alloc(sid, GCHandleType.Pinned);
            IntPtr owner = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr token = IntPtr.Zero;
            try {
                Marshal.WriteIntPtr(owner, pinnedSid.AddrOfPinnedObject());
                if (!OpenProcessToken(
                    GetCurrentProcess(),
                    TokenQuery | TokenAdjustDefault,
                    out token
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (!SetTokenInformation(
                    token,
                    TokenOwnerClass,
                    owner,
                    IntPtr.Size
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                if (token != IntPtr.Zero) {
                    CloseHandle(token);
                }
                Marshal.FreeHGlobal(owner);
                pinnedSid.Free();
            }
        }
    }
}
'@
    }
    [DefenseClaw.WindowsNative.TokenOwner]::SetCurrentUser()
}

function Protect-TestDirectory([string]$Path) {
    $directory = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Path))
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { throw 'current Windows identity has no user SID' }

    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($identity.User)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    foreach ($sid in @($identity.User, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$security.AddAccessRule($rule)
    }
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}

function Initialize-WindowsNativeTestEnvironment([string]$Root) {
    Set-CurrentUserAsDefaultOwner
    $safeRoot = Assert-SafeStateRoot $Root
    Protect-TestDirectory $safeRoot
    $temp = Join-Path $safeRoot 'temp'
    Protect-TestDirectory $temp
    $env:TEMP = $temp
    $env:TMP = $temp
    return $safeRoot
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
        [ValidateRange(1, 4200)][int]$TimeoutSeconds = 600,
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
    $uv = Get-RequiredCommand 'uv.exe'
    Invoke-WindowsNativeProcess $uv @(
        'run', '--no-project', '--python', '3.12', 'python',
        'scripts/gen_envvars_docs.py', '--bundle-only'
    ) `
        -TimeoutSeconds 120 -WorkingDirectory $WorkspaceRoot | Out-Null
    Copy-MatchedFiles (Join-Path $WorkspaceRoot 'policies\rego\*.rego') (Join-Path $data 'policies\rego') '*_test.rego'
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'policies\rego\data.json') -Destination (Join-Path $data 'policies\rego') -Force
    Copy-MatchedFiles (Join-Path $WorkspaceRoot 'policies\*.yaml') (Join-Path $data 'policies')
    Copy-Tree (Join-Path $WorkspaceRoot 'policies\openshell') (Join-Path $data 'policies\openshell')
    foreach ($name in @('default', 'strict', 'permissive')) {
        Copy-Tree (Join-Path $WorkspaceRoot "policies\guardrail\$name") (Join-Path $data "policies\guardrail\$name")
    }
    [IO.Directory]::CreateDirectory((Join-Path $data 'envvars')) | Out-Null
    $generatedRegistry = Join-Path $WorkspaceRoot 'cli\defenseclaw\_data\envvars\registry.json'
    $targetRegistry = Join-Path $data 'envvars\registry.json'
    if (-not ([IO.Path]::GetFullPath($generatedRegistry)).Equals(
        [IO.Path]::GetFullPath($targetRegistry),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        Copy-Item -LiteralPath $generatedRegistry -Destination $targetRegistry -Force
    }
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
    $projectText = Get-Content -LiteralPath (Join-Path $WorkspaceRoot 'pyproject.toml') -Raw -Encoding UTF8
    if ($projectText -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw 'Could not resolve project version from pyproject.toml'
    }
    $packageVersion = $Matches[1]
    if ($packageVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9_.-]+)?$') {
        throw "Invalid package version for Windows artifacts: $packageVersion"
    }
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
        Invoke-WindowsNativeProcess $go @('build', '-ldflags', "-s -w -X main.version=$packageVersion", '-o', (Join-Path $stage 'defenseclaw.exe'), './cmd/defenseclaw') -TimeoutSeconds 900 | Out-Null
        Invoke-WindowsNativeProcess $go @('build', '-ldflags', "-s -w -H=windowsgui -X main.version=$packageVersion", '-o', (Join-Path $stage 'defenseclaw-hook.exe'), './cmd/defenseclaw-hook') -TimeoutSeconds 900 | Out-Null
    } finally {
        if ($null -eq $previousCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
        else { $env:CGO_ENABLED = $previousCgo }
    }
    Compress-Archive -LiteralPath (Join-Path $stage 'defenseclaw.exe'), (Join-Path $stage 'defenseclaw-hook.exe') `
        -DestinationPath (Join-Path $dist "defenseclaw_${packageVersion}_windows_amd64.zip") -Force

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
            'defenseclaw/_data/llm/model_catalog.json',
            'defenseclaw/observability/local_splunk.py',
            'defenseclaw/_data/splunk_local_bridge/compose/docker-compose.local.yml',
            'defenseclaw/_data/splunk_local_bridge/splunk/default.yml',
            'defenseclaw/_data/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/app.conf',
            'defenseclaw/_data/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/lookups/dcso_risk_state_labels.csv',
            'defenseclaw/_data/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/lookups/dcso_severity_labels.csv'
        )) {
            if ($required -notin $entries) { throw "wheel is missing packaged runtime data: $required" }
        }
    } finally { $archive.Dispose() }
    Remove-Item -LiteralPath (Join-Path $dist '.gitignore') -Force -ErrorAction SilentlyContinue
}

function Invoke-BuildInstaller {
    Assert-NativeWindowsX64
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for build-installer' }
    $root = Assert-SafeStateRoot $StateRoot
    $artifacts = Assert-SafeStateRoot $ArtifactRoot
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $projectText = Get-Content -LiteralPath (Join-Path $WorkspaceRoot 'pyproject.toml') -Raw -Encoding UTF8
    if ($projectText -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw 'Could not resolve project version from pyproject.toml'
    }
    $version = $Matches[1]
    $uv = Get-RequiredCommand 'uv.exe'
    Invoke-WindowsNativeProcess $uv @(
        'run', '--frozen', 'python', (Join-Path $WorkspaceRoot 'scripts\generate-upgrade-manifest.py'),
        '--out', (Join-Path $artifacts 'upgrade-manifest.json')
    ) -TimeoutSeconds 120 | Out-Null
    & (Join-Path $WorkspaceRoot 'scripts\build-windows-installer.ps1') `
        -DistRoot $artifacts -OutRoot $artifacts -StateRoot (Join-Path $root 'installer-build') `
        -DistributionFlavor 'oss' `
        -SkipSigning
}

function Initialize-IsolatedProfile([string]$Root) {
    Set-CurrentUserAsDefaultOwner
    $safeRoot = Assert-SafeStateRoot $Root
    [IO.Directory]::CreateDirectory($safeRoot) | Out-Null
    $originalProfile = $env:USERPROFILE
    $profile = Join-Path $safeRoot 'profile'
    $temp = Join-Path $safeRoot 'temp'
    $tools = Join-Path $safeRoot 'tools'
    foreach ($path in @($profile, $temp, $tools, (Join-Path $profile 'AppData\Roaming'), (Join-Path $profile 'AppData\Local'))) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
        Protect-TestDirectory $path
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

function Get-ManagedProcessIdentity([string]$DataDir, [string]$PIDFileName) {
    $pidFile = Join-Path $DataDir $PIDFileName
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
        throw "managed process PID file is missing: $pidFile"
    }
    $record = Get-Content -LiteralPath $pidFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $processId = 0
    if (-not [int]::TryParse([string]$record.pid, [ref]$processId) -or $processId -le 0) {
        throw "managed process PID record is invalid: $pidFile"
    }
    if ($null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        throw "managed process is not running: $processId"
    }
    return [pscustomobject]@{
        ProcessId = $processId
        StartIdentity = [string]$record.start_identity
        Executable = [IO.Path]::GetFullPath([string]$record.executable)
    }
}

function Get-GatewayIdentity([string]$DataDir) {
    return Get-ManagedProcessIdentity $DataDir 'gateway.pid'
}

function Get-WatchdogIdentity([string]$DataDir) {
    return Get-ManagedProcessIdentity $DataDir 'watchdog.pid'
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

function Assert-PackagedAntigravityPlatformGate(
    [string]$Launcher,
    [string]$UserProfile,
    [string]$LogPath
) {
    $result = Invoke-Installed $Launcher @('setup', 'antigravity', '--yes', '--no-restart') `
        @(1) 300 $LogPath
    $combined = $result.StdOut + "`n" + $result.StdErr
    if ($combined -notmatch "connector 'antigravity' is not_certified on windows") {
        throw "packaged Antigravity setup did not enforce its Windows certification gate: $combined"
    }
    $hooksPath = Join-Path $UserProfile '.gemini\config\hooks.json'
    if (Test-Path -LiteralPath $hooksPath) {
        throw "not-certified Antigravity setup unexpectedly wrote hooks: $hooksPath"
    }
}

function New-WizardAgentFixtures([string]$Root) {
    $bin = Join-Path $Root 'wizard-agent-fixtures'
    Protect-TestDirectory $bin
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw "Windows .NET Framework compiler is unavailable: $compiler"
    }
    $fixtures = @(
        [pscustomobject]@{
            Name = 'codex.exe'
            ClassName = 'CodexVersionFixture'
            Version = 'codex-cli 0.124.0'
        },
        [pscustomobject]@{
            Name = 'claude.exe'
            ClassName = 'ClaudeVersionFixture'
            Version = 'claude 2.1.152'
        }
    )
    foreach ($fixture in $fixtures) {
        $path = Join-Path $bin $fixture.Name
        $sourcePath = Join-Path $bin ($fixture.ClassName + '.cs')
        $source = @"
using System;
public static class $($fixture.ClassName) {
    public static int Main(string[] arguments) {
        Console.WriteLine("$($fixture.Version)");
        return 0;
    }
}
"@
        Write-BoundedText $sourcePath $source
        try {
            Invoke-WindowsNativeProcess $compiler @(
                '/nologo', '/target:exe', "/out:$path", $sourcePath
            ) -TimeoutSeconds 60 | Out-Null
        } finally {
            Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "compatible connector fixture was not built: $path"
        }
    }
    return $bin
}

function Get-WizardConnectorSpecification([string]$ConnectorName, [string]$UserProfile) {
    if ($ConnectorName -eq 'codex') {
        return [pscustomobject]@{
            Connector = 'codex'
            OtherConnector = 'claudecode'
            HookScript = 'codex-hook.sh'
            OtherHookScript = 'claude-code-hook.sh'
            ConfigPath = Join-Path $UserProfile '.codex\config.toml'
            OtherConfigPath = Join-Path $UserProfile '.claude\settings.json'
            DoctorLabel = 'Codex hooks'
            OtherDoctorLabel = 'Claude Code hooks'
        }
    }
    if ($ConnectorName -eq 'claudecode') {
        return [pscustomobject]@{
            Connector = 'claudecode'
            OtherConnector = 'codex'
            HookScript = 'claude-code-hook.sh'
            OtherHookScript = 'codex-hook.sh'
            ConfigPath = Join-Path $UserProfile '.claude\settings.json'
            OtherConfigPath = Join-Path $UserProfile '.codex\config.toml'
            DoctorLabel = 'Claude Code hooks'
            OtherDoctorLabel = 'Codex hooks'
        }
    }
    throw "unsupported wizard connector specification: $ConnectorName"
}

function Assert-NoDefenseClawRegistration([string[]]$Paths) {
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $content = [IO.File]::ReadAllText($path)
        if ($content -match '(?i)defenseclaw') {
            throw "unexpected DefenseClaw connector registration remains in $path"
        }
    }
}

function Assert-NoInstalledGatewayProcess([string]$GatewayPath) {
    $full = [IO.Path]::GetFullPath($GatewayPath)
    $owned = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        [IO.Path]::GetFullPath($_.ExecutablePath).Equals(
            $full,
            [StringComparison]::OrdinalIgnoreCase
        )
    })
    if ($owned.Count -ne 0) {
        throw "unexpected installed gateway/watchdog process remains: $($owned.ProcessId -join ', ')"
    }
}

function Assert-OwnedManagedProcess([object]$Identity, [string]$GatewayPath, [string]$Label) {
    $expected = [IO.Path]::GetFullPath($GatewayPath)
    if ([string]::IsNullOrWhiteSpace([string]$Identity.StartIdentity)) {
        throw "$Label PID record omitted its process start identity"
    }
    if (-not ([IO.Path]::GetFullPath([string]$Identity.Executable)).Equals(
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Label is owned by an unexpected executable: $($Identity.Executable)"
    }
    $live = Get-CimInstance Win32_Process -Filter "ProcessId = $($Identity.ProcessId)" -ErrorAction Stop
    if ($null -eq $live -or [string]::IsNullOrWhiteSpace($live.ExecutablePath) -or
        -not ([IO.Path]::GetFullPath($live.ExecutablePath)).Equals(
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label process identity does not resolve to the installed gateway executable"
    }
}

function Assert-OnlyInstalledGatewayProcesses([string]$GatewayPath, [int[]]$ExpectedProcessIDs) {
    $full = [IO.Path]::GetFullPath($GatewayPath)
    $actual = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        [IO.Path]::GetFullPath($_.ExecutablePath).Equals(
            $full,
            [StringComparison]::OrdinalIgnoreCase
        )
    } | ForEach-Object { [int]$_.ProcessId } | Sort-Object)
    $expected = @($ExpectedProcessIDs | Sort-Object)
    if (($actual -join ',') -ne ($expected -join ',')) {
        throw "installed gateway process roster mismatch: actual=$($actual -join ',') expected=$($expected -join ',')"
    }
}

function Get-PackagedConnectorState([string]$Python, [string]$LogPath) {
    $probe = @'
import json
from defenseclaw.config import load

cfg = load()
roster = cfg.active_connectors()
payload = {
    "claw_connector": cfg.claw.mode,
    "guardrail_connector": cfg.guardrail.connector,
    "guardrail_mode": cfg.guardrail.mode,
    "guardrail_enabled": cfg.guardrail.enabled,
    "connector_keys": sorted(cfg.guardrail.connectors),
    "roster": roster,
    "effective_modes": {name: cfg.guardrail.effective_mode(name) for name in roster},
    "effective_enabled": {name: cfg.guardrail.effective_enabled(name) for name in roster},
}
print("DC_WIZARD_STATE=" + json.dumps(payload, sort_keys=True, separators=(",", ":")))
'@
    $result = Invoke-Installed $Python @('-I', '-X', 'utf8', '-c', $probe) -Timeout 120 -Log $LogPath
    $lines = @($result.StdOut -split "`r?`n" | Where-Object { $_.StartsWith('DC_WIZARD_STATE=') })
    if ($lines.Count -ne 1) {
        throw "packaged connector state probe returned $($lines.Count) structured results; expected one"
    }
    return $lines[0].Substring('DC_WIZARD_STATE='.Length) | ConvertFrom-Json
}

function Assert-WizardConnectorState([object]$State, [string]$ConnectorName, [string]$Mode) {
    if ([string]$State.guardrail_connector -ne $ConnectorName -or
        [string]$State.claw_connector -ne $ConnectorName) {
        throw "wizard selection was not persisted under canonical connector '$ConnectorName': $($State | ConvertTo-Json -Compress -Depth 8)"
    }
    if ([string]$State.guardrail_mode -ne $Mode -or -not [bool]$State.guardrail_enabled) {
        throw "wizard mode '$Mode' was not persisted as enabled guardrail state: $($State | ConvertTo-Json -Compress -Depth 8)"
    }
    $roster = @($State.roster)
    if ($roster.Count -ne 1 -or [string]$roster[0] -ne $ConnectorName) {
        throw "wizard created a partial or wrong connector roster: $($roster -join ', ')"
    }
    $keys = @($State.connector_keys)
    if (@($keys | Where-Object { [string]$_ -ne $ConnectorName }).Count -ne 0) {
        throw "wizard persisted a connector override under a non-canonical key: $($keys -join ', ')"
    }
    $effectiveMode = $State.effective_modes.PSObject.Properties[$ConnectorName]
    $effectiveEnabled = $State.effective_enabled.PSObject.Properties[$ConnectorName]
    if ($null -eq $effectiveMode -or [string]$effectiveMode.Value -ne $Mode -or
        $null -eq $effectiveEnabled -or -not [bool]$effectiveEnabled.Value) {
        throw "wizard connector effective mode/enabled state is inconsistent for $ConnectorName"
    }
}

function Assert-SetupInstallState(
    [string]$InstallRoot,
    [string]$ConnectorName,
    [string]$Mode
) {
    $statePath = Join-Path $InstallRoot 'installer\install-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "setup install state is missing: $statePath"
    }
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$state.connector -ne $ConnectorName -or [string]$state.mode -ne $Mode) {
        throw "setup install state did not preserve wizard selections: connector=$($state.connector) mode=$($state.mode)"
    }
}

function Assert-WizardHookRegistration(
    [object]$Specification,
    [string]$DataRoot
) {
    $hookDir = Join-Path $DataRoot 'hooks'
    $expectedHook = Join-Path $hookDir $Specification.HookScript
    $wrongHook = Join-Path $hookDir $Specification.OtherHookScript
    if (-not (Test-Path -LiteralPath $expectedHook -PathType Leaf)) {
        throw "wizard-selected connector hook is missing: $expectedHook"
    }
    if (Test-Path -LiteralPath $wrongHook) {
        throw "wizard configured the wrong connector hook: $wrongHook"
    }
    if (-not (Test-Path -LiteralPath $Specification.ConfigPath -PathType Leaf)) {
        throw "wizard-selected connector registration is missing: $($Specification.ConfigPath)"
    }
    $registration = [IO.File]::ReadAllText($Specification.ConfigPath)
    $pattern = '(?i)defenseclaw-hook(?:\.exe)?[^\r\n]*\bhook\b[^\r\n]*--connector\s+' +
        [regex]::Escape($Specification.Connector) + '\b'
    if ($registration -notmatch $pattern) {
        throw "wizard-selected connector does not use its exact native hook command: $($Specification.ConfigPath)"
    }
    if ($registration -match ('(?i)--connector\s+' + [regex]::Escape($Specification.OtherConnector) + '\b')) {
        throw "wizard-selected connector registration references the wrong connector"
    }
    Assert-NoDefenseClawRegistration @($Specification.OtherConfigPath)
}

function Assert-WizardConnectorHealth(
    [string]$Launcher,
    [object]$Specification,
    [string]$Mode,
    [string]$Logs,
    [string]$Phase
) {
    $statusResult = Invoke-Installed $Launcher @('status', '--json') -Timeout 120 `
        -Log (Join-Path $Logs "wizard-$($Specification.Connector)-$Phase-status.json")
    try { $status = $statusResult.StdOut | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "wizard status did not emit valid JSON: $($_.Exception.Message)" }
    if (-not [bool]$status.sidecar.running) {
        throw "wizard-selected $($Specification.Connector) sidecar is not running"
    }
    $connectors = @($status.connectors)
    if ($connectors.Count -ne 1 -or [string]$connectors[0].name -ne $Specification.Connector -or
        [string]$connectors[0].mode -ne $Mode -or -not [bool]$connectors[0].enabled -or
        [string]$connectors[0].source -ne 'manual') {
        throw "wizard status reported a partial or wrong connector roster: $($connectors | ConvertTo-Json -Compress -Depth 8)"
    }

    $doctorResult = Invoke-Installed $Launcher @('doctor', '--json-output') @(0, 1) 300 `
        (Join-Path $Logs "wizard-$($Specification.Connector)-$Phase-doctor.json")
    try { $doctor = $doctorResult.StdOut | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "wizard doctor did not emit valid JSON: $($_.Exception.Message)" }
    $hookRows = @($doctor.checks | Where-Object {
        [string]::Equals([string]$_.label, $Specification.DoctorLabel, [StringComparison]::Ordinal)
    })
    if ($hookRows.Count -ne 1 -or [string]$hookRows[0].status -ne 'pass' -or
        [string]$hookRows[0].detail -notmatch 'healthy Windows-native executable registration') {
        throw "wizard doctor did not validate the selected native hook: $($hookRows | ConvertTo-Json -Compress -Depth 5)"
    }
    $expectedHookExecutable = Join-Path (Split-Path -Parent $Launcher) 'defenseclaw-hook.exe'
    if (([string]$hookRows[0].detail).IndexOf(
        $expectedHookExecutable,
        [StringComparison]::OrdinalIgnoreCase
    ) -lt 0) {
        throw "wizard doctor validated an unexpected hook executable: $($hookRows[0].detail)"
    }
    $wrongRows = @($doctor.checks | Where-Object {
        [string]::Equals([string]$_.label, $Specification.OtherDoctorLabel, [StringComparison]::Ordinal)
    })
    if ($wrongRows.Count -ne 0) {
        throw "wizard doctor reported a hook row for the unselected connector"
    }
    $proxyRows = @($doctor.checks | Where-Object {
        [string]::Equals([string]$_.label, 'Guardrail proxy', [StringComparison]::Ordinal)
    })
    if ($proxyRows.Count -ne 1 -or [string]$proxyRows[0].status -ne 'pass') {
        throw "wizard doctor did not report healthy guardrail enforcement: $($proxyRows | ConvertTo-Json -Compress -Depth 5)"
    }
}

function Invoke-WizardInstall(
    [string]$Setup,
    [string]$Root,
    [string]$ConnectorName,
    [string]$Mode,
    [bool]$StartGateway,
    [string]$LogPath
) {
    $driver = Join-Path $PSScriptRoot 'test-windows-setup-wizard.ps1'
    $arguments = @{
        SetupPath = $Setup
        StateRoot = (Join-Path $Root "wizard-$ConnectorName-$Mode")
        Connector = $ConnectorName
        Mode = $Mode
        StartGateway = $StartGateway
        ActivateInstall = $true
        TimeoutSeconds = 30
        InstallTimeoutSeconds = 600
    }
    $output = @(& $driver @arguments)
    Write-BoundedText $LogPath ($output -join [Environment]::NewLine)
}

function Invoke-WizardConfigureLaterAcceptance(
    [string]$Setup,
    [string]$Root,
    [string]$Logs,
    [string]$InstallRoot,
    [string]$DataRoot,
    [string]$Gateway,
    [string]$ARPKey,
    [string[]]$ConnectorConfigPaths,
    [AllowNull()][string]$UserPathBefore
) {
    Invoke-WizardInstall $Setup $Root 'none' 'observe' $false `
        (Join-Path $Logs 'wizard-configure-later.json')
    Assert-SetupInstallState $InstallRoot 'none' 'observe'
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'config.yaml')) {
        throw 'Configure later unexpectedly wrote a DefenseClaw connector configuration'
    }
    $hookDir = Join-Path $DataRoot 'hooks'
    if (Test-Path -LiteralPath $hookDir) {
        $hookFiles = @(Get-ChildItem -LiteralPath $hookDir -File -Force -ErrorAction Stop)
        if ($hookFiles.Count -ne 0) {
            throw "Configure later unexpectedly generated connector hooks: $($hookFiles.Name -join ', ')"
        }
    }
    foreach ($pidFile in @('gateway.pid', 'watchdog.pid')) {
        if (Test-Path -LiteralPath (Join-Path $DataRoot $pidFile)) {
            throw "Configure later unexpectedly started a managed process: $pidFile"
        }
    }
    Assert-NoInstalledGatewayProcess $Gateway
    Assert-NoDefenseClawRegistration $ConnectorConfigPaths

    Invoke-WindowsNativeProcess $Setup @('/uninstall', '/quiet', 'DELETEUSERDATA=1') `
        -TimeoutSeconds 600 -LogPath (Join-Path $Logs 'wizard-configure-later-uninstall.log') | Out-Null
    if (Test-Path -LiteralPath $InstallRoot) {
        throw "Configure later uninstall left install root behind: $InstallRoot"
    }
    if (Test-Path -LiteralPath $DataRoot) {
        throw "Configure later uninstall left user data behind: $DataRoot"
    }
    if (Test-Path -LiteralPath $ARPKey) {
        throw 'Configure later uninstall left Installed Apps registration behind'
    }
    if (-not [string]::Equals(
        $UserPathBefore,
        [Environment]::GetEnvironmentVariable('Path', 'User'),
        [StringComparison]::Ordinal
    )) {
        throw 'Configure later uninstall did not restore the original user PATH exactly'
    }
}

function Invoke-WizardConnectorAcceptance(
    [string]$Setup,
    [string]$Root,
    [string]$Logs,
    [string]$InstallRoot,
    [string]$DataRoot,
    [string]$ARPKey,
    [string]$UserProfile,
    [string]$FixtureBin,
    [AllowNull()][string]$UserPathBefore,
    [string]$ConnectorName,
    [ValidateSet('observe', 'action')][string]$Mode
) {
    $specification = Get-WizardConnectorSpecification $ConnectorName $UserProfile
    $launcher = Join-Path $InstallRoot 'bin\defenseclaw.exe'
    $gateway = Join-Path $InstallRoot 'bin\defenseclaw-gateway.exe'
    $python = Join-Path $InstallRoot 'runtime\python\python.exe'
    Invoke-WizardInstall $Setup $Root $ConnectorName $Mode $true `
        (Join-Path $Logs "wizard-$ConnectorName-$Mode-install.json")
    $env:DEFENSECLAW_HOME = $DataRoot
    $env:PATH = "$FixtureBin;$(Join-Path $InstallRoot 'bin');$env:SystemRoot\System32;$env:SystemRoot"

    foreach ($required in @($launcher, $gateway, $python)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "wizard install did not create required file: $required"
        }
    }
    Assert-SetupInstallState $InstallRoot $ConnectorName $Mode
    $beforeState = Get-PackagedConnectorState $python `
        (Join-Path $Logs "wizard-$ConnectorName-before-state.log")
    Assert-WizardConnectorState $beforeState $ConnectorName $Mode
    Assert-WizardHookRegistration $specification $DataRoot

    Invoke-Installed $gateway @('status') -Timeout 30 `
        -Log (Join-Path $Logs "wizard-$ConnectorName-gateway-status.log") | Out-Null
    $beforeGateway = Get-GatewayIdentity $DataRoot
    Assert-OwnedManagedProcess $beforeGateway $gateway 'wizard-started gateway'
    $watchdogRunning = Invoke-Installed $gateway @('watchdog', 'status') -Timeout 30 `
        -Log (Join-Path $Logs "wizard-$ConnectorName-watchdog-status.log")
    if (($watchdogRunning.StdOut + $watchdogRunning.StdErr) -notmatch '(?i)watchdog:\s+running') {
        throw 'STARTGATEWAY did not auto-start the configured watchdog'
    }
    $beforeWatchdog = Get-WatchdogIdentity $DataRoot
    Assert-OwnedManagedProcess $beforeWatchdog $gateway 'wizard-started watchdog'
    if ($beforeGateway.ProcessId -eq $beforeWatchdog.ProcessId) {
        throw 'gateway and watchdog unexpectedly share one process identity'
    }
    Assert-OnlyInstalledGatewayProcesses $gateway @(
        $beforeGateway.ProcessId,
        $beforeWatchdog.ProcessId
    )
    Assert-WizardConnectorHealth $launcher $specification $Mode $Logs 'before-repair'

    $preserved = Join-Path $DataRoot "wizard-$ConnectorName-preservation.txt"
    Set-Content -LiteralPath $preserved -Value 'preserve' -Encoding ascii
    $stateFingerprint = $beforeState | ConvertTo-Json -Compress -Depth 8
    Invoke-WindowsNativeProcess $Setup @('/repair', '/quiet', '/norestart', 'INSTALLSCOPE=user') `
        -TimeoutSeconds 1200 -LogPath (Join-Path $Logs "wizard-$ConnectorName-repair.log") | Out-Null

    $afterState = Get-PackagedConnectorState $python `
        (Join-Path $Logs "wizard-$ConnectorName-after-state.log")
    Assert-WizardConnectorState $afterState $ConnectorName $Mode
    if (($afterState | ConvertTo-Json -Compress -Depth 8) -ne $stateFingerprint) {
        throw "setup repair changed the selected $ConnectorName connector/mode/roster"
    }
    Assert-SetupInstallState $InstallRoot $ConnectorName $Mode
    Assert-WizardHookRegistration $specification $DataRoot
    Assert-WizardConnectorHealth $launcher $specification $Mode $Logs 'after-repair'
    if (-not (Test-Path -LiteralPath $preserved -PathType Leaf)) {
        throw "setup repair did not preserve $ConnectorName user data"
    }
    $afterGateway = Get-GatewayIdentity $DataRoot
    $afterWatchdog = Get-WatchdogIdentity $DataRoot
    Assert-OwnedManagedProcess $afterGateway $gateway 'repair-restored gateway'
    Assert-OwnedManagedProcess $afterWatchdog $gateway 'repair-restored watchdog'
    if (-not (Test-GatewayIdentityChanged $beforeGateway $afterGateway)) {
        throw 'setup repair did not restart the wizard-started gateway'
    }
    if (-not (Test-GatewayIdentityChanged $beforeWatchdog $afterWatchdog)) {
        throw 'setup repair did not restart the wizard-started watchdog'
    }
    Assert-OnlyInstalledGatewayProcesses $gateway @(
        $afterGateway.ProcessId,
        $afterWatchdog.ProcessId
    )

    Invoke-Installed $gateway @('watchdog', 'stop') @(0, 1) 60 `
        (Join-Path $Logs "wizard-$ConnectorName-watchdog-stop.log") | Out-Null
    Invoke-Installed $gateway @('stop') @(0, 1) 60 `
        (Join-Path $Logs "wizard-$ConnectorName-gateway-stop.log") | Out-Null
    Invoke-Installed $gateway @('connector', 'teardown', '--connector', $ConnectorName) `
        @(0, 1) 120 (Join-Path $Logs "wizard-$ConnectorName-teardown.log") | Out-Null
    Invoke-Installed $gateway @('connector', 'verify', '--connector', $ConnectorName) `
        -Timeout 120 -Log (Join-Path $Logs "wizard-$ConnectorName-teardown-verify.log") | Out-Null
    Assert-NoDefenseClawRegistration @(
        $specification.ConfigPath,
        $specification.OtherConfigPath
    )
    Invoke-WindowsNativeProcess $Setup @('/uninstall', '/quiet', 'DELETEUSERDATA=1') `
        -TimeoutSeconds 600 -LogPath (Join-Path $Logs "wizard-$ConnectorName-uninstall.log") | Out-Null
    if (Test-Path -LiteralPath $InstallRoot) {
        throw "wizard $ConnectorName uninstall left install root behind: $InstallRoot"
    }
    if (Test-Path -LiteralPath $DataRoot) {
        throw "wizard $ConnectorName uninstall left user data behind: $DataRoot"
    }
    if (Test-Path -LiteralPath $ARPKey) {
        throw "wizard $ConnectorName uninstall left Installed Apps registration behind"
    }
    Assert-NoInstalledGatewayProcess $gateway
    if (-not [string]::Equals(
        $UserPathBefore,
        [Environment]::GetEnvironmentVariable('Path', 'User'),
        [StringComparison]::Ordinal
    )) {
        throw "wizard $ConnectorName uninstall did not restore the original user PATH exactly"
    }
}

function Invoke-SetupAcceptance {
    Assert-NativeWindowsX64
    if (-not $ArtifactRoot) { throw 'ArtifactRoot is required for setup-acceptance' }
    if (-not $AllowCurrentUserSetupAcceptance -and $env:GITHUB_ACTIONS -ne 'true') {
        throw 'setup-acceptance mutates the current Windows user. Run only on a disposable CI user, or pass -AllowCurrentUserSetupAcceptance explicitly.'
    }
    $root = Assert-SafeStateRoot $StateRoot
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = $root
    $setup = Join-Path ([IO.Path]::GetFullPath($ArtifactRoot)) 'DefenseClawSetup-x64.exe'
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
        throw "native setup executable not found: $setup"
    }
    $logs = Join-Path $root 'logs'
    [IO.Directory]::CreateDirectory($logs) | Out-Null
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $installRoot = Join-Path $localAppData 'Programs\DefenseClaw'
    $dataRoot = Join-Path $userProfile '.defenseclaw'
    $cacheRoot = Join-Path $localAppData 'DefenseClaw\InstallerCache'
    $arpKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw'
    $connectorConfigPaths = @(
        (Join-Path $userProfile '.codex\config.toml'),
        (Join-Path $userProfile '.claude\settings.json')
    )
    if (Test-Path -LiteralPath $installRoot) { throw "refusing to overwrite an existing current-user install: $installRoot" }
    if (Test-Path -LiteralPath $dataRoot) { throw "refusing to overwrite existing current-user data: $dataRoot" }
    if (Test-Path -LiteralPath $arpKey) { throw 'refusing to overwrite existing DefenseClaw Installed Apps registration' }
    $userPathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')
    $processPathBefore = $env:PATH
    $trustedPrefixesBefore = [Environment]::GetEnvironmentVariable('DEFENSECLAW_TRUSTED_BIN_PREFIXES')
    $launcher = Join-Path $installRoot 'bin\defenseclaw.exe'
    $gateway = Join-Path $installRoot 'bin\defenseclaw-gateway.exe'
    $hook = Join-Path $installRoot 'bin\defenseclaw-hook.exe'
    $python = Join-Path $installRoot 'runtime\python\python.exe'
    $cosign = Join-Path $installRoot 'runtime\tools\cosign.exe'
    $disposableGithubRunner = $env:GITHUB_ACTIONS -eq 'true' -and
        $env:RUNNER_ENVIRONMENT -eq 'github-hosted'
    $fixtureBin = ''
    if ($disposableGithubRunner) {
        if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
            -not (Test-PathWithin $root $env:RUNNER_TEMP)) {
            throw 'interactive setup acceptance requires StateRoot below RUNNER_TEMP'
        }
        Assert-NoDefenseClawRegistration $connectorConfigPaths
        Set-CurrentUserAsDefaultOwner
        $fixtureBin = New-WizardAgentFixtures $root
        $env:DEFENSECLAW_TRUSTED_BIN_PREFIXES = if ([string]::IsNullOrWhiteSpace($trustedPrefixesBefore)) {
            $fixtureBin
        } else {
            "$fixtureBin;$trustedPrefixesBefore"
        }
        $env:PATH = "$fixtureBin;$processPathBefore"
    }
    try {
        if ($disposableGithubRunner) {
            Invoke-WizardConfigureLaterAcceptance `
                $setup $root $logs $installRoot $dataRoot $gateway $arpKey `
                $connectorConfigPaths $userPathBefore
            Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue
            $env:PATH = "$fixtureBin;$processPathBefore"

            Invoke-WizardConnectorAcceptance `
                $setup $root $logs $installRoot $dataRoot $arpKey $userProfile `
                $fixtureBin $userPathBefore 'codex' 'observe'
            Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue
            $env:PATH = "$fixtureBin;$processPathBefore"

            Invoke-WizardConnectorAcceptance `
                $setup $root $logs $installRoot $dataRoot $arpKey $userProfile `
                $fixtureBin $userPathBefore 'claudecode' 'action'
            Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue
            $env:PATH = $processPathBefore
        }

        Invoke-WindowsNativeProcess $setup @(
            '/quiet', '/norestart', 'INSTALLSCOPE=user', 'CONNECTOR=none',
            'MODE=observe', 'STARTGATEWAY=0'
        ) -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-install.log') | Out-Null

        foreach ($required in @(
            $launcher, $gateway, $hook, $python, $cosign,
            (Join-Path $installRoot 'bin\skill-scanner.exe'),
            (Join-Path $installRoot 'bin\mcp-scanner.exe'),
            (Join-Path $installRoot 'bin\defenseclaw-observability.exe')
        )) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
                throw "setup install did not create required file: $required"
            }
        }
        $env:DEFENSECLAW_HOME = $dataRoot
        $env:PATH = "$(Join-Path $installRoot 'bin');$env:SystemRoot\System32;$env:SystemRoot"
        $resolved = @(Get-Command defenseclaw -CommandType Application -ErrorAction Stop)[0].Source
        if (-not ([IO.Path]::GetFullPath($resolved)).Equals(
            [IO.Path]::GetFullPath($launcher), [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "setup launcher resolved outside install root: $resolved"
        }
        Invoke-Installed $launcher @('--version') -Timeout 120 -Log (Join-Path $logs 'setup-version.log') | Out-Null
        Invoke-Installed $gateway @('--version') -Timeout 60 -Log (Join-Path $logs 'setup-gateway-version.log') | Out-Null
        Invoke-Installed $cosign @('version') -Timeout 60 -Log (Join-Path $logs 'setup-cosign-version.log') | Out-Null
        Invoke-Installed $hook @() @(2) 30 (Join-Path $logs 'setup-hook.log') | Out-Null
        Invoke-Installed (Join-Path $installRoot 'bin\skill-scanner.exe') @('--help') -Timeout 120 | Out-Null
        Invoke-Installed (Join-Path $installRoot 'bin\mcp-scanner.exe') @('--help') -Timeout 120 | Out-Null
        Assert-ManagedDistributionIntegrity $python (Join-Path $installRoot 'runtime\python')
        Invoke-HeadlessTui $python

        Invoke-Installed $launcher @(
            'init', '--skip-install', '--non-interactive', '--yes', '--connector', 'codex',
            '--profile', 'observe', '--no-start-gateway', '--no-verify'
        ) -Timeout 300 -Log (Join-Path $logs 'setup-init-codex.log') | Out-Null
        # ``init`` is intentionally a first-run/replacement workflow. Add a
        # second hook connector through the documented additive setup path so
        # the acceptance test verifies roster preservation instead of asking a
        # second first-run invocation to retain stale peers.
        Invoke-Installed $launcher @(
            'setup', 'claude-code', '--yes', '--no-restart'
        ) -Timeout 300 -Log (Join-Path $logs 'setup-add-claudecode.log') | Out-Null
        # The packaged Go suite separately executes the hardened absolute-path
        # Antigravity hook command from an untrusted working directory. The
        # installer acceptance must preserve the product's current support
        # contract: Antigravity is not yet certified on native Windows and may
        # not be configured merely because the dormant writer is hardened.
        Assert-PackagedAntigravityPlatformGate $launcher $userProfile `
            (Join-Path $logs 'setup-antigravity.log')

        $rosterProbe = 'import json; from defenseclaw.config import load; print("DC_ROSTER=" + json.dumps(load().active_connectors()))'
        $rosterResult = Invoke-Installed $python @('-I', '-c', $rosterProbe) -Timeout 120 `
            -Log (Join-Path $logs 'setup-connector-roster.log')
        $rosterLines = @($rosterResult.StdOut -split "`r?`n" | Where-Object { $_.StartsWith('DC_ROSTER=') })
        if ($rosterLines.Count -ne 1) {
            throw "packaged connector roster probe returned $($rosterLines.Count) structured results; expected one"
        }
        $rosterLine = $rosterLines[0]
        $roster = @($rosterLine.Substring('DC_ROSTER='.Length) | ConvertFrom-Json)
        foreach ($expectedConnector in @('codex', 'claudecode')) {
            if ($expectedConnector -notin $roster) {
                throw "packaged connector setup collapsed the existing roster; missing $expectedConnector"
            }
        }

        $statePath = Join-Path $installRoot 'installer\install-state.json'
        $installedState = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$installedState.distribution_flavor -ne 'oss' -or
            [string]$installedState.source_commit -notmatch '^[0-9a-f]{40}$') {
            throw 'setup install state is missing exact OSS source provenance'
        }
        $targetVersion = [string]$installedState.version
        $installedState.version = '99.0.0'
        $installedState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
        Invoke-WindowsNativeProcess $setup @('/upgrade', '/quiet', 'INSTALLSCOPE=user') `
            -AllowedExitCodes @(1) -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-downgrade-rejected.log') | Out-Null
        $installedState.version = '0.0.0'
        $installedState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
        Invoke-WindowsNativeProcess $setup @(
            '/upgrade', '/quiet', '/norestart', 'INSTALLSCOPE=user',
            'FROMVERSION=0.0.0'
        ) -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-seeded-upgrade.log') | Out-Null
        $upgradedState = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$upgradedState.version -ne $targetVersion) {
            throw "seeded setup upgrade version mismatch: $($upgradedState.version), expected $targetVersion"
        }

        $lockStream = [IO.FileStream]::new(
            $python,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::None
        )
        try {
            Invoke-WindowsNativeProcess $setup @('/repair', '/quiet', 'INSTALLSCOPE=user') `
                -AllowedExitCodes @(3010) -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-locked-file.log') | Out-Null
        } finally {
            $lockStream.Dispose()
        }
        Invoke-Installed $launcher @('--version') -Timeout 120 | Out-Null

        Assert-PackagedDoctorSmoke $launcher $logs
        Set-MinimalGatewayAcceptanceConfig $python
        Invoke-Installed $gateway @('start') -Timeout 90 -Log (Join-Path $logs 'setup-gateway-start.log') | Out-Null
        Invoke-Installed $gateway @('watchdog', 'start') -Timeout 90 -Log (Join-Path $logs 'setup-watchdog-start.log') | Out-Null
        Invoke-Installed $gateway @('status') -Timeout 30 | Out-Null
        Invoke-Installed $gateway @('watchdog', 'status') -Timeout 30 | Out-Null
        $beforeRepair = Get-GatewayIdentity $dataRoot
        $preserved = Join-Path $dataRoot 'installer-preservation.txt'
        Set-Content -LiteralPath $preserved -Value 'preserve' -Encoding ascii

        Invoke-WindowsNativeProcess $setup @('/repair', '/quiet', '/norestart', 'INSTALLSCOPE=user') `
            -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-repair.log') | Out-Null
        $afterRepair = Get-GatewayIdentity $dataRoot
        if (-not (Test-GatewayIdentityChanged $beforeRepair $afterRepair)) {
            throw 'setup repair did not restart the previously running gateway'
        }
        Invoke-Installed $gateway @('watchdog', 'status') -Timeout 30 | Out-Null
        if (-not (Test-Path -LiteralPath $preserved -PathType Leaf)) {
            throw 'setup repair did not preserve user data'
        }

        Invoke-Installed $gateway @('watchdog', 'stop') @(0, 1) 60 `
            (Join-Path $logs 'setup-watchdog-stop-before-teardown.log') | Out-Null
        Invoke-Installed $gateway @('stop') @(0, 1) 60 `
            (Join-Path $logs 'setup-gateway-stop-before-teardown.log') | Out-Null
        foreach ($configuredConnector in @('codex', 'claudecode')) {
            Invoke-Installed $gateway @('connector', 'teardown', '--connector', $configuredConnector) `
                @(0, 1) 120 (Join-Path $logs "setup-$configuredConnector-teardown.log") | Out-Null
            Invoke-Installed $gateway @('connector', 'verify', '--connector', $configuredConnector) `
                -Timeout 120 -Log (Join-Path $logs "setup-$configuredConnector-teardown-verify.log") | Out-Null
        }
        Assert-NoDefenseClawRegistration $connectorConfigPaths

        Invoke-WindowsNativeProcess $setup @('/uninstall', '/quiet') `
            -TimeoutSeconds 600 -LogPath (Join-Path $logs 'setup-uninstall-preserve.log') | Out-Null
        if (Test-Path -LiteralPath $installRoot) { throw "setup uninstall left install root behind: $installRoot" }
        if (-not (Test-Path -LiteralPath $preserved -PathType Leaf)) { throw 'setup uninstall did not preserve user data' }
        if (Test-Path -LiteralPath $arpKey) { throw 'setup uninstall left Installed Apps registration behind' }
        if (-not [string]::Equals($userPathBefore, [Environment]::GetEnvironmentVariable('Path', 'User'), [StringComparison]::Ordinal)) {
            throw 'setup uninstall did not restore the original user PATH exactly'
        }

        Invoke-WindowsNativeProcess $setup @(
            '/quiet', '/norestart', 'INSTALLSCOPE=user', 'CONNECTOR=none',
            'MODE=observe', 'STARTGATEWAY=0'
        ) -TimeoutSeconds 1200 -LogPath (Join-Path $logs 'setup-reinstall.log') | Out-Null
        Invoke-WindowsNativeProcess $setup @('/uninstall', '/quiet', 'DELETEUSERDATA=1') `
            -TimeoutSeconds 600 -LogPath (Join-Path $logs 'setup-uninstall-delete.log') | Out-Null
        if (Test-Path -LiteralPath $installRoot) { throw "setup uninstall left install root behind: $installRoot" }
        if (Test-Path -LiteralPath $dataRoot) { throw "setup uninstall with DELETEUSERDATA=1 left user data behind: $dataRoot" }
    } finally {
        $env:PATH = $processPathBefore
        Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($trustedPrefixesBefore)) {
            Remove-Item Env:DEFENSECLAW_TRUSTED_BIN_PREFIXES -ErrorAction SilentlyContinue
        } else {
            $env:DEFENSECLAW_TRUSTED_BIN_PREFIXES = $trustedPrefixesBefore
        }
        if (Test-Path -LiteralPath $gateway -PathType Leaf) {
            try { Invoke-Installed $gateway @('watchdog', 'stop') @(0, 1) 60 | Out-Null }
            catch { Write-Warning "setup acceptance watchdog cleanup failed: $($_.Exception.Message)" }
            try { Invoke-Installed $gateway @('stop') @(0, 1) 60 | Out-Null }
            catch { Write-Warning "setup acceptance gateway cleanup failed: $($_.Exception.Message)" }
            foreach ($configuredConnector in @('codex', 'claudecode')) {
                try {
                    Invoke-Installed $gateway @('connector', 'teardown', '--connector', $configuredConnector) `
                        @(0, 1) 120 | Out-Null
                } catch {
                    Write-Warning "setup acceptance $configuredConnector teardown cleanup failed: $($_.Exception.Message)"
                }
            }
        }
        if (Test-Path -LiteralPath $installRoot) {
            try {
                Invoke-WindowsNativeProcess $setup @('/uninstall', '/quiet', 'DELETEUSERDATA=1') `
                    -AllowedExitCodes @(0, 3010) -TimeoutSeconds 600 -LogPath (Join-Path $logs 'setup-final-cleanup.log') | Out-Null
            } catch { Write-Warning "setup acceptance cleanup failed: $($_.Exception.Message)" }
        }
        for ($attempt = 0; $attempt -lt 40 -and (Test-Path -LiteralPath $cacheRoot); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (Test-Path -LiteralPath $cacheRoot) { throw "setup uninstall left installer cache behind: $cacheRoot" }
        if ($disposableGithubRunner) {
            Assert-NoDefenseClawRegistration $connectorConfigPaths
        }
    }
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
        } | Sort-Object @{
            Expression = { if ($_.Name -eq 'wizard-driver.log') { 0 } else { 1 } }
        }, FullName | Select-Object -First 30
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
        'build-installer' { Invoke-BuildInstaller }
        'acceptance' { Invoke-Acceptance }
        'setup-acceptance' { Invoke-SetupAcceptance }
        'contract' { Invoke-Contract }
        'capture' { Invoke-Capture }
        'cleanup' { Invoke-Cleanup }
        'self-test' { Invoke-SelfTest }
    }
}
