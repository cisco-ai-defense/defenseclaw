# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Native Windows x64 CI test-environment, diagnostics, and cleanup harness.

.DESCRIPTION
    Keeps every mutable profile/cache/temp path below StateRoot. The harness is
    intentionally PowerShell-native and never requires WSL, MSYS, or Git Bash.
#>

[CmdletBinding()]
param(
    [ValidateSet('stage-package-data', 'capture', 'cleanup', 'self-test')]
    [string]$Operation = 'self-test',
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) 'defenseclaw-windows-native-ci'),
    [string]$DiagnosticsRoot = '',
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')

$windowsResourceVerifierName = 'DefenseClawWindowsResourceVerifier-x64.exe'
$windowsResourceIconName = 'DefenseClawWindowsResourceIcon.png'
$windowsResourceVersionName = 'DefenseClawWindowsResourceVersion.txt'

$setupStandardUserLauncherSource = Join-Path $PSScriptRoot 'windows-setup-standard-user-launcher.cs'
if (-not ('DefenseClaw.SetupStandardUserLauncher' -as [type])) {
    if (-not (Test-Path -LiteralPath $setupStandardUserLauncherSource -PathType Leaf)) {
        throw "Windows Setup standard-user launcher source is missing: $setupStandardUserLauncherSource"
    }
    Add-Type -Path $setupStandardUserLauncherSource
}

$disposableFileGuardSource = Join-Path $PSScriptRoot 'windows-disposable-file-guard.cs'
if (-not ('DefenseClaw.DisposableFileGuard' -as [type])) {
    if (-not (Test-Path -LiteralPath $disposableFileGuardSource -PathType Leaf)) {
        throw "Windows disposable file guard source is missing: $disposableFileGuardSource"
    }
    Add-Type -Path $disposableFileGuardSource
}

function Get-RedactionValues {
    $names = @(
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AMP_API_KEY', 'AZURE_OPENAI_API_KEY',
        'AWS_BEARER_TOKEN_BEDROCK', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN', 'LLM_API_KEY', 'GH_TOKEN', 'GITHUB_TOKEN',
        'DEFENSECLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_TOKEN', 'DC_E2E_TEST_SECRET',
        'CURSOR_API_KEY'
    )
    return @($names | ForEach-Object { [Environment]::GetEnvironmentVariable($_) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_.Length -ge 8 } |
        Sort-Object -Unique)
}

function Protect-WindowsNativeText([AllowNull()][string]$Text) {
    if ($null -eq $Text) { return '' }
    $safe = $Text
    foreach ($value in Get-RedactionValues) { $safe = $safe.Replace($value, '***REDACTED***') }

    # Keep JSON structure intact while replacing the complete quoted value.
    # This must run separately from the line-oriented HTTP-header rule below;
    # otherwise one sensitive field could consume unrelated sibling keys.
    $safe = [regex]::Replace(
        $safe,
        '(?i)(?<prefix>"(?:api[_-]?key|access[_-]?token|secret[_-]?key|authorization)"\s*:\s*")(?<value>(?:\\.|[^"\\])*)(?<suffix>")',
        '${prefix}***REDACTED***${suffix}'
    )

    # Authorization credentials commonly contain a scheme and a credential
    # separated by whitespace. Redact the entire header value, not just the
    # first token. Limit this rule to an HTTP-style header line so prose and
    # JSON content later on the same line are not swallowed.
    $safe = [regex]::Replace(
        $safe,
        '(?im)(?<prefix>^[ \t]*[<>]?[ \t]*authorization[ \t]*:[ \t]*)[^\r\n]*',
        '${prefix}***REDACTED***'
    )

    # Compact logs can render the same header inline with either separator.
    # Consume a complete scheme-plus-credential pair, but stop at whitespace
    # after the credential so unrelated diagnostic fields remain visible.
    $safe = [regex]::Replace(
        $safe,
        '(?im)(?<prefix>\bauthorization\b[ \t]*[:=][ \t]*)(?:"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''|[A-Za-z][A-Za-z0-9._~+/-]*[ \t]+[^\s,;]+|[^\s,;]+)',
        '${prefix}***REDACTED***'
    )

    # Preserve the existing key/value protection for compact diagnostics such
    # as ``api_key=...``.
    return [regex]::Replace(
        $safe,
        '(?im)(?<prefix>\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''|\S+)',
        '${prefix}***REDACTED***'
    )
}

function Assert-NativeWindowsX64 {
    if (-not $IsWindows) { throw 'Windows Native CI requires native Windows PowerShell' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
        throw 'Windows Native CI certifies only native Windows x64'
    }
}

function Get-WorkspacePackageVersion {
    $projectPath = Join-Path $WorkspaceRoot 'pyproject.toml'
    if (Test-Path -LiteralPath $projectPath -PathType Leaf) {
        $projectText = Get-Content -LiteralPath $projectPath -Raw -Encoding UTF8
        if ($projectText -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
            throw 'Could not resolve project version from pyproject.toml'
        }
        $packageVersion = $Matches[1]
    } else {
        $versionPath = Join-Path $PSScriptRoot $windowsResourceVersionName
        if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
            throw 'Could not resolve project version from the workspace or packaged resource verifier'
        }
        $packageVersion = ([IO.File]::ReadAllText($versionPath)).Trim()
    }
    if ($packageVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9_.-]+)?$') {
        throw "Invalid package version for Windows resources: $packageVersion"
    }
    return $packageVersion
}

function Assert-WindowsExecutableResource(
    [string]$Path,
    [ValidateSet('gateway', 'hook', 'hook-guard', 'launcher', 'startup', 'acp-guard')][string]$Component,
    [string]$Version,
    [switch]$Apply
) {
    $arguments = @(
        '-target', 'windows_amd64',
        '-executable', $Path,
        '-component', $Component,
        '-version', $Version
    )
    $verifier = Join-Path $PSScriptRoot $windowsResourceVerifierName
    $packagedIcon = Join-Path $PSScriptRoot $windowsResourceIconName
    if ((Test-Path -LiteralPath $verifier -PathType Leaf) -and
        (Test-Path -LiteralPath $packagedIcon -PathType Leaf)) {
        $command = $verifier
        $arguments += @('-icon', $packagedIcon)
    } else {
        $command = Get-RequiredCommand 'go.exe'
        $arguments = @('run', './internal/tools/windowsresources') + $arguments + @(
            '-icon', (Join-Path $WorkspaceRoot 'macos\DefenseClawMac\DefenseClawMac\Assets.xcassets\AppIcon.appiconset\icon_256.png')
        )
    }
    if (-not $Apply) { $arguments += '-verify-only' }
    Invoke-WindowsNativeProcess $command $arguments -TimeoutSeconds 300 -WorkingDirectory $WorkspaceRoot | Out-Null
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
    $explicitBase = Resolve-SafeWindowsNativeBase (
        [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT')
    )
    $allowedRoots = @(
        [Environment]::GetEnvironmentVariable('RUNNER_TEMP'),
        [IO.Path]::GetTempPath()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $withinExplicitBase = -not [string]::IsNullOrWhiteSpace($explicitBase) -and
        (Test-PathWithinOrEqual $full $explicitBase)
    if (-not $withinExplicitBase -and
        -not ($allowedRoots | Where-Object { Test-PathWithin $full $_ } | Select-Object -First 1)) {
        throw "StateRoot must be a child of RUNNER_TEMP, DC_WINDOWS_NATIVE_BASE_ROOT, or the system temp directory: $full"
    }
    foreach ($protected in @($WorkspaceRoot, $env:USERPROFILE, [IO.Path]::GetTempPath())) {
        if (-not [string]::IsNullOrWhiteSpace($protected) -and
            $full.Equals([IO.Path]::GetFullPath($protected).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "StateRoot must not equal a workspace, profile, or temp root: $full"
        }
    }
    return Assert-NoReparseAncestors $full
}

function Test-WindowsNativeProcessElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Set-CurrentUserAsDefaultOwner {
    # GitHub's elevated Windows runner token can use BUILTIN\Administrators as
    # its default owner even though processes run as the runner user. That
    # makes ordinary child-created test paths look foreign to the production
    # ownership checks. Normalize only this disposable CI process token; child
    # processes inherit it and create objects owned by the actual runner user.
    # A real standard-user disposable child already creates files with its own
    # SID as owner and cannot adjust TokenOwner. Only the elevated hosted
    # runner token needs this normalization.
    if (-not (Test-WindowsNativeProcessElevated)) { return }
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
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($sid in @($identity.User, $system, $administrators)) {
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
    if ($MaxBytes -lt 0) { throw 'MaxBytes must be non-negative' }
    $safe = Protect-WindowsNativeText $Text
    $bytes = [Text.Encoding]::UTF8.GetBytes($safe)
    if ($bytes.Length -le $MaxBytes) { return $safe }

    $markerBytes = [Text.Encoding]::UTF8.GetBytes("`n[truncated]`n")
    if ($markerBytes.Length -ge $MaxBytes) {
        return [Text.Encoding]::UTF8.GetString($markerBytes, 0, $MaxBytes)
    }

    # Preserve the start for command context and give two thirds of the
    # remaining budget to the tail, where test runners emit their failure.
    $contentBudget = $MaxBytes - $markerBytes.Length
    $headBudget = [int][Math]::Floor($contentBudget / 3)
    $tailBudget = $contentBudget - $headBudget

    # A byte budget can land inside a multi-byte UTF-8 scalar. Move each cut
    # to a code-point boundary so decoding never inserts a replacement rune.
    $headLength = $headBudget
    while ($headLength -gt 0 -and $headLength -lt $bytes.Length -and
        (($bytes[$headLength] -band 0xC0) -eq 0x80)) {
        $headLength--
    }
    $tailStart = $bytes.Length - $tailBudget
    while ($tailStart -lt $bytes.Length -and
        (($bytes[$tailStart] -band 0xC0) -eq 0x80)) {
        $tailStart++
    }

    $head = [Text.Encoding]::UTF8.GetString($bytes, 0, $headLength)
    $tail = [Text.Encoding]::UTF8.GetString($bytes, $tailStart, $bytes.Length - $tailStart)
    return $head + [Text.Encoding]::UTF8.GetString($markerBytes) + $tail
}

function Add-WindowsNativeDiagnosticTail(
    [Collections.Generic.Queue[string]]$Queue,
    [AllowNull()][string]$Text,
    [int]$MaxLines,
    [int]$MaxBytes
) {
    if ($MaxLines -le 0 -or $MaxBytes -le 0) { return }
    # Bound each event before splitting or retaining it. The primary process
    # capture already owns the raw output; diagnostic queues must not multiply
    # an oversized JSON Output event beyond the summary's independent budget.
    $boundedText = Limit-WindowsNativeText ([string]$Text) $MaxBytes
    $retainedBytes = 0
    foreach ($retainedLine in $Queue) {
        $retainedBytes += [Text.Encoding]::UTF8.GetByteCount($retainedLine)
    }
    foreach ($line in [regex]::Split($boundedText, '\r?\n')) {
        if (-not $line) { continue }
        $Queue.Enqueue($line)
        $retainedBytes += [Text.Encoding]::UTF8.GetByteCount($line)
        while ($Queue.Count -gt $MaxLines -or $retainedBytes -gt $MaxBytes) {
            $removed = $Queue.Dequeue()
            $retainedBytes -= [Text.Encoding]::UTF8.GetByteCount($removed)
        }
    }
}

function Get-WindowsNativeJsonString([object]$Object, [string]$Name) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}

function ConvertFrom-WindowsNativeDoctorJson([object]$Result, [string]$Context) {
    if ($null -eq $Result) { throw "$Context returned no process result" }

    $exitCode = Get-WindowsNativeJsonString $Result 'ExitCode'
    $stderr = Limit-WindowsNativeText (Get-WindowsNativeJsonString $Result 'StdErr') 4096
    if ([string]::IsNullOrWhiteSpace($stderr)) { $stderr = '(empty)' }
    $diagnostic = "process exit code ${exitCode}; bounded stderr: $stderr"
    $stdoutProperty = $Result.PSObject.Properties['StdOut']
    if ($null -eq $stdoutProperty -or
        [string]::IsNullOrWhiteSpace([string]$stdoutProperty.Value)) {
        throw "$Context emitted no Doctor JSON on stdout; $diagnostic"
    }

    try {
        $document = [string]$stdoutProperty.Value | ConvertFrom-Json -NoEnumerate -ErrorAction Stop
    } catch {
        throw "$Context emitted invalid Doctor JSON: $($_.Exception.Message); $diagnostic"
    }
    if ($null -eq $document -or $document -isnot [pscustomobject]) {
        throw "$Context must emit one Doctor v2 JSON object; $diagnostic"
    }

    foreach ($name in @(
        'schema_version', 'run_id', 'mode', 'passive', 'outcome', 'exit_code',
        'passed', 'failed', 'warned', 'skipped', 'summary', 'checks',
        'repair_summary', 'repairs'
    )) {
        if ($null -eq $document.PSObject.Properties[$name]) {
            throw "$Context Doctor v2 JSON is missing '$name'; $diagnostic"
        }
    }
    $schemaVersion = 0
    if ($document.schema_version -is [string] -or
        -not [int]::TryParse([string]$document.schema_version, [ref]$schemaVersion) -or
        $schemaVersion -ne 2) {
        throw "$Context did not emit Doctor schema_version 2; $diagnostic"
    }
    if ($document.summary -isnot [pscustomobject] -or
        $document.repair_summary -isnot [pscustomobject] -or
        $document.checks -isnot [array] -or
        $document.repairs -isnot [array]) {
        throw "$Context Doctor v2 JSON has invalid summary/check/repair containers; $diagnostic"
    }
    if (@($document.checks).Count -eq 0) {
        throw "$Context Doctor v2 JSON contains no health checks; $diagnostic"
    }

    foreach ($name in @('passed', 'failed', 'warned', 'skipped')) {
        $topProperty = $document.PSObject.Properties[$name]
        $summaryProperty = $document.summary.PSObject.Properties[$name]
        $topValue = 0
        $summaryValue = 0
        if ($null -eq $summaryProperty -or
            $topProperty.Value -is [string] -or $summaryProperty.Value -is [string] -or
            -not [int]::TryParse([string]$topProperty.Value, [ref]$topValue) -or
            -not [int]::TryParse([string]$summaryProperty.Value, [ref]$summaryValue) -or
            $topValue -lt 0 -or $summaryValue -lt 0 -or $topValue -ne $summaryValue) {
            throw "$Context Doctor v2 JSON has inconsistent '$name' counters; $diagnostic"
        }
    }
    foreach ($check in @($document.checks)) {
        if ($null -eq $check -or $check -isnot [pscustomobject] -or
            $null -eq $check.PSObject.Properties['status'] -or
            $null -eq $check.PSObject.Properties['label'] -or
            $null -eq $check.PSObject.Properties['detail'] -or
            [string]::IsNullOrWhiteSpace([string]$check.label) -or
            [string]$check.status -notin @('pass', 'fail', 'warn', 'skip')) {
            throw "$Context Doctor v2 JSON contains an invalid health-check row; $diagnostic"
        }
    }

    $payloadExitCode = -1
    $processExitCode = -1
    if ($document.exit_code -is [string] -or
        -not [int]::TryParse([string]$document.exit_code, [ref]$payloadExitCode) -or
        -not [int]::TryParse($exitCode, [ref]$processExitCode) -or
        $payloadExitCode -notin @(0, 1) -or $payloadExitCode -ne $processExitCode) {
        throw "$Context Doctor v2 exit_code disagrees with the process result; $diagnostic"
    }
    return $document
}

function Test-WindowsNativeDoctorJsonParser {
    $healthyPayload = [ordered]@{
        schema_version = 2
        run_id = 'doctor-parser-fixture'
        mode = 'check'
        passive = $false
        outcome = 'healthy'
        exit_code = 0
        passed = 1
        failed = 0
        warned = 0
        skipped = 0
        summary = [ordered]@{ passed = 1; failed = 0; warned = 0; skipped = 0 }
        checks = @([ordered]@{ status = 'pass'; label = 'Fixture'; detail = 'healthy' })
        repair_summary = [ordered]@{}
        repairs = @()
    }
    $healthyResult = [pscustomobject]@{
        ExitCode = 0
        StdOut = $healthyPayload | ConvertTo-Json -Compress -Depth 6
        StdErr = ''
    }
    $healthy = ConvertFrom-WindowsNativeDoctorJson $healthyResult 'healthy fixture'
    if (@($healthy.checks).Count -ne 1 -or [string]$healthy.checks[0].status -ne 'pass') {
        throw 'Doctor JSON parser did not preserve a healthy check row'
    }

    $failedPayload = [ordered]@{} + $healthyPayload
    $failedPayload.outcome = 'failed'
    $failedPayload.exit_code = 1
    $failedPayload.passed = 0
    $failedPayload.failed = 1
    $failedPayload.summary = [ordered]@{ passed = 0; failed = 1; warned = 0; skipped = 0 }
    $failedPayload.checks = @([ordered]@{ status = 'fail'; label = 'Fixture'; detail = 'unhealthy' })
    $failedResult = [pscustomobject]@{
        ExitCode = 1
        StdOut = $failedPayload | ConvertTo-Json -Compress -Depth 6
        StdErr = ''
    }
    $failed = ConvertFrom-WindowsNativeDoctorJson $failedResult 'failed fixture'
    if ([int]$failed.failed -ne 1 -or [string]$failed.checks[0].status -ne 'fail') {
        throw 'Doctor JSON parser did not preserve a failed check row'
    }

    $stderrMarker = 'fixture Doctor child failed before JSON'
    $emptyFailedLoud = $false
    try {
        ConvertFrom-WindowsNativeDoctorJson ([pscustomobject]@{
            ExitCode = 1
            StdOut = ''
            StdErr = $stderrMarker
        }) 'empty fixture' | Out-Null
    } catch {
        $emptyFailedLoud = $_.Exception.Message.Contains('no Doctor JSON') -and
            $_.Exception.Message.Contains($stderrMarker)
    }
    if (-not $emptyFailedLoud) {
        throw 'Doctor JSON parser did not expose bounded stderr for empty stdout'
    }

    foreach ($stdout in @('{}', '[]', 'null')) {
        $invalidRejected = $false
        try {
            ConvertFrom-WindowsNativeDoctorJson ([pscustomobject]@{
                ExitCode = 1
                StdOut = $stdout
                StdErr = 'invalid fixture stderr'
            }) 'invalid fixture' | Out-Null
        } catch {
            $invalidRejected = $_.Exception.Message.Contains('bounded stderr')
        }
        if (-not $invalidRejected) {
            throw "Doctor JSON parser accepted an invalid top-level payload: $stdout"
        }
    }
}

function Get-GoTestFailureSummary(
    [AllowNull()][string]$Text,
    [int]$MaxBytes = 262144
) {
    if (-not $Text) { return '' }

    $failedTests = [Collections.Generic.List[object]]::new()
    $failedTestKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $passedTestKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $failedPackages = [Collections.Generic.List[object]]::new()
    $failedPackageNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $failedTestsOmitted = $false
    $failedPackagesOmitted = $false
    $maxFailures = 128
    $reader = [IO.StringReader]::new($Text)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            try {
                $testEvent = $line.TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
            } catch {
                continue
            }
            $action = Get-WindowsNativeJsonString $testEvent 'Action'
            if ($action -ne 'fail' -and $action -ne 'pass') { continue }
            $package = Limit-WindowsNativeText (
                Get-WindowsNativeJsonString $testEvent 'Package'
            ) 1024
            if (-not $package) { continue }
            $test = Limit-WindowsNativeText (
                Get-WindowsNativeJsonString $testEvent 'Test'
            ) 1024
            if ($action -eq 'pass') {
                if ($test) {
                    [void]$passedTestKeys.Add("$($package.Length):$package$test")
                }
                continue
            }
            if ($test) {
                $key = "$($package.Length):$package$test"
                if ($failedTestKeys.Contains($key)) { continue }
                if ($failedTestKeys.Count -ge $maxFailures) {
                    $failedTestsOmitted = $true
                } elseif ($failedTestKeys.Add($key)) {
                    $failedTests.Add([pscustomobject]@{
                        Key = $key
                        Package = $package
                        Test = $test
                        Elapsed = Limit-WindowsNativeText (
                            Get-WindowsNativeJsonString $testEvent 'Elapsed'
                        ) 64
                    })
                }
            } elseif (-not $failedPackageNames.Contains($package)) {
                if ($failedPackageNames.Count -ge $maxFailures) {
                    $failedPackagesOmitted = $true
                } elseif ($failedPackageNames.Add($package)) {
                    $failedPackages.Add([pscustomobject]@{
                        Package = $package
                        Elapsed = Limit-WindowsNativeText (
                            Get-WindowsNativeJsonString $testEvent 'Elapsed'
                        ) 64
                    })
                }
            }
        }
    } finally {
        $reader.Dispose()
    }
    if ($failedTests.Count -eq 0 -and $failedPackages.Count -eq 0) { return '' }

    $testOutput = @{}
    foreach ($failure in $failedTests) {
        $testOutput[$failure.Key] = [Collections.Generic.Queue[string]]::new()
    }
    $packageOutput = @{}
    $packageCriticalOutput = @{}
    $packageCriticalHeader = @{}
    $packageCriticalRecentHeaders = @{}
    $packageRuntimeFault = @{}
    $packageRuntimeFaultOpen = @{}
    $packageCriticalRemaining = @{}
    foreach ($failure in $failedPackages) {
        $packageOutput[$failure.Package] = [Collections.Generic.Queue[string]]::new()
        $packageCriticalOutput[$failure.Package] = [Collections.Generic.Queue[string]]::new()
        $packageCriticalRecentHeaders[$failure.Package] = [Collections.Generic.Queue[string]]::new()
        $packageRuntimeFault[$failure.Package] = [Collections.Generic.Queue[string]]::new()
        $packageRuntimeFaultOpen[$failure.Package] = $false
        $packageCriticalRemaining[$failure.Package] = 0
    }
    # At most 128 failed tests and 128 package-only failures are retained.
    # Per-failure budgets cap aggregate tail queues relative to MaxBytes; the
    # separate critical-context queues have a 2 KiB floor so panic headers and
    # goroutine 1 survive deliberately tiny self-test budgets.
    $tailBytesPerFailure = [Math]::Max(
        256,
        [int][Math]::Floor($MaxBytes / ($maxFailures * 2))
    )

    $reader = [IO.StringReader]::new($Text)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            try {
                $testEvent = $line.TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
            } catch {
                continue
            }
            if ((Get-WindowsNativeJsonString $testEvent 'Action') -ne 'output') { continue }
            $package = Limit-WindowsNativeText (
                Get-WindowsNativeJsonString $testEvent 'Package'
            ) 1024
            $test = Limit-WindowsNativeText (
                Get-WindowsNativeJsonString $testEvent 'Test'
            ) 1024
            $key = "$($package.Length):$package$test"
            if ($test -and $passedTestKeys.Contains($key) -and
                -not $failedTestKeys.Contains($key)) { continue }
            $output = Get-WindowsNativeJsonString $testEvent 'Output'
            if ($packageOutput.ContainsKey($package)) {
                Add-WindowsNativeDiagnosticTail -Queue $packageOutput[$package] `
                    -Text $output -MaxLines 160 -MaxBytes $tailBytesPerFailure
                # "[signal ..." follows a runtime fault header and names the
                # exception and faulting address (rel-1-0-6:GAP-0550).
                $criticalLines = [regex]::Matches(
                    $output,
                    '(?im)^(panic:|fatal error:|\[signal |runtime: out of memory|.*test timed out after|exit status )[^\r\n]*'
                )
                $sawRuntimeFault = $false
                foreach ($criticalLine in $criticalLines) {
                    $header = Limit-WindowsNativeText $criticalLine.Value 512
                    # The Go runtime prints these when the process dies. Only
                    # the final crash dump may fill the reserved block (at most
                    # 4 lines, 1 KiB, printed right after the summary title).
                    # A fault header (fatal error:, unexpected fault address,
                    # runtime: out of memory) that follows other output starts
                    # a new crash and replaces earlier fixture fault lines;
                    # headers with nothing between them form one crash
                    # ("unexpected fault address" then "fatal error: fault").
                    # A "[signal ..." line joins the current crash whatever
                    # output came between, so a still-running child's output
                    # cannot split the fatal line from its signal. The latest
                    # lines win inside a crash; nothing follows the real dump
                    # but its stacks (rel-1-0-6:GAP-0550).
                    if ($header -match '^\[signal ') {
                        Add-WindowsNativeDiagnosticTail -Queue $packageRuntimeFault[$package] `
                            -Text $header -MaxLines 4 -MaxBytes 1024
                        $sawRuntimeFault = $true
                        continue
                    }
                    if ($header -match '^(fatal error:|unexpected fault address|runtime: out of memory)') {
                        if (-not $packageRuntimeFaultOpen[$package]) {
                            $packageRuntimeFault[$package].Clear()
                        }
                        Add-WindowsNativeDiagnosticTail -Queue $packageRuntimeFault[$package] `
                            -Text $header -MaxLines 4 -MaxBytes 1024
                        $packageRuntimeFaultOpen[$package] = $true
                        $sawRuntimeFault = $true
                        continue
                    }
                    $packageRuntimeFaultOpen[$package] = $false
                    if (-not $packageCriticalHeader.ContainsKey($package)) {
                        $packageCriticalHeader[$package] = $header
                    } elseif ($header -cne $packageCriticalHeader[$package] -and
                        -not $packageCriticalRecentHeaders[$package].Contains($header)) {
                        Add-WindowsNativeDiagnosticTail -Queue $packageCriticalRecentHeaders[$package] `
                            -Text $header -MaxLines 8 -MaxBytes 1024
                    }
                }
                if (-not $sawRuntimeFault) {
                    $packageRuntimeFaultOpen[$package] = $false
                }
                if ($criticalLines.Count -gt 0) {
                    $packageCriticalRemaining[$package] = 48
                }
                if ([int]$packageCriticalRemaining[$package] -gt 0) {
                    Add-WindowsNativeDiagnosticTail -Queue $packageCriticalOutput[$package] `
                        -Text $output -MaxLines 64 -MaxBytes ([Math]::Max(2048, $tailBytesPerFailure))
                    $packageCriticalRemaining[$package] = [int]$packageCriticalRemaining[$package] - 1
                }
            }
            if ($test) {
                if ($testOutput.ContainsKey($key)) {
                    # The summary already names each failed test, so Go's own
                    # run and result markers add nothing. Kept, a short
                    # "--- FAIL:" line after a long assertion line pushes the
                    # assertion out of the byte-bounded tail and the summary
                    # shows no failure text (rel-1-0-6:GAP-0840).
                    $detail = [regex]::Replace(
                        $output,
                        '(?m)^[ \t]*(=== (RUN|PAUSE|CONT|NAME)|--- (FAIL|PASS|SKIP):)[^\r\n]*(\r?\n|$)',
                        '')
                    Add-WindowsNativeDiagnosticTail -Queue $testOutput[$key] `
                        -Text $detail -MaxLines 120 -MaxBytes $tailBytesPerFailure
                }
            }
        }
    } finally {
        $reader.Dispose()
    }

    $summary = [Text.StringBuilder]::new()
    [void]$summary.AppendLine('go test failure summary (bounded and redacted)')
    foreach ($failure in $failedPackages) {
        if ($packageRuntimeFault[$failure.Package].Count -eq 0) { continue }
        [void]$summary.AppendLine("runtime fault in package $($failure.Package):")
        foreach ($line in $packageRuntimeFault[$failure.Package]) {
            [void]$summary.AppendLine($line)
        }
    }
    foreach ($failure in $failedTests) {
        $elapsed = if ($failure.Elapsed) { " [$($failure.Elapsed)s]" } else { '' }
        [void]$summary.AppendLine("--- FAIL: $($failure.Test) ($($failure.Package))$elapsed")
        foreach ($line in $testOutput[$failure.Key]) {
            [void]$summary.AppendLine($line)
        }
    }
    foreach ($failure in $failedPackages) {
        $elapsed = if ($failure.Elapsed) { " [$($failure.Elapsed)s]" } else { '' }
        [void]$summary.AppendLine("FAIL package $($failure.Package)$elapsed")
        if ($packageCriticalHeader.ContainsKey($failure.Package)) {
            [void]$summary.AppendLine($packageCriticalHeader[$failure.Package])
            foreach ($header in $packageCriticalRecentHeaders[$failure.Package]) {
                [void]$summary.AppendLine($header)
            }
        }
        foreach ($line in $packageCriticalOutput[$failure.Package]) {
            [void]$summary.AppendLine($line)
        }
        if (-not ($failedTests | Where-Object { $_.Package -eq $failure.Package })) {
            foreach ($line in $packageOutput[$failure.Package]) {
                [void]$summary.AppendLine($line)
            }
        }
    }
    if ($failedTestsOmitted) {
        [void]$summary.AppendLine('[additional failed tests omitted]')
    }
    if ($failedPackagesOmitted) {
        [void]$summary.AppendLine('[additional failed packages omitted]')
    }
    return Limit-WindowsNativeText ($summary.ToString()) $MaxBytes
}

function Write-BoundedText([string]$Path, [AllowNull()][string]$Text, [int]$MaxBytes = 1048576) {
    $safe = Limit-WindowsNativeText $Text $MaxBytes
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    [IO.File]::WriteAllText($Path, $safe, [Text.UTF8Encoding]::new($false))
}

function Get-WindowsNativeProcessTreeSnapshot {
    param(
        [Parameter(Mandatory)][object[]]$RootProcesses,
        [AllowNull()][object[]]$ProcessSnapshot = $null
    )
    $processes = if ($null -eq $ProcessSnapshot) {
        @(Get-CimInstance Win32_Process -OperationTimeoutSec 1 -ErrorAction Stop)
    } else {
        @($ProcessSnapshot)
    }
    $descendants = @()
    $seen = @{}
    $frontier = @($RootProcesses)
    foreach ($root in $frontier) {
        $seen["$($root.ProcessId)|$($root.CreationDate)"] = $true
    }
    while ($frontier.Count -gt 0) {
        $children = @()
        foreach ($parent in $frontier) {
            $parentCreated = [DateTime]::Parse(
                [string]$parent.CreationDate,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).ToUniversalTime()
            $parentExited = $false
            $parentExit = [DateTime]::MinValue
            $exitProperty = $parent.PSObject.Properties['ExitDate']
            if ($null -ne $exitProperty -and
                -not [string]::IsNullOrWhiteSpace([string]$exitProperty.Value)) {
                $parentExit = [DateTime]::Parse(
                    [string]$exitProperty.Value,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).ToUniversalTime()
                $parentExited = $true
            } else {
                $parentMatches = @($processes | Where-Object {
                    if ([int]$_.ProcessId -ne [int]$parent.ProcessId) { return $false }
                    $currentCreated = ([DateTime]$_.CreationDate).ToUniversalTime()
                    return [Math]::Abs(($currentCreated - $parentCreated).TotalMilliseconds) -lt 1
                }).Count -gt 0
                if (-not $parentMatches) { continue }
            }
            foreach ($candidate in @($processes | Where-Object {
                [int]$_.ParentProcessId -eq [int]$parent.ProcessId
            })) {
                $candidateCreated = ([DateTime]$candidate.CreationDate).ToUniversalTime()
                if ($candidateCreated -lt $parentCreated) { continue }
                # Only an exited root may expand without a current exact parent,
                # and then only across the root's recorded lifetime.
                if ($parentExited -and $candidateCreated -gt $parentExit) { continue }
                $child = [pscustomobject]@{
                    ProcessId = [int]$candidate.ProcessId
                    ParentProcessId = [int]$candidate.ParentProcessId
                    CreationDate = $candidateCreated.ToString('O')
                    ExitDate = ''
                    ExecutablePath = [string]$candidate.ExecutablePath
                }
                $key = "$($child.ProcessId)|$($child.CreationDate)"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $children += $child
            }
        }
        $descendants += $children
        $frontier = @($children)
    }
    return @($descendants)
}

function Update-WindowsNativeRootProcessExitBound(
    [object]$RecordedProcess,
    [Diagnostics.Process]$Process
) {
    if (-not $Process.HasExited -or
        -not [string]::IsNullOrWhiteSpace([string]$RecordedProcess.ExitDate)) {
        return
    }
    try {
        $RecordedProcess.ExitDate = $Process.ExitTime.ToUniversalTime().ToString('O')
    } catch {
        Write-Warning (Protect-WindowsNativeText "could not record process exit bound: $($_.Exception.Message)")
    }
}

function Add-WindowsNativeProcessTreeSnapshot([hashtable]$Tracked, [object]$RootProcess) {
    $roots = @($RootProcess) + @($Tracked.Values)
    try {
        foreach ($process in @(Get-WindowsNativeProcessTreeSnapshot $roots)) {
            $key = "$($process.ProcessId)|$($process.CreationDate)"
            $Tracked[$key] = $process
        }
    } catch {
        Write-Warning (Protect-WindowsNativeText "process tree snapshot failed: $($_.Exception.Message)")
    }
}

function Test-WindowsNativeProcessIdentity([object]$RecordedProcess) {
    $native = $null
    try {
        $native = [Diagnostics.Process]::GetProcessById([int]$RecordedProcess.ProcessId)
        $expected = [DateTime]::Parse(
            [string]$RecordedProcess.CreationDate,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
        if ([Math]::Abs(($native.StartTime.ToUniversalTime() - $expected).TotalMilliseconds) -ge 1) {
            return $false
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$RecordedProcess.ExecutablePath)) {
            $currentImage = [string]$native.MainModule.FileName
            if (-not [string]::Equals(
                $currentImage,
                [string]$RecordedProcess.ExecutablePath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $native) { $native.Dispose() }
    }
}

function Stop-WindowsNativeExactProcessTree([object[]]$Descendants) {
    foreach ($recorded in @($Descendants)) {
        if (-not (Test-WindowsNativeProcessIdentity $recorded)) { continue }
        $native = $null
        try {
            $native = [Diagnostics.Process]::GetProcessById([int]$recorded.ProcessId)
            $started = $native.StartTime.ToUniversalTime()
            $expected = [DateTime]::Parse(
                [string]$recorded.CreationDate,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).ToUniversalTime()
            if ([Math]::Abs(($started - $expected).TotalMilliseconds) -ge 1) { continue }
            $native.Kill($true)
        } catch {
            Write-Warning (Protect-WindowsNativeText "could not stop tracked PID $($recorded.ProcessId): $($_.Exception.Message)")
        } finally {
            if ($null -ne $native) { $native.Dispose() }
        }
    }
}

function Wait-WindowsNativeProcessTreeExit([object[]]$Descendants, [int]$TimeoutMilliseconds = 5000) {
    if (@($Descendants).Count -eq 0) { return }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $alive = @($Descendants | Where-Object { Test-WindowsNativeProcessIdentity $_ })
        if ($alive.Count -eq 0) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
}

function Get-WindowsNativeTrackedProcessIdentitySummary([object[]]$Descendants) {
    $rows = @($Descendants | Sort-Object ProcessId, CreationDate | Select-Object -First 16 | ForEach-Object {
        $image = if ([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)) {
            'unknown'
        } else {
            [IO.Path]::GetFileName([string]$_.ExecutablePath)
        }
        "pid=$($_.ProcessId),created=$($_.CreationDate),image=$image"
    })
    if (@($Descendants).Count -gt 16) { $rows += 'additional-identities=truncated' }
    if ($rows.Count -eq 0) { return 'none' }
    return $rows -join ';'
}

function Write-WindowsNativeProcessPhase([string]$FilePath, [int]$ProcessId, [string]$Phase, [string]$Detail = '') {
    $name = [IO.Path]::GetFileName($FilePath)
    $line = "[native-process:$Phase] file=$name pid=$ProcessId"
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $line += " $Detail" }
    [Console]::Out.WriteLine((Protect-WindowsNativeText $line))
    [Console]::Out.Flush()
}

function Wait-WindowsNativeOutputTask([Threading.Tasks.Task]$Task, [DateTime]$Deadline) {
    if ($Task.IsCompleted) { return $true }
    $remaining = [int][Math]::Max(0, [Math]::Min([int]::MaxValue, ($Deadline - [DateTime]::UtcNow).TotalMilliseconds))
    if ($remaining -le 0) { return $false }
    try { return $Task.Wait($remaining) }
    catch { return $true }
}

function Read-WindowsNativeOutputTask([Threading.Tasks.Task[string]]$Task) {
    if (-not $Task.IsCompleted) { return '[redirected output drain did not complete]' }
    try { return [string]$Task.GetAwaiter().GetResult() }
    catch { return "[redirected output unavailable: $($_.Exception.Message)]" }
}

function Test-WindowsNativeOutputTasksHealthy(
    [Threading.Tasks.Task[string]]$StdOutTask,
    [Threading.Tasks.Task[string]]$StdErrTask
) {
    return -not (
        $StdOutTask.IsFaulted -or $StdOutTask.IsCanceled -or
        $StdErrTask.IsFaulted -or $StdErrTask.IsCanceled
    )
}

function Invoke-WindowsNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [ValidateRange(1, 4200)][int]$TimeoutSeconds = 600,
        [string]$LogPath = '',
        [string]$GoTestFailureSummaryPath = '',
        [string]$WorkingDirectory = '',
        [switch]$GoTestTimingSummary,
        [switch]$SuppressOutput
    )
    if ($GoTestFailureSummaryPath -and $SuppressOutput) {
        throw 'Go test failure summaries are prohibited for credential-bearing process output'
    }
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
    if (-not $process.Start()) {
        $process.Dispose()
        throw "failed to start $FilePath"
    }
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $trackedDescendants = @{}
        $rootProcessIdentity = [pscustomobject]@{
            ProcessId = $process.Id
            ParentProcessId = 0
            CreationDate = $process.StartTime.ToUniversalTime().ToString('O')
            ExitDate = ''
            ExecutablePath = ''
        }
        $timeoutIdentitySummary = 'none'
        Write-WindowsNativeProcessPhase $FilePath $process.Id 'started'
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        $timeoutPhase = 'parent'
        if (-not $timedOut) {
            Write-WindowsNativeProcessPhase $FilePath $process.Id 'parent-exited'
            $drainGrace = [DateTime]::UtcNow.AddSeconds(5)
            $drainDeadline = if ($drainGrace -lt $deadline) { $drainGrace } else { $deadline }
            $stdoutComplete = Wait-WindowsNativeOutputTask $stdoutTask $drainDeadline
            $stderrComplete = Wait-WindowsNativeOutputTask $stderrTask $drainDeadline
            if (-not ($stdoutComplete -and $stderrComplete)) {
                $timedOut = $true
                $timeoutPhase = 'output-drain'
            }
        }
        $outputReadFailed = -not $timedOut -and
            -not (Test-WindowsNativeOutputTasksHealthy $stdoutTask $stderrTask)
        if ($timedOut) {
            Update-WindowsNativeRootProcessExitBound $rootProcessIdentity $process
            Add-WindowsNativeProcessTreeSnapshot $trackedDescendants $rootProcessIdentity
            $timeoutIdentitySummary = Get-WindowsNativeTrackedProcessIdentitySummary @($trackedDescendants.Values)
            Write-WindowsNativeProcessPhase $FilePath $process.Id "timeout-$timeoutPhase" "descendants=$timeoutIdentitySummary"
            if (-not $process.HasExited) {
                try { $process.Kill($true) } catch { Write-Warning (Protect-WindowsNativeText $_.Exception.Message) }
                $null = $process.WaitForExit(1000)
            }
            Update-WindowsNativeRootProcessExitBound $rootProcessIdentity $process
            Add-WindowsNativeProcessTreeSnapshot $trackedDescendants $rootProcessIdentity
            $timeoutIdentitySummary = Get-WindowsNativeTrackedProcessIdentitySummary @($trackedDescendants.Values)
            Stop-WindowsNativeExactProcessTree @($trackedDescendants.Values)
            Wait-WindowsNativeProcessTreeExit @($trackedDescendants.Values) 1000
            $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(1)
            $null = Wait-WindowsNativeOutputTask $stdoutTask $cleanupDeadline
            $null = Wait-WindowsNativeOutputTask $stderrTask $cleanupDeadline
            if (-not $stdoutTask.IsCompleted) { $process.StandardOutput.Dispose() }
            if (-not $stderrTask.IsCompleted) { $process.StandardError.Dispose() }
        }
        $rawStdout = Read-WindowsNativeOutputTask $stdoutTask
        $rawStderr = Read-WindowsNativeOutputTask $stderrTask
        if ($GoTestTimingSummary -and -not $SuppressOutput) {
            # One line per package result from the full go test -json stream
            # (the console copy below is bounded), for the recorded package
            # times in scripts/test-timings/go-windows.json.
            foreach ($packageResult in [regex]::Matches([string]$rawStdout,
                    '(?m)^\{"Time":"[^"]*","Action":"(pass|fail|skip)","Package":"([^"]+)","Elapsed":([0-9.]+)')) {
                [Console]::Out.WriteLine(('[go-package-time] {0} {1} {2}' -f
                    $packageResult.Groups[2].Value, $packageResult.Groups[1].Value, $packageResult.Groups[3].Value))
            }
            [Console]::Out.Flush()
        }
        $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
        $goTestFailureSummary = ''
        if ($GoTestFailureSummaryPath -and
            ($timedOut -or $outputReadFailed -or $exitCode -notin $AllowedExitCodes)) {
            $goTestFailureSummary = Get-GoTestFailureSummary $rawStdout
            if ($goTestFailureSummary) {
                Write-BoundedText -Path $GoTestFailureSummaryPath `
                    -Text $goTestFailureSummary -MaxBytes 262144
                Write-Host $goTestFailureSummary
            }
        }
        $stdout = Limit-WindowsNativeText $rawStdout
        $stderr = Limit-WindowsNativeText $rawStderr
        if ($timedOut) {
            $stderr = @($stderr, "[timeout descendants: $timeoutIdentitySummary]" | Where-Object { $_ }) -join [Environment]::NewLine
        }
        $combined = @($stdout, $stderr | Where-Object { $_ }) -join [Environment]::NewLine
        # A structured Go failure summary is the bounded, relevant console
        # diagnostic. Keep the full bounded JSON stream in LogPath without
        # duplicating it into the exception and Actions log.
        if ($combined -and -not $SuppressOutput -and -not $goTestFailureSummary) {
            Write-Host $combined
        }
        if ($LogPath) {
            $logText = if ($SuppressOutput) {
                '[credential-bearing process output intentionally suppressed]'
            } else {
                $combined
            }
            Write-BoundedText -Path $LogPath -Text $logText
        }
        $result = [pscustomobject]@{
            ExitCode = $exitCode
            StdOut = $stdout
            StdErr = $stderr
            TimedOut = $timedOut
            ProcessId = $process.Id
        }
        Write-WindowsNativeProcessPhase $FilePath $process.Id $(if ($timedOut) { 'failed-timeout' } elseif ($outputReadFailed) { 'failed-output' } elseif ($exitCode -in $AllowedExitCodes) { 'completed' } else { 'failed-exit' })
        if ($outputReadFailed) {
            if ($SuppressOutput) { throw "$FilePath redirected output capture failed" }
            $failureOutput = if ($goTestFailureSummary) { $goTestFailureSummary } else { $combined }
            throw "$FilePath redirected output capture failed`n$failureOutput"
        }
        if ($exitCode -notin $AllowedExitCodes) {
            $reason = if ($timedOut) { "timed out after ${TimeoutSeconds}s" } else { "exited $exitCode" }
            if ($SuppressOutput) { throw "$FilePath $reason" }
            $failureOutput = if ($goTestFailureSummary) { $goTestFailureSummary } else { $combined }
            throw "$FilePath $reason`n$failureOutput"
        }
        return $result
    } finally {
        $process.Dispose()
    }
}

function Invoke-WindowsSetupStandardUserProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 600,
        [string]$LogPath = '',
        [string]$WorkingDirectory = '',
        [switch]$AllowRestrictedLuaFallback,
        [switch]$SuppressOutput
    )
    if ($FilePath.IndexOf([char]0) -ge 0 -or $WorkingDirectory.IndexOf([char]0) -ge 0 -or
        @($ArgumentList | Where-Object { $null -eq $_ -or $_.IndexOf([char]0) -ge 0 }).Count -ne 0) {
        throw 'standard-user Setup launcher rejects NUL in its executable, working directory, or arguments'
    }
    $application = [IO.Path]::GetFullPath($FilePath)
    if (-not (Test-Path -LiteralPath $application -PathType Leaf) -or
        -not [IO.Path]::GetExtension($application).Equals(
            '.exe', [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "standard-user Setup launcher requires an existing .exe: $application"
    }
    $working = if ($WorkingDirectory) {
        [IO.Path]::GetFullPath($WorkingDirectory)
    } else {
        [IO.Path]::GetFullPath((Split-Path -Parent $application))
    }

    if (-not [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated()) {
        if ($SuppressOutput) {
            $result = Invoke-WindowsNativeProcess -FilePath $application -ArgumentList $ArgumentList `
                -AllowedExitCodes $AllowedExitCodes -TimeoutSeconds $TimeoutSeconds `
                -LogPath $LogPath -WorkingDirectory $working 6>$null
        } else {
            $result = Invoke-WindowsNativeProcess -FilePath $application -ArgumentList $ArgumentList `
                -AllowedExitCodes $AllowedExitCodes -TimeoutSeconds $TimeoutSeconds `
                -LogPath $LogPath -WorkingDirectory $working
        }
        $result | Add-Member -NotePropertyName LaunchContext -NotePropertyValue 'inherited-standard'
        $result | Add-Member -NotePropertyName StdOutTruncated `
            -NotePropertyValue ([string]$result.StdOut -match '(?m)^\[truncated\]$')
        $result | Add-Member -NotePropertyName StdErrTruncated `
            -NotePropertyValue ([string]$result.StdErr -match '(?m)^\[truncated\]$')
        $result | Add-Member -NotePropertyName StdOutCapturedBytes `
            -NotePropertyValue ([Text.Encoding]::UTF8.GetByteCount([string]$result.StdOut))
        $result | Add-Member -NotePropertyName StdErrCapturedBytes `
            -NotePropertyValue ([Text.Encoding]::UTF8.GetByteCount([string]$result.StdErr))
        return $result
    }

    $environment = @(
        [Environment]::GetEnvironmentVariables('Process').GetEnumerator() |
            ForEach-Object { '{0}={1}' -f [string]$_.Key, [string]$_.Value }
    )
    $hasLinkedLimitedToken = `
        [DefenseClaw.SetupStandardUserLauncher]::CurrentElevatedTokenHasLinkedLimitedToken()
    if (-not $hasLinkedLimitedToken -and -not $AllowRestrictedLuaFallback) {
        throw 'certification requires a real standard user or UAC-linked limited token; restricted LUA fallback is prohibited'
    }
    $launchContext = if ($hasLinkedLimitedToken) {
        'verified-linked-limited-token'
    } else {
        'verified-restricted-lua-default-token-noncertification'
    }
    $process = [DefenseClaw.SetupStandardUserLauncher]::StartRestrictedWithCapture(
        $application,
        [string[]]$ArgumentList,
        $working,
        [string[]]$environment,
        [bool]$AllowRestrictedLuaFallback
    )
    $timedOut = $false
    $outputHealthy = $false
    $cleanupFailure = $null
    try {
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) {
            $process.Kill($true)
            if (-not $process.WaitForExit(30000)) {
                throw 'restricted Setup process tree did not exit within 30 seconds after timeout termination'
            }
        }
        $outputHealthy = $process.CompleteOutput(5000)
        $stdout = Limit-WindowsNativeText ([string]$process.StdOut)
        $stderr = Limit-WindowsNativeText ([string]$process.StdErr)
        $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
        $result = [pscustomobject]@{
            ExitCode = $exitCode
            StdOut = $stdout
            StdErr = $stderr
            StdOutTruncated = [bool]$process.StdOutTruncated
            StdErrTruncated = [bool]$process.StdErrTruncated
            StdOutCapturedBytes = [int]$process.StdOutCapturedBytes
            StdErrCapturedBytes = [int]$process.StdErrCapturedBytes
            OutputCaptureError = [string]$process.OutputCaptureError
            TimedOut = $timedOut
            ProcessId = $process.Id
            LaunchContext = $launchContext
        }
    } catch {
        $cleanupFailure = $_
    } finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(30000)) {
                    throw 'restricted Setup process tree did not exit within 30 seconds during exception cleanup'
                }
            }
        } catch {
            if ($null -eq $cleanupFailure) {
                $cleanupFailure = $_
            } else {
                $cleanupFailure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($cleanupFailure.Exception.Message); cleanup failed: $($_.Exception.Message)",
                        $cleanupFailure.Exception
                    ),
                    'RestrictedSetupCleanupFailed',
                    [Management.Automation.ErrorCategory]::OperationStopped,
                    $application
                )
            }
        }
        $process.Dispose()
    }
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }

    $summary = [ordered]@{
        launch_context = $result.LaunchContext
        process_id = $result.ProcessId
        exit_code = $result.ExitCode
        timed_out = $result.TimedOut
        timeout_seconds = $TimeoutSeconds
        executable = $application
        arguments = @($ArgumentList)
        stdout_truncated = $result.StdOutTruncated
        stderr_truncated = $result.StdErrTruncated
        stdout_captured_bytes = $result.StdOutCapturedBytes
        stderr_captured_bytes = $result.StdErrCapturedBytes
    } | ConvertTo-Json -Depth 4
    $summary = Protect-WindowsNativeText $summary
    $combined = @($result.StdOut, $result.StdErr | Where-Object { $_ }) -join [Environment]::NewLine
    if ($combined -and -not $SuppressOutput) { Write-Host $combined }
    Write-Host $summary
    if ($LogPath) {
        $logText = @(
            $summary,
            '--- stdout ---',
            (Limit-WindowsNativeText $result.StdOut 393216),
            '--- stderr ---',
            (Limit-WindowsNativeText $result.StdErr 393216)
        ) -join [Environment]::NewLine
        Write-BoundedText -Path $LogPath -Text $logText
    }
    if (-not $outputHealthy) {
        throw "$application redirected output capture failed: $($result.OutputCaptureError)"
    }
    if ($result.ExitCode -notin $AllowedExitCodes) {
        $reason = if ($timedOut) { "timed out after ${TimeoutSeconds}s" } else { "exited $($result.ExitCode)" }
        throw "$application $reason under a verified standard-user token`n$combined"
    }
    return $result
}

function Test-WindowsSetupStandardUserLauncher([string]$Root) {
    $scriptPath = Join-Path $Root 'standard-user-launch-smoke.ps1'
    $outputPath = Join-Path $Root 'standard-user-launch-smoke.json'
    $logPath = Join-Path $Root 'standard-user-launch-smoke.log'
    $scriptBody = @'
param(
    [Parameter(Mandatory)][string]$Argument,
    [Parameter(Mandatory)][string]$LauncherSource
)
Add-Type -Path $LauncherSource
$payload = [ordered]@{
    argument = $Argument
    environment = [Environment]::GetEnvironmentVariable('DC_SETUP_LAUNCH_UNICODE')
    elevated = [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated()
    restricted_or_limited = [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessRestrictedOrLimited()
}
[IO.File]::WriteAllText(
    [Environment]::GetEnvironmentVariable('DC_SETUP_LAUNCH_OUTPUT'),
    ($payload | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::Out.WriteLine('captured stdout → Ω')
[Console]::Error.WriteLine('captured stderr → Ж')
$overflow = [DefenseClaw.RestrictedSetupProcess]::MaxCapturedBytesPerStream + 4096
[Console]::Out.Write(('O' * $overflow))
[Console]::Error.Write(('E' * $overflow))
'@
    [IO.File]::WriteAllText($scriptPath, $scriptBody, [Text.UTF8Encoding]::new($false))
    $expectedArgument = 'Setup → quote " and trailing slash \'
    $expectedEnvironment = 'environment → Ω quote " trailing \'
    $previousOutput = [Environment]::GetEnvironmentVariable('DC_SETUP_LAUNCH_OUTPUT')
    $previousUnicode = [Environment]::GetEnvironmentVariable('DC_SETUP_LAUNCH_UNICODE')
    $parentElevated = [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated()
    if ($parentElevated -and
        -not [DefenseClaw.SetupStandardUserLauncher]::CurrentElevatedTokenHasLinkedLimitedToken()) {
        Write-Host (@{
            setup_standard_user_launcher = 'requires-disposable-standard-user'
            reason = 'elevated host has no UAC-linked limited token'
        } | ConvertTo-Json -Compress)
        return
    }
    try {
        $env:DC_SETUP_LAUNCH_OUTPUT = $outputPath
        $env:DC_SETUP_LAUNCH_UNICODE = $expectedEnvironment
        $powershell = (Get-Process -Id $PID).Path
        # Windows paths and executable extensions are case-insensitive. Use an
        # uppercase extension alias so this smoke test covers hosted runners
        # that report PowerShell as pwsh.EXE.
        $powershellCaseAlias = [IO.Path]::ChangeExtension(
            $powershell, [IO.Path]::GetExtension($powershell).ToUpperInvariant()
        )
        $result = Invoke-WindowsSetupStandardUserProcess $powershellCaseAlias @(
            '-NoProfile', '-File', $scriptPath,
            '-Argument', $expectedArgument,
            '-LauncherSource', $setupStandardUserLauncherSource
        ) -TimeoutSeconds 30 -LogPath $logPath -WorkingDirectory $Root -SuppressOutput
    } finally {
        [Environment]::SetEnvironmentVariable('DC_SETUP_LAUNCH_OUTPUT', $previousOutput, 'Process')
        [Environment]::SetEnvironmentVariable('DC_SETUP_LAUNCH_UNICODE', $previousUnicode, 'Process')
    }
    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        throw 'standard-user Setup launcher smoke child did not produce its output'
    }
    $observed = Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$observed.argument -cne $expectedArgument -or
        [string]$observed.environment -cne $expectedEnvironment) {
        throw 'standard-user Setup launcher did not preserve Unicode argv/environment bytes'
    }
    if ([bool]$observed.elevated) {
        throw 'standard-user Setup launcher smoke child remained elevated'
    }
    if ($parentElevated -and -not [bool]$observed.restricted_or_limited) {
        throw 'standard-user Setup launcher smoke child was neither limited nor restricted'
    }
    $expectedContext = if ($parentElevated) {
        'verified-linked-limited-token'
    } else {
        'inherited-standard'
    }
    if ([string]$result.LaunchContext -cne $expectedContext) {
        throw "standard-user Setup launcher context was $($result.LaunchContext), expected $expectedContext"
    }
    if ([string]$result.StdOut -notmatch 'captured stdout → Ω' -or
        [string]$result.StdErr -notmatch 'captured stderr → Ж') {
        throw 'standard-user Setup launcher did not preserve Unicode stdout/stderr'
    }
    if (-not [bool]$result.StdOutTruncated -or -not [bool]$result.StdErrTruncated) {
        throw 'standard-user Setup launcher did not report bounded stdout/stderr truncation'
    }
    if ($parentElevated -and
        ([int]$result.StdOutCapturedBytes -gt
            [DefenseClaw.RestrictedSetupProcess]::MaxCapturedBytesPerStream -or
         [int]$result.StdErrCapturedBytes -gt
            [DefenseClaw.RestrictedSetupProcess]::MaxCapturedBytesPerStream)) {
        throw 'restricted Setup launcher exceeded its per-stream capture bound'
    }
    if ($parentElevated) {
        $log = Get-Content -LiteralPath $logPath -Raw -Encoding UTF8
        if ($log -notmatch 'captured stdout → Ω' -or $log -notmatch 'captured stderr → Ж') {
            throw 'restricted Setup launcher log did not include captured stdout/stderr'
        }
    }
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

function Stage-PackageData(
    [string]$PackageRoot,
    [switch]$RequireExtensionFingerprint
) {
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
    Copy-MatchedFiles (Join-Path $WorkspaceRoot 'policies\*.yaml') (Join-Path $data 'policies')
    foreach ($name in @('default', 'strict', 'permissive')) {
        Copy-Tree (Join-Path $WorkspaceRoot "policies\guardrail\$name") (Join-Path $data "policies\guardrail\$name")
    }
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'policies\guardrail\tool-chains.json') -Destination (Join-Path $data 'policies\guardrail') -Force
    Copy-Tree (Join-Path $WorkspaceRoot 'policies\guardrail-use-cases') (Join-Path $data 'policies\guardrail-use-cases')
    Copy-Tree (Join-Path $WorkspaceRoot 'policies\yara\mcp-tools') (Join-Path $data 'policies\yara\mcp-tools')
    [IO.Directory]::CreateDirectory((Join-Path $data 'envvars')) | Out-Null
    $generatedRegistry = Join-Path $WorkspaceRoot 'cli\defenseclaw\_data\envvars\registry.json'
    $targetRegistry = Join-Path $data 'envvars\registry.json'
    if (-not ([IO.Path]::GetFullPath($generatedRegistry)).Equals(
        [IO.Path]::GetFullPath($targetRegistry),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        Copy-Item -LiteralPath $generatedRegistry -Destination $targetRegistry -Force
    }
    Copy-Tree (Join-Path $WorkspaceRoot 'skills\codeguard') (Join-Path $data 'skills\codeguard')
    [IO.Directory]::CreateDirectory((Join-Path $data 'llm')) | Out-Null
    Copy-Item -LiteralPath (Join-Path $WorkspaceRoot 'bundles\llm\model_catalog.json') -Destination (Join-Path $data 'llm') -Force
    $configData = Join-Path $data 'config\v8'
    [IO.Directory]::CreateDirectory($configData) | Out-Null
    Copy-Item -LiteralPath (
        Join-Path $WorkspaceRoot 'schemas\config\v8\defenseclaw-config.schema.json'
    ) -Destination $configData -Force
    foreach ($name in @('observability.yaml', 'observability.md')) {
        Copy-Item -LiteralPath (
            Join-Path $WorkspaceRoot "schemas\config\v8\reference\$name"
        ) -Destination $configData -Force
    }
    $telemetryData = Join-Path $data 'telemetry\v8'
    [IO.Directory]::CreateDirectory($telemetryData) | Out-Null
    Invoke-WindowsNativeProcess $uv @(
        'run', '--no-project', '--python', '3.12', 'python',
        'scripts/telemetry_runtime_assets.py', '--root', '.', '--stage', $telemetryData
    ) -TimeoutSeconds 120 -WorkingDirectory $WorkspaceRoot | Out-Null
    foreach ($name in @('splunk_local_bridge', 'local_observability_stack', 'splunk_o11y_dashboards')) {
        Copy-Tree (Join-Path $WorkspaceRoot "bundles\$name") (Join-Path $data $name)
    }
    # As make _bundle-data: the optional Fleet assets stay out of the default
    # per-user package; they ship in defenseclaw-fleet-assets.tar.gz.
    foreach ($relative in @(
        'docker-compose.fleet.yml',
        'prometheus\examples\fleet.yml',
        'grafana\dashboards\defenseclaw-fleet.json'
    )) {
        $fleetAsset = Join-Path $data "local_observability_stack\$relative"
        if (Test-Path -LiteralPath $fleetAsset -PathType Leaf) {
            Remove-Item -LiteralPath $fleetAsset -Force
        }
    }
    $extensionSource = Join-Path $WorkspaceRoot 'extensions\defenseclaw'
    $extensionIndex = Join-Path $extensionSource 'dist\index.js'
    if (Test-Path -LiteralPath $extensionIndex -PathType Leaf) {
        $fingerprint = Join-Path $data 'plugin\extension-runtime-fingerprint.json'
        Invoke-WindowsNativeProcess $uv @(
            'run', '--no-project', '--python', '3.12', 'python',
            'scripts/extension_runtime_fingerprint.py', 'stage',
            '--source', $extensionSource, '--output', $fingerprint
        ) -TimeoutSeconds 120 -WorkingDirectory $WorkspaceRoot | Out-Null
        if (-not (Test-Path -LiteralPath $fingerprint -PathType Leaf)) {
            throw 'extension fingerprint staging did not publish the required reference'
        }
    } elseif ($RequireExtensionFingerprint) {
        throw 'extension fingerprint staging requires a built dist/index.js runtime'
    }
}

function Initialize-IsolatedProfile([string]$Root) {
    Set-CurrentUserAsDefaultOwner
    $safeRoot = Assert-SafeStateRoot $Root
    [IO.Directory]::CreateDirectory($safeRoot) | Out-Null
    $originalProfile = $env:USERPROFILE
    $hostPowerShell = [IO.Path]::GetFullPath((Get-Process -Id $PID -ErrorAction Stop).Path)
    $hostPowerShellHome = [IO.Path]::GetDirectoryName($hostPowerShell).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($hostPowerShellHome) -or
        -not (Test-Path -LiteralPath $hostPowerShell -PathType Leaf)) {
        throw 'could not resolve the active PowerShell runtime directory'
    }
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
        $bin, $venvScripts, $tools, $hostPowerShellHome,
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
            # Hermetic hosts (including Codex) may install the running pwsh
            # beneath USERPROFILE. Permit only that exact immutable runtime
            # directory; every other runner-profile PATH entry remains banned.
            $isHostPowerShellHome = $entry -and [IO.Path]::GetFullPath($entry).TrimEnd('\').Equals(
                $hostPowerShellHome, [StringComparison]::OrdinalIgnoreCase
            )
            if ($entry -and (Test-PathWithin $entry $originalProfile) -and
                -not (Test-PathWithin $entry $safeRoot) -and -not $isHostPowerShellHome) {
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
        HostPowerShellHome = $hostPowerShellHome
    }
}

function Get-StateProcesses([string]$Root) {
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $excluded = [Collections.Generic.HashSet[int]]::new()
    $ancestorId = $PID
    while ($ancestorId -gt 0 -and $excluded.Add($ancestorId)) {
        $ancestor = Get-CimInstance Win32_Process -Filter "ProcessId=$ancestorId" `
            -OperationTimeoutSec 30 -ErrorAction SilentlyContinue
        if ($null -eq $ancestor) { break }
        $ancestorId = [int]$ancestor.ParentProcessId
    }
    $rootPattern = [regex]::Escape($full)
    $rootedCommandPattern = '(?i)(?:^|\s|")' + $rootPattern + '\\'
    $stateArgumentPattern = '(?i)-StateRoot\s+"?' + $rootPattern + '(?:\s|"|$)'
    return @(Get-CimInstance Win32_Process -OperationTimeoutSec 30 -ErrorAction Stop | Where-Object {
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

function Test-WindowsNativeReparsePoint([IO.FileSystemInfo]$Item) {
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function New-WindowsNativeFixtureReparsePoint(
    [string]$Path,
    [string]$FileTarget,
    [string]$DirectoryTarget
) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($null -ne (Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue)) {
        throw "native reparse fixture already exists: $full"
    }
    if (-not (Test-Path -LiteralPath $FileTarget -PathType Leaf)) {
        throw "native reparse fixture file target is missing: $FileTarget"
    }
    if (-not (Test-Path -LiteralPath $DirectoryTarget -PathType Container)) {
        throw "native reparse fixture directory target is missing: $DirectoryTarget"
    }

    try {
        # Standard Windows users can create file symlinks only when Developer
        # Mode or SeCreateSymbolicLinkPrivilege is available. Keep that stronger
        # fixture where supported, but fall back to a junction: it is available
        # to standard users and still crosses the same kernel reparse boundary.
        New-Item -ItemType SymbolicLink -Path $full -Target $FileTarget `
            -ErrorAction Stop | Out-Null
    } catch {
        $symlinkFailure = $_.Exception.Message
        if ($null -ne (Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue)) {
            throw "failed file-symlink fixture left an unexpected path at ${full}: $symlinkFailure"
        }
        try {
            New-Item -ItemType Junction -Path $full -Target $DirectoryTarget `
                -ErrorAction Stop | Out-Null
        } catch {
            throw "could not create a standard-user reparse fixture at ${full}; " +
                "file symlink failed: $symlinkFailure; junction failed: $($_.Exception.Message)"
        }
    }

    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not (Test-WindowsNativeReparsePoint $item)) {
        throw "native reparse fixture is not a reparse point: $full"
    }
    return $item
}

function Get-WindowsNativeCaptureFiles([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    try {
        $rootItem = [IO.DirectoryInfo](Get-Item -LiteralPath $Root -Force -ErrorAction Stop)
    } catch {
        return @()
    }
    if (Test-WindowsNativeReparsePoint $rootItem) { return @() }

    $pending = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $pending.Enqueue($rootItem)
    $selected = [Collections.Generic.SortedDictionary[string, IO.FileInfo]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $selectionLimit = 30
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        if (Test-WindowsNativeReparsePoint $directory) { continue }
        try {
            $children = @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction SilentlyContinue)
        } catch {
            continue
        }
        foreach ($child in $children) {
            if (Test-WindowsNativeReparsePoint $child) { continue }
            if ($child.PSIsContainer) {
                $pending.Enqueue([IO.DirectoryInfo]$child)
            } elseif ($child -is [IO.FileInfo] -and @($child | Where-Object {
                ($_.Name -match '^(?:gateway|watchdog|results|doctor).*\.(?:json|jsonl|txt|log)$' -or
                    $_.Name -match '\.log$') -and
                    $_.Length -le 1048576
            }).Count -eq 1) {
                $priority = @($child | ForEach-Object {
                    if ($_.Name -match '^(?:gateway|watchdog).*\.(?:json|jsonl|txt|log)$') { -2 }
                    elseif ($_.Name -in @('go-test-failure-summary.log', 'go-test.log')) { 1 }
                    else { 2 }
                })[0]
                $selectionKey = '{0:D2}|{1}' -f ($priority + 4), $child.FullName
                $selected[$selectionKey] = [IO.FileInfo]$child
                if ($selected.Count -gt $selectionLimit) {
                    $lastKey = @($selected.Keys)[-1]
                    [void]$selected.Remove($lastKey)
                }
            }
        }
    }

    return @($selected.Values)
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
        $captureReader = $null
        try {
            $captureReader = [DefenseClaw.DisposableFileGuard]::OpenRootedReader($root)
        } catch {
            $captureReader = $null
        }
        if ($null -ne $captureReader) {
            try {
                foreach ($file in @(Get-WindowsNativeCaptureFiles $root)) {
                    try {
                        $capturedText = $captureReader.ReadBoundedUtf8($file.FullName, 1048576)
                    } catch {
                        continue
                    }
                    $relative = [IO.Path]::GetRelativePath($root, $file.FullName) -replace '[\\/:*?"<>|]', '_'
                    Write-BoundedText (Join-Path $destination $relative) $capturedText
                }
            } finally {
                $captureReader.Dispose()
            }
        }
    }
}

function Invoke-Cleanup {
    $root = Assert-SafeStateRoot $StateRoot
    # This operation normally runs in a new workflow step, where process-level
    # profile variables from earlier steps no longer exist. Never invoke
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
    Test-WindowsNativeDoctorJsonParser
    $root = Assert-SafeStateRoot $StateRoot
    $originalProfile = $env:USERPROFILE
    $nativeBaseProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    ).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($nativeBaseProfile)) {
        throw 'native self-test could not resolve the current user profile'
    }
    $profile = Initialize-IsolatedProfile $root
    # The calling workflow may publish a short native base below its real
    # runner profile. Rebind only this disposable child process to its own
    # strict descendant of the authoritative Profile Known Folder. The
    # env-only profile remains isolated below StateRoot, the production path
    # guard remains unchanged, and the parent workflow environment is not
    # mutated. This path is authority metadata only; the self-test never
    # creates or writes it.
    $selfTestNativeBase = Join-Path $nativeBaseProfile '.dc-ci\self-test'
    $env:DC_WINDOWS_NATIVE_BASE_ROOT = Resolve-SafeWindowsNativeBase $selfTestNativeBase
    foreach ($name in @(
        'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
        'DEFENSECLAW_HOME', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'HERMES_HOME',
        'ZEPTOCLAW_HOME', 'OPENCODE_CONFIG_DIR',
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
            $isHostPowerShellHome = $entry -and [IO.Path]::GetFullPath($entry).TrimEnd('\').Equals(
                [string]$profile.HostPowerShellHome, [StringComparison]::OrdinalIgnoreCase
            )
            if ($entry -and (Test-PathWithin $entry $originalProfile) -and
                -not (Test-PathWithin $entry $root) -and -not $isHostPowerShellHome) {
                throw "isolated PATH contains the original runner profile: $entry"
            }
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'tools\uv.exe') -PathType Leaf)) { throw 'uv was not isolated' }

    $boundedLimit = 256
    $boundedSecret = 'bounded-secret-value'
    $captureFixture = Join-Path $root 'bounded-capture-selection'
    $symlinkTarget = $null
    $outsideCaptureRoot = $null
    $captureReader = $null
    $originalBoundedSecret = [Environment]::GetEnvironmentVariable('DC_E2E_TEST_SECRET')
    try {
        $env:DC_E2E_TEST_SECRET = $boundedSecret
        $headerSecret = 'header-bearer-secret'
        $inlineEqualsSecret = 'inline-equals-bearer-secret'
        $inlineColonSecret = 'inline-colon-bearer-secret'
        $jsonSecret = 'json-bearer-secret'
        $jsonApiKeySecret = 'json-api-key-secret'
        $redactionProbe = @(
            "Authorization: Bearer $headerSecret",
            "trace authorization=Bearer $inlineEqualsSecret status=preserve",
            "trace Authorization: Bearer $inlineColonSecret status=preserve",
            ('{"authorization": "Bearer ' + $jsonSecret + '", "status": "preserve"}'),
            ('{"api_key": "' + $jsonApiKeySecret + '", "status": "preserve"}'),
            "environment-secret=$boundedSecret"
        ) -join [Environment]::NewLine
        $redactedProbe = Protect-WindowsNativeText $redactionProbe
        if ($redactedProbe.Contains($headerSecret) -or
            $redactedProbe.Contains($inlineEqualsSecret) -or
            $redactedProbe.Contains($inlineColonSecret) -or
            $redactedProbe.Contains($jsonSecret) -or
            $redactedProbe.Contains($jsonApiKeySecret) -or
            $redactedProbe.Contains($boundedSecret)) {
            throw 'native diagnostic redaction leaked a header, JSON, or environment secret'
        }
        if (-not $redactedProbe.Contains('Authorization: ***REDACTED***') -or
            -not $redactedProbe.Contains('trace authorization=***REDACTED*** status=preserve') -or
            -not $redactedProbe.Contains('trace Authorization: ***REDACTED*** status=preserve') -or
            -not $redactedProbe.Contains('{"authorization": "***REDACTED***", "status": "preserve"}') -or
            -not $redactedProbe.Contains('{"api_key": "***REDACTED***", "status": "preserve"}') -or
            -not $redactedProbe.Contains('environment-secret=***REDACTED***')) {
            throw 'native diagnostic redaction damaged structure or omitted a supported credential form'
        }

        $boundedInput = 'HEAD authorization=' + $boundedSecret + ' ' +
            ('unicode-漢🚀-' * 80) + 'TAIL decisive failure'
        $bounded = Limit-WindowsNativeText $boundedInput $boundedLimit
        $boundedBytes = [Text.Encoding]::UTF8.GetByteCount($bounded)
        if ($boundedBytes -gt $boundedLimit) {
            throw "bounded native text exceeded ${boundedLimit} UTF-8 bytes: $boundedBytes"
        }
        if (-not $bounded.StartsWith('HEAD authorization=***REDACTED***') -or
            -not $bounded.EndsWith('TAIL decisive failure')) {
            throw 'bounded native text did not retain both diagnostic head and failure tail'
        }
        if ($bounded -notmatch '(?m)^\[truncated\]$' -or
            $bounded.Contains($boundedSecret) -or $bounded.Contains([char]0xFFFD)) {
            throw 'bounded native text lost truncation, redaction, or UTF-8 integrity guarantees'
        }

        $goTestJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/pkg'
                Test = 'TestPassing'
                Output = "passing output must not be retained`n"
            },
            [pscustomobject]@{
                Action = 'pass'
                Package = 'example.invalid/pkg'
                Test = 'TestPassing'
                Elapsed = 0.01
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/pkg'
                Test = 'TestFailing'
                Output = "Authorization: Bearer $headerSecret`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/pkg'
                Test = 'TestFailing'
                Output = "fixture assertion failed`n"
            },
            [pscustomobject]@{
                Action = 'fail'
                Package = 'example.invalid/pkg'
                Test = 'TestFailing'
                Elapsed = 1.25
            },
            [pscustomobject]@{
                Action = 'fail'
                Package = 'example.invalid/pkg'
                Elapsed = 1.30
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/pkg'
                Output = "panic: package stopped after the test failure`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/pkg'
                Output = "goroutine 1 [running]:`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/crash'
                Test = 'TestActiveWhenProcessStopped'
                Output = "active test before package termination`n"
            },
            [pscustomobject]@{
                Action = 'fail'
                Package = 'example.invalid/crash'
            }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress }
        $goTestSummary = Get-GoTestFailureSummary (
            $goTestJson -join [Environment]::NewLine
        ) 1024
        if (-not $goTestSummary.Contains(
            '--- FAIL: TestFailing (example.invalid/pkg) [1.25s]'
        ) -or -not $goTestSummary.Contains('fixture assertion failed') -or
            -not $goTestSummary.Contains('panic: package stopped after the test failure') -or
            -not $goTestSummary.Contains('goroutine 1 [running]') -or
            -not $goTestSummary.Contains('FAIL package example.invalid/crash') -or
            -not $goTestSummary.Contains('active test before package termination') -or
            $goTestSummary.Contains('passing output must not be retained') -or
            $goTestSummary.Contains($headerSecret) -or
            -not $goTestSummary.Contains('Authorization: ***REDACTED***') -or
            [Text.Encoding]::UTF8.GetByteCount($goTestSummary) -gt 1024) {
            throw 'structured Go test summary lost failure identity, focus, redaction, or bounds'
        }

        # A long assertion line followed by Go's end-of-test marker keeps its
        # text in the bounded summary (rel-1-0-6:GAP-0840).
        $longAssertion = 'ASSERT-HEAD ' + ('detail ' * 140) + 'ASSERT-TAIL'
        $assertionJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/assertion'
                Test = 'TestLongAssertion'
                Output = "=== RUN   TestLongAssertion`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/assertion'
                Test = 'TestLongAssertion'
                Output = "    fixture_test.go:1: $longAssertion`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/assertion'
                Test = 'TestLongAssertion'
                Output = "--- FAIL: TestLongAssertion (0.32s)`n"
            },
            [pscustomobject]@{
                Action = 'fail'
                Package = 'example.invalid/assertion'
                Test = 'TestLongAssertion'
                Elapsed = 0.32
            }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress }
        $assertionSummary = Get-GoTestFailureSummary (
            $assertionJson -join [Environment]::NewLine
        )
        if (-not $assertionSummary.Contains('ASSERT-HEAD') -or
            -not $assertionSummary.Contains('ASSERT-TAIL')) {
            throw 'Go test summary lost a long assertion line to the end-of-test marker'
        }

        $runtimeJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/runtime'
                Test = 'TestPassing'
                Output = "passing output stays out of a package summary`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/runtime'
                Test = 'TestPassing'
                Output = "panic: handled in a passing test`n"
            },
            [pscustomobject]@{
                Action = 'pass'
                Package = 'example.invalid/runtime'
                Test = 'TestPassing'
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/runtime'
                Output = "fatal error: fixture runtime stopped`n"
            }
        )
        $runtimeJson += @(1..96 | ForEach-Object {
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/runtime'
                Output = "stack frame $_ $('x' * 128)`n"
            }
        })
        $runtimeJson += [pscustomobject]@{
            Action = 'fail'
            Package = 'example.invalid/runtime'
        }
        $runtimeSummary = Get-GoTestFailureSummary (
            ($runtimeJson | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join [Environment]::NewLine
        ) 4096
        if (-not $runtimeSummary.Contains('fatal error: fixture runtime stopped') -or
            $runtimeSummary.Contains('passing output stays out of a package summary') -or
            $runtimeSummary.Contains('panic: handled in a passing test') -or
            [Text.Encoding]::UTF8.GetByteCount($runtimeSummary) -gt 4096) {
            throw 'structured Go test summary lost the runtime header or retained a passing test'
        }

        $activeTestJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/active'
                Test = 'TestActiveAtTermination'
                Output = "panic: fixture process stopped during an active test`n"
            }
        )
        $activeTestJson += @(1..96 | ForEach-Object {
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/active'
                Output = "stack frame $_ $('x' * 128)`n"
            }
        })
        $activeTestJson += [pscustomobject]@{
            Action = 'fail'
            Package = 'example.invalid/active'
        }
        $activeTestEvents = ($activeTestJson | ForEach-Object {
            $_ | ConvertTo-Json -Compress
        }) -join [Environment]::NewLine
        foreach ($limit in @(4096, 262144)) {
            $activeTestSummary = Get-GoTestFailureSummary $activeTestEvents $limit
            if (-not $activeTestSummary.Contains('panic: fixture process stopped during an active test') -or
                -not $activeTestSummary.Contains('FAIL package example.invalid/active') -or
                [Text.Encoding]::UTF8.GetByteCount($activeTestSummary) -gt $limit) {
                throw 'structured Go test summary lost an active test runtime header'
            }
        }

        $signalJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/signal'
                Output = "fatal error: unexpected signal during runtime execution`n"
            },
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/signal'
                Output = "[signal 0xc0000005 code=0x0 addr=0x6 pc=0x7ff623ad40ec]`n"
            }
        )
        $signalJson += @(1..96 | ForEach-Object {
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/signal'
                Output = "runtime frame $_ $('x' * 128)`n"
            }
        })
        $signalJson += [pscustomobject]@{
            Action = 'fail'
            Package = 'example.invalid/signal'
        }
        $signalEvents = ($signalJson | ForEach-Object {
            $_ | ConvertTo-Json -Compress
        }) -join [Environment]::NewLine
        foreach ($limit in @(4096, 262144)) {
            $signalSummary = Get-GoTestFailureSummary $signalEvents $limit
            if (-not $signalSummary.Contains('fatal error: unexpected signal during runtime execution') -or
                -not $signalSummary.Contains('[signal 0xc0000005 code=0x0 addr=0x6') -or
                -not $signalSummary.Contains('FAIL package example.invalid/signal') -or
                [Text.Encoding]::UTF8.GetByteCount($signalSummary) -gt $limit) {
                throw 'structured Go test summary lost a runtime fault signal line'
            }
        }

        foreach ($variant in @(
            @{ Name = 'many'; Count = 12; Pad = 0 },
            @{ Name = 'long'; Count = 2; Pad = 480 }
        )) {
            $fullQueueJson = [Collections.Generic.List[object]]::new()
            $fullQueueJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/fullqueue'; Test = 'TestActive'
                Output = "panic: benign diagnostic in active test`n"
            })
            $fullQueueJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/fullqueue'; Test = 'TestActive'
                Output = "fatal error: unexpected signal during runtime execution`n"
            })
            $fullQueueJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/fullqueue'; Test = 'TestActive'
                Output = "[signal 0xc0000005 code=0x0 addr=0x6]`n"
            })
            for ($i = 0; $i -lt $variant.Count; $i++) {
                $fullQueueJson.Add([pscustomobject]@{
                    Action = 'output'; Package = 'example.invalid/fullqueue'; Test = 'TestActive'
                    Output = "panic: later goroutine $i $('x' * $variant.Pad)`n"
                })
            }
            for ($i = 0; $i -lt 96; $i++) {
                $fullQueueJson.Add([pscustomobject]@{
                    Action = 'output'; Package = 'example.invalid/fullqueue'; Test = 'TestActive'
                    Output = "stack frame $i $('x' * 128)`n"
                })
            }
            $fullQueueJson.Add([pscustomobject]@{ Action = 'fail'; Package = 'example.invalid/fullqueue' })
            $fullQueueEvents = ($fullQueueJson | ForEach-Object {
                $_ | ConvertTo-Json -Compress
            }) -join [Environment]::NewLine
            foreach ($limit in @(4096, 262144)) {
                $fullQueueSummary = Get-GoTestFailureSummary $fullQueueEvents $limit
                if (-not $fullQueueSummary.Contains('fatal error: unexpected signal during runtime execution') -or
                    -not $fullQueueSummary.Contains('[signal 0xc0000005 code=0x0 addr=0x6]') -or
                    -not $fullQueueSummary.Contains('FAIL package example.invalid/fullqueue') -or
                    [Text.Encoding]::UTF8.GetByteCount($fullQueueSummary) -gt $limit) {
                    throw "structured Go test summary let later headers ($($variant.Name)) push out the runtime fault"
                }
            }
        }

        # Earlier fixture text that looks like a runtime fault must not stand
        # in for the final crash dump.
        $decoyJson = [Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt 4; $i++) {
            $decoyJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
                Output = "fatal error: child fixture diagnostic $i`n"
            })
            $decoyJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
                Output = "[signal 0xc0000094 fixture $i]`n"
            })
        }
        for ($i = 0; $i -lt 8; $i++) {
            $decoyJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
                Output = "fixture output $i`n"
            })
        }
        for ($i = 0; $i -lt 4; $i++) {
            $decoyJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
                Output = "fatal error: child fixture diagnostic again $i`n"
            })
        }
        $decoyJson.Add([pscustomobject]@{
            Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
            Output = "fatal error: unexpected signal during runtime execution`n"
        })
        $decoyJson.Add([pscustomobject]@{
            Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
            Output = "[signal 0xc0000005 code=0x0 addr=0x6]`n"
        })
        for ($i = 0; $i -lt 96; $i++) {
            $decoyJson.Add([pscustomobject]@{
                Action = 'output'; Package = 'example.invalid/decoy'; Test = 'TestActive'
                Output = "stack frame $i $('x' * 128)`n"
            })
        }
        $decoyJson.Add([pscustomobject]@{ Action = 'fail'; Package = 'example.invalid/decoy' })
        $decoyEvents = ($decoyJson | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join [Environment]::NewLine
        foreach ($limit in @(4096, 262144)) {
            $decoySummary = Get-GoTestFailureSummary $decoyEvents $limit
            $reserved = ($decoySummary -split "`r?`n" | Select-Object -Skip 1 -First 6) -join "`n"
            if (-not $reserved.Contains('runtime fault in package example.invalid/decoy:') -or
                -not $reserved.Contains('fatal error: unexpected signal during runtime execution') -or
                -not $reserved.Contains('[signal 0xc0000005 code=0x0 addr=0x6]') -or
                $reserved.Contains('fixture 0]') -or $reserved.Contains('child fixture diagnostic 0') -or
                [Text.Encoding]::UTF8.GetByteCount($decoySummary) -gt $limit) {
                throw 'structured Go test summary let fixture diagnostics stand in for the final crash dump'
            }
        }

        # Output from a still-running child between the fatal line and its
        # signal must not split them, and an earlier fixture fault before the
        # crash must still be replaced.
        foreach ($tagged in @('TestActive', '')) {
            $splitJson = [Collections.Generic.List[object]]::new()
            foreach ($text in @(
                "fatal error: child fixture diagnostic`n",
                "ordinary fixture output`n",
                "fatal error: unexpected signal during runtime execution`n",
                "ordinary output from a still-running child`n",
                "[signal 0xc0000005 code=0x0 addr=0x6]`n"
            )) {
                $splitJson.Add([pscustomobject]@{
                    Action = 'output'; Package = 'example.invalid/split'; Test = $tagged; Output = $text
                })
            }
            for ($i = 0; $i -lt 96; $i++) {
                $splitJson.Add([pscustomobject]@{
                    Action = 'output'; Package = 'example.invalid/split'; Test = $tagged
                    Output = "stack frame $i $('x' * 128)`n"
                })
            }
            $splitJson.Add([pscustomobject]@{ Action = 'fail'; Package = 'example.invalid/split' })
            $splitEvents = ($splitJson | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join [Environment]::NewLine
            foreach ($limit in @(4096, 262144)) {
                $splitSummary = Get-GoTestFailureSummary $splitEvents $limit
                $reserved = ($splitSummary -split "`r?`n" | Select-Object -Skip 1 -First 5) -join "`n"
                if (-not $reserved.Contains('fatal error: unexpected signal during runtime execution') -or
                    -not $reserved.Contains('[signal 0xc0000005 code=0x0 addr=0x6]') -or
                    $reserved.Contains('child fixture diagnostic') -or
                    [Text.Encoding]::UTF8.GetByteCount($splitSummary) -gt $limit) {
                    throw "structured Go test summary split the fatal line from its signal (test='$tagged')"
                }
            }
        }

        $laterHeaderJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/later'
                Test = 'TestActiveAtTermination'
                Output = "panic: earlier diagnostic line`n"
            }
        )
        $laterHeaderJson += @(1..96 | ForEach-Object {
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/later'
                Test = 'TestActiveAtTermination'
                Output = "earlier frame $_ $('x' * 128)`n"
            }
        })
        $laterHeaderJson += [pscustomobject]@{
            Action = 'output'
            Package = 'example.invalid/later'
            Test = 'TestActiveAtTermination'
            Output = "fatal error: later package runtime failure`n"
        }
        $laterHeaderJson += [pscustomobject]@{
            Action = 'output'
            Package = 'example.invalid/later'
            Test = 'TestActiveAtTermination'
            Output = "panic: later diagnostic line`n"
        }
        $laterHeaderJson += @(1..96 | ForEach-Object {
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/later'
                Test = 'TestActiveAtTermination'
                Output = "later frame $_ $('x' * 128)`n"
            }
        })
        $laterHeaderJson += [pscustomobject]@{
            Action = 'fail'
            Package = 'example.invalid/later'
        }
        $laterHeaderEvents = ($laterHeaderJson | ForEach-Object {
            $_ | ConvertTo-Json -Compress
        }) -join [Environment]::NewLine
        foreach ($limit in @(4096, 262144)) {
            $laterHeaderSummary = Get-GoTestFailureSummary $laterHeaderEvents $limit
            if (-not $laterHeaderSummary.Contains('panic: earlier diagnostic line') -or
                -not $laterHeaderSummary.Contains('fatal error: later package runtime failure') -or
                -not $laterHeaderSummary.Contains('panic: later diagnostic line') -or
                -not $laterHeaderSummary.Contains('FAIL package example.invalid/later') -or
                [Text.Encoding]::UTF8.GetByteCount($laterHeaderSummary) -gt $limit) {
                throw 'structured Go test summary lost a later package runtime header'
            }
        }

        $passingPackageJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/passing'
                Test = 'TestPassing'
                Output = "panic: handled in a passing test`n"
            },
            [pscustomobject]@{
                Action = 'pass'
                Package = 'example.invalid/passing'
                Test = 'TestPassing'
            },
            [pscustomobject]@{
                Action = 'pass'
                Package = 'example.invalid/passing'
            }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress }
        if (Get-GoTestFailureSummary ($passingPackageJson -join [Environment]::NewLine) 4096) {
            throw 'structured Go test summary retained a passing package'
        }

        $largeGoTestJson = @(
            [pscustomobject]@{
                Action = 'output'
                Package = 'example.invalid/large'
                Test = 'TestOversizedOutput'
                Output = (('x' * 1048576) + "`nretained-large-output-tail`n")
            },
            [pscustomobject]@{
                Action = 'fail'
                Package = 'example.invalid/large'
                Test = 'TestOversizedOutput'
            }
        )
        $largeGoTestJson += [pscustomobject]@{
            Action = 'output'
            Package = 'example.invalid/package-0'
            Output = "panic: test timed out after 20m0s`n"
        }
        $largeGoTestJson += [pscustomobject]@{
            Action = 'output'
            Package = 'example.invalid/package-0'
            Output = "goroutine 1 [chan receive]:`n"
        }
        foreach ($index in 0..140) {
            $largeGoTestJson += [pscustomobject]@{
                Action = 'fail'
                Package = "example.invalid/package-$index"
            }
        }
        $largeGoTestSummary = Get-GoTestFailureSummary (
            @($largeGoTestJson | ForEach-Object {
                $_ | ConvertTo-Json -Compress
            }) -join [Environment]::NewLine
        ) 4096
        if ([Text.Encoding]::UTF8.GetByteCount($largeGoTestSummary) -gt 4096 -or
            -not $largeGoTestSummary.Contains('retained-large-output-tail') -or
            -not $largeGoTestSummary.Contains('panic: test timed out after 20m0s') -or
            -not $largeGoTestSummary.Contains('goroutine 1 [chan receive]') -or
            -not $largeGoTestSummary.Contains('[additional failed packages omitted]')) {
            throw 'structured Go test summary buffered oversized output or lost bounded omission evidence'
        }

        [IO.Directory]::CreateDirectory($captureFixture) | Out-Null
        $boundedPath = Join-Path $captureFixture 'go-test.log'
        Write-BoundedText $boundedPath $boundedInput $boundedLimit
        if ([IO.FileInfo]::new($boundedPath).Length -gt $boundedLimit) {
            throw 'bounded diagnostic file is too large for native capture'
        }
        $goTestSummaryPath = Join-Path $captureFixture 'go-test-failure-summary.log'
        Write-BoundedText $goTestSummaryPath $goTestSummary 262144
        foreach ($index in 0..30) {
            Write-BoundedText (Join-Path $captureFixture ("00-before-go-test-{0:D2}.log" -f $index)) 'decoy'
        }
        $oversizedPath = Join-Path $captureFixture '00-oversized.log'
        $oversized = [IO.File]::Open(
            $oversizedPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try { $oversized.SetLength(1048577) } finally { $oversized.Dispose() }
        $outsideCaptureRoot = Join-Path ([IO.Path]::GetTempPath()) (
            'defenseclaw-native-capture-outside-' + [guid]::NewGuid().ToString('N')
        )
        [IO.Directory]::CreateDirectory($outsideCaptureRoot) | Out-Null
        $symlinkTarget = Join-Path $outsideCaptureRoot 'outside-capture-secret.bin'
        $symlinkPath = Join-Path $captureFixture 'doctor.log'
        Set-Content -LiteralPath $symlinkTarget -Value 'sensitive diagnostic fixture' -NoNewline
        New-WindowsNativeFixtureReparsePoint $symlinkPath $symlinkTarget $outsideCaptureRoot | Out-Null

        $captureFiles = @(Get-WindowsNativeCaptureFiles $root)
        if (-not ($captureFiles | Where-Object {
            $_.FullName.Equals($boundedPath, [StringComparison]::OrdinalIgnoreCase)
        })) {
            throw 'bounded go-test.log was not prioritized into native capture'
        }
        if (-not ($captureFiles | Where-Object {
            $_.FullName.Equals($goTestSummaryPath, [StringComparison]::OrdinalIgnoreCase)
        })) {
            throw 'bounded Go failure summary was not prioritized into native capture'
        }
        if ($captureFiles | Where-Object {
            $_.FullName.Equals($oversizedPath, [StringComparison]::OrdinalIgnoreCase)
        }) {
            throw 'oversized diagnostic bypassed the native capture size guard'
        }
        if ($captureFiles | Where-Object {
            $_.FullName.Equals($symlinkPath, [StringComparison]::OrdinalIgnoreCase)
        }) {
            throw 'reparse-point diagnostic bypassed the native capture symlink guard'
        }

        $captureReader = [DefenseClaw.DisposableFileGuard]::OpenRootedReader($captureFixture)
        $guardedBoundedText = $captureReader.ReadBoundedUtf8($boundedPath, 1048576)
        if ($guardedBoundedText -cne [IO.File]::ReadAllText($boundedPath)) {
            throw 'capture retained-root reader changed a verified regular diagnostic'
        }
        $leafSwapRoot = Join-Path $captureFixture 'leaf-swap'
        [IO.Directory]::CreateDirectory($leafSwapRoot) | Out-Null
        $leafSwapPath = Join-Path $leafSwapRoot 'driver.log'
        Set-Content -LiteralPath $leafSwapPath -Value 'safe diagnostic fixture' -NoNewline
        $leafCandidate = @(Get-WindowsNativeCaptureFiles $leafSwapRoot) |
            Where-Object {
                $_.FullName.Equals($leafSwapPath, [StringComparison]::OrdinalIgnoreCase)
            } |
            Select-Object -First 1
        if ($null -eq $leafCandidate) {
            throw 'capture leaf-swap fixture was not selected before replacement'
        }
        [IO.File]::Delete($leafSwapPath)
        New-WindowsNativeFixtureReparsePoint $leafSwapPath $symlinkTarget $outsideCaptureRoot | Out-Null
        $leafSwapRejected = $false
        try {
            $null = $captureReader.ReadBoundedUtf8($leafCandidate.FullName, 1048576)
        } catch {
            $leafSwapRejected = $true
        }
        if (-not $leafSwapRejected) {
            throw 'capture followed a leaf replaced by a reparse point after enumeration'
        }

        $ancestorSwapRoot = Join-Path $captureFixture 'ancestor-swap'
        [IO.Directory]::CreateDirectory($ancestorSwapRoot) | Out-Null
        $ancestorSwapPath = Join-Path $ancestorSwapRoot 'doctor.log'
        Set-Content -LiteralPath $ancestorSwapPath -Value 'safe diagnostic fixture' -NoNewline
        $ancestorCandidate = @(Get-WindowsNativeCaptureFiles $ancestorSwapRoot) |
            Where-Object {
                $_.FullName.Equals($ancestorSwapPath, [StringComparison]::OrdinalIgnoreCase)
            } |
            Select-Object -First 1
        if ($null -eq $ancestorCandidate) {
            throw 'capture ancestor-swap fixture was not selected before replacement'
        }
        Set-Content -LiteralPath (Join-Path $outsideCaptureRoot 'doctor.log') `
            -Value 'outside diagnostic fixture' -NoNewline
        Remove-SafeDisposableTree -Path $ancestorSwapRoot -Root $captureFixture
        New-Item -ItemType Junction -Path $ancestorSwapRoot -Target $outsideCaptureRoot -ErrorAction Stop | Out-Null
        $ancestorSwapRejected = $false
        try {
            $null = $captureReader.ReadBoundedUtf8($ancestorCandidate.FullName, 1048576)
        } catch {
            $ancestorSwapRejected = $true
        }
        if (-not $ancestorSwapRejected) {
            throw 'capture followed a replaced ancestor outside its retained root'
        }
    } finally {
        [Environment]::SetEnvironmentVariable('DC_E2E_TEST_SECRET', $originalBoundedSecret)
        if ($null -ne $captureReader) {
            $captureReader.Dispose()
        }
        if (Test-Path -LiteralPath $captureFixture) {
            Remove-SafeDisposableTree -Path $captureFixture -Root $root
        }
        if ($outsideCaptureRoot -and (Test-Path -LiteralPath $outsideCaptureRoot)) {
            Remove-SafeDisposableTree -Path $outsideCaptureRoot -Root $outsideCaptureRoot
        }
    }

    $healthyOutput = [Threading.Tasks.TaskCompletionSource[string]]::new()
    $healthyOutput.SetResult('complete')
    $faultedOutput = [Threading.Tasks.TaskCompletionSource[string]]::new()
    $faultedOutput.SetException([IO.IOException]::new('injected output read failure'))
    if (-not (Test-WindowsNativeOutputTasksHealthy $healthyOutput.Task $healthyOutput.Task)) {
        throw 'native process helper rejected completed redirected output tasks'
    }
    if (Test-WindowsNativeOutputTasksHealthy $faultedOutput.Task $healthyOutput.Task) {
        throw 'native process helper accepted a faulted redirected output task'
    }

    $pwsh = (Get-Process -Id $PID).Path
    $mock = Join-Path $WorkspaceRoot 'scripts\live-connector-e2e\testdata\windows-mock.ps1'
    $processTestRoot = Join-Path $root 'native-process-timeout-test'
    $unrelatedRoot = Join-Path $processTestRoot 'unrelated'
    $drainRoot = Join-Path $processTestRoot 'drain'
    foreach ($path in @($unrelatedRoot, $drainRoot)) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
    $unrelated = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $unrelatedRoot
    ) -PassThru -WindowStyle Hidden
    try {
        $unrelatedStarted = $unrelated.StartTime.ToUniversalTime()
        $timedOut = $false
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-WindowsNativeProcess $pwsh @(
                '-NoProfile', '-File', $mock, '-Action', 'drain-timeout', '-StateRoot', $drainRoot
            ) -TimeoutSeconds 5 | Out-Null
        } catch {
            $timedOut = $_.Exception.Message -match 'timed out after 5s'
        } finally {
            $stopwatch.Stop()
        }
        if (-not $timedOut) { throw 'native process helper did not bound inherited redirected handles' }
        if ($stopwatch.Elapsed -ge [TimeSpan]::FromSeconds(15)) {
            throw "native process helper exceeded its bounded timeout cleanup: $($stopwatch.Elapsed)"
        }
        $childPidPath = Join-Path $drainRoot 'drain-child.pid'
        if (-not (Test-Path -LiteralPath $childPidPath -PathType Leaf)) {
            throw 'native process helper timeout child did not start'
        }
        $childPid = [int][IO.File]::ReadAllText($childPidPath)
        if ($null -ne (Get-Process -Id $childPid -ErrorAction SilentlyContinue)) {
            throw "native process helper left its exact descendant running: $childPid"
        }
        $unrelatedLive = Get-Process -Id $unrelated.Id -ErrorAction SilentlyContinue
        if ($null -eq $unrelatedLive -or
            [Math]::Abs(($unrelatedLive.StartTime.ToUniversalTime() - $unrelatedStarted).TotalMilliseconds) -ge 1) {
            throw 'native process helper stopped an unrelated same-image process'
        }
    } finally {
        Stop-Process -Id $unrelated.Id -Force -ErrorAction SilentlyContinue
        $unrelated.Dispose()
    }

    Test-WindowsSetupStandardUserLauncher $root

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
        'capture' { Invoke-Capture }
        'cleanup' { Invoke-Cleanup }
        'self-test' { Invoke-SelfTest }
    }
}
