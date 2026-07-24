# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Exercises the public Windows bootstrap against one exact sealed candidate.

.DESCRIPTION
    Native Setup derives its per-user layout from token-bound Windows Known
    Folders. Environment-variable profile spoofing is intentionally unsupported.
    The parent mode therefore delegates to the repository's disposable
    standard-user launcher. Child mode runs with a real isolated profile and
    HKCU hive, installs through scripts/install.ps1, repeats the authenticated
    handoff, verifies the installed version, and proves complete uninstall.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseDir,
    [Parameter(Mandatory = $true)][string]$TargetVersion,
    [Parameter(DontShow = $true)][switch]$Child,
    [Parameter(DontShow = $true)][string]$StateRoot = "",
    [Parameter(DontShow = $true)][string]$DiagnosticsRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($TargetVersion -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
    throw "TargetVersion must be canonical X.Y.Z"
}

$ReleaseDir = (Resolve-Path -LiteralPath $ReleaseDir -ErrorAction Stop).Path
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = (& $FilePath @ArgumentList 2>&1 | Out-String -Width 32768)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output = [string]$output
    }
}

function Assert-ExactVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion
    )

    $probe = Invoke-CapturedProcess -FilePath $Executable -ArgumentList @("--version")
    if ($probe.ExitCode -ne 0) {
        throw "Version probe failed for ${Executable}:`n$($probe.Output)"
    }
    $versions = @(
        [regex]::Matches(
            $probe.Output,
            '(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])'
        ) | ForEach-Object { $_.Groups[1].Value }
    )
    if ($versions.Count -ne 1 -or $versions[0] -cne $ExpectedVersion) {
        throw "${Executable} did not report exact version ${ExpectedVersion}: $($probe.Output)"
    }
}

function Assert-BootstrapSucceeded {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    foreach ($expected in @(
        "Release checksum signature verified (Sigstore)",
        "Authenticated DefenseClawSetup-x64.exe for DefenseClaw $ExpectedVersion",
        "Starting authenticated native Setup",
        "Native DefenseClaw Setup completed successfully"
    )) {
        if ($Result.Output -notmatch [regex]::Escape($expected)) {
            throw "${Phase} did not report '$expected':`n$($Result.Output)"
        }
    }
    if ($Result.Output -notmatch (
            "Setup Authenticode signature verified" +
            "|Setup is explicitly unverified by Authenticode"
        )) {
        throw "${Phase} did not report an explicit Setup signing state:`n$($Result.Output)"
    }
    if ($Result.ExitCode -ne 0) {
        throw "${Phase} failed ($($Result.ExitCode)):`n$($Result.Output)"
    }
}

function Get-UserPathEntryCount {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$ExpectedEntry
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    return @(
        $Value.Split(
            [char[]]@(";"),
            [StringSplitOptions]::RemoveEmptyEntries
        ) | Where-Object {
            ([IO.Path]::GetFullPath($_.Trim())).TrimEnd('\').Equals(
                ([IO.Path]::GetFullPath($ExpectedEntry)).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    ).Count
}

function Wait-ForPathRemoval {
    param([Parameter(Mandatory = $true)][string]$Path)

    for ($attempt = 0; $attempt -lt 80 -and (Test-Path -LiteralPath $Path); $attempt++) {
        Start-Sleep -Milliseconds 250
    }
}

if (-not $Child) {
    if (-not $IsWindows) {
        throw "Fresh Windows release smoke requires native Windows"
    }
    if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
        throw "Fresh Windows release smoke is restricted to GitHub-hosted Windows CI"
    }
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        throw "RUNNER_TEMP is required for disposable Windows release smoke"
    }

    $helper = Join-Path $Root "scripts\invoke-windows-setup-standard-user-ci.ps1"
    $stateBase = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        Join-Path $env:RUNNER_TEMP (
            "defenseclaw-bootstrap-acceptance-" + [guid]::NewGuid().ToString("N")
        )
    } else {
        [IO.Path]::GetFullPath($StateRoot)
    }
    $helperCompleted = $false
    try {
        & $helper `
            -Mode bootstrap-acceptance `
            -ArtifactRoot $ReleaseDir `
            -StateRoot $stateBase `
            -TargetVersion $TargetVersion `
            -DiagnosticsRoot $DiagnosticsRoot `
            -TimeoutSeconds 1800
        $helperCompleted = $true
    } finally {
        $resolvedState = [IO.Path]::GetFullPath($stateBase).TrimEnd('\')
        $approvedStateBases = @(
            $env:RUNNER_TEMP,
            $env:DC_WINDOWS_NATIVE_BASE_ROOT
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
        $approvedBoundary = $approvedStateBases | Where-Object {
            $resolvedState.StartsWith(
                $_ + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            )
        } | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace([string]$approvedBoundary) -or
            -not ([IO.Path]::GetFileName($resolvedState)).StartsWith(
                "defenseclaw-bootstrap-acceptance-",
                [StringComparison]::Ordinal
            )) {
            throw "Refusing to clean unexpected bootstrap acceptance state: $resolvedState"
        }
        if (Test-Path -LiteralPath $resolvedState) {
            if ($helperCompleted) {
                Remove-Item -LiteralPath $resolvedState -Recurse -Force -ErrorAction Stop
            } else {
                Write-Warning (
                    "Disposable bootstrap state was preserved after failure: $resolvedState"
                )
            }
        }
    }
    return
}

if (-not $IsWindows) {
    throw "Disposable bootstrap acceptance child requires native Windows"
}
if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    throw "Disposable bootstrap acceptance child requires StateRoot"
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$accountName = ($identity.Name -split '\\')[-1]
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($accountName -notmatch '^dcacc[0-9a-f]{10}$' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Bootstrap acceptance child must be a disposable real Windows standard user"
}

$profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$localAppData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
if ([string]::IsNullOrWhiteSpace($profile) -or
    [string]::IsNullOrWhiteSpace($localAppData) -or
    [string]::IsNullOrWhiteSpace($env:USERPROFILE) -or
    -not ([IO.Path]::GetFullPath($env:USERPROFILE)).TrimEnd('\').Equals(
        ([IO.Path]::GetFullPath($profile)).TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Disposable bootstrap child does not have a token-bound real user profile"
}

$installer = Join-Path $PSScriptRoot "install.ps1"
$powerShell = Join-Path $PSHOME "pwsh.exe"
$cosign = Join-Path $ReleaseDir "cosign-windows-amd64.exe"
$setup = Join-Path $ReleaseDir "DefenseClawSetup-x64.exe"
$installRoot = Join-Path $localAppData "Programs\DefenseClaw"
$dataRoot = Join-Path $profile ".defenseclaw"
$cacheRoot = Join-Path $localAppData "DefenseClaw\InstallerCache"
$arpKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
$launcher = Join-Path $installRoot "bin\defenseclaw.exe"
$gateway = Join-Path $installRoot "bin\defenseclaw-gateway.exe"
$installed = $false
$userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")

foreach ($path in @(
    $installRoot,
    $dataRoot,
    $cacheRoot,
    $arpKey
)) {
    if (Test-Path -LiteralPath $path) {
        throw "Bootstrap acceptance refuses pre-existing product state: $path"
    }
}
foreach ($path in @($installer, $powerShell, $cosign, $setup)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Bootstrap acceptance input is missing: $path"
    }
}

# The supported public path has no custom home override. Setup and the
# compatibility bootstrap must agree on the account's real Known Folder.
Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue

$bootstrapArguments = @(
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    $installer,
    "-Local",
    $ReleaseDir,
    "-CosignPath",
    $cosign,
    "-Version",
    $TargetVersion,
    "-Connector",
    "none",
    "-Yes"
)

try {
    $first = Invoke-CapturedProcess `
        -FilePath $powerShell `
        -ArgumentList $bootstrapArguments
    Assert-BootstrapSucceeded `
        -Result $first `
        -ExpectedVersion $TargetVersion `
        -Phase "First public bootstrap"
    $installed = $true

    foreach ($path in @($launcher, $gateway)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Public bootstrap did not install native executable: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $arpKey)) {
        throw "Public bootstrap did not publish the per-user Installed Apps registration"
    }
    Assert-ExactVersion -Executable $launcher -ExpectedVersion $TargetVersion
    Assert-ExactVersion -Executable $gateway -ExpectedVersion $TargetVersion
    if ((Get-UserPathEntryCount `
            -Value ([Environment]::GetEnvironmentVariable("Path", "User")) `
            -ExpectedEntry (Join-Path $installRoot "bin")) -ne 1) {
        throw "Public bootstrap did not publish exactly one native user PATH entry"
    }

    $firstHashes = @(
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    $second = Invoke-CapturedProcess `
        -FilePath $powerShell `
        -ArgumentList $bootstrapArguments
    Assert-BootstrapSucceeded `
        -Result $second `
        -ExpectedVersion $TargetVersion `
        -Phase "Repeated public bootstrap"
    Assert-ExactVersion -Executable $launcher -ExpectedVersion $TargetVersion
    Assert-ExactVersion -Executable $gateway -ExpectedVersion $TargetVersion
    $secondHashes = @(
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    if (($firstHashes -join ":") -cne ($secondHashes -join ":")) {
        throw "Repeated public bootstrap changed the exact installed candidate bytes"
    }

    $uninstall = Invoke-CapturedProcess `
        -FilePath $setup `
        -ArgumentList @("/uninstall", "/quiet", "DELETEUSERDATA=1")
    if ($uninstall.ExitCode -ne 0) {
        throw "Native uninstall failed ($($uninstall.ExitCode)):`n$($uninstall.Output)"
    }
    $installed = $false
    Wait-ForPathRemoval -Path $cacheRoot
    foreach ($path in @($installRoot, $dataRoot, $cacheRoot, $arpKey)) {
        if (Test-Path -LiteralPath $path) {
            throw "Public bootstrap uninstall left managed state behind: $path"
        }
    }
    if (-not [string]::Equals(
            $userPathBefore,
            [Environment]::GetEnvironmentVariable("Path", "User"),
            [StringComparison]::Ordinal
        )) {
        throw "Public bootstrap uninstall did not restore the original user PATH exactly"
    }
    Write-Host "Fresh Windows public bootstrap passed: $TargetVersion" -ForegroundColor Green
} finally {
    if ($installed -or (Test-Path -LiteralPath $installRoot)) {
        try {
            $cleanup = Invoke-CapturedProcess `
                -FilePath $setup `
                -ArgumentList @("/uninstall", "/quiet", "DELETEUSERDATA=1")
            if ($cleanup.ExitCode -ne 0) {
                Write-Warning "Emergency native uninstall failed ($($cleanup.ExitCode))"
            }
        } catch {
            Write-Warning "Emergency native uninstall failed: $($_.Exception.Message)"
        }
    }
}
