# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
Exercise the exact sealed candidate through install.ps1 in an isolated profile.
The second invocation must refuse before changing any installed file or attribute.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseDir,
    [Parameter(Mandatory = $true)][string]$TargetVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($TargetVersion -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
    throw "TargetVersion must be canonical X.Y.Z"
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Installer = Join-Path $Root "scripts\install.ps1"
$ReleaseDir = (Resolve-Path -LiteralPath $ReleaseDir).Path
$PowerShell = (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
$WindowsPowerShellCommand = Get-Command powershell.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
$WindowsPowerShell = if ($WindowsPowerShellCommand) { $WindowsPowerShellCommand.Source } else { "" }
$WorkRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "defenseclaw-fresh-release-" + [guid]::NewGuid().ToString("N")
)
$HomeRoot = Join-Path $WorkRoot "home"
$TempRoot = Join-Path $WorkRoot "temp"
$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$savedEnvironment = @{}
foreach ($name in @("USERPROFILE", "HOME", "DEFENSECLAW_HOME", "TEMP", "TMP")) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Get-TreeSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $rootItem = Get-Item -LiteralPath $Path -Force
    $items = @($rootItem) + @(
        Get-ChildItem -LiteralPath $Path -Force -Recurse |
            Sort-Object -Property FullName
    )
    $rows = foreach ($item in $items) {
        $relative = if ($item.FullName -eq $rootItem.FullName) {
            "."
        } else {
            [IO.Path]::GetRelativePath($rootItem.FullName, $item.FullName).Replace('\', '/')
        }
        $row = [ordered]@{
            path = $relative
            attributes = [string]$item.Attributes
            last_write_utc_ticks = $item.LastWriteTimeUtc.Ticks
            kind = if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                "reparse"
            } elseif ($item.PSIsContainer) {
                "directory"
            } else {
                "file"
            }
        }
        if ($row["kind"] -eq "reparse") {
            $row["target"] = [string]($item.Target -join "|")
        } elseif ($row["kind"] -eq "file") {
            $row["length"] = [long]$item.Length
            $row["sha256"] = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
        [pscustomobject]$row
    }
    return ($rows | ConvertTo-Json -Compress -Depth 4)
}

function Invoke-FreshInstaller {
    param(
        [string]$RequestedVersion = $TargetVersion,
        [switch]$InjectFailureBeforeShim,
        [switch]$InjectConcurrentShimBeforePublish,
        [switch]$InjectPolicyCleanupFailure
    )
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", $Installer,
        "-Local", $ReleaseDir,
        "-Version", $RequestedVersion,
        "-Connector", "none",
        "-Yes"
    )
    if ($InjectFailureBeforeShim -or
        $InjectConcurrentShimBeforePublish -or
        $InjectPolicyCleanupFailure) {
        $arguments += "-TestMode"
    }
    if ($InjectFailureBeforeShim) { $arguments += "-InjectFailureBeforeShim" }
    if ($InjectConcurrentShimBeforePublish) {
        $arguments += "-InjectConcurrentShimBeforePublish"
    }
    if ($InjectPolicyCleanupFailure) { $arguments += "-InjectPolicyCleanupFailure" }
    $output = (& $PowerShell @arguments 2>&1 | Out-String)
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Assert-ExactVersion {
    param([Parameter(Mandatory = $true)][string]$Command)

    $output = (& $Command --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Version probe failed: $Command`n$output" }
    $versions = @(
        [regex]::Matches(
            $output,
            '(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])'
        ) | ForEach-Object { $_.Groups[1].Value }
    )
    if ($versions.Count -ne 1 -or $versions[0] -cne $TargetVersion) {
        throw "Version output did not report exact ${TargetVersion}: $output"
    }
}

function Assert-NoInstallerCustody {
    $leftovers = @(
        Get-ChildItem -LiteralPath $TempRoot -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like "defenseclaw-install-policy-*" -or
                $_.Name -like "dc-gw-*" -or
                $_.Name -like "dc-cli-*"
            }
    )
    if ($leftovers.Count -ne 0) {
        throw "Fresh Windows installer left plaintext/private custody behind: $($leftovers.FullName -join ', ')"
    }
}

function Assert-NoFreshPayload {
    foreach ($path in @(
        $env:DEFENSECLAW_HOME,
        (Join-Path $HomeRoot ".local/bin/defenseclaw-gateway.exe"),
        (Join-Path $HomeRoot ".local/bin/defenseclaw.cmd")
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "Failed fresh install left a managed payload marker: $path"
        }
    }
}

function Remove-InjectedPolicyResidue {
    param([Parameter(Mandatory = $true)][string]$Output)

    $match = [regex]::Match(
        $Output,
        "Private release-policy cleanup was incomplete; installer-owned custody remains at '([^']+)'"
    )
    if (-not $match.Success) {
        throw "Policy cleanup failure did not report its private residual path:`n$Output"
    }
    $residual = [IO.Path]::GetFullPath($match.Groups[1].Value)
    $separator = [IO.Path]::DirectorySeparatorChar
    $tempPrefix = [IO.Path]::GetFullPath($TempRoot).TrimEnd($separator) + $separator
    if (-not $residual.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $residual) -notlike 'defenseclaw-install-policy-*') {
        throw "Policy cleanup warning reported an unsafe residual path: $residual"
    }
    if (-not (Test-Path -LiteralPath $residual -PathType Container)) {
        throw "Policy cleanup warning residual does not exist: $residual"
    }
    Remove-Item -LiteralPath $residual -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $residual) {
        throw "Could not retire injected policy cleanup residual: $residual"
    }
    return $residual
}

try {
    [void](New-Item -ItemType Directory -Path $HomeRoot -Force)
    [void](New-Item -ItemType Directory -Path $TempRoot -Force)
    $env:USERPROFILE = $HomeRoot
    $env:HOME = $HomeRoot
    $env:DEFENSECLAW_HOME = Join-Path $HomeRoot ".defenseclaw"
    $env:TEMP = $TempRoot
    $env:TMP = $TempRoot

    if ($WindowsPowerShell) {
        $legacyHelp = (& $WindowsPowerShell -NoProfile -NonInteractive -File $Installer -Help 2>&1 |
            Out-String)
        if ($LASTEXITCODE -ne 0 -or $legacyHelp -notmatch 'DefenseClaw Installer \(Windows\)') {
            throw "Windows PowerShell 5.1 could not parse/compile install.ps1:`n$legacyHelp"
        }
    }

    $mismatch = Invoke-FreshInstaller -RequestedVersion "999.999.999"
    if ($mismatch.ExitCode -eq 0 -or $mismatch.Output -notmatch 'does not match -Version') {
        throw "Manifest-version refusal did not fail inside authenticated policy setup:`n$($mismatch.Output)"
    }
    Assert-NoInstallerCustody
    if (
        (Test-Path -LiteralPath $env:DEFENSECLAW_HOME) -or
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local/bin/defenseclaw-gateway.exe")) -or
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local/bin/defenseclaw.cmd"))
    ) {
        throw "Manifest-version refusal left installed state behind"
    }

    $userPathBeforeFailure = [Environment]::GetEnvironmentVariable("Path", "User")
    $injected = Invoke-FreshInstaller `
        -InjectFailureBeforeShim `
        -InjectPolicyCleanupFailure
    if ($injected.ExitCode -eq 0 -or
        $injected.Output -notmatch 'Injected fresh-install failure before CLI shim publication' -or
        $injected.Output -notmatch 'Injected private release-policy cleanup failure' -or
        $injected.Output -notmatch 'Gateway installed' -or
        $injected.Output -notmatch 'Installing DefenseClaw CLI' -or
        $injected.Output -notmatch 'Fresh-install payload rollback completed; retry is safe') {
        throw "Post-venv fresh-install rollback injection was not exercised:`n$($injected.Output)"
    }
    [void](Remove-InjectedPolicyResidue -Output $injected.Output)
    Assert-NoInstallerCustody
    Assert-NoFreshPayload
    if (Test-Path -LiteralPath (Join-Path $HomeRoot ".local")) {
        throw "Failed fresh install left installer-created binary directories behind"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Failed fresh install changed the user PATH"
    }

    $collision = Invoke-FreshInstaller -InjectConcurrentShimBeforePublish
    $unclaimedShim = Join-Path $HomeRoot ".local/bin/defenseclaw.cmd"
    if ($collision.ExitCode -eq 0 -or
        $collision.Output -notmatch 'CLI appeared during installation; it was preserved' -or
        $collision.Output -notmatch 'rollback preserved changed or concurrent state') {
        throw "Concurrent fresh-install shim collision was not preserved:`n$($collision.Output)"
    }
    Assert-NoInstallerCustody
    if (-not (Test-Path -LiteralPath $unclaimedShim -PathType Leaf)) {
        throw "Concurrent unclaimed shim disappeared during rollback"
    }
    $unclaimedBytes = [IO.File]::ReadAllText($unclaimedShim, [Text.Encoding]::ASCII)
    if ($unclaimedBytes -cne "@echo off`r`necho concurrent-unclaimed-shim`r`n") {
        throw "Concurrent unclaimed shim bytes changed during rollback"
    }
    if ((Test-Path -LiteralPath $env:DEFENSECLAW_HOME) -or
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local/bin/defenseclaw-gateway.exe"))) {
        throw "Concurrent shim collision retained installer-owned gateway or venv state"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Concurrent shim collision changed the user PATH"
    }
    [IO.File]::Delete($unclaimedShim)
    [IO.Directory]::Delete((Join-Path $HomeRoot ".local/bin"))
    [IO.Directory]::Delete((Join-Path $HomeRoot ".local"))
    Assert-NoFreshPayload

    $first = Invoke-FreshInstaller -InjectPolicyCleanupFailure
    if ($first.ExitCode -ne 0 -or
        $first.Output -notmatch 'DefenseClaw installed successfully' -or
        $first.Output -notmatch 'Private release-policy cleanup was incomplete') {
        throw "Fresh Windows install did not survive policy cleanup failure ($($first.ExitCode)):`n$($first.Output)"
    }

    $cli = Join-Path $HomeRoot ".defenseclaw/.venv/Scripts/defenseclaw.exe"
    $gateway = Join-Path $HomeRoot ".local/bin/defenseclaw-gateway.exe"
    $installedBeforeCleanup = @(
        (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    [void](Remove-InjectedPolicyResidue -Output $first.Output)
    $installedAfterCleanup = @(
        (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    if (($installedBeforeCleanup -join ':') -cne ($installedAfterCleanup -join ':')) {
        throw "Policy cleanup failure or residual retirement changed installed bytes"
    }
    Assert-NoInstallerCustody
    Assert-ExactVersion -Command $cli
    Assert-ExactVersion -Command $gateway
    $before = Get-TreeSnapshot -Path $HomeRoot
    $userPathBeforeSecond = [Environment]::GetEnvironmentVariable("Path", "User")

    $second = Invoke-FreshInstaller
    if ($second.ExitCode -eq 0) { throw "Second fresh-installer invocation unexpectedly succeeded" }
    if ($second.Output -notmatch 'existing DefenseClaw installation' -or
        $second.Output -notmatch 'No changes were made') {
        throw "Second invocation did not report the pre-mutation refusal:`n$($second.Output)"
    }
    if ($second.Output -match 'Detecting platform') {
        throw "Second invocation crossed the fresh-install preflight boundary"
    }
    $after = Get-TreeSnapshot -Path $HomeRoot
    if ($after -cne $before) { throw "Second fresh-installer invocation changed installed state" }
    $userPathAfterSecond = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPathAfterSecond -cne $userPathBeforeSecond) {
        throw "Second fresh-installer invocation changed the user PATH"
    }
    Assert-NoInstallerCustody

    Write-Host "Fresh Windows install passed: $TargetVersion" -ForegroundColor Green
} finally {
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }
    if (Test-Path -LiteralPath $WorkRoot) {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
