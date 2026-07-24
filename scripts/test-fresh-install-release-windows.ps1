# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
Exercise the exact sealed candidate through install.ps1 in an isolated profile.
The second invocation must refuse before changing any installed file or attribute.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseDir,
    [Parameter(Mandatory = $true)][string]$TargetVersion,
    [switch]$SuccessPathOnly
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
$WindowsPowerShell = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
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
        [switch]$InjectPolicyCleanupFailure,
        [switch]$InjectPolicyCustodyMoveBeforeCleanup,
        [switch]$InjectFailureAfterFreshDirectoryMove
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
        $InjectPolicyCleanupFailure -or
        $InjectPolicyCustodyMoveBeforeCleanup -or
        $InjectFailureAfterFreshDirectoryMove) {
        $arguments += "-TestMode"
    }
    if ($InjectFailureBeforeShim) { $arguments += "-InjectFailureBeforeShim" }
    if ($InjectConcurrentShimBeforePublish) {
        $arguments += "-InjectConcurrentShimBeforePublish"
    }
    if ($InjectPolicyCleanupFailure) { $arguments += "-InjectPolicyCleanupFailure" }
    if ($InjectPolicyCustodyMoveBeforeCleanup) {
        $arguments += "-InjectPolicyCustodyMoveBeforeCleanup"
    }
    if ($InjectFailureAfterFreshDirectoryMove) {
        $arguments += "-InjectFailureAfterFreshDirectoryMove"
    }
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
    param(
        [string]$Phase = "fresh-install rollback",
        [string]$Context = ""
    )
    foreach ($path in @(
        $env:DEFENSECLAW_HOME,
        (Join-Path $HomeRoot ".local\bin\defenseclaw-gateway.exe"),
        (Join-Path $HomeRoot ".local\bin\defenseclaw.cmd")
    )) {
        if (Test-Path -LiteralPath $path) {
            $diagnostic = if ($Context) { "`nInstaller output:`n$Context" } else { "" }
            throw "Failed fresh install left a managed payload marker during ${Phase}: $path$diagnostic"
        }
    }
}

function Remove-InjectedPolicyResidue {
    param([Parameter(Mandatory = $true)][string]$Output)

    $match = [regex]::Match(
        $Output,
        "Last expected path: '([^']+)'\. Last cleanup error:"
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

function Remove-MovedPolicyCustodyResidue {
    param([Parameter(Mandatory = $true)][string]$Output)

    $match = [regex]::Match(
        $Output,
        "Last expected path: '([^']+)'\. Last cleanup error:"
    )
    if (-not $match.Success) {
        throw "Moved policy custody did not report its preserved canonical path:`n$Output"
    }
    $canonical = [IO.Path]::GetFullPath($match.Groups[1].Value)
    $displaced = "$canonical.installer-owned-original"
    $separator = [IO.Path]::DirectorySeparatorChar
    $tempPrefix = [IO.Path]::GetFullPath($TempRoot).TrimEnd($separator) + $separator
    if (-not $canonical.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $canonical) -notlike 'defenseclaw-install-policy-*') {
        throw "Moved policy cleanup reported an unsafe canonical path: $canonical"
    }
    if (Test-Path -LiteralPath $canonical) {
        throw "Moved policy cleanup recreated or deleted through the canonical namespace: $canonical"
    }
    if (-not (Test-Path -LiteralPath $displaced -PathType Container)) {
        throw "Creation-bound policy custody was not preserved at its moved path: $displaced"
    }
    if (@(Get-ChildItem -LiteralPath $displaced -Force).Count -eq 0) {
        throw "Preserved moved policy custody unexpectedly lost its authenticated contents"
    }
    Remove-Item -LiteralPath $displaced -Recurse -Force -ErrorAction Stop
}

try {
    [void](New-Item -ItemType Directory -Path $HomeRoot -Force)
    [void](New-Item -ItemType Directory -Path $TempRoot -Force)
    $env:USERPROFILE = $HomeRoot
    $env:HOME = $HomeRoot
    $env:DEFENSECLAW_HOME = Join-Path $HomeRoot ".defenseclaw"
    $env:TEMP = $TempRoot
    $env:TMP = $TempRoot

    $legacyHelp = (& $WindowsPowerShell -NoProfile -NonInteractive -File $Installer -Help 2>&1 |
        Out-String)
    if ($LASTEXITCODE -ne 0 -or $legacyHelp -notmatch 'DefenseClaw native Windows bootstrap') {
        throw "Windows PowerShell 5.1 could not parse/compile install.ps1:`n$legacyHelp"
    }
    $userPathBeforeFailure = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $SuccessPathOnly) {
        $legacyNativeRoot = Join-Path $TempRoot "windows-powershell-native-private"
    [void](New-Item -ItemType Directory -Path $legacyNativeRoot)
    $legacyNative = (& $WindowsPowerShell `
        -NoProfile `
        -NonInteractive `
        -File $Installer `
        -TestMode `
        -NativePrivateDirectorySelfTestRoot $legacyNativeRoot 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $legacyNative -notmatch 'Native private directory lifecycle passed' -or
        $legacyNative -notmatch 'Native snapshotted-child move-out refusal passed' -or
        $legacyNative -notmatch 'Native namespace retirement wait passed' -or
        $legacyNative -notmatch 'Native fresh directory fault boundaries passed') {
        throw "Windows PowerShell 5.1 native private lifecycle failed:`n$legacyNative"
    }
    if (@(Get-ChildItem -LiteralPath $legacyNativeRoot -Force).Count -ne 0) {
        throw "Windows PowerShell 5.1 native private lifecycle left custody behind"
    }
    [IO.Directory]::Delete($legacyNativeRoot)

    $modernNativeRoot = Join-Path $TempRoot "powershell-native-private"
    [void](New-Item -ItemType Directory -Path $modernNativeRoot)
    $modernNative = (& $PowerShell `
        -NoProfile `
        -NonInteractive `
        -File $Installer `
        -TestMode `
        -NativePrivateDirectorySelfTestRoot $modernNativeRoot 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $modernNative -notmatch 'Native private directory lifecycle passed' -or
        $modernNative -notmatch 'Native snapshotted-child move-out refusal passed' -or
        $modernNative -notmatch 'Native namespace retirement wait passed' -or
        $modernNative -notmatch 'Native fresh directory fault boundaries passed') {
        throw "PowerShell 7 native private lifecycle failed:`n$modernNative"
    }
    if (@(Get-ChildItem -LiteralPath $modernNativeRoot -Force).Count -ne 0) {
        throw "PowerShell 7 native private lifecycle left custody behind"
    }
    [IO.Directory]::Delete($modernNativeRoot)

    $mismatch = Invoke-FreshInstaller -RequestedVersion "999.999.999"
    if ($mismatch.ExitCode -eq 0 -or $mismatch.Output -notmatch 'does not match -Version') {
        throw "Manifest-version refusal did not fail inside authenticated policy setup:`n$($mismatch.Output)"
    }
    Assert-NoInstallerCustody
    if (
        (Test-Path -LiteralPath $env:DEFENSECLAW_HOME) -or
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local\bin\defenseclaw-gateway.exe")) -or
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local\bin\defenseclaw.cmd"))
    ) {
        throw "Manifest-version refusal left installed state behind"
    }

    $postMove = Invoke-FreshInstaller -InjectFailureAfterFreshDirectoryMove
    if ($postMove.ExitCode -eq 0 -or
        $postMove.Output -notmatch 'Injected fresh-install directory failure after publishing' -or
        $postMove.Output -notmatch 'rollback safety boundary did not complete' -or
        $postMove.Output -notmatch 'rollback preserved changed or concurrent state' -or
        $postMove.Output -match 'Fresh-install payload rollback completed; retry is safe') {
        throw "Post-move fresh-directory cleanup was not exact:`n$($postMove.Output)"
    }
    Assert-NoInstallerCustody
    if (Test-Path -LiteralPath $env:DEFENSECLAW_HOME) {
        Write-Host "--- post-move installer output ---" -ForegroundColor Yellow
        Write-Host $postMove.Output
        Write-Host "--- bounded residual path inventory (names and kinds only) ---" -ForegroundColor Yellow
        @(
            Get-ChildItem -LiteralPath $HomeRoot -Force -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 100
        ) | ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($HomeRoot, $_.FullName)
            $kind = if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                "reparse"
            } elseif ($_.PSIsContainer) {
                "directory"
            } else {
                "file"
            }
            Write-Host "$kind`t$relative"
        }
    }
    Assert-NoFreshPayload -Phase "post-directory-publication injection" -Context $postMove.Output
    if (Test-Path -LiteralPath (Join-Path $HomeRoot ".local")) {
        throw "Post-move fresh-directory failure left .local or bin custody behind"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Post-move fresh-directory failure changed the user PATH"
    }

    $injected = Invoke-FreshInstaller `
        -InjectFailureBeforeShim `
        -InjectPolicyCleanupFailure
    if ($injected.ExitCode -eq 0 -or
        $injected.Output -notmatch 'Injected fresh-install failure before CLI shim publication' -or
        $injected.Output -notmatch 'Injected private release-policy cleanup failure' -or
        $injected.Output -notmatch 'Gateway installed' -or
        $injected.Output -notmatch 'Installing DefenseClaw CLI' -or
        $injected.Output -notmatch 'rollback preserved changed or concurrent state' -or
        $injected.Output -notmatch 'creation-bound private directory cleanup remains incomplete' -or
        $injected.Output -match 'Fresh-install payload rollback completed; retry is safe') {
        throw "Post-venv fresh-install rollback injection was not exercised:`n$($injected.Output)"
    }
    [void](Remove-InjectedPolicyResidue -Output $injected.Output)
    Assert-NoInstallerCustody
    Assert-NoFreshPayload `
        -Phase "post-venv policy-cleanup injection" `
        -Context $injected.Output
    if (Test-Path -LiteralPath (Join-Path $HomeRoot ".local")) {
        throw "Failed fresh install left installer-created binary directories behind"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Failed fresh install changed the user PATH"
    }

    $movedCustody = Invoke-FreshInstaller `
        -InjectFailureBeforeShim `
        -InjectPolicyCustodyMoveBeforeCleanup
    if ($movedCustody.ExitCode -eq 0 -or
        $movedCustody.Output -notmatch 'Injected fresh-install failure before CLI shim publication' -or
        $movedCustody.Output -notmatch 'canonical binding was lost' -or
        $movedCustody.Output -notmatch 'current location of installer-owned custody may be unknown' -or
        $movedCustody.Output -notmatch 'Retained creation identity:' -or
        $movedCustody.Output -notmatch 'creation-bound private directory cleanup remains incomplete' -or
        $movedCustody.Output -notmatch 'rollback preserved changed or concurrent state' -or
        $movedCustody.Output -match 'Fresh-install payload rollback completed; retry is safe') {
        throw "Moved private-policy custody was not retained:`n$($movedCustody.Output)"
    }
    Remove-MovedPolicyCustodyResidue -Output $movedCustody.Output
    Assert-NoInstallerCustody
    Assert-NoFreshPayload `
        -Phase "moved policy-custody injection" `
        -Context $movedCustody.Output
    if (Test-Path -LiteralPath (Join-Path $HomeRoot ".local")) {
        throw "Moved policy custody left installer-created binary directories behind"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Moved policy custody changed the user PATH"
    }

    $collision = Invoke-FreshInstaller -InjectConcurrentShimBeforePublish
    $unclaimedShim = Join-Path $HomeRoot ".local\bin\defenseclaw.cmd"
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
        (Test-Path -LiteralPath (Join-Path $HomeRoot ".local\bin\defenseclaw-gateway.exe"))) {
        throw "Concurrent shim collision retained installer-owned gateway or venv state"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Concurrent shim collision changed the user PATH"
    }
    [IO.File]::Delete($unclaimedShim)
    [IO.Directory]::Delete((Join-Path $HomeRoot ".local\bin"))
    [IO.Directory]::Delete((Join-Path $HomeRoot ".local"))
    Assert-NoFreshPayload -Phase "concurrent shim collision" -Context $collision.Output
    }

    $first = if ($SuccessPathOnly) {
        Invoke-FreshInstaller
    } else {
        Invoke-FreshInstaller -InjectPolicyCleanupFailure
    }
    $expectedInstallDir = Join-Path $HomeRoot ".local\bin"
    if ($first.ExitCode -ne 0 -or
        $first.Output -notmatch 'DefenseClaw installed successfully' -or
        $first.Output -notmatch 'Persistent User PATH was not modified' -or
        $first.Output -notmatch "Edit environment variables for your account" -or
        -not $first.Output.Contains($expectedInstallDir) -or
        -not $first.Output.Contains("& `"$expectedInstallDir\defenseclaw.cmd`" init") -or
        $first.Output -match 'Added .* to your user PATH') {
        throw "Fresh Windows install failed ($($first.ExitCode)):`n$($first.Output)"
    }
    if ($SuccessPathOnly) {
        if ($first.Output -match 'Private release-policy cleanup was incomplete') {
            throw "Fresh Windows success path retained private policy custody:`n$($first.Output)"
        }
    } elseif ($first.Output -notmatch 'Private release-policy cleanup was incomplete') {
        throw "Fresh Windows install did not exercise policy cleanup failure:`n$($first.Output)"
    }
    if ([Environment]::GetEnvironmentVariable("Path", "User") -cne $userPathBeforeFailure) {
        throw "Modern fresh install mutated the persistent user PATH"
    }

    $cli = Join-Path $HomeRoot ".defenseclaw/.venv/Scripts/defenseclaw.exe"
    $gateway = Join-Path $HomeRoot ".local\bin\defenseclaw-gateway.exe"
    $installedBeforeCleanup = @(
        (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    if (-not $SuccessPathOnly) {
        [void](Remove-InjectedPolicyResidue -Output $first.Output)
    }
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
