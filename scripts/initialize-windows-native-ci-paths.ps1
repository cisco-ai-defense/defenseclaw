# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$')]
    [string]$Leaf,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
    [string]$DiagnosticsLeaf,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
    [string]$ArtifactLeaf = '',
    # Put the state root (and so TEMP/TMP, which
    # Initialize-WindowsNativeTestEnvironment points below it) on the runner
    # work drive (the drive of RUNNER_TEMP, D: on hosted runners) instead of
    # the profile on C:. Hosted runners whose C: is slow made Go test file
    # flushes miss the package timeout (rel-1-0-6:GAP-0443). The base is
    # <drive>\dc-ci, directly below the drive root: the RUNNER_TEMP chain
    # has a NETWORK SERVICE owner, which the audit store rightly refuses as an
    # ancestor owner.
    [switch]$StateOnRunnerDrive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')

if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    throw 'GITHUB_ENV is required to publish Windows-native CI paths.'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'RUNNER_TEMP is required to isolate Windows-native diagnostics and artifacts.'
}

if ($StateOnRunnerDrive) {
    $stateBase = Resolve-SafeWindowsNativeBase (Get-WindowsNativeRunnerDriveBase)
    # The hosted runner work drive root is owned by NETWORK SERVICE, an
    # owner the audit store refuses on every ancestor of its database (and
    # must). This disposable runner gives its drive root to Administrators;
    # the DACL is unchanged, so the runner keeps its access.
    $driveRoot = [IO.Path]::GetPathRoot($stateBase)
    $driveOwner = (Get-Acl -LiteralPath $driveRoot).Owner
    if ($driveOwner -notin @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\TrustedInstaller')) {
        & icacls.exe $driveRoot /setowner '*S-1-5-32-544' /c /q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "could not give $driveRoot (owner $driveOwner) to Administrators" }
    }
    New-Item -ItemType Directory -Force -Path $stateBase | Out-Null
    # The owners the audit store checks, for the job log.
    for ($path = $stateBase; $path; $path = Split-Path -Parent $path) {
        Write-Host "state base ancestor $path owner $((Get-Acl -LiteralPath $path).Owner)"
    }
} else {
    $stateBase = Resolve-SafeWindowsNativeBase (Join-Path $env:USERPROFILE '.dc-ci')
}
$stateRoot = [IO.Path]::GetFullPath((Join-Path $stateBase $Leaf)).TrimEnd('\')
if (-not (Test-PathWithin $stateRoot $stateBase)) {
    throw "DC_STATE_ROOT must be a strict child of its base: $stateRoot"
}
if ($stateRoot.Length -gt 48) {
    throw "DC_STATE_ROOT exceeds native build path budget: $stateRoot"
}

$lines = [Collections.Generic.List[string]]::new()
$lines.Add("DC_WINDOWS_NATIVE_BASE_ROOT=$stateBase")
$lines.Add("DC_STATE_ROOT=$stateRoot")
$lines.Add("DC_DIAGNOSTICS=$([IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP $DiagnosticsLeaf)))")
if (-not [string]::IsNullOrWhiteSpace($ArtifactLeaf)) {
    $lines.Add("DC_ARTIFACT_ROOT=$([IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP $ArtifactLeaf)))")
}
[IO.File]::AppendAllLines([IO.Path]::GetFullPath($env:GITHUB_ENV), $lines)
