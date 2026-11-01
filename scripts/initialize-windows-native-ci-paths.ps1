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
    # work disk, RUNNER_TEMP, instead of the profile on C:. Hosted runners
    # whose C: is slow made Go test file flushes miss the package timeout
    # (rel-1-0-6:GAP-0443). Such a root is a RUNNER_TEMP child, which
    # Assert-SafeStateRoot accepts; no DC_WINDOWS_NATIVE_BASE_ROOT is set.
    [switch]$StateOnRunnerTemp
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

if ($StateOnRunnerTemp) {
    $stateBase = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'dc-ci')).TrimEnd('\')
    if (-not (Test-PathWithin $stateBase $env:RUNNER_TEMP)) {
        throw "DC_STATE_ROOT base must be a strict child of RUNNER_TEMP: $stateBase"
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
if (-not $StateOnRunnerTemp) {
    $lines.Add("DC_WINDOWS_NATIVE_BASE_ROOT=$stateBase")
}
$lines.Add("DC_STATE_ROOT=$stateRoot")
$lines.Add("DC_DIAGNOSTICS=$([IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP $DiagnosticsLeaf)))")
if (-not [string]::IsNullOrWhiteSpace($ArtifactLeaf)) {
    $lines.Add("DC_ARTIFACT_ROOT=$([IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP $ArtifactLeaf)))")
}
[IO.File]::AppendAllLines([IO.Path]::GetFullPath($env:GITHUB_ENV), $lines)
