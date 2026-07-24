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
    [string]$ArtifactLeaf = ''
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

$stateBase = Resolve-SafeWindowsNativeBase (Join-Path $env:USERPROFILE '.dc-ci')
$stateRoot = [IO.Path]::GetFullPath((Join-Path $stateBase $Leaf)).TrimEnd('\')
if (-not (Test-PathWithin $stateRoot $stateBase)) {
    throw "DC_STATE_ROOT must be a strict child of DC_WINDOWS_NATIVE_BASE_ROOT: $stateRoot"
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
