# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

function Test-PathWithin([string]$Path, [string]$Root) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $candidate.StartsWith($parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-PathWithinOrEqual([string]$Path, [string]$Root) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $candidate.Equals($parent, [StringComparison]::OrdinalIgnoreCase) -or
        (Test-PathWithin $candidate $parent)
}

# Get-WindowsNativeRunnerDriveBase is the CI state base on the hosted
# runner test volume (T:, a VHDX on the runner work drive that
# initialize-windows-native-ci-paths.ps1 -StateOnRunnerDrive attaches),
# T\dc-ci; empty outside CI (rel-1-0-6:GAP-0443).
function Get-WindowsNativeRunnerDriveBase {
    $runnerTemp = [Environment]::GetEnvironmentVariable('RUNNER_TEMP')
    if ([string]::IsNullOrWhiteSpace($runnerTemp)) { return '' }
    return 'T:\dc-ci'
}

function Resolve-SafeWindowsNativeBase([AllowNull()][string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    # The one base allowed outside the profile: the runner drive base.
    $runnerDriveBase = Get-WindowsNativeRunnerDriveBase
    if ($runnerDriveBase -and $full.Equals($runnerDriveBase, [StringComparison]::OrdinalIgnoreCase)) {
        return $full
    }
    $userProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    ).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($userProfile) -or
        -not (Test-PathWithin $full $userProfile)) {
        throw "DC_WINDOWS_NATIVE_BASE_ROOT must be a strict child of the current user's profile: $full"
    }
    return $full
}

function Assert-WindowsNativePathsDisjoint([string[]]$Paths) {
    $fullPaths = @($Paths | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            throw 'A disjoint Windows-native path must not be empty.'
        }
        [IO.Path]::GetFullPath($_).TrimEnd('\')
    })
    for ($left = 0; $left -lt $fullPaths.Count; $left++) {
        for ($right = $left + 1; $right -lt $fullPaths.Count; $right++) {
            $a = $fullPaths[$left]
            $b = $fullPaths[$right]
            if ($a.Equals($b, [StringComparison]::OrdinalIgnoreCase) -or
                (Test-PathWithin $a $b) -or (Test-PathWithin $b $a)) {
                throw "Windows-native roots must be pairwise non-equal and non-nested: '$a', '$b'"
            }
        }
    }
    return $fullPaths
}
