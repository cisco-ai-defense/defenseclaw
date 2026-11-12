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
    throw 'RUNNER_TEMP is required to isolate Windows-native diagnostics.'
}

if ($StateOnRunnerDrive -and $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    # The test volume below changes the runner: disposable hosted runners only.
    Write-Host "RUNNER_ENVIRONMENT is not github-hosted: the state root stays in the profile"
    $StateOnRunnerDrive = $false
}
if ($StateOnRunnerDrive) {
    # This alters the hosted runner. The state goes on a test volume of its
    # own (an expandable VHDX in RUNNER_TEMP on the runner work drive D:,
    # attached as T:), not on D: itself: the D: root of hosted runners
    # differs from runner to runner (owner NETWORK SERVICE on some, a
    # modify grant to Authenticated Users on others), and the audit store
    # refuses both on an ancestor of its database, as it must. The volume
    # root gets owner Administrators and a protected DACL of Administrators
    # and SYSTEM, the trust chain the profile gives on C:.
    $stateBase = Resolve-SafeWindowsNativeBase (Get-WindowsNativeRunnerDriveBase)
    $volumeRoot = [IO.Path]::GetPathRoot($stateBase)
    if (Test-Path -LiteralPath $volumeRoot) { throw "test volume $volumeRoot already exists" }
    $vhd = Join-Path $env:RUNNER_TEMP 'dc-ci.vhdx'
    $script = Join-Path $env:RUNNER_TEMP 'dc-ci-diskpart.txt'
    [IO.File]::WriteAllLines($script, @(
        "create vdisk file=`"$vhd`" maximum=40960 type=expandable",
        'attach vdisk',
        'create partition primary',
        'format fs=ntfs quick label=dcci',
        "assign letter=$($volumeRoot.Substring(0, 1))"
    ))
    & diskpart.exe /s $script | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $volumeRoot)) { throw "could not attach the test volume $volumeRoot" }
    Remove-Item -LiteralPath $script -Force
    $rootSecurity = [Security.AccessControl.DirectorySecurity]::new()
    $rootSecurity.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $rootSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    $rootSecurity.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $volumeRoot -AclObject $rootSecurity
    New-Item -ItemType Directory -Force -Path $stateBase | Out-Null
    # The owners and grants the audit store checks, for the job log.
    for ($path = $stateBase; $path; $path = Split-Path -Parent $path) {
        $acl = Get-Acl -LiteralPath $path
        Write-Host "state base ancestor $path owner $($acl.Owner) access $(($acl.Access | ForEach-Object { $_.IdentityReference }) -join ', ')"
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
[IO.File]::AppendAllLines([IO.Path]::GetFullPath($env:GITHUB_ENV), $lines)
