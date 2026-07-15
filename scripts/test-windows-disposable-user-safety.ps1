# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')
. (Join-Path $PSScriptRoot 'windows-disposable-user-safety.ps1')

$base = Join-Path ([IO.Path]::GetTempPath()) (
    'dc-disposable-safety-' + [guid]::NewGuid().ToString('N')
)
$outside = Join-Path ([IO.Path]::GetTempPath()) (
    'dc-disposable-outside-' + [guid]::NewGuid().ToString('N')
)
try {
    [IO.Directory]::CreateDirectory($base) | Out-Null
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'sentinel.txt'), 'preserve')
    $readOnlyProbe = Join-Path $base 'access-denied-probe.txt'
    [IO.File]::WriteAllText($readOnlyProbe, 'preserve')
    [IO.File]::SetAttributes($readOnlyProbe, [IO.FileAttributes]::ReadOnly)
    Assert-ChildOperationAccessDenied 'wrapped access-denied regression' {
        [IO.File]::Delete($readOnlyProbe)
    }
    if (-not (Test-Path -LiteralPath $readOnlyProbe -PathType Leaf)) {
        throw 'access-denied assertion allowed its protected probe to be deleted'
    }
    [IO.File]::SetAttributes($readOnlyProbe, [IO.FileAttributes]::Normal)
    $wrongFailureRejected = $false
    try {
        Assert-ChildOperationAccessDenied 'wrong-error regression' {
            throw [IO.FileNotFoundException]::new('not access denied')
        }
    } catch { $wrongFailureRejected = $true }
    if (-not $wrongFailureRejected) {
        throw 'access-denied assertion accepted an unrelated failure code'
    }
    $childSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-546')
    $sandbox = Join-Path $base 'sandbox'
    $state = Join-Path $sandbox 'state'
    $payload = Join-Path $sandbox 'workspace'
    Set-DisposableProtectedDirectoryAcl $sandbox $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Set-DisposableProtectedDirectoryAcl $state $childSid `
        ([Security.AccessControl.FileSystemRights]::FullControl) -InheritChildRights
    Set-DisposableProtectedDirectoryAcl $payload $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -InheritChildRights
    Assert-DisposableChildAcl $sandbox $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Assert-DisposableChildAcl $state $childSid `
        ([Security.AccessControl.FileSystemRights]::FullControl) `
        -ExpectInheritance -AllowOwnershipBootstrap
    Assert-DisposableChildAcl $payload $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -ExpectInheritance

    $leaseBoundary = Join-Path $base 'lease-boundary'
    $leaseMiddle = Join-Path $leaseBoundary 'middle'
    $leaseBase = Join-Path $leaseMiddle 'state-base'
    [IO.Directory]::CreateDirectory($leaseBase) | Out-Null
    $leasePaths = @($leaseBoundary, $leaseMiddle, $leaseBase)
    $leaseSnapshots = @{}
    $leaseSections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    foreach ($path in $leasePaths) {
        $security = [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.DirectoryInfo]::new($path),
            $leaseSections
        )
        $leaseSnapshots[$path] = Get-DisposableAclSemanticFingerprint $security
    }
    $ancestorLease = @()
    try {
        $ancestorLease = @(Grant-DisposableAncestorReadLease `
            $leaseBoundary $leaseBase $childSid)
        if ($ancestorLease.Count -ne $leasePaths.Count) {
            throw 'ancestor ACL lease did not include every path component'
        }
        for ($index = 0; $index -lt $leasePaths.Count; $index++) {
            if (-not ([string]$ancestorLease[$index].Path).Equals(
                    $leasePaths[$index],
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw 'ancestor ACL lease path order is not boundary-to-base'
            }
        }
        Assert-DisposableAncestorReadLease $ancestorLease $childSid
    } finally {
        if ($ancestorLease.Count -ne 0) {
            Restore-DisposableAncestorReadLease $ancestorLease
            $ancestorLease = @()
        }
    }
    foreach ($path in $leasePaths) {
        $security = [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.DirectoryInfo]::new($path),
            $leaseSections
        )
        if ((Get-DisposableAclSemanticFingerprint $security) -cne
            [string]$leaseSnapshots[$path]) {
            throw "ancestor ACL lease did not restore the exact descriptor: $path"
        }
        $remaining = @($security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ) | Where-Object { $_.IdentityReference.Equals($childSid) })
        if ($remaining.Count -ne 0) {
            throw "ancestor ACL lease retained a child-SID ACE: $path"
        }
    }
    $outsideLeaseRejected = $false
    try {
        $null = Grant-DisposableAncestorReadLease $leaseBoundary $outside $childSid
    } catch { $outsideLeaseRejected = $true }
    if (-not $outsideLeaseRejected) {
        throw 'ancestor ACL lease accepted a state base outside its boundary'
    }

    $created = [datetime]::UtcNow
    $baselineProcess = [pscustomobject]@{ ProcessId = 4242; CreationDate = $created }
    $unverifiableBaseline = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    [void]$unverifiableBaseline.Add((Get-DisposableProcessIdentityKey $baselineProcess))
    Assert-UnverifiableProcessWasBaselined $baselineProcess $unverifiableBaseline
    $reuseRejected = $false
    try {
        Assert-UnverifiableProcessWasBaselined ([pscustomobject]@{
            ProcessId = 4242
            CreationDate = $created.AddTicks(1)
        }) $unverifiableBaseline
    } catch { $reuseRejected = $true }
    if (-not $reuseRejected) {
        throw 'unverifiable-process baseline masked PID reuse with a new CreationDate'
    }

    $diagnostics = Join-Path $sandbox 'diagnostics'
    Set-DisposableProtectedDirectoryAcl $diagnostics $childSid `
        ([Security.AccessControl.FileSystemRights]::Modify) -InheritChildRights
    [IO.File]::WriteAllText((Join-Path $diagnostics 'processes.json'), '{}')
    [IO.File]::WriteAllText((Join-Path $diagnostics 'listeners.txt'), '')
    $handoff = Join-Path $base 'handoff'
    Copy-BoundedDisposableDiagnostics $diagnostics $handoff $sandbox $base
    if (-not (Test-Path -LiteralPath (Join-Path $handoff 'processes.json') -PathType Leaf)) {
        throw 'bounded diagnostic handoff did not copy the expected regular file'
    }

    $results = Join-Path $sandbox 'results'
    Set-DisposableProtectedDirectoryAcl $results $childSid `
        ([Security.AccessControl.FileSystemRights]::Modify) -InheritChildRights
    $result = Join-Path $results 'result.json'
    [IO.File]::WriteAllText($result, '{"succeeded":true}')
    if ((Read-BoundedDisposableResult $result $results) -cne '{"succeeded":true}') {
        throw 'handle-validated result read changed the expected UTF-8 bytes'
    }

    $resultHardlink = Join-Path $base 'result-hardlink.json'
    New-Item -ItemType HardLink -Path $resultHardlink -Target $result `
        -ErrorAction Stop | Out-Null
    $resultHardlinkRejected = $false
    try { $null = Read-BoundedDisposableResult $result $results }
    catch { $resultHardlinkRejected = $true }
    if (-not $resultHardlinkRejected) {
        throw 'result handoff accepted an NTFS file with more than one link'
    }
    Remove-Item -LiteralPath $resultHardlink -Force

    $diagnosticHardlinkTarget = Join-Path $outside 'diagnostic-hardlink.log'
    [IO.File]::WriteAllText($diagnosticHardlinkTarget, 'do not copy through a hardlink')
    $diagnosticHardlink = Join-Path $diagnostics 'gateway.log'
    New-Item -ItemType HardLink -Path $diagnosticHardlink `
        -Target $diagnosticHardlinkTarget -ErrorAction Stop | Out-Null
    $diagnosticHardlinkRejected = $false
    try {
        Copy-BoundedDisposableDiagnostics $diagnostics `
            (Join-Path $base 'hardlink-handoff') $sandbox $base
    } catch { $diagnosticHardlinkRejected = $true }
    if (-not $diagnosticHardlinkRejected) {
        throw 'diagnostic handoff accepted an NTFS file with more than one link'
    }
    Remove-Item -LiteralPath $diagnosticHardlink -Force

    $junction = Join-Path $diagnostics 'escape'
    New-Item -ItemType Junction -Path $junction -Target $outside -ErrorAction Stop | Out-Null
    $reparseRejected = $false
    try {
        Copy-BoundedDisposableDiagnostics $diagnostics (Join-Path $base 'unsafe-handoff') `
            $sandbox $base
    } catch { $reparseRejected = $true }
    if (-not $reparseRejected) {
        throw 'diagnostic handoff accepted a child-controlled reparse point'
    }

    Remove-DisposableTreeSafely $sandbox $base
    if (-not (Test-Path -LiteralPath (Join-Path $outside 'sentinel.txt') -PathType Leaf)) {
        throw 'safe sandbox cleanup traversed a child-controlled junction'
    }
    Write-Host 'Disposable-user filesystem safety tests passed.'
} finally {
    foreach ($path in @($base, $outside)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
