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
    $childSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-546')
    $sandbox = Join-Path $base 'sandbox'
    $state = Join-Path $sandbox 'state'
    $payload = Join-Path $sandbox 'workspace'
    Set-DisposableProtectedDirectoryAcl $sandbox $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Set-DisposableProtectedDirectoryAcl $state $childSid `
        ([Security.AccessControl.FileSystemRights]::Modify) -InheritChildRights
    Set-DisposableProtectedDirectoryAcl $payload $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -InheritChildRights
    Assert-DisposableChildAcl $sandbox $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Assert-DisposableChildAcl $state $childSid `
        ([Security.AccessControl.FileSystemRights]::Modify) -ExpectInheritance
    Assert-DisposableChildAcl $payload $childSid `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -ExpectInheritance

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
