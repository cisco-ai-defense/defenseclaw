# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

Set-StrictMode -Version Latest

function Assert-DisposableNoReparseAncestors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot,
        [switch]$RequireExists
    )

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\')
    if (-not (Test-PathWithinOrEqual $full $root)) {
        throw "disposable path escaped its approved root: $full"
    }
    if ($RequireExists -and -not (Test-Path -LiteralPath $full)) {
        throw "required disposable path does not exist: $full"
    }

    $drive = [IO.Path]::GetPathRoot($full)
    $cursor = $drive
    foreach ($segment in $full.Substring($drive.Length).Split(
        [char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries
    )) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "disposable path traverses a reparse point: $cursor"
        }
    }
    return $full
}

function Remove-DisposableTreeSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )

    $full = Assert-DisposableNoReparseAncestors -Path $Path -AllowedRoot $AllowedRoot
    $root = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\')
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "disposable cleanup root is a reparse point: $full"
    }

    foreach ($child in @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            if ($child.PSIsContainer) { [IO.Directory]::Delete($child.FullName) }
            else { [IO.File]::Delete($child.FullName) }
            continue
        }
        if ($child.PSIsContainer) {
            Remove-DisposableTreeSafely -Path $child.FullName -AllowedRoot $root
        } else {
            [IO.File]::Delete($child.FullName)
        }
    }
    [IO.Directory]::Delete($full)
}

function Set-DisposableProtectedDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ChildSid,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$ChildRights,
        [switch]$InheritChildRights
    )

    $directory = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Path))
    $parentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $parentSid) { throw 'runner identity has no user SID' }
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($parentSid)
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($parentSid, $systemSid)) {
        [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $childInheritance = if ($InheritChildRights) {
        $inherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $ChildSid,
        $ChildRights,
        $childInheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}

function Assert-DisposableChildAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ChildSid,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$ExpectedRights,
        [switch]$ExpectInheritance
    )

    $security = [IO.FileSystemAclExtensions]::GetAccessControl(
        [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path)),
        [Security.AccessControl.AccessControlSections]::Access
    )
    if (-not $security.AreAccessRulesProtected) {
        throw "disposable directory inherits an untrusted ACL: $Path"
    }
    $rules = @($security.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ) | Where-Object {
        $_.IdentityReference.Equals($ChildSid) -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
    })
    if ($rules.Count -ne 1) {
        throw "disposable directory has $($rules.Count) explicit child ACEs, expected one: $Path"
    }
    $rule = $rules[0]
    $normalizedRights = $rule.FileSystemRights -band `
        (-bnot [int][Security.AccessControl.FileSystemRights]::Synchronize)
    $normalizedExpected = $ExpectedRights -band `
        (-bnot [int][Security.AccessControl.FileSystemRights]::Synchronize)
    if ($normalizedRights -ne $normalizedExpected) {
        throw "disposable child rights on $Path are $($rule.FileSystemRights), expected $ExpectedRights"
    }
    $inherits = $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None
    if ($inherits -ne [bool]$ExpectInheritance) {
        throw "disposable child ACE inheritance is unexpected on $Path"
    }
    $privileged = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    if (($rule.FileSystemRights -band $privileged) -ne 0) {
        throw "disposable child received privileged filesystem rights on $Path"
    }
}

function Copy-BoundedDisposableDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][string]$SandboxRoot,
        [Parameter(Mandatory)][string]$DestinationBoundary,
        [ValidateRange(1, 64)][int]$MaximumFiles = 40,
        [ValidateRange(1024, 2097152)][long]$MaximumFileBytes = 1048576,
        [ValidateRange(1024, 33554432)][long]$MaximumTotalBytes = 16777216
    )

    $source = Assert-DisposableNoReparseAncestors -Path $SourceRoot `
        -AllowedRoot $SandboxRoot -RequireExists
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if (-not $sourceItem.PSIsContainer) {
        throw "disposable diagnostics source is not a directory: $source"
    }
    $entries = @(Get-ChildItem -LiteralPath $source -Force -ErrorAction Stop)
    if ($entries.Count -gt $MaximumFiles) {
        throw "disposable diagnostics contains too many entries: $($entries.Count)"
    }
    $expectedName = '^(?:processes\.json|listeners\.txt|[A-Za-z0-9_. -]{1,180}\.(?:json|txt|log))$'
    $total = 0L
    foreach ($entry in $entries) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $entry.PSIsContainer) {
            throw "disposable diagnostics contains a reparse point or directory: $($entry.FullName)"
        }
        if ($entry.Name -notmatch $expectedName) {
            throw "disposable diagnostics contains an unexpected file: $($entry.Name)"
        }
        if ($entry.Length -gt $MaximumFileBytes) {
            throw "disposable diagnostic exceeds the per-file bound: $($entry.Name)"
        }
        $total += $entry.Length
        if ($total -gt $MaximumTotalBytes) {
            throw 'disposable diagnostics exceeds the aggregate byte bound'
        }
    }

    $destination = Assert-DisposableNoReparseAncestors -Path $DestinationRoot `
        -AllowedRoot $DestinationBoundary
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $destination = Assert-DisposableNoReparseAncestors -Path $destination `
        -AllowedRoot $DestinationBoundary -RequireExists
    $destinationEntries = @(Get-ChildItem -LiteralPath $destination -Force -ErrorAction Stop)
    if ($destinationEntries.Count -ne 0) {
        throw 'disposable diagnostic destination must be a new empty directory'
    }
    foreach ($entry in $entries) {
        $target = Join-Path $destination $entry.Name
        $null = Assert-DisposableNoReparseAncestors -Path $target `
            -AllowedRoot $destination
        $input = [IO.File]::Open(
            $entry.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            $output = [IO.File]::Open(
                $target,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            try { $input.CopyTo($output) } finally { $output.Dispose() }
        } finally { $input.Dispose() }
    }
}

function Read-BoundedDisposableResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ResultsRoot,
        [ValidateRange(1024, 1048576)][long]$MaximumBytes = 65536
    )

    $full = Assert-DisposableNoReparseAncestors -Path $Path `
        -AllowedRoot $ResultsRoot -RequireExists
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -gt $MaximumBytes) {
        throw "disposable result is not a bounded regular file: $full"
    }
    return [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8)
}
