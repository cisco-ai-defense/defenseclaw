# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

Set-StrictMode -Version Latest

$disposableFileGuardSource = Join-Path $PSScriptRoot 'windows-disposable-file-guard.cs'
if (-not ('DefenseClaw.DisposableFileGuard' -as [type])) {
    if (-not (Test-Path -LiteralPath $disposableFileGuardSource -PathType Leaf)) {
        throw "disposable file guard source is missing: $disposableFileGuardSource"
    }
    Add-Type -Path $disposableFileGuardSource
}

function Assert-ChildOperationAccessDenied {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Operation
    )
    try {
        & $Operation
    } catch {
        $failure = $_.Exception
        while ($null -ne $failure) {
            $errorCode = $failure.HResult -band 0xFFFF
            if ($failure -is [UnauthorizedAccessException] -or $errorCode -eq 5) {
                return
            }
            $failure = $failure.InnerException
        }
        throw "$Label failed without an ERROR_ACCESS_DENIED/5 cause"
    }
    throw "$Label unexpectedly succeeded"
}

function Get-DisposableProcessIdentityKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Process)

    $processId = [int]$Process.ProcessId
    if ($processId -le 0 -or $null -eq $Process.CreationDate) {
        throw 'live process identity requires a positive PID and CreationDate'
    }
    $created = ([datetime]$Process.CreationDate).ToUniversalTime().Ticks
    return ('{0}:{1}' -f $processId, $created)
}

function Assert-UnverifiableProcessWasBaselined {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Process,
        [Parameter(Mandatory)][Collections.Generic.HashSet[string]]$Baseline
    )

    $identity = Get-DisposableProcessIdentityKey $Process
    if (-not $Baseline.Contains($identity)) {
        throw "new or PID-reused process has an unverifiable owner: $identity"
    }
}

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
        [switch]$ExpectInheritance,
        [switch]$AllowOwnershipBootstrap
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
    if (-not $AllowOwnershipBootstrap -and
        ($rule.FileSystemRights -band $privileged) -ne 0) {
        throw "disposable child received privileged filesystem rights on $Path"
    }
}

function Assert-DisposableAncestorReadLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Lease,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ChildSid
    )

    $expected = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    foreach ($entry in $Lease) {
        $security = [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.DirectoryInfo]::new([string]$entry.Path),
            [Security.AccessControl.AccessControlSections]::Access
        )
        $rules = @($security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ) | Where-Object { $_.IdentityReference.Equals($ChildSid) })
        if ($rules.Count -ne 1) {
            throw "ancestor lease has $($rules.Count) exact child ACEs, expected one: $($entry.Path)"
        }
        $rule = $rules[0]
        $rights = $rule.FileSystemRights -band `
            (-bnot [int][Security.AccessControl.FileSystemRights]::Synchronize)
        $expectedRights = $expected -band `
            (-bnot [int][Security.AccessControl.FileSystemRights]::Synchronize)
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rights -ne $expectedRights -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "ancestor lease is not an exact non-inheriting ReadAndExecute ACE: $($entry.Path)"
        }
    }
}

function Restore-DisposableAncestorReadLease {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Lease)

    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    $failures = [Collections.Generic.List[string]]::new()
    for ($index = $Lease.Count - 1; $index -ge 0; $index--) {
        $entry = $Lease[$index]
        try {
            $descriptor = [Convert]::FromBase64String([string]$entry.Descriptor)
            $restored = [Security.AccessControl.DirectorySecurity]::new()
            $restored.SetSecurityDescriptorBinaryForm($descriptor, $sections)
            $directory = [IO.DirectoryInfo]::new([string]$entry.Path)
            [IO.FileSystemAclExtensions]::SetAccessControl($directory, $restored)

            $observed = [IO.FileSystemAclExtensions]::GetAccessControl(
                $directory,
                $sections
            )
            $observedDescriptor = [Convert]::ToBase64String(
                $observed.GetSecurityDescriptorBinaryForm()
            )
            if ($observedDescriptor -cne [string]$entry.Descriptor -or
                $observed.GetSecurityDescriptorSddlForm($sections) -cne
                    [string]$entry.Sddl) {
                throw 'restored security descriptor does not match its snapshot'
            }
            $remaining = @($observed.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            ) | Where-Object {
                $_.IdentityReference.Value -eq [string]$entry.ChildSid
            })
            if ($remaining.Count -ne 0) {
                throw 'restored security descriptor retains an exact child-SID ACE'
            }
        } catch {
            $failures.Add("$($entry.Path): $($_.Exception.Message)")
        }
    }
    if ($failures.Count -ne 0) {
        throw "ancestor ACL lease restore failed: $($failures -join '; ')"
    }
}

function Grant-DisposableAncestorReadLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StateBoundary,
        [Parameter(Mandatory)][string]$StateBase,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ChildSid
    )

    $boundary = Assert-DisposableNoReparseAncestors -Path $StateBoundary `
        -AllowedRoot $StateBoundary -RequireExists
    $base = Assert-DisposableNoReparseAncestors -Path $StateBase `
        -AllowedRoot $boundary -RequireExists
    if (-not [IO.Directory]::Exists($boundary) -or -not [IO.Directory]::Exists($base)) {
        throw 'ancestor ACL lease endpoints must be existing directories'
    }

    $paths = [Collections.Generic.List[string]]::new()
    $cursor = $base
    while ($true) {
        $paths.Add($cursor)
        if ($cursor.Equals($boundary, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent -or
            -not (Test-PathWithinOrEqual $parent.FullName $boundary)) {
            throw "ancestor ACL lease could not reach its approved boundary from: $base"
        }
        $cursor = $parent.FullName.TrimEnd('\')
    }
    $paths.Reverse()

    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    $lease = [Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        $verified = Assert-DisposableNoReparseAncestors -Path $path `
            -AllowedRoot $boundary -RequireExists
        if (-not [IO.Directory]::Exists($verified)) {
            throw "ancestor ACL lease component is not a directory: $verified"
        }
        $directory = [IO.DirectoryInfo]::new($verified)
        $security = [IO.FileSystemAclExtensions]::GetAccessControl($directory, $sections)
        $existing = @($security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ) | Where-Object { $_.IdentityReference.Equals($ChildSid) })
        if ($existing.Count -ne 0) {
            throw "ancestor ACL lease found a pre-existing exact child-SID ACE: $verified"
        }
        $lease.Add([pscustomobject]@{
            Path = $verified
            ChildSid = $ChildSid.Value
            Descriptor = [Convert]::ToBase64String(
                $security.GetSecurityDescriptorBinaryForm()
            )
            Sddl = $security.GetSecurityDescriptorSddlForm($sections)
        })
    }

    try {
        foreach ($entry in $lease) {
            $directory = [IO.DirectoryInfo]::new([string]$entry.Path)
            $security = [IO.FileSystemAclExtensions]::GetAccessControl($directory, $sections)
            [void]$security.AddAccessRule(
                [Security.AccessControl.FileSystemAccessRule]::new(
                    $ChildSid,
                    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                    [Security.AccessControl.InheritanceFlags]::None,
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow
                )
            )
            [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
        }
        Assert-DisposableAncestorReadLease @($lease) $ChildSid
    } catch {
        $grantFailure = $_.Exception.Message
        try { Restore-DisposableAncestorReadLease @($lease) }
        catch { throw "$grantFailure; rollback failed: $($_.Exception.Message)" }
        throw $grantFailure
    }
    return $lease.ToArray()
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
        $remaining = $MaximumTotalBytes - $total
        if ($remaining -lt 0) {
            throw 'disposable diagnostics exceeds the aggregate byte bound'
        }
        $bound = [Math]::Min($MaximumFileBytes, $remaining)
        $copied = [DefenseClaw.DisposableFileGuard]::CopyBoundedRegularFile(
            $entry.FullName,
            $target,
            $bound
        )
        $total += $copied
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
    return [DefenseClaw.DisposableFileGuard]::ReadBoundedUtf8($full, $MaximumBytes)
}
