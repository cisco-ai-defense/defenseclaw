# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Reference Intune Win32 app detection script for a DefenseClaw custom rule
    pack installed by Install-DefenseClawRulePack.ps1.

.DESCRIPTION
    Intune runs detection scripts without arguments, so set the three
    defaults in param() below: the pack name, the folder that holds the
    pack, and the tree SHA-256 that Install-DefenseClawRulePack.ps1 -PlanOnly
    prints for the approved pack. The pack is detected (exit 0 and one line
    on STDOUT) when <PacksRoot>\<PackName> has that tree SHA-256, only
    SYSTEM and Administrators own and can change it and its parent, no
    standard user can read them, and NT SERVICE\DefenseClawGateway can read
    them and list every folder above. Otherwise it exits 1 with the reason on
    STDERR, and Intune runs the install command, which repairs the pack.

    Detection rule (Intune > App > Detection rules): Use a custom detection
    script, this file, Run script as 32-bit process on 64-bit clients: No,
    Enforce script signature check: No (or sign it).
#>
[CmdletBinding()]
param(
    [string]$PackName = '',
    [string]$PacksRoot = 'C:\ProgramData\DefenseClaw-RulePacks',
    [string]$ExpectedTreeSha256 = ''
)

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    [Console]::Error.WriteLine('The DefenseClaw rule pack detection requires PowerShell FullLanguage. Allow or sign the DefenseClaw kit scripts in WDAC/AppLocker.')
    exit 1
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# region DefenseClaw rule pack helpers
# Identical in Install-DefenseClawRulePack.ps1 and Detect-DefenseClawRulePack.ps1
# (a test enforces it), so each script can be uploaded to Intune on its own.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.

# NT SERVICE\DefenseClawGateway. Windows derives a service SID from the
# service name, so the grant works before DefenseClaw is installed.
$script:DcGatewaySid = 'S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274'
$script:DcAdminSids = @(
    'S-1-5-18',     # LocalSystem
    'S-1-5-32-544', # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
)
# The SIDs an NT SERVICE virtual account's token carries: its own, NT
# SERVICE\ALL SERVICES, SERVICE, Authenticated Users, Users, Everyone, LOCAL.
$script:DcGatewayTokenSids = @($script:DcGatewaySid, 'S-1-5-80-0', 'S-1-5-6', 'S-1-5-11', 'S-1-5-32-545', 'S-1-1-0', 'S-1-2-0')
# Standard users may not read a pack: a pack is one profile's policy.
$script:DcStandardUserSids = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4')
# The gateway walks at most this many entries of a pack.
$script:DcMaxPackEntries = 4096
# FILE_READ_DATA (FILE_LIST_DIRECTORY on a folder) and READ_CONTROL: the
# gateway lists and reads a pack, and reads the permissions of every folder
# above it.
$script:DcReadData = [int64]0x1
$script:DcReadControl = [int64]0x20000
# Write data, append, write extended attributes, delete child, write
# attributes, delete, change permissions, take ownership.
$script:DcWriteRights = [int64]0xD0156

function Test-DcRulePackName {
    param([AllowEmptyString()][string]$Name)
    return ($Name -cmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
}

function Test-DcPacksRoot {
    # An absolute local folder below a drive root, without . or .. segments.
    param([AllowEmptyString()][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\[^<>:"/|?*]*[^<>:"/|?*\\. ]$') { return $false }
    return ($Path -notmatch '\\\\' -and $Path -notmatch '\\\.{1,2}(\\|$)')
}

function ConvertTo-DcSpecificRights {
    # Maps the generic bits of an access mask to the file rights they grant.
    param([int64]$Rights)
    $mask = $Rights -band 0xFFFFFFFFL
    if ($mask -band 0x10000000L) { $mask = $mask -bor 0x1F01FFL }
    if ($mask -band 0x80000000L) { $mask = $mask -bor 0x120089L }
    if ($mask -band 0x40000000L) { $mask = $mask -bor 0x120116L }
    if ($mask -band 0x20000000L) { $mask = $mask -bor 0x1200A0L }
    return ($mask -band 0x0FFFFFFFL)
}

function Get-DcRulePackTree {
    # Walks a pack folder without following links. Returns its items and the
    # tree SHA-256: the SHA-256 of one "<relative/path><TAB><file sha256>"
    # line per file, sorted ordinally, each ending in a newline.
    param([Parameter(Mandatory = $true)][string]$Path)
    $root = Get-Item -LiteralPath $Path -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "rule pack $Path is not a folder"
    }
    $full = $root.FullName.TrimEnd([char[]]@('\', '/'))
    $items = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($full)
    while ($pending.Count -gt 0) {
        $folder = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $folder -Force)) {
            if ($items.Count -ge $script:DcMaxPackEntries) {
                throw "rule pack $Path has more than $($script:DcMaxPackEntries) files and folders"
            }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "rule pack $Path contains a link or junction: $($item.FullName)"
            }
            $items.Add([pscustomobject]@{ Path = $item.FullName; IsDirectory = [bool]$item.PSIsContainer })
            if ($item.PSIsContainer) { $pending.Push($item.FullName); continue }
            $relative = $item.FullName.Substring($full.Length + 1).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $lines.Add("$relative`t$hash")
        }
    }
    if ($lines.Count -eq 0) { throw "rule pack $Path has no files" }
    $sorted = $lines.ToArray()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $text = ($sorted | ForEach-Object { "$_`n" }) -join ''
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return [pscustomobject]@{
        Sha256 = (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
        Items  = $items.ToArray()
    }
}

function Get-DcAclState {
    # The owner SID and the access entries (SID, rights, allow, inherit-only)
    # of a file or folder.
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [Security.Principal.SecurityIdentifier]
    $entries = @()
    foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
        $entries += [pscustomobject]@{
            Sid         = $rule.IdentityReference.Value
            Rights      = ([int64][int]$rule.FileSystemRights) -band 0xFFFFFFFFL
            Allow       = ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
            InheritOnly = (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
        }
    }
    return [pscustomobject]@{ Owner = $acl.GetOwner($sidType).Value; Entries = $entries }
}

function Get-DcAclProblems {
    # Role 'pack' is the pack folder, everything in it and its parent folder:
    # owned and writable only by administrators, readable by the gateway
    # service and by no standard user. Role 'ancestor' is every folder above:
    # the gateway can list it and read its permissions.
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$IsDirectory,
        [ValidateSet('pack', 'ancestor')][string]$Role
    )
    $problems = @()
    $need = $script:DcReadData
    if ($IsDirectory) { $need = $need -bor $script:DcReadControl }
    $allowed = [int64]0
    $denied = [int64]0
    foreach ($entry in @($State.Entries)) {
        if ($entry.InheritOnly) { continue }
        $rights = ConvertTo-DcSpecificRights -Rights $entry.Rights
        if ($script:DcGatewayTokenSids -contains $entry.Sid) {
            if ($entry.Allow) { $allowed = $allowed -bor $rights } else { $denied = $denied -bor $rights }
        }
        if ($Role -ne 'pack' -or -not $entry.Allow) { continue }
        if ($script:DcAdminSids -notcontains $entry.Sid -and ($rights -band $script:DcWriteRights)) {
            $problems += "$Path can be changed by $($entry.Sid), which is not SYSTEM or Administrators"
        }
        if ($script:DcStandardUserSids -contains $entry.Sid -and ($rights -band $script:DcReadData)) {
            $problems += "$Path can be read by standard users ($($entry.Sid))"
        }
    }
    if ((($allowed -band (-bnot $denied)) -band $need) -ne $need) {
        $problems += "the gateway service account NT SERVICE\DefenseClawGateway cannot read $Path"
    }
    if ($Role -eq 'pack' -and $script:DcAdminSids -notcontains [string]$State.Owner) {
        $problems += "$Path is owned by $($State.Owner), not by SYSTEM or Administrators"
    }
    return , $problems
}

function Test-DcRulePack {
    # Checks an installed pack: its tree SHA-256 (when one is expected) and
    # the permissions of the pack, everything in it, its parent and every
    # folder above. Returns the tree SHA-256 and the problems found.
    param(
        [Parameter(Mandatory = $true)][string]$PacksRoot,
        [Parameter(Mandatory = $true)][string]$PackName,
        [AllowEmptyString()][string]$ExpectedTreeSha256 = ''
    )
    $pack = Join-Path $PacksRoot $PackName
    if (-not (Test-Path -LiteralPath $pack -PathType Container)) {
        return [pscustomobject]@{ Sha256 = ''; Problems = @("rule pack folder $pack does not exist") }
    }
    $tree = Get-DcRulePackTree -Path $pack
    $problems = @()
    if ($ExpectedTreeSha256 -and $tree.Sha256 -cne $ExpectedTreeSha256.ToLowerInvariant()) {
        $problems += "rule pack $pack has tree sha256 $($tree.Sha256), not $($ExpectedTreeSha256.ToLowerInvariant())"
    }
    $checks = @([pscustomobject]@{ Path = $PacksRoot; IsDirectory = $true }, [pscustomobject]@{ Path = $pack; IsDirectory = $true }) + @($tree.Items)
    foreach ($check in $checks) {
        $problems += Get-DcAclProblems -State (Get-DcAclState -Path $check.Path) -Path $check.Path -IsDirectory $check.IsDirectory -Role 'pack'
    }
    $ancestor = [IO.Path]::GetDirectoryName($PacksRoot)
    while ($ancestor) {
        $problems += Get-DcAclProblems -State (Get-DcAclState -Path $ancestor) -Path $ancestor -IsDirectory $true -Role 'ancestor'
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    return [pscustomobject]@{ Sha256 = $tree.Sha256; Problems = $problems }
}
# endregion DefenseClaw rule pack helpers

function Invoke-DcRulePackDetect {
    param(
        [AllowEmptyString()][string]$PackName,
        [AllowEmptyString()][string]$PacksRoot,
        [AllowEmptyString()][string]$ExpectedTreeSha256
    )
    if (-not (Test-DcRulePackName -Name $PackName) -or -not (Test-DcPacksRoot -Path $PacksRoot) -or $ExpectedTreeSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        [Console]::Error.WriteLine('set $PackName, $PacksRoot and $ExpectedTreeSha256 in param() of this script (Install-DefenseClawRulePack.ps1 -PlanOnly prints the tree sha256)')
        return 1
    }
    $check = Test-DcRulePack -PacksRoot $PacksRoot -PackName $PackName -ExpectedTreeSha256 $ExpectedTreeSha256
    if (@($check.Problems).Count -ne 0) {
        [Console]::Error.WriteLine("DefenseClaw rule pack $PackName is not ready: $(@($check.Problems)[0])")
        return 1
    }
    [Console]::Out.WriteLine("DefenseClaw rule pack $PackName installed in $(Join-Path $PacksRoot $PackName) (tree sha256 $($check.Sha256))")
    return 0
}

# Dot-sourcing (the kit tests) loads the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $code = Invoke-DcRulePackDetect -PackName $PackName -PacksRoot $PacksRoot -ExpectedTreeSha256 $ExpectedTreeSha256
} catch {
    [Console]::Error.WriteLine("DefenseClaw rule pack detection failed: $($_.Exception.Message)")
    $code = 1
}
exit $code
