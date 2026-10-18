# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Reference Intune Win32 app install command for a DefenseClaw custom rule
    pack: installs the pack before the DefenseClaw base app.

.DESCRIPTION
    A base config that names a custom rule pack (guardrail.custom_packs.<name>.path)
    needs that pack on the device before Setup runs; Setup refuses CONFIG=
    (exit 1639) when the pack is missing or when the gateway service account
    NT SERVICE\DefenseClawGateway cannot read the pack or the folder that
    holds it. This script, run as SYSTEM by Intune from the pack app's
    content folder, copies the pack folder <PackName> next to it to
    <PacksRoot>\<PackName> and sets the permissions Setup checks:

    - <PacksRoot> (the parent): owner Administrators, no inherited entries,
      SYSTEM and Administrators Full control, NT SERVICE\DefenseClawGateway
      Read & execute, no Users or Authenticated Users entry;
    - the pack and everything in it: the same entries, inherited, owner
      Administrators.

    It then verifies the copy (tree SHA-256) and the permissions of the pack,
    its parent and every folder above, and exits 0. Run again it changes
    nothing when the pack and its permissions are already correct, and
    repairs only what differs. A changed pack is copied next to the old one
    and swapped in.

    The tree SHA-256 is the SHA-256 of one "<relative/path><TAB><file sha256>"
    line per file, sorted. Pass it as -ExpectedTreeSha256 to refuse a pack
    folder whose content differs, and set it in Detect-DefenseClawRulePack.ps1.
    -PlanOnly prints the tree SHA-256 and the commands without changing
    anything, on any computer; use it on the administrator workstation.

    The parent folder's access list is written with Set-Acl by SID: the
    service SID resolves only once the DefenseClawGateway service exists, and
    icacls fails on it before (1332), which is the documented order (this app
    before the base app). icacls only runs /reset, which names no account.

    -PacksRoot must be a folder of its own: the install refuses (1639) a drive
    root, a Windows, program, profile or DefenseClaw folder, an existing
    folder that is not empty and that this script did not set up (no
    .defenseclaw-rule-packs marker file, which it writes, and not its access
    list), and one that holds anything other than rule pack folders.

    Exit codes: 0 installed or already installed, 1603 failed (the message
    names the problem), 1639 invalid arguments.

    Install command (Intune > App > Program):
      %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawRulePack.ps1 -PackName my-pack -ExpectedTreeSha256 <tree sha256>
    Uninstall command:
      %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawRulePack.ps1 -PackName my-pack -Remove
#>
[CmdletBinding()]
param(
    [string]$PackName = '',
    [string]$SourcePath = '',
    [string]$PacksRoot = 'C:\ProgramData\DefenseClaw-RulePacks',
    [string]$ExpectedTreeSha256 = '',
    [switch]$Remove,
    [switch]$PlanOnly
)

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output 'The DefenseClaw rule pack install requires PowerShell FullLanguage. Allow or sign the DefenseClaw kit scripts in WDAC/AppLocker, then retry.'
    exit 1603
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# region DefenseClaw rule pack helpers
# Identical in Install-DefenseClawRulePack.ps1 and Detect-DefenseClawRulePack.ps1
# (a test enforces it), so each script can be uploaded to Intune on its own.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.

# NT SERVICE\DefenseClawGateway. Windows derives a service SID from the
# service name, but looks it up only once the service exists: before the
# first install icacls fails on it (1332, No mapping between account names
# and security IDs), so the install writes it with Set-Acl, by SID.
$script:DcGatewaySid = 'S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274'
# The owner and access list the install gives <PacksRoot>: owner
# Administrators, no inherited entries, SYSTEM and Administrators Full
# control, the gateway Read & execute, for the folder, subfolders and files.
$script:DcPacksRootSddl = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$($script:DcGatewaySid))"
# The file the install writes in <PacksRoot>; a folder without it is not one
# the install set up.
$script:DcPacksRootMarker = '.defenseclaw-rule-packs'
$script:DcAdminSids = @(
    'S-1-5-18',     # LocalSystem
    'S-1-5-32-544', # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
)
# The SIDs an NT SERVICE virtual account's token carries: its own, NT
# SERVICE\ALL SERVICES, SERVICE, Authenticated Users, Users, Everyone, LOCAL.
$script:DcGatewayTokenSids = @($script:DcGatewaySid, 'S-1-5-80-0', 'S-1-5-6', 'S-1-5-11', 'S-1-5-32-545', 'S-1-1-0', 'S-1-2-0')
# Standard users may not read a pack: a pack is one profile's policy. Domain
# Users (S-1-5-21-<domain>-513) counts too, as in Setup's check.
$script:DcStandardUserSids = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4')
# The install replaces the owner and permissions of <PacksRoot>, so it may
# not be one of these folders (relative to the drive root) or below them...
$script:DcRefusedPackTrees = @(
    'windows', 'program files', 'program files (x86)', 'users', 'documents and settings',
    'recovery', 'system volume information', '$recycle.bin', 'boot', 'efi', 'perflogs', 'config.msi',
    'programdata\microsoft', 'programdata\package cache', 'programdata\cisco\defenseclaw', 'programdata\defenseclaw'
)
# ...or one of these folders, which hold more than rule packs.
$script:DcRefusedPackRoots = @('programdata', 'programdata\cisco')
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
    # An absolute local folder below a drive root, without . or .. segments,
    # short (8.3) names or segments Windows trims, that is not a Windows,
    # program, profile or DefenseClaw folder.
    param([AllowEmptyString()][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\[^<>:"/|?*~]*[^<>:"/|?*~\\. ]$') { return $false }
    if ($Path -match '\\\\' -or $Path -match '[. ]\\') { return $false }
    $relative = $Path.Substring(3).ToLowerInvariant()
    foreach ($tree in $script:DcRefusedPackTrees) {
        if ($relative -eq $tree -or $relative.StartsWith($tree + '\', [StringComparison]::Ordinal)) { return $false }
    }
    return ($script:DcRefusedPackRoots -notcontains $relative)
}

function Test-DcStandardUserSid {
    param([AllowEmptyString()][string]$Sid)
    return ($script:DcStandardUserSids -contains $Sid -or $Sid -match '^S-1-5-21-[0-9-]+-513$')
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
    return [pscustomobject]@{ Owner = $acl.GetOwner($sidType).Value; Protected = $acl.AreAccessRulesProtected; Entries = $entries }
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
        if ((Test-DcStandardUserSid -Sid $entry.Sid) -and ($rights -band $script:DcReadData)) {
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
    if (-not (Test-Path -LiteralPath (Join-Path $PacksRoot $script:DcPacksRootMarker) -PathType Leaf)) {
        $problems += "$PacksRoot has no $($script:DcPacksRootMarker) file, which Install-DefenseClawRulePack.ps1 writes"
    }
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

function Write-DcLine {
    # Output for Intune and the administrator; function return values stay
    # the exit codes.
    param([AllowEmptyString()][string]$Text)
    [Console]::Out.WriteLine($Text)
}

function Join-DcPackPath {
    # <Root>\<Name> with the Windows separator for a Windows path, also in a
    # -PlanOnly run on another operating system.
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Name)
    if ($Root -match '^[A-Za-z]:\\') { return ($Root + '\' + $Name) }
    return (Join-Path $Root $Name)
}

function Format-DcIcacls {
    # One icacls command line as an administrator types it.
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return ('icacls "' + $Arguments[0] + '" ' + (($Arguments | Select-Object -Skip 1) -join ' '))
}

# What the marker file in <PacksRoot> says.
$script:DcPacksRootMarkerText = 'DefenseClaw rule packs: Install-DefenseClawRulePack.ps1 manages this folder'

function Format-DcSetAcl {
    # The Set-Acl command line that gives $Path the owner (and access list)
    # of $Sddl, as an administrator types it.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Sddl, [string]$Sections = 'Owner, Access')
    $quoted = "'" + $Path.Replace("'", "''") + "'"
    return "`$a = Get-Acl -LiteralPath $quoted; `$a.SetSecurityDescriptorSddlForm('$Sddl', '$Sections'); Set-Acl -LiteralPath $quoted -AclObject `$a"
}

function Get-DcRulePackPlan {
    # What the install runs after the copy, as administrator command lines.
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Pack)
    $quoted = "'" + $Pack.Replace("'", "''") + "'"
    return @(
        (Format-DcSetAcl -Path $Root -Sddl $script:DcPacksRootSddl),
        "Set-Content -LiteralPath '$((Join-DcPackPath -Root $Root -Name $script:DcPacksRootMarker).Replace("'", "''"))' -Value '$($script:DcPacksRootMarkerText)'",
        (Format-DcIcacls -Arguments @($Pack, '/reset', '/T', '/C')),
        ("foreach (`$p in @($quoted) + @(Get-ChildItem -LiteralPath $quoted -Recurse -Force | ForEach-Object FullName)) { " + (Format-DcSetAcl -Path 'PATH' -Sddl 'O:BA' -Sections 'Owner').Replace("'PATH'", '$p') + ' }')
    )
}

function Set-DcAcl {
    # Gives $Path the owner (and access list) of $Sddl with Set-Acl. SDDL
    # names every account by SID and Set-Acl writes it without a lookup, so
    # this works before the DefenseClawGateway service exists.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Sddl, [string]$Sections = 'Owner, Access')
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm($Sddl, $Sections)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-DcPacksRootAcl {
    # <PacksRoot>: this script's owner and access list, and its marker file.
    param([Parameter(Mandatory = $true)][string]$Path)
    Set-DcAcl -Path $Path -Sddl $script:DcPacksRootSddl
    $marker = Join-Path $Path $script:DcPacksRootMarker
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        Set-Content -LiteralPath $marker -Encoding Ascii -Value $script:DcPacksRootMarkerText
    }
}

function Set-DcRulePackAcl {
    # The pack and everything in it: only the entries inherited from
    # <PacksRoot>, owner Administrators.
    param([Parameter(Mandatory = $true)][string]$Path)
    Invoke-DcIcacls -Arguments @($Path, '/reset', '/T', '/C')
    foreach ($item in @($Path) + @((Get-DcRulePackTree -Path $Path).Items | ForEach-Object { $_.Path })) {
        Set-DcAcl -Path $item -Sddl 'O:BA' -Sections 'Owner'
    }
}

function Invoke-DcIcacls {
    # Only for commands that name no account (/reset): icacls looks every
    # account up, and the gateway's SID resolves only once its service exists.
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $exe = Join-Path ([Environment]::SystemDirectory) 'icacls.exe'
    # Windows PowerShell 5.1 turns native stderr into a terminating error
    # under Stop; the exit code decides here.
    $ErrorActionPreference = 'Continue'
    $output = & $exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$(Format-DcIcacls -Arguments $Arguments) exited $LASTEXITCODE`: $(($output | Out-String).Trim())"
    }
}

function Test-DcElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -eq 'S-1-5-18') { return $true }
    return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-DcRulePackFolder {
    # A folder whose permissions an earlier icacls emptied cannot be
    # deleted until it inherits again.
    param([Parameter(Mandatory = $true)][string]$Path)
    Invoke-DcIcacls -Arguments @($Path, '/reset', '/T', '/C')
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Get-DcPacksRootRefusal {
    # The install gives <PacksRoot> its own owner and permissions, so an
    # existing one must be empty or one this script set up: it holds the
    # marker file, or it already has the access list this script (or the
    # windows.mdx steps) set. It may then hold only rule pack folders, the
    # marker and the .<pack>.new- and .<pack>.old- folders an interrupted run
    # leaves. Returns why the folder is refused, or nothing.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $root = Get-Item -LiteralPath $Path -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return 'is a file or a link' }
    $items = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($items.Count -eq 0) { return '' }
    $isMarker = { param($Item) $Item.Name -ceq $script:DcPacksRootMarker -and -not $Item.PSIsContainer -and -not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) }
    $marked = @($items | Where-Object { & $isMarker $_ }).Count -gt 0
    if (-not $marked) {
        $state = Get-DcAclState -Path $Path
        $gateway = @($state.Entries | Where-Object { $_.Sid -eq $script:DcGatewaySid -and $_.Allow -and -not $_.InheritOnly }).Count -gt 0
        if (-not ($state.Owner -eq 'S-1-5-32-544' -and $state.Protected -and $gateway)) {
            return "is not empty and was not set up by this script (no $($script:DcPacksRootMarker) file, and not its access list)"
        }
    }
    foreach ($item in $items) {
        if (& $isMarker $item) { continue }
        $folder = $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
        $packLike = (Test-DcRulePackName -Name $item.Name) -or ($item.Name -cmatch '^\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.(new|old)-[0-9a-f]{8}$')
        if (-not ($folder -and $packLike)) { return "holds $($item.FullName), which is not a rule pack folder" }
    }
    return ''
}

function Invoke-DcRulePackInstall {
    param(
        [AllowEmptyString()][string]$PackName,
        [AllowEmptyString()][string]$SourcePath,
        [AllowEmptyString()][string]$PacksRoot,
        [AllowEmptyString()][string]$ExpectedTreeSha256,
        [switch]$Remove,
        [switch]$PlanOnly
    )
    if (-not (Test-DcRulePackName -Name $PackName)) {
        Write-DcLine 'invalid_arguments: -PackName must be the guardrail.custom_packs name: 1 to 64 letters, digits, - or _'
        return 1639
    }
    if (-not (Test-DcPacksRoot -Path $PacksRoot)) {
        Write-DcLine 'invalid_arguments: -PacksRoot must be an absolute local folder below a drive root that is not a Windows, program, profile or DefenseClaw folder, for example C:\ProgramData\DefenseClaw-RulePacks'
        return 1639
    }
    if ($ExpectedTreeSha256 -and $ExpectedTreeSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        Write-DcLine 'invalid_arguments: -ExpectedTreeSha256 must be 64 hex characters (the tree sha256 that -PlanOnly prints)'
        return 1639
    }
    $expected = $ExpectedTreeSha256.ToLowerInvariant()
    $target = Join-DcPackPath -Root $PacksRoot -Name $PackName
    if ($Remove) {
        if ($PlanOnly) {
            Write-DcLine (Format-DcIcacls -Arguments @($target, '/reset', '/T', '/C'))
            Write-DcLine "then delete $target"
            return 0
        }
        if (-not (Test-DcElevated)) {
            Write-DcLine 'elevation_required: run as SYSTEM (Intune install behavior System) or as an elevated administrator'
            return 1603
        }
        if (Test-Path -LiteralPath $target) {
            Remove-DcRulePackFolder -Path $target
            Write-DcLine "removed rule pack $PackName from $target"
        } else {
            Write-DcLine "rule pack $PackName is not installed in $target; nothing changed"
        }
        return 0
    }
    $refusal = Get-DcPacksRootRefusal -Path $PacksRoot
    if ($refusal) {
        Write-DcLine "invalid_arguments: -PacksRoot $PacksRoot $refusal; the install would replace its permissions. Use a folder of its own, for example C:\ProgramData\DefenseClaw-RulePacks"
        return 1639
    }
    if (-not $SourcePath) { $SourcePath = Join-Path $PSScriptRoot $PackName }
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Container)) {
        Write-DcLine "invalid_arguments: rule pack folder $SourcePath not found; put the pack folder $PackName next to this script in the Win32 app content"
        return 1639
    }
    $source = Get-DcRulePackTree -Path $SourcePath
    if ($expected -and $source.Sha256 -cne $expected) {
        Write-DcLine "rule_pack_hash_mismatch: $SourcePath has tree sha256 $($source.Sha256), not $expected; rebuild the pack app from the approved pack"
        return 1603
    }
    if ($PlanOnly) {
        Write-DcLine "rule pack $PackName tree sha256 $($source.Sha256)"
        Write-DcLine "copy $SourcePath to $target, then run:"
        foreach ($line in (Get-DcRulePackPlan -Root $PacksRoot -Pack $target)) { Write-DcLine $line }
        return 0
    }
    if (-not (Test-DcElevated)) {
        Write-DcLine 'elevation_required: run as SYSTEM (Intune install behavior System) or as an elevated administrator'
        return 1603
    }
    if (Test-Path -LiteralPath $target -PathType Container) {
        $installed = Test-DcRulePack -PacksRoot $PacksRoot -PackName $PackName -ExpectedTreeSha256 $source.Sha256
        if (@($installed.Problems).Count -eq 0) {
            Write-DcLine "rule pack $PackName is already installed in $target (tree sha256 $($source.Sha256)); nothing changed"
            return 0
        }
    }
    if (Test-Path -LiteralPath $PacksRoot -PathType Container) {
        # Folders an interrupted earlier run left behind.
        foreach ($leftover in @(Get-ChildItem -LiteralPath $PacksRoot -Force -Directory)) {
            if ($leftover.Name.StartsWith(".$PackName.new-", [StringComparison]::Ordinal) -or $leftover.Name.StartsWith(".$PackName.old-", [StringComparison]::Ordinal)) {
                Remove-DcRulePackFolder -Path $leftover.FullName
            }
        }
    } else {
        New-Item -ItemType Directory -Path $PacksRoot -Force | Out-Null
    }
    Set-DcPacksRootAcl -Path $PacksRoot
    $current = $false
    if (Test-Path -LiteralPath $target -PathType Container) {
        try { $current = ((Get-DcRulePackTree -Path $target).Sha256 -ceq $source.Sha256) } catch { $current = $false }
    }
    if (-not $current) {
        # Copy beside the pack and swap it in, so the pack folder is never
        # half copied.
        $suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $stage = Join-Path $PacksRoot ".$PackName.new-$suffix"
        Copy-Item -LiteralPath $SourcePath -Destination $stage -Recurse -Force
        if ((Get-DcRulePackTree -Path $stage).Sha256 -cne $source.Sha256) { throw "the copy in $stage differs from $SourcePath" }
        if (Test-Path -LiteralPath $target) {
            $old = ".$PackName.old-$suffix"
            Invoke-DcIcacls -Arguments @($target, '/reset', '/T', '/C')
            Rename-Item -LiteralPath $target -NewName $old
            Rename-Item -LiteralPath $stage -NewName $PackName
            Remove-Item -LiteralPath (Join-Path $PacksRoot $old) -Recurse -Force
        } else {
            Rename-Item -LiteralPath $stage -NewName $PackName
        }
    }
    Set-DcRulePackAcl -Path $target
    $check = Test-DcRulePack -PacksRoot $PacksRoot -PackName $PackName -ExpectedTreeSha256 $source.Sha256
    if (@($check.Problems).Count -ne 0) {
        foreach ($problem in @($check.Problems)) { Write-DcLine "rule_pack_not_ready: $problem" }
        Write-DcLine "the install set the permissions -PlanOnly lists (by SID with Set-Acl, which works before DefenseClaw is installed); find what changed them again, then run this script again"
        return 1603
    }
    Write-DcLine "installed rule pack $PackName in $target (tree sha256 $($source.Sha256)); NT SERVICE\DefenseClawGateway can read it and its parent folder"
    return 0
}

# Dot-sourcing (the kit tests) loads the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $code = Invoke-DcRulePackInstall -PackName $PackName -SourcePath $SourcePath -PacksRoot $PacksRoot `
        -ExpectedTreeSha256 $ExpectedTreeSha256 -Remove:$Remove -PlanOnly:$PlanOnly
} catch {
    Write-DcLine "rule_pack_install_failed: $($_.Exception.Message)"
    $code = 1603
}
exit $code
