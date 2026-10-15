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
    -PlanOnly prints the tree SHA-256 and the icacls commands without changing
    anything, on any computer; use it on the administrator workstation.

    Exit codes: 0 installed or already installed, 1603 failed (the message
    names the problem and the icacls fix), 1639 invalid arguments.

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

function Get-DcRulePackAclCommands {
    # The icacls argument lists for the parent folder ($Root) and the pack
    # ($Pack), in the order the install runs them.
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Pack)
    $grant = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "*$($script:DcGatewaySid):(OI)(CI)RX")
    $rootCommands = New-Object System.Collections.Generic.List[object]
    $rootCommands.Add([string[]]@($Root, '/setowner', '*S-1-5-32-544', '/C'))
    $rootCommands.Add([string[]](@($Root, '/inheritance:r', '/grant:r') + $grant))
    $rootCommands.Add([string[]]@($Root, '/remove:g', '*S-1-5-32-545', '*S-1-5-11', '*S-1-1-0', '*S-1-5-4'))
    $packCommands = New-Object System.Collections.Generic.List[object]
    $packCommands.Add([string[]]@($Pack, '/reset', '/T', '/C'))
    $packCommands.Add([string[]](@($Pack, '/grant:r') + $grant))
    $packCommands.Add([string[]]@($Pack, '/setowner', '*S-1-5-32-544', '/T', '/C'))
    return [pscustomobject]@{ Root = $rootCommands.ToArray(); Pack = $packCommands.ToArray() }
}

function Invoke-DcIcacls {
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
        Write-DcLine 'invalid_arguments: -PacksRoot must be an absolute local folder below a drive root, for example C:\ProgramData\DefenseClaw-RulePacks'
        return 1639
    }
    if ($ExpectedTreeSha256 -and $ExpectedTreeSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        Write-DcLine 'invalid_arguments: -ExpectedTreeSha256 must be 64 hex characters (the tree sha256 that -PlanOnly prints)'
        return 1639
    }
    $expected = $ExpectedTreeSha256.ToLowerInvariant()
    $target = Join-DcPackPath -Root $PacksRoot -Name $PackName
    $commands = Get-DcRulePackAclCommands -Root $PacksRoot -Pack $target
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
        foreach ($command in @($commands.Root) + @($commands.Pack)) { Write-DcLine (Format-DcIcacls -Arguments $command) }
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
    foreach ($command in @($commands.Root)) { Invoke-DcIcacls -Arguments $command }
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
    foreach ($command in @($commands.Pack)) { Invoke-DcIcacls -Arguments $command }
    $check = Test-DcRulePack -PacksRoot $PacksRoot -PackName $PackName -ExpectedTreeSha256 $source.Sha256
    if (@($check.Problems).Count -ne 0) {
        foreach ($problem in @($check.Problems)) { Write-DcLine "rule_pack_not_ready: $problem" }
        Write-DcLine "fix the permissions, for example: icacls `"$PacksRoot`" /grant `"NT SERVICE\DefenseClawGateway:RX`" and icacls `"$target`" /grant `"NT SERVICE\DefenseClawGateway:(OI)(CI)RX`", then run this script again"
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
