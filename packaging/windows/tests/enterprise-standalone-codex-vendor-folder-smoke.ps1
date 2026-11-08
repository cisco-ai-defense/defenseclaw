# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0092: an empty vendor folder an administrator created under ProgramData
# (C:\ProgramData\OpenAI, or OpenAI\Codex) inherits ProgramData's inherit-only
# CREATOR OWNER entry, which grants nothing to the folder or to what an
# administrator creates in it. The standalone Codex vendor-folder check refused
# it with a raw "untrusted principal S-1-3-0 has inheritable write-like access",
# so Setup /ensure failed 1603. It now reads the creator templates as the
# GAP-0915 root check does, so the folder is adopted (case b of the g582 vendor
# folder ruling: DefenseClaw did not create it and it holds no DefenseClaw
# file). Any other inheritable write entry is still refused. Only install,
# ensure and repair adopt (-Adopt); Setup /verify only checks (g582 review 7
# L1). The folder is checked again after the stamp, and every folder beneath
# it must be administrator-owned (review 7 S2). Runs elevated in a
# disposable scratch folder that carries ProgramData's own access list, so the
# stand-in folders inherit exactly what a folder made in ProgramData inherits.
# No real machine root is touched.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# A failure outside the checks below (a cmdlet that cannot run) names its line.
trap {
    Microsoft.PowerShell.Utility\Write-Output ('enterprise-standalone-codex-vendor-folder-smoke: FAILED ' + $_.Exception.Message + "`n" + $_.InvocationInfo.PositionMessage + "`n" + $_.ScriptStackTrace)
    throw
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-codex-vendor-folder-smoke: SKIP (requires an elevated token)'
    exit 0
}
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
# Windows PowerShell 5.1 on a GitHub runner cannot load the security module's
# type data into the script scope ("member ... is already present"); the
# product module's own scope can, which is where the other smokes read and set
# access lists. These helpers do the same.
function Get-AclInModule {
    param([Parameter(Mandatory)][string]$Path)
    return (& $module { param($p) Microsoft.PowerShell.Security\Get-Acl -LiteralPath $p } $Path)
}
function Set-AclInModule {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Acl)
    & $module { param($p, $a) Microsoft.PowerShell.Security\Set-Acl -LiteralPath $p -AclObject $a } $Path $Acl
}
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-smoke-g092-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)
$scratchSecurity = [Security.AccessControl.DirectorySecurity]::new()
$scratchSecurity.SetSecurityDescriptorSddlForm(
    (Get-AclInModule -Path $programData).Sddl,
    [Security.AccessControl.AccessControlSections]::Access)
Set-AclInModule -Path $scratch -Acl $scratchSecurity
$roots = [Collections.Generic.List[string]]::new()
$roots.Add($scratch)
# An administrator's object is owned by the group BUILTIN\Administrators. A GitHub
# runner (and any host whose "Default owner for objects created by members of
# the Administrators group" is "Object creator") leaves what an elevated user
# creates owned by that user, with an access entry for the user, which the trust
# rules rightly treat as another account's. The fixtures set the owner and take
# the inherited entries again, so they are the same on every host.
function Set-AdministratorsOwner {
    param([Parameter(Mandatory)][string]$Path)
    $result = & icacls.exe $Path /setowner '*S-1-5-32-544' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner Administrators on $Path failed: $result" }
    $result = & icacls.exe $Path /reset 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls /reset on $Path failed: $result" }
}
function New-AdministratorDirectory {
    param([Parameter(Mandatory)][string]$Path)
    [void][IO.Directory]::CreateDirectory($Path)
    Set-AdministratorsOwner -Path $Path
}
function New-StandIn {
    $path = [IO.Path]::Combine($scratch, [Guid]::NewGuid().ToString('N'))
    New-AdministratorDirectory -Path $path
    return $path
}
$failures = [Collections.Generic.List[string]]::new()
try {
    foreach ($standalone in @($true, $false)) {
        $vendor = New-StandIn
        $codex = [IO.Path]::Combine($vendor, 'Codex')
        New-AdministratorDirectory -Path $codex
        $inherited = (Get-AclInModule -Path $vendor).Sddl
        $result = & $module {
            param($Vendor, $Codex, $Standalone)
            if ($Standalone) { function Test-DefenseClawStandaloneProfile { return $true } }
            else { function Test-DefenseClawStandaloneProfile { return $false } }
            $errors = @()
            foreach ($path in @($Vendor, $Codex)) {
                try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $path -Adopt }
                catch { $errors += "${path}: $($_.Exception.Message)" }
            }
            return , $errors
        } $vendor $codex $standalone
        if (@($result).Count -ne 0) {
            $failures.Add("standalone=$standalone an empty administrator folder with the ProgramData ACL ($inherited) was refused: $($result -join ' | ')")
        }
        elseif ($standalone) {
            foreach ($path in @($vendor, $codex)) {
                $after = Get-AclInModule -Path $path
                # The vendor folder is stamped protected; Codex below it then
                # inherits only the trusted entries.
                if (($path -eq $vendor -and -not $after.AreAccessRulesProtected) -or $after.Sddl -match '\(A;[^;]*;[^;]*DC[^;]*;;;BU\)') {
                    $failures.Add("the adopted folder $path does not carry the protected access list: $($after.Sddl)")
                }
            }
        }
    }

    # A vendor folder with a file in it is not adopted on standalone: it keeps the refusal.
    $occupied = New-StandIn
    [IO.File]::WriteAllText([IO.Path]::Combine($occupied, 'vendor.json'), '{}')
    $kept = & $module {
        param($Path)
        function Test-DefenseClawStandaloneProfile { return $true }
        try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $Path -Adopt; return $false }
        catch { return $true }
    } $occupied
    if (-not $kept) {
        $failures.Add('a vendor folder holding a file was taken over on standalone')
    }

    # Setup /verify (no -Adopt) checks only: the empty folder keeps the refusal and its access list.
    $verified = New-StandIn
    $before = (Get-AclInModule -Path $verified).Sddl
    $verifyRefused = & $module {
        param($Path)
        function Test-DefenseClawStandaloneProfile { return $true }
        try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $Path; return $false }
        catch { return $true }
    } $verified
    $after = (Get-AclInModule -Path $verified).Sddl
    if (-not $verifyRefused -or $after -ne $before) {
        $failures.Add("the check without -Adopt adopted an empty vendor folder (refused=$verifyRefused): $before -> $after")
    }

    # An empty folder beneath it that another account owns is not empty: no adoption.
    $foreignChild = New-StandIn
    $child = [IO.Path]::Combine($foreignChild, 'Codex')
    [void][IO.Directory]::CreateDirectory($child)
    $setOwner = & icacls.exe $child /setowner '*S-1-5-32-545' 2>&1
    if ($LASTEXITCODE -ne 0) {
        $failures.Add("icacls /setowner Users on $child failed: $setOwner")
    }
    else {
        $childKept = & $module {
            param($Path)
            function Test-DefenseClawStandaloneProfile { return $true }
            try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $Path -Adopt; return $false }
            catch { return $true }
        } $foreignChild
        if (-not $childKept) {
            $failures.Add('a vendor folder holding a folder BUILTIN\Users owns was taken over on standalone')
        }
    }

    # g582 round 9 (the g091 round 4 integrated case): a Repair's selector
    # snapshot writes DefenseClaw's own lock into the empty Codex folder before
    # the adoption of the folder above it runs. That lock is no vendor content:
    # the folder is adopted. A lock a standard user owns, any other file and
    # requirements.toml keep the refusal.
    foreach ($row in @(
        @{ Name = 'selector lock'; Files = @('.defenseclaw-managed-runtime-selector.lock'); Owner = ''; Adopted = $true },
        @{ Name = 'writer lock, writer copy and hook copy'; Files = @('.defenseclaw-managed-hooks.writer.lock', '.defenseclaw-managed-hooks.state.committed', '.defenseclaw-managed-hooks.state.18'); Owner = ''; Adopted = $true },
        @{ Name = 'lock of 1.0.8 and state of 1.0.8'; Files = @('.defenseclaw-managed-hooks.lock', '.defenseclaw-managed-hooks.state'); Owner = ''; Adopted = $true },
        @{ Name = 'selector lock owned by Users'; Files = @('.defenseclaw-managed-runtime-selector.lock'); Owner = '*S-1-5-32-545'; Adopted = $false },
        @{ Name = 'selector lock beside a foreign file'; Files = @('.defenseclaw-managed-runtime-selector.lock', 'notes.txt'); Owner = ''; Adopted = $false },
        @{ Name = 'requirements.toml'; Files = @('requirements.toml'); Owner = ''; Adopted = $false },
        @{ Name = 'hook copy with a leading zero'; Files = @('.defenseclaw-managed-hooks.state.04'); Owner = ''; Adopted = $false }
    )) {
        $ownVendor = New-StandIn
        $ownCodex = [IO.Path]::Combine($ownVendor, 'Codex')
        New-AdministratorDirectory -Path $ownCodex
        foreach ($name in $row.Files) {
            $path = [IO.Path]::Combine($ownCodex, $name)
            [IO.File]::WriteAllBytes($path, [byte[]]@())
            Set-AdministratorsOwner -Path $path
            if ($row.Owner -ne '' -and $name -like '.defenseclaw-*') {
                $ownerResult = & icacls.exe $path /setowner $row.Owner 2>&1
                if ($LASTEXITCODE -ne 0) {
                    $failures.Add("icacls /setowner $($row.Owner) on $path failed: $ownerResult")
                }
            }
        }
        $ownResult = & $module {
            param($Vendor, $Codex)
            function Test-DefenseClawStandaloneProfile { return $true }
            $errors = @()
            foreach ($path in @($Vendor, $Codex)) {
                try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $path -Adopt }
                catch { $errors += "${path}: $($_.Exception.Message)"; break }
            }
            return , $errors
        } $ownVendor $ownCodex
        $adopted = @($ownResult).Count -eq 0
        if ($adopted -ne $row.Adopted) {
            $failures.Add("codex folder holding $($row.Name): adopted=$adopted, want $($row.Adopted): $($ownResult -join ' | ')")
        }
        elseif ($adopted) {
            foreach ($name in $row.Files) {
                if (-not [IO.File]::Exists([IO.Path]::Combine($ownCodex, $name))) {
                    $failures.Add("the adoption removed DefenseClaw's own file $name")
                }
            }
        }
    }

    # An entry added between the emptiness check and the stamp is caught after the stamp.
    $raced = New-StandIn
    $racedMessage = & $module {
        param($Path)
        function Test-DefenseClawStandaloneProfile { return $true }
        $real = ${function:Set-DefenseClawPathAcl}
        function Set-DefenseClawPathAcl {
            [IO.File]::WriteAllText([IO.Path]::Combine($Path, 'planted.json'), '{}')
            & $real @args
        }
        try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $Path -Adopt; return '' }
        catch { return $_.Exception.Message }
    } $raced
    if ($racedMessage -notmatch 'an entry appeared in') {
        $failures.Add("an entry added before the stamp was adopted with the folder: '$racedMessage'")
    }

    # The creator templates only: any other inheritable write entry stays a refusal.
    $strict = New-StandIn
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        'O:BAG:BAD:P(A;OICIIO;GA;;;CO)(A;OICIIO;FA;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)',
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    Set-AclInModule -Path $strict -Acl $security
    $refused = & $module {
        param($Path)
        function Test-DefenseClawStandaloneProfile { return $true }
        $writers = @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)
        try {
            Assert-DefenseClawPathAcl -Path $Path -AllowedWriterSIDs $writers -AllowUsersRead -AllowInheritance -IgnoreCreatorTemplates
            return $false
        }
        catch { return $_.Exception.Message -match 'S-1-5-32-545 has inheritable write-like access' }
    } $strict
    if (-not $refused) {
        $failures.Add('an inheritable BUILTIN\Users write entry was not refused next to the CREATOR OWNER template')
    }
}
finally {
    foreach ($root in $roots) {
        if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
    }
}
if ($failures.Count -ne 0) {
    throw ($failures -join [Environment]::NewLine)
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-codex-vendor-folder-smoke: OK'
