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
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-codex-vendor-folder-smoke: SKIP (requires an elevated token)'
    exit 0
}
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-smoke-g092-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)
$scratchSecurity = [Security.AccessControl.DirectorySecurity]::new()
$scratchSecurity.SetSecurityDescriptorSddlForm(
    (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $programData).Sddl,
    [Security.AccessControl.AccessControlSections]::Access)
Microsoft.PowerShell.Security\Set-Acl -LiteralPath $scratch -AclObject $scratchSecurity
$roots = [Collections.Generic.List[string]]::new()
$roots.Add($scratch)
function New-StandIn {
    $path = [IO.Path]::Combine($scratch, [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}
$failures = [Collections.Generic.List[string]]::new()
try {
    foreach ($standalone in @($true, $false)) {
        $vendor = New-StandIn
        $codex = [IO.Path]::Combine($vendor, 'Codex')
        [void][IO.Directory]::CreateDirectory($codex)
        $inherited = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
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
                $after = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path
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
    $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $verified).Sddl
    $verifyRefused = & $module {
        param($Path)
        function Test-DefenseClawStandaloneProfile { return $true }
        try { Assert-DefenseClawCodexMachinePolicyDirectory -Path $Path; return $false }
        catch { return $true }
    } $verified
    $after = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $verified).Sddl
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
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $strict -AclObject $security
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
