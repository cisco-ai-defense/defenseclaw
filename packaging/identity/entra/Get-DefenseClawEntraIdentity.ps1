# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
<#
.SYNOPSIS
Shows what a Windows computer tells DefenseClaw about an Entra ID user. Read-only.

.DESCRIPTION
DefenseClaw never calls Entra ID. On Windows it reads who a user is from the
computer: the account SID, the UPN and provider in the identity store cache, the
tenant in the join state and, for groups, the sign-in token. This script prints
those same facts so you can check a computer before you write a profile
assignment, and explain why one does not match.

It reports:
  1. The join state from dsregcmd /status: Entra joined, domain joined, tenant, PRT.
  2. The Entra accounts in the identity store cache: SID, UPN, provider (read as SYSTEM in the
     live tests; an administrator may be refused).
  3. The tenant in the cloud join info (an administrator or SYSTEM).
  4. The sign-in token of the account that runs the script: its user SID and groups,
     with the Entra group SIDs (S-1-12-1-...) marked.
  5. Which built-in local groups list an Entra SID. Windows puts an Entra group SID in
     a token only for a group that one of them lists.
  6. With -GroupSid: for each SID, whether it is listed and whether it is in this token.
  7. With -User, or when DefenseClaw is installed: what DefenseClaw answers for the
     account (guardrail profile explain). On a standalone enterprise computer this
     needs an elevated prompt.

Run it as the user you want to inspect for the token sections (a per-user view), and
as SYSTEM (for example an Intune platform script, or a scheduled task that runs as SYSTEM) for section 2. The
script changes nothing. Tested on Windows Server 2025 in Windows PowerShell 5.1 and
PowerShell 7, and against a saved dsregcmd output. The registry values and token
groups it reads were captured on an Entra-joined Windows 11 computer during the live
tests, but this script itself has not run on one yet.

.PARAMETER GroupSid
Entra group SIDs to check (S-1-12-1-<a>-<b>-<c>-<d>). Read a SID with
entra_setup.py sids --group NAME.

.PARAMETER User
The account to ask DefenseClaw about: a SID or AzureAD\Name. A UPN is not accepted
by the Windows lookup. The default is the account that runs the script.

.PARAMETER Connector
The connector for the profile answer. The default is claudecode.

.PARAMETER DsregStatusPath
Read this saved dsregcmd /status output instead of running the command. Useful when a
user sends you the output.

.PARAMETER AsJson
Print one JSON document instead of text.

.EXAMPLE
.\Get-DefenseClawEntraIdentity.ps1

.EXAMPLE
.\Get-DefenseClawEntraIdentity.ps1 -GroupSid S-1-12-1-1111111111-2222222222-3333333333-4444444444 -AsJson
#>
[CmdletBinding()]
param(
    [string[]]$GroupSid = @(),
    [string]$User,
    [string]$Connector = 'claudecode',
    [string]$DsregStatusPath,
    [switch]$AsJson
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Exit-WithError {
    param([string]$Message)
    [Console]::Error.WriteLine("error: $Message")
    exit 1
}

foreach ($sid in $GroupSid) {
    if ($sid -notmatch '^S-1-12-1-\d+-\d+-\d+-\d+$') {
        Exit-WithError "'$sid' is not the SID of an Entra group (S-1-12-1-<a>-<b>-<c>-<d>)."
    }
}
if ($User -and $User -match '@') {
    Exit-WithError "A Windows computer cannot look up a UPN. Pass the user's SID or AzureAD\Name to -User."
}

if (-not ('DcIdentityKit.LocalGroupMembers' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace DcIdentityKit
{
    public static class LocalGroupMembers
    {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buffer, int maxLength, out int entriesRead, out int totalEntries, ref IntPtr resume);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        public static string[] Members(string group)
        {
            IntPtr buffer;
            int read;
            int total;
            IntPtr resume = IntPtr.Zero;
            int status = NetLocalGroupGetMembers(null, group, 0, out buffer, -1, out read, out total, ref resume);
            if (status != 0)
            {
                throw new Win32Exception(status);
            }
            List<string> sids = new List<string>();
            try
            {
                for (int i = 0; i < read; i++)
                {
                    IntPtr pointer = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    sids.Add(new SecurityIdentifier(pointer).Value);
                }
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
            return sids.ToArray();
        }
    }
}
'@
}

function Get-PropertyValue {
    param($Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    [string]$property.Value
}

function Get-JoinState {
    param([string]$Path)
    if ($Path) {
        $lines = Get-Content -LiteralPath $Path
    }
    else {
        $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
        if (-not (Test-Path -LiteralPath $exe)) { return [ordered]@{ Error = 'dsregcmd.exe was not found' } }
        $lines = & $exe /status 2>&1
    }
    $wanted = @('AzureAdJoined', 'EnterpriseJoined', 'DomainJoined', 'DeviceAuthStatus', 'TenantName', 'TenantId', 'MdmUrl',
        'AzureAdPrt', 'IsUserAzureAD', 'Executing Account Name', 'WorkplaceJoined')
    $all = @{}
    foreach ($line in $lines) {
        if ([string]$line -match '^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*(.*?)\s*$') {
            if (-not $all.ContainsKey($Matches[1])) { $all[$Matches[1]] = $Matches[2] }
        }
    }
    $state = [ordered]@{}
    foreach ($key in $wanted) {
        if ($all.ContainsKey($key)) { $state[$key] = $all[$key] }
    }
    $state
}

function Get-IdentityStoreAccount {
    $base = 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache'
    try {
        $keys = @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)
    }
    catch {
        return [pscustomobject]@{ Readable = $false; Message = $_.Exception.Message; Accounts = @() }
    }
    $accounts = @()
    foreach ($key in $keys) {
        $sid = $key.PSChildName
        $cache = Join-Path $key.PSPath "IdentityCache\$sid"
        if (-not (Test-Path -LiteralPath $cache)) { continue }
        $values = Get-ItemProperty -LiteralPath $cache
        $accounts += [pscustomobject]@{
            Sid      = $sid
            UserName = Get-PropertyValue $values 'UserName'
            Provider = Get-PropertyValue $values 'ProviderName'
            SamName  = Get-PropertyValue $values 'SAMName'
        }
    }
    [pscustomobject]@{ Readable = $true; Message = ''; Accounts = $accounts }
}

function Get-CloudJoinInfo {
    $info = @()
    $message = ''
    foreach ($path in 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo', 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo') {
        try {
            foreach ($key in @(Get-ChildItem -LiteralPath $path -ErrorAction Stop)) {
                $values = Get-ItemProperty -LiteralPath $key.PSPath
                $info += [pscustomobject]@{
                    Key         = (Split-Path $path -Leaf)
                    TenantId    = Get-PropertyValue $values 'TenantId'
                    IdpDomain   = Get-PropertyValue $values 'IdpDomain'
                    DisplayName = Get-PropertyValue $values 'DisplayName'
                }
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] { continue }
        catch { $message = $_.Exception.Message }
    }
    [pscustomobject]@{ Entries = $info; Message = $message }
}

function Convert-SidToName {
    param([System.Security.Principal.SecurityIdentifier]$Sid)
    try { $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { '' }
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$tokenGroups = @()
foreach ($group in $identity.Groups) {
    $tokenGroups += [pscustomobject]@{
        Sid     = $group.Value
        Name    = Convert-SidToName $group
        IsEntra = $group.Value.StartsWith('S-1-12-1-')
    }
}
$tokenSids = @($tokenGroups | ForEach-Object { $_.Sid })

$builtIn = [ordered]@{
    'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-545' = 'Users'; 'S-1-5-32-546' = 'Guests'
    'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-555' = 'Remote Desktop Users'; 'S-1-5-32-580' = 'Remote Management Users'
}
$localGroups = @()
foreach ($groupSidValue in $builtIn.Keys) {
    $name = Convert-SidToName (New-Object System.Security.Principal.SecurityIdentifier($groupSidValue))
    $name = if ($name) { ($name -split '\\')[-1] } else { $builtIn[$groupSidValue] }
    try {
        $members = @([DcIdentityKit.LocalGroupMembers]::Members($name))
        $message = ''
    }
    catch {
        $members = @()
        $message = $_.Exception.Message
    }
    $localGroups += [pscustomobject]@{
        Group      = $name
        Sid        = $groupSidValue
        EntraSids  = @($members | Where-Object { $_.StartsWith('S-1-12-1-') })
        MemberCount = $members.Count
        Message    = $message
    }
}

$checks = @()
foreach ($sid in $GroupSid) {
    $listedIn = @($localGroups | Where-Object { $_.EntraSids -contains $sid } | ForEach-Object { $_.Group })
    $inToken = $tokenSids -contains $sid
    if ($inToken) { $verdict = 'in this account''s sign-in token: a groups assignment naming this SID can match' }
    elseif ($listedIn.Count -gt 0) { $verdict = 'listed in a built-in local group but not in this token: sign out and sign in again' }
    else { $verdict = 'not listed in any built-in local group that this script can see, so Windows may not put it in a token (see Add-EntraGroupToLocalGroup.ps1); the list can miss SIDs the computer cannot resolve' }
    $checks += [pscustomobject]@{ GroupSid = $sid; ListedIn = $listedIn; InThisToken = $inToken; Verdict = $verdict }
}

$cliPath = ''
$cliMode = 'none'
$enterpriseCli = Join-Path $env:ProgramFiles 'Cisco\DefenseClaw\bin\defenseclaw.exe'
if ((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Cisco\DefenseClaw\Enterprise') -and (Test-Path -LiteralPath $enterpriseCli)) {
    $cliPath = $enterpriseCli
    $cliMode = 'enterprise'
}
else {
    $found = Get-Command defenseclaw -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $cliPath = $found.Source
        $cliMode = 'per-user'
    }
}
$explain = [ordered]@{ Mode = $cliMode; Command = ''; ExitCode = $null; Output = '' }
if ($cliMode -ne 'none') {
    if ($cliMode -eq 'enterprise') {
        $target = if ($User) { $User } else { $identity.User.Value }
        $arguments = @('enterprise', 'windows', 'profile-explain', '--user', $target, '--connector', $Connector)
    }
    else {
        $arguments = @('guardrail', 'profile', 'explain', '--connector', $Connector, '--json')
        if ($User) { $arguments += @('--user', $User) }
    }
    $explain.Command = 'defenseclaw ' + ($arguments -join ' ')
    $output = & $cliPath @arguments 2>&1 | Out-String
    $explain.ExitCode = $LASTEXITCODE
    $explain.Output = $output.Trim()
}

$report = [ordered]@{
    ComputerName  = $env:COMPUTERNAME
    RunAs         = $identity.Name
    RunAsSid      = $identity.User.Value
    JoinState     = Get-JoinState -Path $DsregStatusPath
    IdentityStore = Get-IdentityStoreAccount
    CloudJoin     = Get-CloudJoinInfo
    TokenGroups   = $tokenGroups
    LocalGroups   = $localGroups
    GroupChecks   = $checks
    DefenseClaw   = $explain
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 6
    return
}

function Write-Section {
    param([string]$Title)
    Write-Output ''
    Write-Output "== $Title"
}

Write-Output "Computer: $($report.ComputerName)    Run as: $($report.RunAs) ($($report.RunAsSid))"
Write-Section 'Join state (dsregcmd /status)'
foreach ($key in $report.JoinState.Keys) { Write-Output ('{0,-24} {1}' -f $key, $report.JoinState[$key]) }

Write-Section 'Entra accounts in the identity store cache (run as SYSTEM if it is not readable)'
if (-not $report.IdentityStore.Readable) { Write-Output "not readable: $($report.IdentityStore.Message)" }
elseif ($report.IdentityStore.Accounts.Count -eq 0) { Write-Output 'none' }
else { foreach ($a in $report.IdentityStore.Accounts) { Write-Output ('{0}  {1}  provider={2}  sam={3}' -f $a.Sid, $a.UserName, $a.Provider, $a.SamName) } }

Write-Section 'Cloud join info (tenant)'
if ($report.CloudJoin.Entries.Count -eq 0) { Write-Output ('none' + $(if ($report.CloudJoin.Message) { ": $($report.CloudJoin.Message)" } else { '' })) }
foreach ($e in $report.CloudJoin.Entries) { Write-Output ('{0}  tenant={1}  domain={2}  name={3}' -f $e.Key, $e.TenantId, $e.IdpDomain, $e.DisplayName) }

Write-Section 'Sign-in token of this account (Entra group SIDs are marked)'
foreach ($g in $report.TokenGroups) { Write-Output ('{0}  {1}{2}' -f $g.Sid, $g.Name, $(if ($g.IsEntra) { '   <-- Entra' } else { '' })) }
if (@($report.TokenGroups | Where-Object { $_.IsEntra }).Count -eq 0) { Write-Output 'No Entra group SID in this token.' }

Write-Section 'Entra SIDs listed in built-in local groups'
foreach ($g in $report.LocalGroups) {
    $detail = if ($g.Message) { "cannot read: $($g.Message)" } elseif ($g.EntraSids.Count -gt 0) { $g.EntraSids -join ', ' } else { 'none' }
    Write-Output ('{0,-24} {1}' -f $g.Group, $detail)
}

if ($report.GroupChecks.Count -gt 0) {
    Write-Section 'Groups you asked about'
    foreach ($c in $report.GroupChecks) { Write-Output "$($c.GroupSid): $($c.Verdict)" }
}

Write-Section 'What DefenseClaw answers'
if ($report.DefenseClaw.Mode -eq 'none') { Write-Output 'DefenseClaw is not installed on this computer.' }
else {
    Write-Output "> $($report.DefenseClaw.Command)   (exit $($report.DefenseClaw.ExitCode))"
    Write-Output $report.DefenseClaw.Output
}
