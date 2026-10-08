# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
<#
.SYNOPSIS
Adds the SID of a Microsoft Entra group to a built-in local group, or removes it.

.DESCRIPTION
An Entra-joined Windows computer puts an Entra group's SID (S-1-12-1-...) into a
user's sign-in token only when a built-in local group lists that group. Windows
documents this for Administrators, Users, Guests, Power Users, Remote Desktop
Users and Remote Management Users. Until then, a DefenseClaw `groups` assignment
or an enrollment include_groups / exclude_groups entry that names the Entra group
matches no one.

This script makes that membership with NetLocalGroupAddMembers, the API that the
Intune Account protection (Local user group membership) and LocalUsersAndGroups
policies use. Use the policy for a fleet. Use this script to try it on one
computer. For Intune, use an Account protection policy: Intune platform scripts
receive no arguments, while this script requires -GroupSid.

It is idempotent: a group that is already a member is reported, not an error.
Run it elevated (an administrator, or SYSTEM from an MDM). Users must sign out and
back in before the new membership is in their token.

Tested on Windows 11 and Windows Server 2025 with a throwaway local group. The
Intune delivery of the same membership was not tested yet.

.PARAMETER GroupSid
One or more Entra group SIDs (S-1-12-1-<a>-<b>-<c>-<d>). Read a group's SID with
entra_setup.py sids --group NAME, or from the securityIdentifier property of the
group in Microsoft Graph.
When calling with powershell.exe -File, separate multiple SIDs with commas in
one argument (PowerShell does not bind an array across process arguments).

.PARAMETER LocalGroup
The local group, by name or SID. The default is Users (S-1-5-32-545), the least
privileged choice. Administrators gives every member of the Entra group
administrator rights, so the script warns when you name it.

.PARAMETER Remove
Remove the SIDs from the local group instead of adding them.

.EXAMPLE
.\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-1111111111-2222222222-3333333333-4000000000 -WhatIf

Shows what would change and changes nothing.

.EXAMPLE
.\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-1111111111-2222222222-3333333333-4000000000

Adds the Entra group to the built-in Users group.

.EXAMPLE
.\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-1111111111-2222222222-3333333333-4000000000 -Remove

Removes it again.

.EXAMPLE
powershell.exe -File .\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-1111111111-2222222222-3333333333-4000000000,S-1-12-1-1-2-3-4 -WhatIf

Checks two SIDs from a separate process.

.OUTPUTS
One object per SID with GroupSid, LocalGroup and Action: Added, AlreadyMember,
Removed, NotMember or WhatIf.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$GroupSid,

    [string]$LocalGroup = 'S-1-5-32-545',

    [switch]$Remove
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output 'error: Constrained Language Mode prevents this script from using the Windows local-group API. Run it in an approved FullLanguage administrator session or use Intune Account protection.'
    exit 1
}

function Exit-WithError {
    param([string]$Message)
    [Console]::Error.WriteLine("error: $Message")
    exit 1
}

$GroupSid = @($GroupSid | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() })
$entraSidPattern = '^S-1-12-1-(?:[0-9]|[1-9][0-9]{1,9})-(?:[0-9]|[1-9][0-9]{1,9})-(?:[0-9]|[1-9][0-9]{1,9})-(?:[0-9]|[1-9][0-9]{1,9})$'
foreach ($sid in $GroupSid) {
    $valid = $sid -cmatch $entraSidPattern
    if ($valid) {
        foreach ($component in @($sid -split '-') | Select-Object -Skip 4) {
            if ([uint64]$component -gt [uint32]::MaxValue) { $valid = $false; break }
        }
    }
    if (-not $valid) {
        Exit-WithError "'$sid' is not the SID of an Entra group (S-1-12-1-<a>-<b>-<c>-<d>). Read it with: entra_setup.py sids --group <name>"
    }
}

if (-not ('DcIdentityKit.LocalGroupApi' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace DcIdentityKit
{
    public static class LocalGroupApi
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MemberInfo0 { public IntPtr Sid; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupAddMembers(string server, string group, int level, ref MemberInfo0 members, int count);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupDelMembers(string server, string group, int level, ref MemberInfo0 members, int count);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buffer, int maxLength, out int entriesRead, out int totalEntries, ref IntPtr resume);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        // Returns the Win32 status: 0 success, 1378 already a member, 1377 not a member.
        public static int Change(string group, string sid, bool add)
        {
            SecurityIdentifier identifier = new SecurityIdentifier(sid);
            byte[] binary = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(binary, 0);
            IntPtr memory = Marshal.AllocHGlobal(binary.Length);
            try
            {
                Marshal.Copy(binary, 0, memory, binary.Length);
                MemberInfo0 member = new MemberInfo0();
                member.Sid = memory;
                if (add)
                {
                    return NetLocalGroupAddMembers(null, group, 0, ref member, 1);
                }
                return NetLocalGroupDelMembers(null, group, 0, ref member, 1);
            }
            finally
            {
                Marshal.FreeHGlobal(memory);
            }
        }

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

function Resolve-LocalGroup {
    param([string]$Value)
    try {
        if ($Value -match '^S-\d+(-\d+)+$') {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($Value)
            $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
        }
        else {
            $sid = (New-Object System.Security.Principal.NTAccount($Value)).Translate([System.Security.Principal.SecurityIdentifier])
            $account = $Value
        }
    }
    catch {
        Exit-WithError "The local group '$Value' was not found on this computer."
    }
    [pscustomobject]@{ Sid = $sid.Value; Name = ($account -split '\\')[-1] }
}

$group = Resolve-LocalGroup -Value $LocalGroup
$wellKnown = @('S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-32-547', 'S-1-5-32-555', 'S-1-5-32-580')
if ($wellKnown -notcontains $group.Sid) {
    $format = "'{0}' is not one of the local groups that Windows reads Entra group SIDs from (Administrators, Users, Guests, " +
        'Power Users, Remote Desktop Users, Remote Management Users). The membership is made, but a sign-in token will not carry the Entra group.'
    Write-Warning ($format -f $group.Name)
}
if ($group.Sid -eq 'S-1-5-32-544' -and -not $Remove) {
    Write-Warning 'Every member of the Entra group becomes a local administrator of this computer.'
}

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    Exit-WithError 'Run this script elevated (as an administrator or as SYSTEM). Use -WhatIf to preview without elevation.'
}

# Windows may not list the SID of an Entra group that this computer cannot resolve, so the list is a hint only:
# the status of the change itself (1378 already a member, 1377 not a member) is what decides the result.
try {
    $listed = [DcIdentityKit.LocalGroupApi]::Members($group.Name)
}
catch {
    Exit-WithError "Cannot read the members of '$($group.Name)': $($_.Exception.Message)"
}

$verb = if ($Remove) { 'Remove' } else { 'Add' }
foreach ($sid in $GroupSid) {
    $isListed = $listed -contains $sid
    if ($Remove -and -not $isListed -and $WhatIfPreference) { $action = 'WhatIf' }
    elseif (-not $Remove -and $isListed) { $action = 'AlreadyMember' }
    elseif ($PSCmdlet.ShouldProcess($group.Name, "$verb Entra group $sid")) {
        $status = [DcIdentityKit.LocalGroupApi]::Change($group.Name, $sid, (-not $Remove))
        switch ($status) {
            0 { $action = if ($Remove) { 'Removed' } else { 'Added' } }
            1378 { $action = 'AlreadyMember' }
            1377 { $action = 'NotMember' }
            default { Exit-WithError ('{0} {1} failed with Win32 error {2}: {3}' -f $verb, $sid, $status, (New-Object System.ComponentModel.Win32Exception($status)).Message) }
        }
    }
    else { $action = 'WhatIf' }
    [pscustomobject]@{ GroupSid = $sid; LocalGroup = $group.Name; Action = $action }
}

if (-not $WhatIfPreference) {
    Write-Verbose 'Users must sign out and back in before the change is in their sign-in token.'
}
