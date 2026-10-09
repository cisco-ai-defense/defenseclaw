# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'native service logon tests require Windows'
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'native service logon tests require an elevated administrator token'
}

$modulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Get-Module DefenseClawEnterprise -ErrorAction Stop
$native = & $module { Initialize-DefenseClawNativeSecurity }

# An independent test-only LSA reader/writer verifies the real production
# helper's marshaling and additive behavior. Every mutation uses a new random
# virtual-service SID; no production service, group or rights list is changed.
$namespace = 'DefenseClaw.Tests.Lsa_' + [Guid]::NewGuid().ToString('N')
$compiled = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace $namespace
{
    public static class FixturePolicy
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Attributes
        {
            public uint Length;
            public IntPtr Root, Name;
            public uint Flags;
            public IntPtr Descriptor, Quality;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length, MaximumLength;
            public IntPtr Buffer;
        }
        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(IntPtr system, ref Attributes attributes, uint access, out IntPtr handle);
        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(IntPtr handle, IntPtr sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid, ref UnicodeString right, uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, [MarshalAs(UnmanagedType.Bool)] bool all, IntPtr rights, uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr handle);

        private static void Check(uint status)
        {
            if (status != 0) { throw new Win32Exception((int)LsaNtStatusToWinError(status)); }
        }
        public static string[] Apply(string value, string add, bool remove)
        {
            SecurityIdentifier sid = new SecurityIdentifier(value);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            IntPtr sidBuffer = Marshal.AllocHGlobal(bytes.Length);
            IntPtr handle = IntPtr.Zero, rights = IntPtr.Zero, name = IntPtr.Zero;
            try
            {
                Marshal.Copy(bytes, 0, sidBuffer, bytes.Length);
                Attributes attributes = new Attributes();
                attributes.Length = (uint)Marshal.SizeOf(typeof(Attributes));
                Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x800 | 0x10, out handle));
                if (remove)
                {
                    uint removed = LsaRemoveAccountRights(handle, sidBuffer, true, IntPtr.Zero, 0);
                    if (removed != 0 && LsaNtStatusToWinError(removed) != 2) { Check(removed); }
                    return new string[0];
                }
                // PowerShell converts a null string argument to String.Empty.
                // Both representations mean a read-only fixture operation.
                if (!String.IsNullOrEmpty(add))
                {
                    name = Marshal.StringToHGlobalUni(add);
                    UnicodeString right = new UnicodeString();
                    right.Length = checked((ushort)(add.Length * 2));
                    right.MaximumLength = checked((ushort)(right.Length + 2));
                    right.Buffer = name;
                    Check(LsaAddAccountRights(handle, sidBuffer, ref right, 1));
                }
                uint count;
                uint status = LsaEnumerateAccountRights(handle, sidBuffer, out rights, out count);
                if (status != 0 && LsaNtStatusToWinError(status) == 2) { return new string[0]; }
                Check(status);
                List<string> result = new List<string>();
                int stride = Marshal.SizeOf(typeof(UnicodeString));
                for (uint index = 0; index < count; index++)
                {
                    UnicodeString right = (UnicodeString)Marshal.PtrToStructure(
                        IntPtr.Add(rights, checked((int)index * stride)), typeof(UnicodeString));
                    result.Add(Marshal.PtrToStringUni(right.Buffer, right.Length / 2));
                }
                return result.ToArray();
            }
            finally
            {
                if (rights != IntPtr.Zero) { LsaFreeMemory(rights); }
                if (handle != IntPtr.Zero) { LsaClose(handle); }
                if (name != IntPtr.Zero) { Marshal.FreeHGlobal(name); }
                Marshal.FreeHGlobal(sidBuffer);
            }
        }
    }
}
"@ -Language CSharp -PassThru -ErrorAction Stop)
$fixture = @($compiled | Where-Object { $_.Name -ceq 'FixturePolicy' })[0]

foreach ($invalidSID in @('S-1-5-18', 'S-1-5-80-0')) {
    $caught = $false
    try { [void]$native::EnsureServiceLogonRight($invalidSID) }
    catch {
        $exception = $_.Exception
        while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
        if ($exception -isnot [ArgumentException]) { throw }
        $caught = $true
    }
    if (-not $caught) { throw "native helper accepted non-service/broad SID $invalidSID" }
}

foreach ($preexistingRight in @('', 'SeBatchLogonRight')) {
    $serviceName = 'DefenseClawCertGateway_' + ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
    $sid = & $module {
        param($name)
        Get-DefenseClawDeterministicServiceSID -ServiceName $name
    } $serviceName
    $before = @($fixture::Apply($sid, $null, $false))
    if ($before.Count -ne 0) { throw "random test SID already has rights; refusing to mutate $sid" }
    try {
        if ($preexistingRight) { [void]$fixture::Apply($sid, $preexistingRight, $false) }
        if (-not $native::EnsureServiceLogonRight($sid)) { throw 'missing service right was not added' }
        $after = @($fixture::Apply($sid, $null, $false) | Sort-Object)
        $expected = @('SeServiceLogonRight')
        if ($preexistingRight) { $expected += $preexistingRight }
        $expected = @($expected | Sort-Object)
        if (($after -join ',') -cne ($expected -join ',')) {
            throw "grant did not preserve exact prior account rights: $($after -join ',')"
        }
        if ($native::EnsureServiceLogonRight($sid)) { throw 'repeated grant was not idempotent' }
        $repeated = @($fixture::Apply($sid, $null, $false) | Sort-Object)
        if (($repeated -join ',') -cne ($after -join ',')) { throw 'repeated grant changed existing rights' }
    }
    finally {
        # Only this random fixture's entry is removed. Production rollback and
        # uninstall deliberately have no corresponding rights-removal call.
        [void]$fixture::Apply($sid, $null, $true)
    }
    if (@($fixture::Apply($sid, $null, $false)).Count -ne 0) { throw 'test LSA entry cleanup failed' }
}

# Verify the production registry/account binding using a disabled disposable
# service. Its dummy image is never executed. Wrong-account validation must
# fail before any rights are granted, then the exact virtual account succeeds.
$serviceName = 'DefenseClawCertGateway_' + ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$sid = & $module {
    param($name)
    if (Test-DefenseClawServiceExists -Name $name) { throw 'random fixture service already exists' }
    Get-DefenseClawDeterministicServiceSID -ServiceName $name
} $serviceName
if (@($fixture::Apply($sid, $null, $false)).Count -ne 0) { throw 'random fixture SID already has rights' }
$created = $false
try {
    & $module {
        param($name)
        $image = '"{0}"' -f ([IO.Path]::Combine($script:WindowsDirectory, 'System32', 'cmd.exe'))
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $name, 'binPath=', $image, 'start=', 'disabled', 'obj=', 'LocalSystem'
        ))
    } $serviceName
    $created = $true
    $wrongAccountRejected = $false
    try {
        [void](& $module {
            param($name)
            Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $name
        } $serviceName)
    }
    catch {
        if ($_.Exception.Message -notmatch 'expected virtual account') { throw }
        $wrongAccountRejected = $true
    }
    if (-not $wrongAccountRejected) { throw 'LocalSystem fixture passed virtual-account validation' }
    if (@($fixture::Apply($sid, $null, $false)).Count -ne 0) { throw 'wrong-account failure granted rights' }
    & $module {
        param($name)
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $name, 'obj=', "NT SERVICE\$name"
        ))
    } $serviceName
    $beforeGrant = @($fixture::Apply($sid, $null, $false))
    $receipt = & $module {
        param($name)
        Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $name
    } $serviceName
    $expectedOutcome = if ($beforeGrant -contains 'SeServiceLogonRight') { 'already_granted' } else { 'added' }
    if ($receipt.sid -cne $sid -or $receipt.account -cne "NT SERVICE\$serviceName" -or
        $receipt.outcome -cne $expectedOutcome) {
        throw 'provisioning receipt does not match the configured virtual service identity'
    }
    $expectedRights = @(@($beforeGrant) + @('SeServiceLogonRight') | Sort-Object -Unique)
    $rights = @($fixture::Apply($sid, $null, $false) | Sort-Object)
    if (($rights -join ',') -cne ($expectedRights -join ',')) { throw 'virtual service right was not granted additively' }
    if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw 'disabled fixture service unexpectedly started'
    }
}
finally {
    if ($created) {
        & $module {
            param($name)
            [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('delete', $name))
        } $serviceName
        [void]$fixture::Apply($sid, $null, $true)
    }
}
Write-Output 'enterprise-service-logon-native-smoke OK'
