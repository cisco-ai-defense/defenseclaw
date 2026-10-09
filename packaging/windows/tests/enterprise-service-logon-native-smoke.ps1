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

# Verify identity binding and the actual production SCM startup wrapper with
# a disposable, runnable service. Every allow/deny mutation below is confined
# to its new random SID; existing services and ALL SERVICES are untouched.
$serviceName = 'DefenseClawCertGateway_' + ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$sid = & $module {
    param($name)
    if (Test-DefenseClawServiceExists -Name $name) { throw 'random fixture service already exists' }
    Get-DefenseClawDeterministicServiceSID -ServiceName $name
} $serviceName
if (@($fixture::Apply($sid, $null, $false)).Count -ne 0) { throw 'random fixture SID already has rights' }
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$fixtureLeaf = 'DefenseClawServiceLogon_' + [Guid]::NewGuid().ToString('N')
$fixtureRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($tempRoot, $fixtureLeaf))
if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($fixtureRoot), $tempRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'service fixture directory is outside its expected temporary parent'
}
if (Test-Path -LiteralPath $fixtureRoot) { throw 'random fixture directory already exists' }
$fixtureDirectoryCreated = $false
$created = $false
try {
    [void](New-Item -ItemType Directory -Path $fixtureRoot -ErrorAction Stop)
    $fixtureDirectoryCreated = $true
    $sourcePath = Join-Path $fixtureRoot 'Fixture.cs'
    $imagePath = Join-Path $fixtureRoot 'Fixture.exe'
    @'
using System.ServiceProcess;
public sealed class ServiceLogonFixture : ServiceBase
{
    private ServiceLogonFixture(string name)
    {
        ServiceName = name;
        CanStop = true;
        AutoLog = false;
    }
    public static void Main(string[] args)
    {
        ServiceBase.Run(new ServiceLogonFixture(args[0]));
    }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
}
'@ | Set-Content -LiteralPath $sourcePath -Encoding ASCII
    # Build a .NET Framework service with the trusted in-box compiler so the
    # same fixture can be hosted by both Windows PowerShell and PowerShell 7.
    $compiler = & $module {
        [IO.Path]::Combine($script:WindowsDirectory, 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe')
    }
    & $compiler /nologo /target:exe "/out:$imagePath" /reference:System.ServiceProcess.dll $sourcePath
    if ($LASTEXITCODE -ne 0) { throw "service fixture compilation failed: $LASTEXITCODE" }
    $image = '"{0}" {1}' -f $imagePath, $serviceName
    & $module {
        param($name, $image)
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $name, 'binPath=', $image, 'start=', 'disabled', 'obj=', 'LocalSystem'
        ))
    } $serviceName $image
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
    & $module {
        param($path, $serviceSID)
        [void](Invoke-DefenseClawNative -File $script:IcaclsExe -Arguments @(
            $path, '/grant', "*${serviceSID}:(OI)(CI)(RX)"
        ))
    } $fixtureRoot $sid
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

    # An explicit deny is deterministic even on hosts that authorize all
    # virtual services through a group grant. Provisioning must preserve the
    # deny, and the exact production startup catch must retain the native error.
    [void]$fixture::Apply($sid, 'SeDenyServiceLogonRight', $false)
    $deniedReceipt = & $module {
        param($name)
        Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $name
    } $serviceName
    if ($deniedReceipt.sid -cne $sid -or $deniedReceipt.outcome -cne 'already_granted') {
        throw 'repeated provisioning did not preserve the existing direct allow'
    }
    $deniedRights = @($fixture::Apply($sid, $null, $false) | Sort-Object)
    $expectedDeniedRights = @(@($expectedRights) + @('SeDenyServiceLogonRight') | Sort-Object -Unique)
    if (($deniedRights -join ',') -cne ($expectedDeniedRights -join ',')) {
        throw 'production provisioning changed the fixture deny or other existing rights'
    }
    & $module {
        param($name)
        Set-DefenseClawServiceStartMode -Name $name -StartMode 3
    } $serviceName
    $failure = $null
    try {
        & $module {
            param($name, $serviceSID)
            Start-DefenseClawService -Name $name -GatewayServiceSID $serviceSID
        } $serviceName $sid
    }
    catch { $failure = $_.Exception }
    if ($null -eq $failure) { throw 'fixture with denied service logon unexpectedly started' }
    $nativeCode = & $module {
        param($exception)
        Get-DefenseClawWin32ErrorCode -Exception $exception
    } $failure
    if ($nativeCode -notin @(1069, 1385)) {
        throw "startup wrapper lost the native service logon failure: $failure"
    }
    foreach ($fragment in @($serviceName, "NT SERVICE\$serviceName", $sid, [string]$nativeCode,
            'could not log on', 'SeServiceLogonRight', 'deny', 'GPO/MDM')) {
        if ($failure.Message.IndexOf($fragment, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "production startup diagnostic omitted $fragment"
        }
    }
    if ($failure -isnot [InvalidOperationException] -or $null -eq $failure.InnerException -or
        $null -eq $failure.InnerException.InnerException) {
        throw 'production startup diagnostic flattened the original SCM exception chain'
    }
    $originalCode = & $module {
        param($exception)
        Get-DefenseClawWin32ErrorCode -Exception $exception
    } $failure.InnerException
    if ($originalCode -ne $nativeCode -or
        -not $failure.Message.Contains($failure.InnerException.Message)) {
        throw 'production startup diagnostic did not preserve the original startup exception'
    }
    if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw 'denied fixture service did not remain stopped'
    }

    # Remove only this fixture SID's entry, then reprovision while disabled.
    # An existing host group grant can mask a causal missing-allow failure;
    # this positive leg verifies direct provisioning and real SCM startup.
    [void]$fixture::Apply($sid, $null, $true)
    & $module {
        param($name)
        Set-DefenseClawServiceStartMode -Name $name -StartMode 4
    } $serviceName
    $allowedReceipt = & $module {
        param($name)
        Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $name
    } $serviceName
    $allowedRights = @($fixture::Apply($sid, $null, $false))
    if ($allowedReceipt.sid -cne $sid -or $allowedReceipt.outcome -cne 'added' -or
        $allowedRights.Count -ne 1 -or $allowedRights[0] -cne 'SeServiceLogonRight') {
        throw 'disabled fixture was not provisioned with the exact direct service logon allow'
    }
    & $module {
        param($name, $serviceSID)
        Set-DefenseClawServiceStartMode -Name $name -StartMode 3
        Start-DefenseClawService -Name $name -GatewayServiceSID $serviceSID
    } $serviceName $sid
    if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw 'fixture with provisioned service logon allow did not reach Running'
    }
}
finally {
    try {
        if ($created) {
            try {
                & $module {
                    param($name)
                    Stop-DefenseClawService -Name $name
                } $serviceName
            }
            finally {
                & $module {
                    param($name)
                    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('delete', $name))
                } $serviceName
            }
        }
    }
    finally {
        try {
            if ($created) { [void]$fixture::Apply($sid, $null, $true) }
        }
        finally {
            if ($fixtureDirectoryCreated) {
                $resolvedFixture = [IO.Path]::GetFullPath((Get-Item -LiteralPath $fixtureRoot -Force).FullName)
                if (-not [string]::Equals($resolvedFixture, $fixtureRoot, [StringComparison]::OrdinalIgnoreCase) -or
                    -not [string]::Equals([IO.Path]::GetDirectoryName($resolvedFixture), $tempRoot,
                        [StringComparison]::OrdinalIgnoreCase) -or
                    -not [string]::Equals([IO.Path]::GetFileName($resolvedFixture), $fixtureLeaf,
                        [StringComparison]::Ordinal)) {
                    throw 'refusing cleanup of a service fixture outside its exact temporary directory'
                }
                Remove-Item -LiteralPath $resolvedFixture -Recurse -Force -ErrorAction Stop
            }
        }
    }
}
if (@($fixture::Apply($sid, $null, $false)).Count -ne 0) { throw 'service fixture LSA entry cleanup failed' }
Write-Output 'enterprise-service-logon-native-smoke OK'
