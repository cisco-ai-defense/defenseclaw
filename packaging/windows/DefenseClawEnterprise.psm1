# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-DefenseClawTrustedMachineRoot {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -match '[\x00-\x1f%]' -or
        -not [IO.Path]::IsPathRooted($Value)) {
        throw "trusted $Label root is empty, relative, or contains an invalid character"
    }
    $provided = $Value.TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    $driveRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($driveRoot) -or
        $driveRoot -notmatch '^[A-Za-z]:\\$' -or
        -not [string]::Equals(
            $provided,
            $full,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':')) -or
        -not [IO.Directory]::Exists($full)) {
        throw "trusted $Label root is not an existing canonical local directory: $full"
    }
    return $full
}

function Get-DefenseClawTrustedMachineRoots {
    # GetFolderPath can return an empty string when Windows PowerShell 5.1 is
    # launched with the deliberately reduced certification environment. Read
    # fixed machine registration instead of process-controlled environment.
    $windows = ConvertTo-DefenseClawTrustedMachineRoot `
        -Value ([IO.Path]::GetDirectoryName([Environment]::SystemDirectory)) `
        -Label 'Windows'
    $base = $null
    $currentVersion = $null
    $shell = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $currentVersion = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion',
            $false
        )
        if ($null -eq $currentVersion) {
            throw 'trusted Program Files machine registration is missing'
        }
        $programFilesRaw = [string]$currentVersion.GetValue(
            'ProgramFilesDir',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $shell = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            $false
        )
        if ($null -eq $shell) {
            throw 'trusted ProgramData machine registration is missing'
        }
        $programDataRaw = [string]$shell.GetValue(
            'Common AppData',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    finally {
        if ($null -ne $shell) { $shell.Dispose() }
        if ($null -ne $currentVersion) { $currentVersion.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
    return [pscustomobject]@{
        Windows = $windows
        ProgramFiles = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programFilesRaw `
            -Label 'Program Files'
        ProgramData = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programDataRaw `
            -Label 'ProgramData'
    }
}

# Bind privileged cmdlets to modules shipped with the current PowerShell
# engine. Windows PowerShell 5.1 can otherwise auto-select an incompatible
# PowerShell 7 module when a parent tool prepends its module directory; an
# ambient session can also preload a fake module under one of these names.
foreach ($engineModuleName in @(
    'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.Utility',
    'Microsoft.PowerShell.Security'
)) {
    $engineModulePath = [IO.Path]::Combine(
        $PSHOME,
        'Modules',
        $engineModuleName,
        "$engineModuleName.psd1"
    )
    if (-not [IO.File]::Exists($engineModulePath)) {
        throw "trusted engine-local module is missing: $engineModulePath"
    }
    Microsoft.PowerShell.Core\Import-Module `
        -Name $engineModulePath `
        -Force `
        -ErrorAction Stop
}

$script:SystemSID = 'S-1-5-18'
$script:OwnerRightsSID = 'S-1-3-4'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:UsersSID = 'S-1-5-32-545'
$script:AuthenticatedUsersSID = 'S-1-5-11'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:ServiceSDDL = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;BU)'
$script:ServiceDescription = 'Administrator-managed DefenseClaw service; standard users have query-only SCM access.'
$script:ServiceFailureRestartQuiescenceSeconds = 65
$script:SchemaVersion = 1
$script:AgentApplicationControlAttestationSchemaVersion = 2
$script:AgentApplicationControlPrerequisite = 'wdac_or_applocker_approved_agent_client_rules'
$trustedMachineRoots = Get-DefenseClawTrustedMachineRoots
$script:ProgramFiles = [string]$trustedMachineRoots.ProgramFiles
$script:ProgramData = [string]$trustedMachineRoots.ProgramData
$script:WindowsDirectory = [string]$trustedMachineRoots.Windows
$script:System32 = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($script:WindowsDirectory, 'System32')
).TrimEnd('\')
$script:ScExe = [IO.Path]::Combine($script:System32, 'sc.exe')
$script:DefenseClawNativeSecurityType = $null

function Initialize-DefenseClawNativeSecurity {
    if ($null -ne $script:DefenseClawNativeSecurityType) {
        return $script:DefenseClawNativeSecurityType
    }
    # Never trust a predictable type name in an ambient elevated PowerShell
    # session. A profile can preload arbitrary Add-Type classes before this
    # signed module is imported. Compile into an unpredictable namespace and
    # retain the exact Type object returned by this invocation.
    $nativeNamespace = 'DefenseClaw.Windows.Generated_' + [Guid]::NewGuid().ToString('N')
    $previousSystemRoot = [Environment]::GetEnvironmentVariable('SystemRoot', 'Process')
    $previousWindir = [Environment]::GetEnvironmentVariable('windir', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('SystemRoot', $script:WindowsDirectory, 'Process')
        [Environment]::SetEnvironmentVariable('windir', $script:WindowsDirectory, 'Process')
        $compiledTypes = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace $nativeNamespace
{
    public static class NativeSecurity
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            internal uint LowPart;
            internal int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            internal LUID Luid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            internal uint PrivilegeCount;
            internal LUID_AND_ATTRIBUTES Privileges;
        }

        public sealed class RegularFileSecuritySnapshot
        {
            public string Identity { get; private set; }
            public byte[] SecurityDescriptor { get; private set; }

            internal RegularFileSecuritySnapshot(
                string identity,
                byte[] securityDescriptor)
            {
                Identity = identity;
                SecurityDescriptor = securityDescriptor;
            }
        }

        public sealed class PathSecuritySnapshot
        {
            public string Identity { get; private set; }
            public byte[] SecurityDescriptor { get; private set; }

            internal PathSecuritySnapshot(
                string identity,
                byte[] securityDescriptor)
            {
                Identity = identity;
                SecurityDescriptor = securityDescriptor;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal uint dwX;
            internal uint dwY;
            internal uint dwXSize;
            internal uint dwYSize;
            internal uint dwXCountChars;
            internal uint dwYCountChars;
            internal uint dwFillAttribute;
            internal uint dwFlags;
            internal ushort wShowWindow;
            internal ushort cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            uint stringSDRevision,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectoryW(
            string path,
            ref SECURITY_ATTRIBUTES securityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string rootPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformationW(
            string rootPathName,
            StringBuilder volumeName,
            int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemName,
            int fileSystemNameSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeNameForVolumeMountPointW(
            string volumeMountPoint,
            StringBuilder volumeName,
            int bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            string volumeName,
            [Out] char[] volumePathNames,
            uint bufferLength,
            out uint returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            [Out] char[] targetPath,
            int maximumLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            IntPtr file,
            out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInformation,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint SetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorOwner(
            IntPtr securityDescriptor,
            out IntPtr owner,
            [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorGroup(
            IntPtr securityDescriptor,
            out IntPtr group,
            [MarshalAs(UnmanagedType.Bool)] out bool groupDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
            out IntPtr dacl,
            [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW(
            string systemName,
            string name,
            out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr token,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState,
            uint bufferLength,
            out TOKEN_PRIVILEGES previousState,
            out uint returnLength);

        [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RestoreTokenPrivileges(
            IntPtr token,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState,
            uint bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityDescriptorLength(
            IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorControl(
            IntPtr securityDescriptor,
            out ushort control,
            out uint revision);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MakeSelfRelativeSD(
            IntPtr absoluteSecurityDescriptor,
            [Out] byte[] selfRelativeSecurityDescriptor,
            ref uint bufferLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenServiceW(
            IntPtr serviceControlManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process,
            out System.Runtime.InteropServices.ComTypes.FILETIME creationTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME exitTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME kernelTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME userTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr process,
            uint flags,
            StringBuilder executablePath,
            ref uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        private static SECURITY_ATTRIBUTES SecurityAttributes(string sddl, out IntPtr descriptor)
        {
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "invalid security descriptor");
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.lpSecurityDescriptor = descriptor;
            attributes.bInheritHandle = false;
            return attributes;
        }

        public static bool CreateDirectorySecure(string path, string sddl)
        {
            IntPtr descriptor;
            SECURITY_ATTRIBUTES attributes = SecurityAttributes(sddl, out descriptor);
            try
            {
                if (CreateDirectoryW(path, ref attributes))
                    return true;
                int error = Marshal.GetLastWin32Error();
                if (error == 183)
                    return false;
                throw new Win32Exception(error, "secure directory creation failed: " + path);
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        public static bool ServiceExistsChecked(string name)
        {
            const uint SC_MANAGER_CONNECT = 0x0001;
            const uint SERVICE_QUERY_STATUS = 0x0004;
            const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
            if (String.IsNullOrWhiteSpace(name))
                throw new ArgumentException("service name is required", "name");
            IntPtr manager = OpenSCManagerW(
                null,
                null,
                SC_MANAGER_CONNECT);
            if (manager == IntPtr.Zero)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open service control manager for checked query failed");
            try
            {
                IntPtr service = OpenServiceW(
                    manager,
                    name,
                    SERVICE_QUERY_STATUS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ERROR_SERVICE_DOES_NOT_EXIST)
                        return false;
                    throw new Win32Exception(
                        error,
                        "checked service query failed: " + name);
                }
                try
                {
                    return true;
                }
                finally
                {
                    if (!CloseServiceHandle(service))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "close checked service query handle failed: " + name);
                }
            }
            finally
            {
                if (!CloseServiceHandle(manager))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "close service control manager handle failed");
            }
        }

        public static uint GetDriveType(string root)
        {
            return GetDriveTypeW(root);
        }

        public static string GetFileSystem(string root)
        {
            StringBuilder volume = new StringBuilder(261);
            StringBuilder fileSystem = new StringBuilder(261);
            uint serial;
            uint maximumComponentLength;
            uint flags;
            if (!GetVolumeInformationW(
                root,
                volume,
                volume.Capacity,
                out serial,
                out maximumComponentLength,
                out flags,
                fileSystem,
                fileSystem.Capacity))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetVolumeInformation failed");
            return fileSystem.ToString();
        }

        private static List<string> ParseMultiString(
            char[] buffer,
            int length,
            string operation)
        {
            if (length <= 0 || length > buffer.Length)
                throw new InvalidOperationException(
                    operation + " returned an invalid length");
            List<string> values = new List<string>();
            int start = 0;
            bool terminated = false;
            for (int index = 0; index < length; index++)
            {
                if (buffer[index] != '\0')
                    continue;
                if (index == start)
                {
                    terminated = true;
                    break;
                }
                values.Add(new string(buffer, start, index - start));
                start = index + 1;
            }
            if (!terminated || values.Count == 0)
                throw new InvalidOperationException(
                    operation + " returned a malformed MULTI_SZ value");
            return values;
        }

        private static string QueryDevice(string deviceName)
        {
            char[] target = new char[32768];
            uint length = QueryDosDeviceW(deviceName, target, target.Length);
            if (length == 0)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryDosDevice failed for " + deviceName);
            List<string> targets = ParseMultiString(
                target,
                checked((int)length),
                "QueryDosDevice " + deviceName);
            if (targets.Count != 1 ||
                String.IsNullOrEmpty(targets[0]) ||
                !targets[0].StartsWith(
                    @"\Device\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "QueryDosDevice returned a malformed or multi-target mapping for " +
                    deviceName);
            return targets[0];
        }

        public static string QueryDriveTarget(string drive)
        {
            return QueryDevice(drive);
        }

        public static string AssertCanonicalDriveRoot(string root, string drive)
        {
            if (String.IsNullOrEmpty(root) ||
                root.Length != 3 ||
                !Char.IsLetter(root[0]) ||
                root[1] != ':' ||
                root[2] != '\\' ||
                !String.Equals(
                    drive,
                    root.Substring(0, 2),
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "managed path root is not a canonical DOS drive root: " + root);

            StringBuilder volumeName = new StringBuilder(261);
            if (!GetVolumeNameForVolumeMountPointW(
                root,
                volumeName,
                volumeName.Capacity))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumeNameForVolumeMountPoint failed for " + root);
            string volume = volumeName.ToString();
            if (!volume.StartsWith(
                    @"\\?\Volume{",
                    StringComparison.OrdinalIgnoreCase) ||
                !volume.EndsWith(@"}\", StringComparison.Ordinal) ||
                volume.Length <= 13)
                throw new InvalidOperationException(
                    "managed path volume identity is not canonical: " + volume);
            Guid volumeGuid;
            string volumeGuidText =
                volume.Substring(11, volume.Length - 13);
            if (!Guid.TryParseExact(volumeGuidText, "D", out volumeGuid) ||
                !String.Equals(
                    volume,
                    @"\\?\Volume{" + volumeGuid.ToString("D") + @"}\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "managed path volume GUID identity is malformed: " + volume);

            string volumeDeviceName =
                volume.Substring(4, volume.Length - 5);
            string driveTarget = QueryDevice(drive);
            string globalDriveTarget = QueryDevice(@"Global\" + drive);
            string volumeTarget = QueryDevice(volumeDeviceName);
            if (!String.Equals(
                    driveTarget,
                    globalDriveTarget,
                    StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(
                    driveTarget,
                    volumeTarget,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "managed DOS drive target differs from its global authoritative volume");

            char[] paths = new char[32768];
            uint required;
            if (!GetVolumePathNamesForVolumeNameW(
                volume,
                paths,
                (uint)paths.Length,
                out required))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumePathNamesForVolumeName failed for " + volume);
            List<string> mountPaths = ParseMultiString(
                paths,
                checked((int)required),
                "GetVolumePathNamesForVolumeName " + volume);
            int rootMatches = 0;
            foreach (string path in mountPaths)
            {
                if (String.Equals(path, root, StringComparison.OrdinalIgnoreCase))
                    rootMatches++;
            }
            if (rootMatches != 1)
                throw new InvalidOperationException(
                    "managed DOS drive root is not registered with Mount Manager");
            return driveTarget;
        }

        public static string GetFileIdentity(string path)
        {
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint FILE_SHARE_DELETE = 0x00000004;
            const uint OPEN_EXISTING = 3;
            IntPtr handle = CreateFileW(
                path,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open file for identity failed: " + path);
            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query file identity failed: " + path);
                return String.Format(
                    System.Globalization.CultureInfo.InvariantCulture,
                    "{0:x8}:{1:x8}{2:x8}",
                    information.VolumeSerialNumber,
                    information.FileIndexHigh,
                    information.FileIndexLow);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public static uint GetRegularFileLinkCountNoFollow(string path)
        {
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint FILE_SHARE_DELETE = 0x00000004;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
            const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
            IntPtr handle = CreateFileW(
                path,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open regular file for link-count query failed: " + path);
            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query regular file link count failed: " + path);
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    throw new InvalidOperationException(
                        "refusing link-count query through a reparse point: " + path);
                if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    throw new InvalidOperationException(
                        "link-count query requires a regular file: " + path);
                if (information.NumberOfLinks == 0)
                    throw new InvalidOperationException(
                        "regular file reported an invalid zero link count: " + path);
                return information.NumberOfLinks;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public static byte[] GetFileSecurityDescriptor(string path)
        {
            const uint READ_CONTROL = 0x00020000;
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint FILE_SHARE_DELETE = 0x00000004;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
            const int SE_FILE_OBJECT = 1;
            const uint OWNER_SECURITY_INFORMATION = 0x00000001;
            const uint GROUP_SECURITY_INFORMATION = 0x00000002;
            const uint DACL_SECURITY_INFORMATION = 0x00000004;
            const ushort SE_SELF_RELATIVE = 0x8000;
            const int ERROR_INSUFFICIENT_BUFFER = 122;

            IntPtr handle = CreateFileW(
                path,
                READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open file for raw security query failed: " + path);
            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query file attributes for raw security failed: " + path);
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    throw new InvalidOperationException(
                        "refusing raw security query through a reparse point: " + path);

                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                IntPtr sacl;
                IntPtr descriptor;
                uint result = GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION |
                        GROUP_SECURITY_INFORMATION |
                        DACL_SECURITY_INFORMATION,
                    out owner,
                    out group,
                    out dacl,
                    out sacl,
                    out descriptor);
                if (result != 0)
                    throw new Win32Exception(
                        checked((int)result),
                        "raw file security query failed: " + path);
                if (descriptor == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "raw file security query returned a null descriptor: " + path);
                try
                {
                    ushort control;
                    uint revision;
                    if (!GetSecurityDescriptorControl(
                        descriptor,
                        out control,
                        out revision))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "query raw security descriptor control failed: " + path);

                    if ((control & SE_SELF_RELATIVE) != 0)
                    {
                        uint length = GetSecurityDescriptorLength(descriptor);
                        if (length == 0 || length > 1048576)
                            throw new InvalidOperationException(
                                "raw security descriptor length is invalid: " + path);
                        byte[] bytes = new byte[checked((int)length)];
                        Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                        return bytes;
                    }

                    uint required = 0;
                    if (MakeSelfRelativeSD(descriptor, null, ref required))
                        throw new InvalidOperationException(
                            "raw security conversion returned no required length: " + path);
                    int conversionError = Marshal.GetLastWin32Error();
                    if (conversionError != ERROR_INSUFFICIENT_BUFFER ||
                        required == 0 ||
                        required > 1048576)
                        throw new Win32Exception(
                            conversionError,
                            "size raw self-relative security descriptor failed: " + path);
                    byte[] relative = new byte[checked((int)required)];
                    if (!MakeSelfRelativeSD(descriptor, relative, ref required))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "convert raw security descriptor failed: " + path);
                    if (required != relative.Length)
                        throw new InvalidOperationException(
                            "raw security descriptor conversion length changed: " + path);
                    return relative;
                }
                finally
                {
                    LocalFree(descriptor);
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static string FileIdentity(
            BY_HANDLE_FILE_INFORMATION information)
        {
            return String.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "{0:x8}:{1:x8}{2:x8}",
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow);
        }

        private static void ValidateFixedRegularFile(
            BY_HANDLE_FILE_INFORMATION information,
            uint expectedSize,
            string path)
        {
            const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
            const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
            if ((information.FileAttributes &
                    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                throw new InvalidOperationException(
                    "managed secret is not a no-follow regular file: " + path);
            if (information.NumberOfLinks != 1)
                throw new InvalidOperationException(
                    "managed secret must have exactly one hard link: " + path);
            ulong size = ((ulong)information.FileSizeHigh << 32) |
                (ulong)information.FileSizeLow;
            if (size != expectedSize)
                throw new InvalidOperationException(
                    "managed secret has an invalid fixed length: " + path);
        }

        private static byte[] GetFileSecurityDescriptorFromHandle(
            IntPtr handle,
            string path)
        {
            const int SE_FILE_OBJECT = 1;
            const uint OWNER_SECURITY_INFORMATION = 0x00000001;
            const uint GROUP_SECURITY_INFORMATION = 0x00000002;
            const uint DACL_SECURITY_INFORMATION = 0x00000004;
            const ushort SE_SELF_RELATIVE = 0x8000;
            const int ERROR_INSUFFICIENT_BUFFER = 122;
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            uint result = GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION |
                    GROUP_SECURITY_INFORMATION |
                    DACL_SECURITY_INFORMATION,
                out owner,
                out group,
                out dacl,
                out sacl,
                out descriptor);
            if (result != 0)
                throw new Win32Exception(
                    checked((int)result),
                    "query managed secret security failed: " + path);
            if (descriptor == IntPtr.Zero)
                throw new InvalidOperationException(
                    "managed secret security query returned null: " + path);
            try
            {
                ushort control;
                uint revision;
                if (!GetSecurityDescriptorControl(
                    descriptor,
                    out control,
                    out revision))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query managed secret security control failed: " + path);
                if ((control & SE_SELF_RELATIVE) != 0)
                {
                    uint length = GetSecurityDescriptorLength(descriptor);
                    if (length == 0 || length > 1048576)
                        throw new InvalidOperationException(
                            "managed secret security length is invalid: " + path);
                    byte[] bytes = new byte[checked((int)length)];
                    Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                    return bytes;
                }
                uint required = 0;
                if (MakeSelfRelativeSD(descriptor, null, ref required))
                    throw new InvalidOperationException(
                        "managed secret security conversion returned no size: " + path);
                int conversionError = Marshal.GetLastWin32Error();
                if (conversionError != ERROR_INSUFFICIENT_BUFFER ||
                    required == 0 ||
                    required > 1048576)
                    throw new Win32Exception(
                        conversionError,
                        "size managed secret security failed: " + path);
                byte[] relative = new byte[checked((int)required)];
                if (!MakeSelfRelativeSD(descriptor, relative, ref required))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "convert managed secret security failed: " + path);
                if (required != relative.Length)
                    throw new InvalidOperationException(
                        "managed secret security conversion changed length: " + path);
                return relative;
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        private static IntPtr OpenFixedRegularFileSecurity(
            string path,
            uint desiredAccess,
            uint expectedSize,
            out BY_HANDLE_FILE_INFORMATION information)
        {
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            IntPtr handle = CreateFileW(
                path,
                desiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open managed secret metadata failed: " + path);
            try
            {
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query managed secret identity failed: " + path);
                ValidateFixedRegularFile(information, expectedSize, path);
                return handle;
            }
            catch
            {
                CloseHandle(handle);
                throw;
            }
        }

        public static RegularFileSecuritySnapshot
            GetRegularFileSecuritySnapshotNoFollow(
                string path,
                uint expectedSize)
        {
            const uint FILE_READ_ATTRIBUTES = 0x00000080;
            const uint READ_CONTROL = 0x00020000;
            BY_HANDLE_FILE_INFORMATION information;
            IntPtr handle = OpenFixedRegularFileSecurity(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                expectedSize,
                out information);
            try
            {
                return new RegularFileSecuritySnapshot(
                    FileIdentity(information),
                    GetFileSecurityDescriptorFromHandle(handle, path));
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public static PathSecuritySnapshot
            GetRegularFileSecuritySnapshotNoFollowIfExists(string path)
        {
            const int ERROR_FILE_NOT_FOUND = 2;
            const int ERROR_PATH_NOT_FOUND = 3;
            const uint FILE_READ_ATTRIBUTES = 0x00000080;
            const uint READ_CONTROL = 0x00020000;
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint FILE_SHARE_DELETE = 0x00000004;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
            const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
            IntPtr handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_FILE_NOT_FOUND ||
                    error == ERROR_PATH_NOT_FOUND)
                    return null;
                throw new Win32Exception(
                    error,
                    "open managed receipt metadata failed: " + path);
            }
            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query managed receipt identity failed: " + path);
                if ((information.FileAttributes &
                        (FILE_ATTRIBUTE_DIRECTORY |
                            FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                    throw new InvalidOperationException(
                        "managed receipt is not a no-follow regular file: " +
                        path);
                if (information.NumberOfLinks != 1)
                    throw new InvalidOperationException(
                        "managed receipt must have exactly one hard link: " +
                        path);
                return new PathSecuritySnapshot(
                    FileIdentity(information),
                    GetFileSecurityDescriptorFromHandle(handle, path));
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static IntPtr OpenDirectorySecurity(
            string path,
            uint desiredAccess,
            bool shareDelete,
            out BY_HANDLE_FILE_INFORMATION information)
        {
            const uint FILE_SHARE_READ = 0x00000001;
            const uint FILE_SHARE_WRITE = 0x00000002;
            const uint FILE_SHARE_DELETE = 0x00000004;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
            const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
            IntPtr handle = CreateFileW(
                path,
                desiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE |
                    (shareDelete ? FILE_SHARE_DELETE : 0),
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open managed directory metadata failed: " + path);
            try
            {
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query managed directory identity failed: " + path);
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    throw new InvalidOperationException(
                        "refusing managed directory metadata through a reparse point: " +
                        path);
                if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    throw new InvalidOperationException(
                        "managed directory metadata requires a directory: " + path);
                return handle;
            }
            catch
            {
                CloseHandle(handle);
                throw;
            }
        }

        public static PathSecuritySnapshot
            GetDirectorySecuritySnapshotNoFollow(string path)
        {
            const uint FILE_READ_ATTRIBUTES = 0x00000080;
            const uint READ_CONTROL = 0x00020000;
            BY_HANDLE_FILE_INFORMATION information;
            IntPtr handle = OpenDirectorySecurity(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                true,
                out information);
            try
            {
                return new PathSecuritySnapshot(
                    FileIdentity(information),
                    GetFileSecurityDescriptorFromHandle(handle, path));
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        public static PathSecuritySnapshot
            GetDirectorySecuritySnapshotNoFollowIfExists(string path)
        {
            const int ERROR_FILE_NOT_FOUND = 2;
            const int ERROR_PATH_NOT_FOUND = 3;
            try
            {
                return GetDirectorySecuritySnapshotNoFollow(path);
            }
            catch (Win32Exception error)
            {
                if (error.NativeErrorCode == ERROR_FILE_NOT_FOUND ||
                    error.NativeErrorCode == ERROR_PATH_NOT_FOUND)
                    return null;
                throw;
            }
        }

        public static PathSecuritySnapshot SetDirectoryDaclNoFollow(
            string path,
            byte[] securityDescriptor,
            string expectedIdentity)
        {
            const uint FILE_READ_ATTRIBUTES = 0x00000080;
            const uint READ_CONTROL = 0x00020000;
            const uint WRITE_DAC = 0x00040000;
            const int SE_FILE_OBJECT = 1;
            const uint DACL_SECURITY_INFORMATION = 0x00000004;
            const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
            const ushort SE_SELF_RELATIVE = 0x8000;

            if (securityDescriptor == null ||
                securityDescriptor.Length == 0 ||
                securityDescriptor.Length > 1048576)
                throw new InvalidOperationException(
                    "managed directory descriptor length is invalid");
            GCHandle descriptorHandle = GCHandle.Alloc(
                securityDescriptor,
                GCHandleType.Pinned);
            try
            {
                IntPtr descriptor = descriptorHandle.AddrOfPinnedObject();
                ushort control;
                uint revision;
                if (!GetSecurityDescriptorControl(
                        descriptor,
                        out control,
                        out revision))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query managed directory descriptor control failed");
                if ((control & SE_SELF_RELATIVE) == 0)
                    throw new InvalidOperationException(
                        "managed directory descriptor is not self-relative");
                IntPtr dacl;
                bool daclPresent;
                bool daclDefaulted;
                if (!GetSecurityDescriptorDacl(
                        descriptor,
                        out daclPresent,
                        out dacl,
                        out daclDefaulted) ||
                    !daclPresent ||
                    dacl == IntPtr.Zero)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "managed directory descriptor has no DACL");

                BY_HANDLE_FILE_INFORMATION before;
                IntPtr handle = OpenDirectorySecurity(
                    path,
                    FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                    false,
                    out before);
                try
                {
                    string beforeIdentity = FileIdentity(before);
                    if (!String.Equals(
                            beforeIdentity,
                            expectedIdentity,
                            StringComparison.Ordinal))
                        throw new InvalidOperationException(
                            "managed directory identity changed before DACL update: " +
                            path);

                    uint result = SetSecurityInfo(
                        handle,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION |
                            PROTECTED_DACL_SECURITY_INFORMATION,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        dacl,
                        IntPtr.Zero);
                    if (result != 0)
                        throw new Win32Exception(
                            checked((int)result),
                            "set managed directory DACL failed: " + path);

                    BY_HANDLE_FILE_INFORMATION after;
                    if (!GetFileInformationByHandle(handle, out after))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "recheck managed directory identity failed: " + path);
                    string afterIdentity = FileIdentity(after);
                    if (!String.Equals(
                            beforeIdentity,
                            afterIdentity,
                            StringComparison.Ordinal))
                        throw new InvalidOperationException(
                            "managed directory identity changed during DACL update: " +
                            path);
                    return new PathSecuritySnapshot(
                        afterIdentity,
                        GetFileSecurityDescriptorFromHandle(handle, path));
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            finally
            {
                descriptorHandle.Free();
            }
        }

        public static RegularFileSecuritySnapshot
            SetRegularFileSecurityDescriptorNoFollow(
                string path,
                string sddl,
                uint expectedSize,
                string expectedIdentity)
        {
            const uint FILE_READ_ATTRIBUTES = 0x00000080;
            const uint READ_CONTROL = 0x00020000;
            const uint WRITE_DAC = 0x00040000;
            const uint WRITE_OWNER = 0x00080000;
            const int SE_FILE_OBJECT = 1;
            const uint OWNER_SECURITY_INFORMATION = 0x00000001;
            const uint GROUP_SECURITY_INFORMATION = 0x00000002;
            const uint DACL_SECURITY_INFORMATION = 0x00000004;
            const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
            const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
            const uint TOKEN_QUERY = 0x00000008;
            const uint SE_PRIVILEGE_ENABLED = 0x00000002;
            const int ERROR_NOT_ALL_ASSIGNED = 1300;

            IntPtr descriptor;
            SECURITY_ATTRIBUTES ignored = SecurityAttributes(
                sddl,
                out descriptor);
            try
            {
                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                bool ownerDefaulted;
                bool groupDefaulted;
                bool daclPresent;
                bool daclDefaulted;
                if (!GetSecurityDescriptorOwner(
                        descriptor,
                        out owner,
                        out ownerDefaulted) ||
                    owner == IntPtr.Zero)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "managed secret descriptor has no owner");
                if (!GetSecurityDescriptorGroup(
                        descriptor,
                        out group,
                        out groupDefaulted) ||
                    group == IntPtr.Zero)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "managed secret descriptor has no group");
                if (!GetSecurityDescriptorDacl(
                        descriptor,
                        out daclPresent,
                        out dacl,
                        out daclDefaulted) ||
                    !daclPresent ||
                    dacl == IntPtr.Zero)
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "managed secret descriptor has no DACL");

                BY_HANDLE_FILE_INFORMATION before;
                IntPtr handle = OpenFixedRegularFileSecurity(
                    path,
                    FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                    expectedSize,
                    out before);
                try
                {
                    string beforeIdentity = FileIdentity(before);
                    if (!String.Equals(
                            beforeIdentity,
                            expectedIdentity,
                            StringComparison.Ordinal))
                        throw new InvalidOperationException(
                            "managed secret identity changed before security update: " + path);

                    IntPtr token;
                    if (!OpenProcessToken(
                            GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                            out token))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "open installer token for managed secret owner update failed");
                    uint setResult = 0;
                    int restoreError = 0;
                    try
                    {
                        LUID restoreLuid;
                        if (!LookupPrivilegeValueW(
                                null,
                                "SeRestorePrivilege",
                                out restoreLuid))
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "resolve SeRestorePrivilege failed");
                        TOKEN_PRIVILEGES enabled = new TOKEN_PRIVILEGES();
                        enabled.PrivilegeCount = 1;
                        enabled.Privileges.Luid = restoreLuid;
                        enabled.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
                        TOKEN_PRIVILEGES previous;
                        uint previousLength;
                        if (!AdjustTokenPrivileges(
                                token,
                                false,
                                ref enabled,
                                checked((uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES))),
                                out previous,
                                out previousLength))
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "enable SeRestorePrivilege failed");
                        int enableError = Marshal.GetLastWin32Error();
                        if (enableError == ERROR_NOT_ALL_ASSIGNED)
                            throw new Win32Exception(
                                enableError,
                                "installer token lacks SeRestorePrivilege");
                        try
                        {
                            setResult = SetSecurityInfo(
                                handle,
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION |
                                    GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION |
                                    PROTECTED_DACL_SECURITY_INFORMATION,
                                owner,
                                group,
                                dacl,
                                IntPtr.Zero);
                        }
                        finally
                        {
                            if (!RestoreTokenPrivileges(
                                    token,
                                    false,
                                    ref previous,
                                    0,
                                    IntPtr.Zero,
                                    IntPtr.Zero))
                                restoreError = Marshal.GetLastWin32Error();
                        }
                    }
                    finally
                    {
                        CloseHandle(token);
                    }
                    if (restoreError != 0)
                        throw new Win32Exception(
                            restoreError,
                            "restore installer token privileges failed");
                    if (setResult != 0)
                        throw new Win32Exception(
                            checked((int)setResult),
                            "set managed secret owner and DACL failed: " + path);

                    BY_HANDLE_FILE_INFORMATION after;
                    if (!GetFileInformationByHandle(handle, out after))
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "recheck managed secret identity failed: " + path);
                    ValidateFixedRegularFile(after, expectedSize, path);
                    string afterIdentity = FileIdentity(after);
                    if (!String.Equals(
                            beforeIdentity,
                            afterIdentity,
                            StringComparison.Ordinal))
                        throw new InvalidOperationException(
                            "managed secret identity changed during security update: " + path);
                    return new RegularFileSecuritySnapshot(
                        afterIdentity,
                        GetFileSecurityDescriptorFromHandle(handle, path));
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            finally
            {
                LocalFree(descriptor);
            }
        }

        private static IntPtr OpenProcessForIdentity(uint processId)
        {
            const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
            IntPtr process = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                processId);
            if (process == IntPtr.Zero)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "open process for identity failed: " + processId);
            return process;
        }

        public static long GetProcessCreationFileTime(uint processId)
        {
            IntPtr process = OpenProcessForIdentity(processId);
            try
            {
                System.Runtime.InteropServices.ComTypes.FILETIME creation;
                System.Runtime.InteropServices.ComTypes.FILETIME exit;
                System.Runtime.InteropServices.ComTypes.FILETIME kernel;
                System.Runtime.InteropServices.ComTypes.FILETIME user;
                if (!GetProcessTimes(
                    process,
                    out creation,
                    out exit,
                    out kernel,
                    out user))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query process creation time failed: " + processId);
                return ((long)(uint)creation.dwHighDateTime << 32) |
                    (long)(uint)creation.dwLowDateTime;
            }
            finally
            {
                CloseHandle(process);
            }
        }

        public static string GetProcessImagePath(uint processId)
        {
            IntPtr process = OpenProcessForIdentity(processId);
            try
            {
                StringBuilder path = new StringBuilder(32768);
                uint size = (uint)path.Capacity;
                if (!QueryFullProcessImageNameW(
                    process,
                    0,
                    path,
                    ref size))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "query process image path failed: " + processId);
                return path.ToString();
            }
            finally
            {
                CloseHandle(process);
            }
        }

        public static uint StartDetachedProcess(
            string applicationPath,
            string commandLine,
            string workingDirectory,
            string[] environmentEntries)
        {
            if (String.IsNullOrWhiteSpace(applicationPath) ||
                !Path.IsPathRooted(applicationPath) ||
                String.IsNullOrWhiteSpace(commandLine) ||
                String.IsNullOrWhiteSpace(workingDirectory) ||
                !Path.IsPathRooted(workingDirectory))
                throw new ArgumentException(
                    "detached process paths and command line must be absolute and non-empty");
            if (commandLine.Length >= 32767)
                throw new ArgumentException("detached process command line is too long");

            SortedDictionary<string, string> environment =
                new SortedDictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase);
            if (environmentEntries != null)
            {
                foreach (string entry in environmentEntries)
                {
                    if (entry == null || entry.IndexOf('\0') >= 0)
                        throw new ArgumentException(
                            "detached process environment contains an invalid entry");
                    int separator = entry.IndexOf('=');
                    if (separator <= 0)
                        throw new ArgumentException(
                            "detached process environment entry has no key");
                    string key = entry.Substring(0, separator);
                    string value = entry.Substring(separator + 1);
                    if (key.IndexOf('=') >= 0)
                        throw new ArgumentException(
                            "detached process environment key contains '='");
                    environment.Add(key, value);
                }
            }
            StringBuilder environmentBlock = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in environment)
            {
                environmentBlock.Append(pair.Key);
                environmentBlock.Append('=');
                environmentBlock.Append(pair.Value);
                environmentBlock.Append('\0');
            }
            environmentBlock.Append('\0');
            byte[] environmentBytes = Encoding.Unicode.GetBytes(
                environmentBlock.ToString());
            IntPtr environmentPointer = Marshal.AllocHGlobal(
                environmentBytes.Length);
            try
            {
                Marshal.Copy(
                    environmentBytes,
                    0,
                    environmentPointer,
                    environmentBytes.Length);
                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION processInformation;
                const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                const uint CREATE_NO_WINDOW = 0x08000000;
                if (!CreateProcessW(
                    applicationPath,
                    new StringBuilder(commandLine),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environmentPointer,
                    workingDirectory,
                    ref startup,
                    out processInformation))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "non-inheriting detached process creation failed");
                try
                {
                    return processInformation.dwProcessId;
                }
                finally
                {
                    if (processInformation.hThread != IntPtr.Zero)
                        CloseHandle(processInformation.hThread);
                    if (processInformation.hProcess != IntPtr.Zero)
                        CloseHandle(processInformation.hProcess);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(environmentPointer);
            }
        }

    }
}
"@ -Language CSharp -PassThru -ErrorAction Stop)
        $nativeType = $null
        foreach ($compiledType in $compiledTypes) {
            if ([string]::Equals(
                [string]$compiledType.Namespace,
                $nativeNamespace,
                [StringComparison]::Ordinal
            ) -and [string]::Equals(
                [string]$compiledType.Name,
                'NativeSecurity',
                [StringComparison]::Ordinal
            )) {
                $nativeType = $compiledType
                break
            }
        }
        if ($null -eq $nativeType) {
            throw 'DefenseClaw native security helper did not compile its exact generated type'
        }
        $script:DefenseClawNativeSecurityType = $nativeType
    }
    finally {
        [Environment]::SetEnvironmentVariable('SystemRoot', $previousSystemRoot, 'Process')
        [Environment]::SetEnvironmentVariable('windir', $previousWindir, 'Process')
    }
    return $script:DefenseClawNativeSecurityType
}

function Assert-DefenseClawAdministrator {
    if (-not (Test-DefenseClawAdministrator)) {
        throw 'DefenseClaw Windows enterprise lifecycle changes require an elevated administrator token'
    }
}

function Test-DefenseClawAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-DefenseClawLogicalDisk {
    param([Parameter(Mandatory)][string]$DriveID)
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    $drive = $DriveID.TrimEnd('\')
    if ($drive -cnotmatch '^[A-Za-z]:$') {
        throw "managed path drive identifier is not canonical: $DriveID"
    }
    $root = $drive + '\'
    $target = $nativeSecurityType::AssertCanonicalDriveRoot($root, $drive)
    $driveType = $nativeSecurityType::GetDriveType($root)
    $fileSystem = $nativeSecurityType::GetFileSystem($root)
    $recheckedTarget =
        $nativeSecurityType::AssertCanonicalDriveRoot($root, $drive)
    if (-not [string]::Equals(
            $target,
            $recheckedTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "managed path drive identity changed during validation: $DriveID"
    }
    return [pscustomobject]@{
        DriveType = [int]$driveType
        FileSystem = $fileSystem
        Target = $target
    }
}

function Assert-DefenseClawCanonicalVolumePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    $full = Resolve-DefenseClawFullPath -Path $Path
    if ($full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "$Label must use a local Win32 drive path: $full"
    }
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $logicalDisk = Get-DefenseClawLogicalDisk `
        -DriveID $driveRoot.TrimEnd('\')
    if ($null -eq $logicalDisk -or
        [int]$logicalDisk.DriveType -ne 3 -or
        -not [string]::Equals(
            [string]$logicalDisk.FileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label must be on a mount-manager-authorized fixed NTFS volume: $full"
    }
    return $full
}

function Resolve-DefenseClawFullPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$MustExist,
        [switch]$Leaf
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains('"') -or
        [Text.RegularExpressions.Regex]::IsMatch($Path, '[\x00-\x1f]')) {
        throw "invalid managed path: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathRooted($full)) {
        throw "managed path is not absolute: $Path"
    }
    if ($MustExist) {
        $kind = if ($Leaf) { 'Leaf' } else { 'Any' }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $full -PathType $kind)) {
            throw "required path is missing: $full"
        }
    }
    return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-DefenseClawSafeRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$RequiredBase
    )
    $full = Resolve-DefenseClawFullPath -Path $Path
    $base = Resolve-DefenseClawFullPath -Path $RequiredBase -MustExist
    if ($full.StartsWith('\\') -or $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or $full.StartsWith('\\.\')) {
        throw "$Label must use a local Win32 drive path, not UNC/device syntax: $full"
    }
    if ($full.Length -gt 2 -and $full.Substring(2).Contains(':')) {
        throw "$Label contains an alternate data stream or invalid colon: $full"
    }
    if (-not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be a strict descendant of $base, got $full"
    }
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $driveID = $driveRoot.TrimEnd('\')
    $logicalDisk = Get-DefenseClawLogicalDisk -DriveID $driveID
    if ($null -eq $logicalDisk -or [int]$logicalDisk.DriveType -ne 3) {
        throw "$Label must be on a local fixed disk (subst, mapped, removable, and network drives are rejected): $full"
    }
    if (-not [string]::Equals([string]$logicalDisk.FileSystem, 'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be on NTFS, got $($logicalDisk.FileSystem): $full"
    }
    Assert-DefenseClawNoReparsePath -Path $base
    Assert-DefenseClawNoReparsePath -Path $full -AllowMissingLeaf
    Assert-DefenseClawTrustedAncestors -Path $full -RequiredBase $base
    return $full
}

function ConvertTo-DefenseClawSID {
    param([Parameter(Mandatory)]$Identity)
    if ($Identity -is [Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    $identityText = [string]$Identity
    if ($identityText.StartsWith('S-', [StringComparison]::OrdinalIgnoreCase)) {
        return [Security.Principal.SecurityIdentifier]::new($identityText).Value
    }
    switch ($identityText.ToUpperInvariant()) {
        'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES' { return 'S-1-15-2-1' }
        'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES' { return 'S-1-15-2-2' }
        'CREATOR OWNER' { return 'S-1-3-0' }
    }
    $account = [Security.Principal.NTAccount]::new($identityText)
    try {
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        # Keep unresolved identities distinguishable and untrusted. Read-only
        # unknown ACEs on public install ancestors are harmless; any write/read
        # on protected paths will be rejected by the caller.
        return "UNRESOLVED:$identityText"
    }
}

function Test-DefenseClawReplacementRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    $rightsValue = [uint64][int64]$Rights
    $replacementMask = [uint64](
        [int64][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [int64][Security.AccessControl.FileSystemRights]::Delete -bor
        [int64][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [int64][Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    # FileSystemRights normally contains expanded object-specific rights, but
    # reject unresolved generic write/all bits as well if a provider returns
    # them. ProgramData's default Users 0x116 create/append/EA/attribute ACE is
    # intentionally tolerated because it cannot delete or replace children.
    $genericReplacementMask = [uint64]0x50000000
    return (($rightsValue -band ($replacementMask -bor $genericReplacementMask)) -ne 0)
}

function Assert-DefenseClawTrustedAncestor {
    param([Parameter(Mandatory)][string]$Path)
    # 'C:' is drive-relative and resolves to the current directory on that drive.
    # Callers trim the trailing separator, so restore it before touching disk.
    if ($Path -match '^[A-Za-z]:$') {
        $Path = $Path + '\'
    }
    Assert-DefenseClawNoReparsePath -Path $Path
    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
    $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith('D:', [StringComparison]::OrdinalIgnoreCase)) {
        throw "managed path has an absent or null DACL: $Path"
    }
    $ownerSID = ConvertTo-DefenseClawSID -Identity $acl.Owner
    if ($ownerSID -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
        throw "untrusted ancestor owner $ownerSID can replace managed content through: $Path"
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)) {
            continue
        }
        $sid = ConvertTo-DefenseClawSID -Identity $rule.IdentityReference
        if ($sid -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) -and
            (Test-DefenseClawReplacementRights -Rights $rule.FileSystemRights)) {
            throw "untrusted principal $sid can delete, rename, or retake an ancestor of managed content: $Path"
        }
    }
}

function Assert-DefenseClawTrustedAncestors {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RequiredBase
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $base = [IO.Path]::GetFullPath($RequiredBase).TrimEnd('\')
    if (-not ($full -eq $base -or $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase))) {
        throw "managed path is outside its required ancestor base: $full"
    }

    $current = $base
    Assert-DefenseClawTrustedAncestor -Path $current
    $relative = $full.Substring($base.Length).TrimStart('\')
    if (-not [string]::IsNullOrWhiteSpace($relative)) {
        foreach ($component in $relative.Split('\')) {
            $current = Microsoft.PowerShell.Management\Join-Path $current $component
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current)) {
                break
            }
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current -PathType Container)) {
                throw "managed root ancestor is not a directory: $current"
            }
            Assert-DefenseClawTrustedAncestor -Path $current
        }
    }
}

function Assert-DefenseClawDistinctRoots {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$StateRoot
    )
    $install = $InstallRoot.TrimEnd('\') + '\'
    $state = $StateRoot.TrimEnd('\') + '\'
    if ($install.StartsWith($state, [StringComparison]::OrdinalIgnoreCase) -or
        $state.StartsWith($install, [StringComparison]::OrdinalIgnoreCase)) {
        throw "InstallRoot and StateRoot must be distinct non-nested trees: $InstallRoot ; $StateRoot"
    }
}

function Assert-DefenseClawDescendant {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its managed root: $full"
    }
    return $full
}

function Assert-DefenseClawNoReparsePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissingLeaf
    )
    $full = [IO.Path]::GetFullPath($Path)
    $current = $full
    while (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current)) {
        if (-not $AllowMissingLeaf) {
            throw "managed path is missing: $full"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            throw "cannot resolve existing ancestor for managed path: $full"
        }
        $current = $parent
    }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse points are not allowed in managed path: $current"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
}

function Get-DefenseClawStableScopeSHA256 {
    param([Parameter(Mandatory)][string[]]$Values)
    $canonical = (
        $Values |
            Microsoft.PowerShell.Core\ForEach-Object {
                ([string]$_).ToLowerInvariant()
            }
    ) -join ([char]0)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return (
            [BitConverter]::ToString(
                $algorithm.ComputeHash($bytes)
            ).Replace('-', '').ToLowerInvariant()
        )
    }
    finally {
        $algorithm.Dispose()
    }
}

function Assert-DefenseClawServiceName {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
        throw "invalid Windows service name: $Name"
    }
}

# Get-DefenseClawEnumeratorServiceName derives the third-service SCM
# name from the guardian's, matching the same production /
# certification-run-ID discipline the existing gateway + guardian
# names already carry (Get-DefenseClawLayout enforces those two).
#
# Production: `DefenseClawHookGuardian` → `DefenseClawHookEnumerator`.
# Certification: `DefenseClawCertGuardian_<10hex>` → `DefenseClawCertEnumerator_<10hex>`.
#
# Kept as a derivation rather than a separate parameter across the
# ~230 GuardianServiceName call-sites so the enumerator's name is
# always in lockstep with the guardian's. Every caller that today
# passes `-GuardianServiceName` gets the enumerator name for free
# via this helper — no threading required. See spec 005 D1.
function Get-DefenseClawEnumeratorServiceName {
    param([Parameter(Mandatory)][string]$GuardianServiceName)
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    if ($GuardianServiceName -ceq 'DefenseClawHookGuardian') {
        return 'DefenseClawHookEnumerator'
    }
    if ($GuardianServiceName -cmatch '^DefenseClawCertGuardian_([a-f0-9]{10})$') {
        return "DefenseClawCertEnumerator_$($Matches[1])"
    }
    throw "cannot derive enumerator service name from unexpected guardian name: $GuardianServiceName"
}

function Get-DefenseClawCMIDBrokerServiceName {
    param([Parameter(Mandatory)][string]$GatewayServiceName)
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    if ($GatewayServiceName -ceq 'DefenseClawGateway') {
        return 'DefenseClawCMIDBroker'
    }
    if ($GatewayServiceName -cmatch '^DefenseClawCertGateway_([a-f0-9]{10})$') {
        return "DefenseClawCMIDBroker_$($Matches[1])"
    }
    throw "cannot derive credential broker service name from unexpected gateway name: $GatewayServiceName"
}

function Get-DefenseClawCMIDBrokerImage {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    if ([string]::IsNullOrWhiteSpace([string]$Layout.ProviderLibraryPath)) {
        throw 'credential broker provider library path is missing'
    }
    return '"{0}" service --service-name {1} --gateway-service-name {2} --pipe-name {3} --auth-key "{4}" --cmid-library "{5}" --log "{6}"' -f `
        $Layout.BrokerPath, $Layout.BrokerServiceName, $GatewayServiceName, `
        $Layout.BrokerPipeName, $Layout.BrokerAuthKeyPath, `
        $Layout.ProviderLibraryPath, $Layout.BrokerLogPath
}

function Get-DefenseClawManagedServiceNames {
    param(
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    return @(
        $GatewayServiceName,
        (Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName),
        $GuardianServiceName,
        (Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName)
    )
}

function Resolve-DefenseClawCertificationCodexHome {
    param(
        [string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$AllowMissing
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }
    if ($GatewayServiceName -cnotmatch '^DefenseClawCertGateway_[a-f0-9]{10}$' -or
        $GuardianServiceName -cnotmatch '^DefenseClawCertGuardian_[a-f0-9]{10}$') {
        throw '-CertificationCodexHome is allowed only for exact disposable DefenseClaw certification service names'
    }
    $gatewayRunID = $GatewayServiceName.Substring('DefenseClawCertGateway_'.Length)
    $guardianRunID = $GuardianServiceName.Substring('DefenseClawCertGuardian_'.Length)
    if ($gatewayRunID -cne $guardianRunID) {
        throw 'certification gateway and guardian service names must use the same run identifier'
    }

    $full = Resolve-DefenseClawFullPath -Path $Path
    if ($full.StartsWith('\\') -or $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "certification CODEX_HOME must use a local Win32 path: $full"
    }
    $expectedLeaf = ".codex-defenseclaw-cert-$gatewayRunID"
    if (-not [string]::Equals(
        [IO.Path]::GetFileName($full),
        $expectedLeaf,
        [StringComparison]::Ordinal
    )) {
        throw "certification CODEX_HOME basename must be exactly $expectedLeaf"
    }
    $exists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $full `
        -PathType Container
    if (-not $exists -and -not $AllowMissing) {
        throw "certification CODEX_HOME must be an existing directory: $full"
    }
    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $full) -and
        -not $exists) {
        throw "certification CODEX_HOME must be a directory when present: $full"
    }
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $logicalDisk = Get-DefenseClawLogicalDisk -DriveID $driveRoot.TrimEnd('\')
    if ($null -eq $logicalDisk -or [int]$logicalDisk.DriveType -ne 3 -or
        -not [string]::Equals(
            [string]$logicalDisk.FileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "certification CODEX_HOME must be on a local fixed NTFS volume: $full"
    }
    Assert-DefenseClawNoReparsePath `
        -Path $full `
        -AllowMissingLeaf:(-not $exists)
    return $full
}

function Assert-DefenseClawUnsignedCertificationScope {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [string]$CertificationCodexHome
    )
    $prefix = '-AllowUnsigned is restricted to exact disposable DefenseClaw certification scope'
    if ($Action -notin @(
        'Install',
        'Upgrade',
        'Repair',
        'Reconcile',
        'Status',
        'Verify',
        'Uninstall'
    )) {
        throw "$prefix; action is outside the enterprise lifecycle"
    }
    if ($GatewayServiceName -cnotmatch '^DefenseClawCertGateway_([a-f0-9]{10})$') {
        throw "$prefix; gateway service name is outside the certification namespace"
    }
    $runID = [string]$Matches[1]
    $expectedGuardian = "DefenseClawCertGuardian_$runID"
    if ($GuardianServiceName -cne $expectedGuardian) {
        throw "$prefix; guardian service name must be exactly $expectedGuardian"
    }
    $expectedInstall = [IO.Path]::Combine(
        $script:ProgramFiles,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw-Cert',
        $runID
    ).TrimEnd('\')
    $expectedState = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw-Cert',
        $runID
    ).TrimEnd('\')
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\'),
        $expectedInstall,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; InstallRoot must be exactly $expectedInstall"
    }
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($StateRoot).TrimEnd('\'),
        $expectedState,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; StateRoot must be exactly $expectedState"
    }
    if ([string]::IsNullOrWhiteSpace($CertificationCodexHome) -or
        [IO.Path]::GetFileName(
            [IO.Path]::GetFullPath($CertificationCodexHome).TrimEnd('\')
        ) -cne ".codex-defenseclaw-cert-$runID") {
        throw "$prefix; CertificationCodexHome must be the exact local run-scoped directory"
    }
}

function Assert-DefenseClawRegularSource {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Authenticode,
        [switch]$AllowUnsigned
    )
    $full = Resolve-DefenseClawFullPath -Path $Path -MustExist -Leaf
    Assert-DefenseClawNoReparsePath -Path $full
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer) {
        throw "$Label is not a regular file: $full"
    }
    if ($Authenticode) {
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $full
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -and -not $AllowUnsigned) {
            throw "$Label Authenticode signature is not valid ($($signature.Status)): $full; use -AllowUnsigned only for controlled test builds"
        }
    }
    return $full
}

function Assert-DefenseClawTrustedSource {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    $full = Resolve-DefenseClawFullPath -Path $Path -MustExist -Leaf
    if ($full.StartsWith('\\') -or $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "$Label source must use a local Win32 file path without device or alternate-stream syntax: $full"
    }
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $driveID = $driveRoot.TrimEnd('\')
    $logicalDisk = Get-DefenseClawLogicalDisk -DriveID $driveID
    if ($null -eq $logicalDisk -or [int]$logicalDisk.DriveType -ne 3 -or
        -not [string]::Equals([string]$logicalDisk.FileSystem, 'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label source must be on a local fixed NTFS volume: $full"
    }
    Assert-DefenseClawTrustedAncestors `
        -Path ([IO.Path]::GetDirectoryName($full)) `
        -RequiredBase $driveRoot
    Assert-DefenseClawPathAcl `
        -Path $full `
        -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
        -AllowInheritance
    return $full
}

function Get-DefenseClawSourceDescriptor {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Authenticode,
        [switch]$AllowUnsigned
    )
    $full = Resolve-DefenseClawFullPath -Path $Path -MustExist -Leaf
    [void](Assert-DefenseClawTrustedSource -Path $full -Label $Label)
    $full = Assert-DefenseClawRegularSource `
        -Path $Path `
        -Label $Label `
        -Authenticode:$Authenticode `
        -AllowUnsigned:$AllowUnsigned
    $descriptor = @{
        path = $full
        label = $Label
        authenticode = [bool]$Authenticode
        allow_unsigned = [bool]$AllowUnsigned
        sha256 = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    }
    if ($Authenticode) {
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full
        $descriptor['signature_status'] = [string]$signature.Status
        $descriptor['signer_thumbprint'] = if ($null -eq $signature.SignerCertificate) {
            ''
        }
        else {
            ([string]$signature.SignerCertificate.Thumbprint).ToLowerInvariant()
        }
        $descriptor['signer_subject'] = if ($null -eq $signature.SignerCertificate) {
            ''
        }
        else {
            [string]$signature.SignerCertificate.Subject
        }
        $descriptor['file_version'] = [string](
            Microsoft.PowerShell.Management\Get-Item `
                -LiteralPath $full `
                -Force
        ).VersionInfo.FileVersion
    }
    return $descriptor
}

function Assert-DefenseClawSourceDescriptorCurrent {
    param([Parameter(Mandatory)][hashtable]$Source)
    foreach ($required in @(
        'path',
        'label',
        'authenticode',
        'allow_unsigned',
        'sha256'
    )) {
        if (-not $Source.ContainsKey($required)) {
            throw "lifecycle source descriptor is missing $required"
        }
    }
    $current = Get-DefenseClawSourceDescriptor `
        -Path ([string]$Source.path) `
        -Label ([string]$Source.label) `
        -Authenticode:([bool]$Source.authenticode) `
        -AllowUnsigned:([bool]$Source.allow_unsigned)
    foreach ($field in @('path', 'label', 'sha256')) {
        if (-not [string]::Equals(
                [string]$current[$field],
                [string]$Source[$field],
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                "lifecycle source $field changed after authorization: " +
                [string]$Source.path
            )
        }
    }
    foreach ($field in @('authenticode', 'allow_unsigned')) {
        if ([bool]$current[$field] -ne [bool]$Source[$field]) {
            throw (
                "lifecycle source $field changed after authorization: " +
                [string]$Source.path
            )
        }
    }
    if ([bool]$Source.authenticode) {
        foreach ($field in @(
            'signature_status',
            'signer_thumbprint',
            'signer_subject',
            'file_version'
        )) {
            if (-not [string]::Equals(
                    [string]$current[$field],
                    [string]$Source[$field],
                    [StringComparison]::Ordinal
                )) {
                throw (
                    "lifecycle source $field changed after authorization: " +
                    [string]$Source.path
                )
            }
        }
    }
    return $current
}

function Install-DefenseClawSourceDescriptor {
    param(
        [Parameter(Mandatory)][hashtable]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    $sourcePath = [string]$Source.path
    # Recheck mount-manager identity, ancestry, ACLs, digest, and signer
    # immediately before the source is opened for its atomic copy.
    [void](Assert-DefenseClawSourceDescriptorCurrent -Source $Source)
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    if (-not [string]::Equals(
        $sourcePath,
        $destinationPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        Install-DefenseClawFileAtomic `
            -Source $sourcePath `
            -Destination $destinationPath `
            -ExpectedSHA256 ([string]$Source.sha256)
    }
    else {
        $actual = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
        if (-not [string]::Equals(
            $actual,
            [string]$Source.sha256,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "installed source changed during lifecycle validation: $destinationPath"
        }
    }
    if ([bool]$Source.authenticode) {
        [void](Assert-DefenseClawRegularSource `
            -Path $destinationPath `
            -Label ([string]$Source.label) `
            -Authenticode `
            -AllowUnsigned:([bool]$Source.allow_unsigned))
        $installedSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $destinationPath
        $installedThumbprint = if ($null -eq $installedSignature.SignerCertificate) {
            ''
        }
        else {
            ([string]$installedSignature.SignerCertificate.Thumbprint).ToLowerInvariant()
        }
        if (-not [string]::Equals(
            $installedThumbprint,
            [string]$Source.signer_thumbprint,
            [StringComparison]::Ordinal
        )) {
            throw "installed Authenticode signer changed during lifecycle validation: $destinationPath"
        }
    }
}

function ConvertTo-DefenseClawWindowsCommandLineArgument {
    param([AllowEmptyString()][string]$Argument)
    if ($null -eq $Argument -or $Argument.IndexOf([char]0) -ge 0) {
        throw 'native process argument is null or contains NUL'
    }
    if ($Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    # ProcessStartInfo on .NET Framework exposes only a single command-line
    # string. Encode each argv element with the inverse of CommandLineToArgvW
    # so Windows PowerShell 5.1 cannot strip literal quotes from values such as
    # an SCM binPath containing a quoted executable and quoted manifest.
    $encoded = [Text.StringBuilder]::new($Argument.Length + 2)
    [void]$encoded.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]0x5c) {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$encoded.Append([char]0x5c, (2 * $backslashes) + 1)
            [void]$encoded.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$encoded.Append([char]0x5c, $backslashes)
            $backslashes = 0
        }
        [void]$encoded.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$encoded.Append([char]0x5c, 2 * $backslashes)
    }
    [void]$encoded.Append('"')
    return $encoded.ToString()
}

function ConvertTo-DefenseClawWindowsCommandLine {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [object[]]$Arguments
    )
    $encoded = [Collections.Generic.List[string]]::new()
    foreach ($argument in $Arguments) {
        # Preserve and authenticate the element before scalar [string]
        # binding can coerce $null to ''. Empty strings remain valid argv.
        if ($null -eq $argument -or $argument -isnot [string]) {
            throw 'native process arguments must be non-null strings'
        }
        $encoded.Add((
            ConvertTo-DefenseClawWindowsCommandLineArgument `
                -Argument $argument
        ))
    }
    $commandLine = $encoded -join ' '
    if ($commandLine.Length -ge 32767) {
        throw 'native process command line is too long'
    }
    return $commandLine
}

function ConvertFrom-DefenseClawProcessText {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return @()
    }
    return @(
        $Text.TrimEnd([char[]]@([char]13, [char]10)) -split '\r?\n'
    )
}

function Invoke-DefenseClawProcess {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string[]]$Arguments,
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 300
    )
    $resolved = [IO.Path]::GetFullPath($File)
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $resolved `
            -PathType Leaf)) {
        throw "required native executable is missing: $resolved"
    }
    Assert-DefenseClawNoReparsePath -Path $resolved

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $resolved
    $start.Arguments = ConvertTo-DefenseClawWindowsCommandLine `
        -Arguments $Arguments
    if ($resolved.Length + $start.Arguments.Length + 4 -ge 32767) {
        throw 'native process application path plus command line is too long'
    }
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName($resolved)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "native process did not start: $resolved"
        }
        # Begin both reads before waiting so neither redirected pipe can fill
        # and deadlock the child. ExitCode comes from the Process object, never
        # ambient automatic-variable state in a fresh module scope.
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch {}
            try { $process.WaitForExit() } catch {}
            throw "native process timed out after $TimeoutSeconds seconds: $resolved"
        }
        $process.WaitForExit()
        $stdout = [string]$standardOutput.Result
        $stderr = [string]$standardError.Result
        return [pscustomobject]@{
            exit_code = [int]$process.ExitCode
            stdout = $stdout
            stderr = $stderr
            output = @(
                @(ConvertFrom-DefenseClawProcessText -Text $stdout) +
                @(ConvertFrom-DefenseClawProcessText -Text $stderr)
            )
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-DefenseClawNative {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Capture
    )
    $resolved = [IO.Path]::GetFullPath($File)
    if (-not $resolved.StartsWith($script:System32 + '\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetDirectoryName($resolved) -ine $script:System32) {
        throw "refusing elevated native tool outside System32: $File"
    }
    $result = Invoke-DefenseClawProcess `
        -File $resolved `
        -Arguments $Arguments
    if ([int]$result.exit_code -ne 0) {
        $detail = ($result.output | Microsoft.PowerShell.Utility\Out-String).Trim()
        throw "$resolved exited $($result.exit_code) while running '$($Arguments -join ' ')': $detail"
    }
    if ($Capture) {
        return @($result.output)
    }
}

function Get-DefenseClawServiceSID {
    param([Parameter(Mandatory)][string]$ServiceName)
    $account = [Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")
    try {
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "cannot resolve virtual service SID for $ServiceName; create the SCM service before applying runtime ACLs"
    }
}

function Get-DefenseClawDeterministicServiceSID {
    param([Parameter(Mandatory)][string]$ServiceName)
    Assert-DefenseClawServiceName -Name $ServiceName
    # `sc.exe showsid` computes the S-1-5-80 virtual-service SID from the
    # service name even when the SCM row is missing. This lets authenticated
    # active-deployment repair validate a service-owned secret before safely
    # recreating the service, and lets committed uninstall recovery retire the
    # exact SID grant after the service row is gone. Fresh installs never use
    # this path.
    $lines = @(Invoke-DefenseClawNative `
        -File $script:ScExe `
        -Arguments @('showsid', $ServiceName) `
        -Capture)
    $matches = [regex]::Matches(
        ($lines -join "`n"),
        '(?<![0-9-])S-1-5-80-(?:[0-9]{1,10}-){4}[0-9]{1,10}(?![0-9-])',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $values = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($match in $matches) {
        [void]$values.Add([string]$match.Value)
    }
    if ($values.Count -ne 1) {
        throw "sc.exe showsid did not return exactly one virtual-service SID for $ServiceName"
    }
    $value = @($values)[0]
    try {
        $sid = [Security.Principal.SecurityIdentifier]::new($value)
    }
    catch {
        throw "sc.exe showsid returned an invalid SID for $ServiceName"
    }
    if (-not $sid.Value.StartsWith('S-1-5-80-', [StringComparison]::Ordinal)) {
        throw "sc.exe showsid returned a SID outside the NT SERVICE authority for $ServiceName"
    }
    if (Test-DefenseClawServiceExists -Name $ServiceName) {
        $resolved = Get-DefenseClawServiceSID -ServiceName $ServiceName
        if ($resolved -cne $sid.Value) {
            throw "resolved and deterministic service SIDs disagree for $ServiceName"
        }
    }
    return $sid.Value
}

function Get-DefenseClawServiceSIDForRecovery {
    param([Parameter(Mandatory)][string]$ServiceName)
    if (Test-DefenseClawServiceExists -Name $ServiceName) {
        return Get-DefenseClawServiceSID -ServiceName $ServiceName
    }
    return Get-DefenseClawDeterministicServiceSID -ServiceName $ServiceName
}

function New-DefenseClawCanonicalPathAcl {
    param(
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)]
        [ValidateSet('InstallDirectory', 'InstallFile', 'ServiceInstallDirectory', 'ServiceInstallFile', 'StateDirectory', 'AdminDirectory', 'AdminFile', 'ConfigDirectory', 'ConfigFile', 'MachinePolicyFile', 'RuntimeDirectory', 'RuntimeFile', 'RuntimeSecretFile', 'AuthorizationDirectory', 'AuthorizationFile', 'LogDirectory', 'GatewayLogDirectory', 'ManagedIPCDirectory')]
        [string]$Kind,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )

    $directoryKinds = @(
        'InstallDirectory',
        'ServiceInstallDirectory',
        'StateDirectory',
        'AdminDirectory',
        'ConfigDirectory',
        'RuntimeDirectory',
        'AuthorizationDirectory',
        'LogDirectory',
        'GatewayLogDirectory',
        'ManagedIPCDirectory'
    )
    if ($IsDirectory -ne ($Kind -in $directoryKinds)) {
        throw "ACL kind $Kind does not match the managed path object type"
    }

    if ($Kind -eq 'RuntimeSecretFile') {
        # The correlation key is a persistent service secret, not an ordinary
        # writable runtime file. OWNER RIGHTS suppresses the file owner's
        # implicit WRITE_DAC while preserving READ_CONTROL; the exact gateway
        # service SID receives read-only data access. Setup can replace this
        # descriptor only through the no-follow, privilege-scoped native path
        # in Set-DefenseClawPathAcl.
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetSecurityDescriptorSddlForm(
            ((
                'O:{0}G:BAD:P(A;;RC;;;{1})(A;;FA;;;SY)' +
                '(A;;FA;;;BA)(A;;FR;;;{0})'
            ) -f $GatewayServiceSID, $script:OwnerRightsSID),
            [Security.AccessControl.AccessControlSections]::All
        )
        return $security
    }

    $security = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $administrators = [Security.Principal.SecurityIdentifier]::new(
        $script:AdministratorsSID
    )
    $security.SetOwner($administrators)
    $security.SetGroup($administrators)
    # Start from a new descriptor and discard inheritance. AddAccessRule below
    # therefore defines the whole DACL; unlike icacls /grant:r, this cannot
    # retain an explicit ACE for a retired service SID or another principal.
    $security.SetAccessRuleProtection($true, $false)

    $entries = [Collections.Generic.List[object]]::new()
    $entries.Add([pscustomobject]@{
        sid = $script:SystemSID
        rights = [Security.AccessControl.FileSystemRights]::FullControl
    })
    $entries.Add([pscustomobject]@{
        sid = $script:AdministratorsSID
        rights = [Security.AccessControl.FileSystemRights]::FullControl
    })
    switch ($Kind) {
        'InstallDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $script:UsersSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'InstallFile' {
            $entries.Add([pscustomobject]@{
                sid = $script:UsersSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'ServiceInstallDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $script:UsersSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'ServiceInstallFile' {
            $entries.Add([pscustomobject]@{
                sid = $script:UsersSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'StateDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'ConfigDirectory' {
            # Traverse only; the service cannot open ConfigFile without it.
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'ConfigFile' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::Read
            })
        }
        'MachinePolicyFile' {
            $entries.Add([pscustomobject]@{
                sid = $script:UsersSID
                rights = [Security.AccessControl.FileSystemRights]::Read
            })
        }
        'RuntimeDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::Modify
            })
        }
        'RuntimeFile' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::Modify
            })
        }
        'AuthorizationDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            })
        }
        'AuthorizationFile' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::Read
            })
        }
        'GatewayLogDirectory' {
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::Modify
            })
        }
        'ManagedIPCDirectory' {
            # Match the gateway's bind-time IPC baseline: only the exact
            # service SID may create/remove the socket, while authenticated
            # clients receive path traversal and child-name lookup only.
            $entries.Add([pscustomobject]@{
                sid = $GatewayServiceSID
                rights = [Security.AccessControl.FileSystemRights]::FullControl
            })
            $entries.Add([pscustomobject]@{
                sid = $script:AuthenticatedUsersSID
                rights = (
                    [Security.AccessControl.FileSystemRights]::ListDirectory -bor
                    [Security.AccessControl.FileSystemRights]::Traverse
                )
            })
        }
    }

    $inheritanceFlags = if ($IsDirectory -and $Kind -ne 'ManagedIPCDirectory') {
        [Security.AccessControl.InheritanceFlags]::ObjectInherit -bor
            [Security.AccessControl.InheritanceFlags]::ContainerInherit
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($entry in $entries) {
        $identity = [Security.Principal.SecurityIdentifier]::new(
            [string]$entry.sid
        )
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]$entry.rights,
            $inheritanceFlags,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Test-DefenseClawExactRawDACL {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Actual,
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Expected,
        [int]$IgnoredControlFlags = [int](
            [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
        )
    )

    # NTFS may persist a protected DACL with the benign AutoInherited (AI)
    # control flag even when Set-Acl received an otherwise identical D:P
    # descriptor. Mask only that metadata bit, then require every other
    # descriptor control flag and the raw DACL bytes to match exactly. RawAcl
    # equality preserves ACE order, revision, type, flags, mask, SID, and
    # duplicates; it cannot hide an unrecognized or inherited ACE.
    $actualFlags = (
        [int]$Actual.ControlFlags -band (-bnot $IgnoredControlFlags)
    )
    $expectedFlags = (
        [int]$Expected.ControlFlags -band (-bnot $IgnoredControlFlags)
    )
    if ($actualFlags -ne $expectedFlags) {
        return $false
    }

    $actualDACL = $Actual.DiscretionaryAcl
    $expectedDACL = $Expected.DiscretionaryAcl
    if ($null -eq $actualDACL -or $null -eq $expectedDACL) {
        return $false
    }
    if ($actualDACL.BinaryLength -ne $expectedDACL.BinaryLength) {
        return $false
    }
    $actualBytes = [byte[]]::new($actualDACL.BinaryLength)
    $expectedBytes = [byte[]]::new($expectedDACL.BinaryLength)
    $actualDACL.GetBinaryForm($actualBytes, 0)
    $expectedDACL.GetBinaryForm($expectedBytes, 0)
    for ($index = 0; $index -lt $actualBytes.Length; $index++) {
        if ($actualBytes[$index] -ne $expectedBytes[$index]) {
            return $false
        }
    }
    return $true
}

function Assert-DefenseClawCanonicalRawPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Actual,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Expected
    )
    $expectedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $Expected.GetSecurityDescriptorBinaryForm(),
        0
    )
    $protectedFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    if (([int]$Actual.ControlFlags -band $protectedFlag) -eq 0) {
        throw "managed DACL is not protected after exact ACL replacement: $Path"
    }
    $ownerSID = if ($null -eq $Actual.Owner) {
        ''
    }
    else {
        $Actual.Owner.Value
    }
    $groupSID = if ($null -eq $Actual.Group) {
        ''
    }
    else {
        $Actual.Group.Value
    }
    $expectedOwnerSID = if ($null -eq $expectedDescriptor.Owner) {
        ''
    }
    else {
        $expectedDescriptor.Owner.Value
    }
    $expectedGroupSID = if ($null -eq $expectedDescriptor.Group) {
        ''
    }
    else {
        $expectedDescriptor.Group.Value
    }
    if ($ownerSID -cne $expectedOwnerSID -or
        $groupSID -cne $expectedGroupSID) {
        throw (
            'managed path owner/group do not match the exact canonical ' +
            "descriptor after ACL replacement: $Path"
        )
    }
    if (-not (Test-DefenseClawExactRawDACL `
        -Actual $Actual `
        -Expected $expectedDescriptor)) {
        throw "managed path does not have the exact canonical DACL: $Path"
    }
}

function Test-DefenseClawCanonicalRawPathAcl {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Actual,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Expected
    )
    $expectedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $Expected.GetSecurityDescriptorBinaryForm(),
        0
    )
    $protectedFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    if (([int]$Actual.ControlFlags -band $protectedFlag) -eq 0) {
        return $false
    }
    if ($null -eq $Actual.Owner -or
        $null -eq $Actual.Group -or
        $null -eq $expectedDescriptor.Owner -or
        $null -eq $expectedDescriptor.Group -or
        $Actual.Owner.Value -cne $expectedDescriptor.Owner.Value -or
        $Actual.Group.Value -cne $expectedDescriptor.Group.Value) {
        return $false
    }
    return [bool](Test-DefenseClawExactRawDACL `
        -Actual $Actual `
        -Expected $expectedDescriptor)
}

function Assert-DefenseClawCanonicalPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Expected
    )
    Assert-DefenseClawNoReparsePath -Path $Path
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $actualDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $nativeSecurity::GetFileSecurityDescriptor($Path),
        0
    )
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $Path `
        -Actual $actualDescriptor `
        -Expected $Expected
}

function Set-DefenseClawPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [ValidateSet('InstallDirectory', 'InstallFile', 'ServiceInstallDirectory', 'ServiceInstallFile', 'StateDirectory', 'AdminDirectory', 'AdminFile', 'ConfigDirectory', 'ConfigFile', 'MachinePolicyFile', 'RuntimeDirectory', 'RuntimeFile', 'RuntimeSecretFile', 'AuthorizationDirectory', 'AuthorizationFile', 'LogDirectory', 'GatewayLogDirectory', 'ManagedIPCDirectory')]
        [string]$Kind,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    Assert-DefenseClawNoReparsePath -Path $Path
    $isDirectory = [bool](
        Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $Path `
            -Force `
            -ErrorAction Stop
    ).PSIsContainer
    $security = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $isDirectory `
        -Kind $Kind `
        -GatewayServiceSID $GatewayServiceSID
    if ($Kind -eq 'RuntimeSecretFile') {
        $nativeSecurity = Initialize-DefenseClawNativeSecurity
        $before = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollow(
            $Path,
            [uint32]32
        )
        $sddl = $security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
        $after = $nativeSecurity::SetRegularFileSecurityDescriptorNoFollow(
            $Path,
            $sddl,
            [uint32]32,
            [string]$before.Identity
        )
        if ([string]$after.Identity -cne [string]$before.Identity) {
            throw "managed secret identity changed during ACL replacement: $Path"
        }
        Assert-DefenseClawCanonicalRawPathAcl `
            -Path $Path `
            -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$after.SecurityDescriptor,
                0
            )) `
            -Expected $security
        return
    }
    Microsoft.PowerShell.Security\Set-Acl `
        -LiteralPath $Path `
        -AclObject $security `
        -ErrorAction Stop
    Assert-DefenseClawCanonicalPathAcl -Path $Path -Expected $security
}

function Set-DefenseClawBootstrapRootAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUsersRead
    )
    Assert-DefenseClawNoReparsePath -Path $Path
    $kind = if ($AllowUsersRead) {
        'InstallDirectory'
    }
    else {
        'AdminDirectory'
    }
    Set-DefenseClawPathAcl `
        -Path $Path `
        -Kind $kind `
        -GatewayServiceSID $script:AdministratorsSID
}

function New-DefenseClawProtectedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUsersRead,
        [string]$StagingMarkerSID
    )
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parent -PathType Container)) {
        throw "protected directory parent must already exist: $parent"
    }
    Assert-DefenseClawTrustedAncestor -Path $parent

    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    $sddl = 'O:BAG:BAD:P'
    if (-not [string]::IsNullOrWhiteSpace($StagingMarkerSID)) {
        $marker = [Security.Principal.SecurityIdentifier]::new(
            $StagingMarkerSID
        )
        if ($marker.Value -cne $StagingMarkerSID) {
            throw 'managed-root staging marker SID is not canonical'
        }
        $sddl += "(D;;FA;;;$StagingMarkerSID)"
    }
    $sddl += '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($AllowUsersRead -and
        [string]::IsNullOrWhiteSpace($StagingMarkerSID)) {
        $sddl += '(A;OICI;0x1200a9;;;BU)'
    }
    # CreateDirectoryW receives the protected descriptor in SECURITY_ATTRIBUTES,
    # so the object is never visible with an inherited permissive DACL. If
    # another principal wins the absent->create race, ERROR_ALREADY_EXISTS is
    # returned and the immediate strict validation rejects that object before
    # ownership or ACLs are changed.
    $created = $nativeSecurityType::CreateDirectorySecure($Path, $sddl)
    Assert-DefenseClawNoReparsePath -Path $Path
    Assert-DefenseClawPathAcl `
        -Path $Path `
        -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
        -AllowUsersRead:($AllowUsersRead -and
            [string]::IsNullOrWhiteSpace($StagingMarkerSID))
    return [bool]$created
}

# Directories strictly between the required base and a managed root. The base
# is an OS directory and the root carries its own canonical DACL, so neither is
# returned.
function Get-DefenseClawManagedRootAncestors {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RequiredBase
    )
    $base = [IO.Path]::GetFullPath($RequiredBase).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "managed root is outside its required ancestor base: $full"
    }
    $relative = $full.Substring($base.Length).TrimStart('\')
    $components = @($relative.Split('\') |
        Microsoft.PowerShell.Core\Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ancestors = [Collections.Generic.List[string]]::new()
    $current = $base
    for ($index = 0; $index -lt $components.Count - 1; $index++) {
        $current = Microsoft.PowerShell.Management\Join-Path $current $components[$index]
        [void]$ancestors.Add($current)
    }
    return @($ancestors)
}

# Execute to traverse the ancestor, read-control to read the descriptor the
# gateway's own ancestor trust check inspects.
$script:StateAncestorTraverseRights =
    [Security.AccessControl.FileSystemRights]::ReadAndExecute

# A state-root ancestor is a shared vendor directory this installer does not
# own, so the owner and every other ACE are preserved and one ACE is added.
# The ACE is not inherited, keeping the grant off sibling trees.
function Add-DefenseClawStateAncestorTraverseRule {
    param(
        [Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Security,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    $identity = [Security.Principal.SecurityIdentifier]::new($GatewayServiceSID)
    # Repeated installs converge on exactly one ACE for this SID.
    [void]$Security.PurgeAccessRules($identity)
    [void]$Security.AddAccessRule(
        [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            $script:StateAncestorTraverseRights,
            [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
    return $Security
}

function Grant-DefenseClawStateAncestorTraverse {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    Assert-DefenseClawNoReparsePath -Path $Path
    Assert-DefenseClawTrustedAncestor -Path $Path
    $security = Add-DefenseClawStateAncestorTraverseRule `
        -Security (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path) `
        -GatewayServiceSID $GatewayServiceSID
    Microsoft.PowerShell.Security\Set-Acl `
        -LiteralPath $Path `
        -AclObject $security `
        -ErrorAction Stop
    Assert-DefenseClawStateAncestorTraverse `
        -Path $Path `
        -GatewayServiceSID $GatewayServiceSID
}

function Assert-DefenseClawStateAncestorTraverse {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    # No untrusted principal may own the ancestor or hold rights that would let
    # it replace what sits underneath.
    Assert-DefenseClawTrustedAncestor -Path $Path
    $required = $script:StateAncestorTraverseRights
    $granted = [Security.AccessControl.FileSystemRights]0
    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)) {
            continue
        }
        if ((ConvertTo-DefenseClawSID -Identity $rule.IdentityReference) -ne $GatewayServiceSID) {
            continue
        }
        if ($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None) {
            throw (
                'gateway traverse grant on a shared managed ancestor must not ' +
                "be inheritable: $Path"
            )
        }
        $granted = $granted -bor $rule.FileSystemRights
    }
    if (($granted -band $required) -ne $required) {
        throw (
            "gateway service $GatewayServiceSID cannot traverse an ancestor of " +
            "its own state root: $Path"
        )
    }
}

# Drops the grant added by Grant-DefenseClawStateAncestorTraverse. Valid only
# after both services are deleted, when the SID is stale.
function Revoke-DefenseClawStateAncestorTraverse {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Path `
            -PathType Container)) {
        return
    }
    Assert-DefenseClawNoReparsePath -Path $Path
    Assert-DefenseClawTrustedAncestor -Path $Path
    $security = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
    $explicit = $false
    foreach ($rule in $security.Access) {
        if ($rule.IsInherited) {
            continue
        }
        if ((ConvertTo-DefenseClawSID -Identity $rule.IdentityReference) -eq
            $GatewayServiceSID) {
            $explicit = $true
            break
        }
    }
    if (-not $explicit) {
        return
    }
    [void]$security.PurgeAccessRules(
        [Security.Principal.SecurityIdentifier]::new($GatewayServiceSID)
    )
    Microsoft.PowerShell.Security\Set-Acl `
        -LiteralPath $Path `
        -AclObject $security `
        -ErrorAction Stop
}

function Initialize-DefenseClawManagedRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$RequiredBase,
        [switch]$AllowUsersRead,
        [switch]$PassThruCreationResult,
        [string]$StagingMarkerSID,
        [switch]$DeferFinalAcl
    )
    if ($DeferFinalAcl -and
        [string]::IsNullOrWhiteSpace($StagingMarkerSID)) {
        throw 'deferred managed-root ACL publication requires a staging marker SID'
    }
    $base = [IO.Path]::GetFullPath($RequiredBase).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    Assert-DefenseClawTrustedAncestors -Path $full -RequiredBase $base

    $current = $base
    $relative = $full.Substring($base.Length).TrimStart('\')
    $components = @($relative.Split('\') | Microsoft.PowerShell.Core\Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $rootCreated = $false
    for ($index = 0; $index -lt $components.Count; $index++) {
        $current = Microsoft.PowerShell.Management\Join-Path $current $components[$index]
        $isLeaf = $index -eq $components.Count - 1
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current)) {
            $createdThisComponent = New-DefenseClawProtectedDirectory `
                -Path $current `
                -AllowUsersRead:$AllowUsersRead `
                -StagingMarkerSID $(if ($isLeaf) {
                    $StagingMarkerSID
                }
                else {
                    ''
                })
            if ($index -eq $components.Count - 1) {
                $rootCreated = [bool]$createdThisComponent
                if (-not $rootCreated -and $DeferFinalAcl) {
                    # Absence was already recorded in the protected receipt.
                    # A competing creator may be adopted only when it carries
                    # this transaction's unguessable exact staging descriptor;
                    # never canonicalize an unrelated race winner in place.
                    [void](Assert-DefenseClawManagedRootStagingAcl `
                        -Path $current `
                        -MarkerSID $StagingMarkerSID)
                    $rootCreated = $true
                }
            }
        }
        elseif (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current -PathType Container)) {
            throw "$Label ancestor is occupied by a non-directory: $current"
        }
        else {
            if ($isLeaf -and $DeferFinalAcl) {
                # Crash re-entry can find the exact marker-staged leaf before
                # its identity was copied into the receipt. The secret marker
                # makes that inode transaction-owned; any other pre-existing
                # leaf fails closed without an ownership or DACL rewrite.
                [void](Assert-DefenseClawManagedRootStagingAcl `
                    -Path $current `
                    -MarkerSID $StagingMarkerSID)
                $rootCreated = $true
            }
            else {
                Assert-DefenseClawTrustedAncestor -Path $current
            }
        }
    }

    if ($rootCreated -and $DeferFinalAcl) {
        [void](Assert-DefenseClawManagedRootStagingAcl `
            -Path $Path `
            -MarkerSID $StagingMarkerSID)
        return [pscustomobject]@{
            created = $true
            state = 'staged'
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path) {
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Container)) {
            throw "$Label is occupied by a non-directory: $Path"
        }
        # Never seize a user-controlled tree. First prove the existing owner
        # and all effective write ACEs are already administrator-controlled;
        # only then replace inheritance with the canonical protected DACL.
        Assert-DefenseClawPathAcl `
            -Path $Path `
            -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
            -AllowUsersRead:$AllowUsersRead `
            -AllowInheritance
    }
    else {
        throw "$Label secure creation did not produce the requested root: $Path"
    }
    Set-DefenseClawBootstrapRootAcl -Path $Path -AllowUsersRead:$AllowUsersRead
    Assert-DefenseClawPathAcl `
        -Path $Path `
        -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
        -AllowUsersRead:$AllowUsersRead
    if ($PassThruCreationResult) {
        return [pscustomobject]@{
            created = [bool]$rootCreated
            state = 'canonical'
        }
    }
}

function Assert-DefenseClawManagedRootStagingAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$MarkerSID
    )
    $marker = [Security.Principal.SecurityIdentifier]::new($MarkerSID)
    if ($marker.Value -cne $MarkerSID) {
        throw 'managed-root staging marker SID is not canonical'
    }
    $expected = [Security.AccessControl.DirectorySecurity]::new()
    $expected.SetSecurityDescriptorSddlForm(
        "O:BAG:BAD:P(D;;FA;;;$MarkerSID)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        [Security.AccessControl.AccessControlSections]::All
    )
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
        $Path
    )
    if ($null -eq $captured) {
        throw 'managed-root staging directory is missing'
    }
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $Path `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$captured.SecurityDescriptor,
            0
        )) `
        -Expected $expected
    return $captured
}

function Complete-DefenseClawManagedRootStaging {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$MarkerSID,
        [Parameter(Mandatory)][string]$ExpectedIdentity,
        [switch]$AllowUsersRead
    )
    $before = Assert-DefenseClawManagedRootStagingAcl `
        -Path $Path `
        -MarkerSID $MarkerSID
    if ([string]$before.Identity -cne $ExpectedIdentity) {
        throw 'managed-root staging identity changed before final publication'
    }
    Set-DefenseClawBootstrapRootAcl `
        -Path $Path `
        -AllowUsersRead:$AllowUsersRead
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $after = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
        $Path
    )
    if ($null -eq $after -or
        [string]$after.Identity -cne $ExpectedIdentity) {
        throw 'managed-root identity changed during final ACL publication'
    }
    return $after
}

function Initialize-DefenseClawTransactionManagedRoot {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)]
        [ValidateSet('install_root', 'state_root')]
        [string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$RequiredBase,
        [switch]$AllowUsersRead
    )
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    $marker = [string]$intent."${Root}_marker_sid"
    $creation = Initialize-DefenseClawManagedRoot `
        -Path $Path `
        -Label $Label `
        -RequiredBase $RequiredBase `
        -AllowUsersRead:$AllowUsersRead `
        -PassThruCreationResult `
        -StagingMarkerSID $marker `
        -DeferFinalAcl:(-not [string]::IsNullOrWhiteSpace($marker))
    if (-not [bool]$creation.created) {
        [void](Set-DefenseClawInstallPreparationRootIdentity `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Root $Root `
            -State existing)
        return $false
    }
    $intent = Set-DefenseClawInstallPreparationRootIdentity `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Root $Root `
        -State staged
    $identity = [string]$intent."${Root}_identity"
    [void](Complete-DefenseClawManagedRootStaging `
        -Path $Path `
        -MarkerSID $marker `
        -ExpectedIdentity $identity `
        -AllowUsersRead:$AllowUsersRead)
    [void](Set-DefenseClawInstallPreparationRootIdentity `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Root $Root `
        -State canonical)
    return $true
}

function Enter-DefenseClawLifecycleLock {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [int]$TimeoutSeconds = 30
    )
    $path = Assert-DefenseClawDescendant `
        -Path $Layout.LifecycleLockPath `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'lifecycle lock file'
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path)) {
        try {
            $created = [IO.File]::Open(
                $path,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            $created.Dispose()
            $security = [Security.AccessControl.FileSecurity]::new()
            $security.SetSecurityDescriptorSddlForm(
                'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',
                [Security.AccessControl.AccessControlSections]::All
            )
            Microsoft.PowerShell.Security\Set-Acl `
                -LiteralPath $path `
                -AclObject $security
        }
        catch [IO.IOException] {
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $path `
                -PathType Leaf)) {
                throw
            }
        }
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "protected lifecycle lock is not a regular file: $path"
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ([int64]$item.Length -ne 0) {
        throw "protected lifecycle lock has unexpected content: $path"
    }
    $adminRights = New-DefenseClawRequiredRights -Kind Admin
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights $adminRights `
        -RejectUntrustedRead

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $lock = [IO.File]::Open(
                $path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            if ($lock.Length -ne 0) {
                $lock.Dispose()
                throw "protected lifecycle lock changed while opening: $path"
            }
            return $lock
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "another DefenseClaw enterprise lifecycle mutation holds the protected file lock for more than $TimeoutSeconds seconds"
            }
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 100
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "another DefenseClaw enterprise lifecycle mutation holds the protected file lock for more than $TimeoutSeconds seconds"
}

function Exit-DefenseClawLifecycleLock {
    param([Parameter(Mandatory)]$Lock)
    # The protected machine-wide lock identity intentionally persists across
    # deployments. Only the handle is released here; deleting/recreating the
    # predictable path would weaken cross-run serialization and reopen a
    # squatting race between consecutive lifecycle processes.
    $Lock.Dispose()
}

function Test-DefenseClawWriteLikeRights {
    param([Security.AccessControl.FileSystemRights]$Rights)
    $writeLike = [Security.AccessControl.FileSystemRights]::WriteData `
        -bor [Security.AccessControl.FileSystemRights]::AppendData `
        -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
        -bor [Security.AccessControl.FileSystemRights]::WriteAttributes `
        -bor [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $rightsValue = [uint64]([int64]$Rights -band 0xffffffffL)
    return (($Rights -band $writeLike) -ne 0 -or
        ($rightsValue -band [uint64]0x50000000) -ne 0)
}

function Test-DefenseClawReadLikeRights {
    param([Security.AccessControl.FileSystemRights]$Rights)
    $readLike = [Security.AccessControl.FileSystemRights]::ReadData `
        -bor [Security.AccessControl.FileSystemRights]::ReadExtendedAttributes `
        -bor [Security.AccessControl.FileSystemRights]::ReadAttributes `
        -bor [Security.AccessControl.FileSystemRights]::ReadPermissions `
        -bor [Security.AccessControl.FileSystemRights]::ExecuteFile
    return (($Rights -band $readLike) -ne 0)
}

function Assert-DefenseClawPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$AllowedWriterSIDs,
        [string[]]$AllowedReaderSIDs = @(),
        [hashtable]$RequiredRights = @{},
        [string[]]$AllowedOwnerSIDs = @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ),
        [switch]$AllowUsersRead,
        [switch]$RejectUntrustedRead,
        [switch]$AllowInheritance
    )
    Assert-DefenseClawNoReparsePath -Path $Path
    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
    $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith('D:', [StringComparison]::OrdinalIgnoreCase)) {
        throw "managed path has an absent or null DACL: $Path"
    }
    $ownerSID = ConvertTo-DefenseClawSID -Identity $acl.Owner
    if ($ownerSID -notin $AllowedOwnerSIDs) {
        throw "untrusted owner $ownerSID on managed path: $Path"
    }
    if (-not $AllowInheritance -and -not $acl.AreAccessRulesProtected) {
        throw "managed DACL inherits from an ancestor: $Path"
    }
    $grantedBySID = @{}
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            if ($RequiredRights.Count -gt 0) {
                throw "managed path contains a non-canonical deny ACE for $($rule.IdentityReference): $Path"
            }
            continue
        }
        $sid = ConvertTo-DefenseClawSID -Identity $rule.IdentityReference
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) {
            $currentRights = if ($grantedBySID.ContainsKey($sid)) {
                [Security.AccessControl.FileSystemRights]$grantedBySID[$sid]
            }
            else {
                [Security.AccessControl.FileSystemRights]0
            }
            $grantedBySID[$sid] = $currentRights -bor $rule.FileSystemRights
        }
        if ((Test-DefenseClawWriteLikeRights -Rights $rule.FileSystemRights) -and $sid -notin $AllowedWriterSIDs) {
            throw "untrusted principal $sid has write-like access to managed path: $Path"
        }
        if ($RejectUntrustedRead -and
            (Test-DefenseClawReadLikeRights -Rights $rule.FileSystemRights) -and
            $sid -notin $AllowedReaderSIDs -and
            -not ($AllowUsersRead -and $sid -eq $script:UsersSID)) {
            throw "untrusted principal $sid can read protected managed path: $Path"
        }
    }
    foreach ($entry in $RequiredRights.GetEnumerator()) {
        $sid = [string]$entry.Key
        $required = [Security.AccessControl.FileSystemRights]$entry.Value
        $actual = if ($grantedBySID.ContainsKey($sid)) {
            [Security.AccessControl.FileSystemRights]$grantedBySID[$sid]
        }
        else {
            [Security.AccessControl.FileSystemRights]0
        }
        if (($actual -band $required) -ne $required) {
            throw "managed path is missing required rights for $sid (required=$required actual=$actual): $Path"
        }
    }
}

function New-DefenseClawDirectory {
    param([Parameter(Mandatory)][string]$Path)
    Assert-DefenseClawNoReparsePath -Path $Path -AllowMissingLeaf
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path) {
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Container)) {
            throw "managed directory path is occupied by a non-directory: $Path"
        }
        return
    }
    [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $Path -Force)
    Assert-DefenseClawNoReparsePath -Path $Path
}

function Install-DefenseClawFileAtomic {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [string]$ExpectedSHA256,
        [switch]$SkipIfContentMatches
    )
    Assert-DefenseClawNoReparsePath -Path $Source
    Assert-DefenseClawNoReparsePath -Path $Destination -AllowMissingLeaf
    if ($SkipIfContentMatches -and [IO.File]::Exists($Destination)) {
        $sourceItem = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $Source `
            -Force
        $destinationItem = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $Destination `
            -Force
        if ([int64]$sourceItem.Length -eq [int64]$destinationItem.Length) {
            $sourceHash = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Source `
                    -Algorithm SHA256
            ).Hash
            if (-not [string]::IsNullOrWhiteSpace($ExpectedSHA256) -and
                -not [string]::Equals(
                    $sourceHash,
                    $ExpectedSHA256,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "source changed while checking managed artifact: $Source"
            }
            $destinationHash = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Destination `
                    -Algorithm SHA256
            ).Hash
            if ([string]::Equals(
                $sourceHash,
                $destinationHash,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                return
            }
        }
    }
    New-DefenseClawDirectory -Path ([IO.Path]::GetDirectoryName($Destination))
    $temporary = "$Destination.new.$([Guid]::NewGuid().ToString('N'))"
    $backup = ''
    try {
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $Source -Destination $temporary -Force
        Assert-DefenseClawNoReparsePath -Path $temporary
        $copiedHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $temporary `
                -Algorithm SHA256
        ).Hash
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSHA256)) {
            if (-not [string]::Equals(
                $copiedHash,
                $ExpectedSHA256,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "source changed while staging managed artifact: $Source"
            }
        }
        if ([IO.File]::Exists($Destination)) {
            # Move-Item -Force does not reliably replace an existing file on
            # Windows PowerShell 5.1. File.Replace requires a non-empty backup
            # path on both .NET Framework and modern .NET. Keep the prior file
            # beside the protected destination until the replacement hash is
            # verified, then retire only that unique recovery artifact.
            $backup = "$Destination.backup.$([Guid]::NewGuid().ToString('N'))"
            Assert-DefenseClawNoReparsePath -Path $backup -AllowMissingLeaf
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $backup) {
                throw "atomic replacement backup path unexpectedly exists: $backup"
            }
            [IO.File]::Replace($temporary, $Destination, $backup, $true)
        }
        else {
            [IO.File]::Move($temporary, $Destination)
        }
        Assert-DefenseClawNoReparsePath -Path $Destination
        $installedHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Destination `
                -Algorithm SHA256
        ).Hash
        if (-not [string]::Equals(
            $installedHash,
            $copiedHash,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "atomic replacement verification failed: $Destination"
        }
        if (-not [string]::IsNullOrWhiteSpace($backup)) {
            Assert-DefenseClawNoReparsePath -Path $backup
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $backup `
                -Force
            $backup = ''
        }
    }
    finally {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $temporary) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Write-DefenseClawJsonAtomic {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path
    )
    New-DefenseClawDirectory -Path ([IO.Path]::GetDirectoryName($Path))
    $temporary = "$Path.new.$([Guid]::NewGuid().ToString('N'))"
    try {
        $json = $Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12
        # Windows PowerShell 5.1's -Encoding UTF8 emits a BOM, which Go's
        # encoding/json intentionally rejects. Use explicit BOM-less UTF-8 so
        # every PowerShell version publishes byte-identical JSON.
        [IO.File]::WriteAllText(
            $temporary,
            $json,
            [Text.UTF8Encoding]::new($false)
        )
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $temporary) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Test-DefenseClawServiceExists {
    param([Parameter(Mandatory)][string]$Name)
    Assert-DefenseClawServiceName -Name $Name
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    # OpenService distinguishes the only safe absence result (Win32 1060)
    # from access-denied, SCM failure, and malformed-query errors. Destructive
    # rollback callers therefore cannot reinterpret a failed query as absence.
    return [bool]$nativeSecurity::ServiceExistsChecked($Name)
}

function Assert-DefenseClawServicesAbsentChecked {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names,
        [Parameter(Mandatory)][string]$Operation
    )
    foreach ($name in $Names) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "$Operation while service exists: $name"
        }
    }
}

function Get-DefenseClawServiceChecked {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        return $null
    }
    try {
        return Microsoft.PowerShell.Management\Get-Service `
            -Name $Name `
            -ErrorAction Stop
    }
    catch {
        # Disappearance between OpenService and ServiceController construction
        # is the only tolerated race. If the native checked query still sees
        # the service, propagate the PowerShell/SCM failure.
        if (-not (Test-DefenseClawServiceExists -Name $Name)) {
            return $null
        }
        throw
    }
}

function Stop-DefenseClawService {
    param([Parameter(Mandatory)][string]$Name)
    $service = Get-DefenseClawServiceChecked -Name $Name
    if ($null -eq $service) { return }
    if ($service.Status -eq
        [ServiceProcess.ServiceControllerStatus]::Stopped) {
        return
    }
    Microsoft.PowerShell.Management\Stop-Service -Name $Name -ErrorAction Stop
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
}

function Start-DefenseClawService {
    param([Parameter(Mandatory)][string]$Name)
    $service = Microsoft.PowerShell.Management\Get-Service -Name $Name -ErrorAction Stop
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Microsoft.PowerShell.Management\Start-Service -Name $Name -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
    }
}

function Remove-DefenseClawService {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        return
    }
    Stop-DefenseClawService -Name $Name
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('delete', $Name))
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Test-DefenseClawServiceExists -Name $Name) -and [DateTime]::UtcNow -lt $deadline) {
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 100
    }
    if (Test-DefenseClawServiceExists -Name $Name) {
        throw "Windows service remains after deletion: $Name"
    }
}

function Get-DefenseClawServiceEnvironmentValues {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$AuthorizationDirectory,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$LogPath,
        [string]$BrokerPipeName,
        [string]$BrokerServiceName,
        [string]$BrokerAuthKeyPath,
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified
    )
    $values = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        "DEFENSECLAW_HOME=$RuntimeDirectory",
        "DEFENSECLAW_CONFIG=$ConfigPath",
        'DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise',
        "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$AuthorizationDirectory",
        "DEFENSECLAW_WINDOWS_SERVICE_NAME=$Name",
        "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME=$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT=NT SERVICE\$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_LOG=$LogPath"
    )) {
        $values.Add($value)
    }
    $brokerValues = @($BrokerPipeName, $BrokerServiceName, $BrokerAuthKeyPath)
    $brokerValueCount = @($brokerValues | Microsoft.PowerShell.Core\Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    }).Count
    if ($brokerValueCount -ne 0 -and $brokerValueCount -ne 3) {
        throw 'credential broker service environment is partially configured'
    }
    if ($brokerValueCount -eq 3) {
        $values.Add("DEFENSECLAW_CMID_BROKER_PIPE=$BrokerPipeName")
        $values.Add("DEFENSECLAW_CMID_BROKER_SERVICE_NAME=$BrokerServiceName")
        $values.Add("DEFENSECLAW_CMID_BROKER_AUTH_KEY=$BrokerAuthKeyPath")
    }
    if ($AgentApplicationControlAttested) {
        $values.Add('DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1')
        $values.Add('DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1')
    }
    if ($ClaudeEffectivePolicyVerified) {
        $values.Add('DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1')
    }
    return [string[]]$values.ToArray()
}

function Set-DefenseClawServiceEnvironment {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$AuthorizationDirectory,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$LogPath,
        [string]$BrokerPipeName,
        [string]$BrokerServiceName,
        [string]$BrokerAuthKeyPath,
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified
    )
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $serviceKey)) {
        throw "service registry key is missing: $Name"
    }
    $values = [string[]]@(Get-DefenseClawServiceEnvironmentValues `
        -Name $Name `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $LogPath `
        -BrokerPipeName $BrokerPipeName `
        -BrokerServiceName $BrokerServiceName `
        -BrokerAuthKeyPath $BrokerAuthKeyPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified)
    [void](Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $serviceKey -Name Environment -PropertyType MultiString -Value $values -Force)
}

function Set-DefenseClawCMIDBrokerAuthKey {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    $gatewaySID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    $directory = [IO.Path]::GetDirectoryName($Path)
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory -PathType Container)) {
        throw "credential broker key directory is missing: $directory"
    }
    Assert-DefenseClawNoReparsePath -Path $directory
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$gatewaySID)",
        (
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor
            [Security.AccessControl.AccessControlSections]::Access
        )
    )
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Leaf) {
        Assert-DefenseClawNoReparsePath -Path $Path
        $existing = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
        if ([int64]$existing.Length -ne 32) {
            throw 'credential broker authentication key must be exactly 32 bytes'
        }
        Microsoft.PowerShell.Security\Set-Acl `
            -LiteralPath $Path `
            -AclObject $security `
            -ErrorAction Stop
        return
    }
    $temporary = Microsoft.PowerShell.Management\Join-Path `
        $directory `
        ('.broker-auth.{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
    $key = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($key)
        [IO.File]::WriteAllBytes($temporary, $key)
        Microsoft.PowerShell.Security\Set-Acl `
            -LiteralPath $temporary `
            -AclObject $security `
            -ErrorAction Stop
        Microsoft.PowerShell.Management\Move-Item `
            -LiteralPath $temporary `
            -Destination $Path `
            -Force
    }
    finally {
        $generator.Dispose()
        [Array]::Clear($key, 0, $key.Length)
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $temporary) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Get-DefenseClawFailureActionsBytes {
    $values = [uint32[]]@(
        86400, # reset period seconds
        0,     # reboot message offset
        0,     # command offset
        3,     # 5s/15s/60s restarts; SCM repeats the last action indefinitely
        20,    # action array offset
        1, 5000,
        1, 15000,
        1, 60000
    )
    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($value in $values) {
        $bytes.AddRange([BitConverter]::GetBytes($value))
    }
    return ,$bytes.ToArray()
}

function Set-DefenseClawExactFailureActions {
    param([Parameter(Mandatory)][string]$Name)
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    [void](Microsoft.PowerShell.Management\New-ItemProperty `
        -LiteralPath $serviceKey `
        -Name FailureActions `
        -PropertyType Binary `
        -Value (Get-DefenseClawFailureActionsBytes) `
        -Force)
    [void](Microsoft.PowerShell.Management\New-ItemProperty `
        -LiteralPath $serviceKey `
        -Name FailureActionsOnNonCrashFailures `
        -PropertyType DWord `
        -Value 1 `
        -Force)
}

function Set-DefenseClawServiceRegistryAcl {
    param([Parameter(Mandatory)][string]$Name)
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $serviceKey)) {
        throw "service registry key is missing: $Name"
    }
    $security = [Security.AccessControl.RegistrySecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        'O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)',
        (
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor
            [Security.AccessControl.AccessControlSections]::Access
        )
    )
    # The registry provider mishandles -LiteralPath (Get-Acl on 5.1, Set-Acl on
    # 7). Key names cannot contain wildcards, so -Path is safe here.
    Microsoft.PowerShell.Security\Set-Acl -Path $serviceKey -AclObject $security
    Reset-DefenseClawServiceSecuritySubkeyInheritance -Path "$serviceKey\Security"
}

function Reset-DefenseClawServiceSecuritySubkeyInheritance {
    # sc.exe sdset leaves the Security subkey with a protected DACL and explicit
    # ACEs. Restore inheritance so the subkey derives its rights from the managed
    # parent key. The Security value itself is left alone.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Microsoft.PowerShell.Management\Test-Path -Path $Path)) {
        return
    }
    $acl = Microsoft.PowerShell.Security\Get-Acl -Path $Path
    foreach ($rule in @($acl.Access | Microsoft.PowerShell.Core\Where-Object { -not $_.IsInherited })) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $acl.SetAccessRuleProtection($false, $false)
    Microsoft.PowerShell.Security\Set-Acl -Path $Path -AclObject $acl
}

function Assert-DefenseClawServiceSecurityRegistrySubkey {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $children = @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $Path `
            -ErrorAction Stop
    )
    if ($children.Count -ne 0) {
        throw "service $Name SCM Security registry key contains unexpected child keys"
    }

    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $Path `
        -ErrorAction Stop
    $valueNames = @($item.GetValueNames())
    if ($valueNames.Count -ne 1 -or
        -not [string]::Equals(
            [string]$valueNames[0],
            'Security',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "service $Name SCM Security registry key does not contain exactly the Security value"
    }
    if ($item.GetValueKind('Security') -ne
        [Microsoft.Win32.RegistryValueKind]::Binary) {
        throw "service $Name SCM Security registry value is not REG_BINARY"
    }
    $descriptorBytes = [byte[]]$item.GetValue(
        'Security',
        $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    )
    if ($null -eq $descriptorBytes -or $descriptorBytes.Length -lt 20) {
        throw "service $Name SCM Security registry value is empty or truncated"
    }
    try {
        [void][Security.AccessControl.RawSecurityDescriptor]::new(
            $descriptorBytes,
            0
        )
    }
    catch {
        throw "service $Name SCM Security registry value is not a valid security descriptor: $($_.Exception.Message)"
    }

    $acl = Microsoft.PowerShell.Security\Get-Acl -Path $Path
    $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith('D:', [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name SCM Security registry key has an absent or null DACL"
    }
    $ownerSID = ConvertTo-DefenseClawSID -Identity $acl.Owner
    if ($ownerSID -notin @(
        $script:SystemSID,
        $script:AdministratorsSID,
        $script:TrustedInstallerSID
    )) {
        throw "service $Name SCM Security registry key has untrusted owner $ownerSID"
    }
    if ($acl.AreAccessRulesProtected) {
        throw "service $Name SCM Security registry key does not inherit the managed service-key DACL"
    }

    $required = @{}
    $required[$script:SystemSID] =
        [Security.AccessControl.RegistryRights]::FullControl
    $required[$script:AdministratorsSID] =
        [Security.AccessControl.RegistryRights]::FullControl
    $required[$script:UsersSID] =
        [Security.AccessControl.RegistryRights]::ReadKey
    $granted = @{}
    $writeMask = [Security.AccessControl.RegistryRights]::SetValue -bor
        [Security.AccessControl.RegistryRights]::CreateSubKey -bor
        [Security.AccessControl.RegistryRights]::Delete -bor
        [Security.AccessControl.RegistryRights]::ChangePermissions -bor
        [Security.AccessControl.RegistryRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if (-not $rule.IsInherited) {
            throw "service $Name SCM Security registry key contains an explicit ACE"
        }
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow) {
            throw "service $Name SCM Security registry key contains a deny ACE"
        }
        $sid = ConvertTo-DefenseClawSID -Identity $rule.IdentityReference
        $appliesToKey = (
            ($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
        )
        if ($appliesToKey -and
            ($rule.RegistryRights -band $writeMask) -ne 0 -and
            $sid -notin @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID
            )) {
            throw "untrusted principal $sid can change the service $Name SCM Security registry value"
        }
        if ($appliesToKey) {
            $current = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.RegistryRights]$granted[$sid]
            }
            else {
                [Security.AccessControl.RegistryRights]0
            }
            $granted[$sid] = $current -bor $rule.RegistryRights
        }
    }
    foreach ($entry in $required.GetEnumerator()) {
        $actual = if ($granted.ContainsKey([string]$entry.Key)) {
            [Security.AccessControl.RegistryRights]$granted[[string]$entry.Key]
        }
        else {
            [Security.AccessControl.RegistryRights]0
        }
        $needed = [Security.AccessControl.RegistryRights]$entry.Value
        if (($actual -band $needed) -ne $needed) {
            throw "service $Name SCM Security registry key is missing required rights for $($entry.Key)"
        }
    }
}

function Assert-DefenseClawServiceRegistryAcl {
    param([Parameter(Mandatory)][string]$Name)
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $serviceKey)) {
        throw "service registry key is missing: $Name"
    }
    $subkeys = @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $serviceKey `
            -ErrorAction Stop
    )
    $securitySubkeys = @(
        $subkeys |
            Microsoft.PowerShell.Core\Where-Object {
                [string]::Equals(
                    [string]$_.PSChildName,
                    'Security',
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    $unexpectedSubkeys = @(
        $subkeys |
            Microsoft.PowerShell.Core\Where-Object {
                -not [string]::Equals(
                    [string]$_.PSChildName,
                    'Security',
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($unexpectedSubkeys.Count -ne 0 -or $securitySubkeys.Count -gt 1) {
        $names = @(
            $unexpectedSubkeys |
                Microsoft.PowerShell.Core\ForEach-Object {
                    [string]$_.PSChildName
                }
        )
        throw "service $Name contains unexpected registry subkeys: $($names -join ', ')"
    }
    if ($securitySubkeys.Count -eq 1) {
        Assert-DefenseClawServiceSecurityRegistrySubkey `
            -Name $Name `
            -Path ([string]$securitySubkeys[0].PSPath)
    }

    $acl = Microsoft.PowerShell.Security\Get-Acl -Path $serviceKey
    $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith('D:', [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name registry key has an absent or null DACL"
    }
    $ownerSID = ConvertTo-DefenseClawSID -Identity $acl.Owner
    if ($ownerSID -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
        throw "service $Name registry key has untrusted owner $ownerSID"
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw "service $Name registry key inherits its DACL"
    }
    $required = @{}
    $required[$script:SystemSID] = [Security.AccessControl.RegistryRights]::FullControl
    $required[$script:AdministratorsSID] = [Security.AccessControl.RegistryRights]::FullControl
    $required[$script:UsersSID] = [Security.AccessControl.RegistryRights]::ReadKey
    $granted = @{}
    $writeMask = [Security.AccessControl.RegistryRights]::SetValue -bor
        [Security.AccessControl.RegistryRights]::CreateSubKey -bor
        [Security.AccessControl.RegistryRights]::Delete -bor
        [Security.AccessControl.RegistryRights]::ChangePermissions -bor
        [Security.AccessControl.RegistryRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "service $Name registry key contains a non-canonical deny ACE"
        }
        $sid = ConvertTo-DefenseClawSID -Identity $rule.IdentityReference
        if (($rule.RegistryRights -band $writeMask) -ne 0 -and
            $sid -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
            throw "untrusted principal $sid can change the service $Name registry configuration"
        }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) {
            $current = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.RegistryRights]$granted[$sid]
            }
            else {
                [Security.AccessControl.RegistryRights]0
            }
            $granted[$sid] = $current -bor $rule.RegistryRights
        }
    }
    foreach ($entry in $required.GetEnumerator()) {
        $actual = if ($granted.ContainsKey([string]$entry.Key)) {
            [Security.AccessControl.RegistryRights]$granted[[string]$entry.Key]
        }
        else {
            [Security.AccessControl.RegistryRights]0
        }
        $needed = [Security.AccessControl.RegistryRights]$entry.Value
        if (($actual -band $needed) -ne $needed) {
            throw "service $Name registry key is missing required rights for $($entry.Key)"
        }
    }
}

function Set-DefenseClawManagedServices {
    param(
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)][string]$BrokerServiceName,
        [Parameter(Mandatory)][string]$BrokerPath,
        [Parameter(Mandatory)][string]$BrokerPipeName,
        [Parameter(Mandatory)][string]$BrokerAuthKeyPath,
        [Parameter(Mandatory)][string]$ProviderLibraryPath,
        [Parameter(Mandatory)][string]$BrokerLogPath,
        [Parameter(Mandatory)][string]$GatewayPath,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$AuthorizationDirectory,
        [Parameter(Mandatory)][string]$GatewayLogPath,
        [Parameter(Mandatory)][string]$GuardianLogPath,
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified,
        [switch]$DeferAutomaticStart
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    Assert-DefenseClawServiceName -Name $BrokerServiceName
    if ($BrokerServiceName -cne (Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName)) {
        throw 'credential broker service name does not match the gateway identity'
    }
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    Assert-DefenseClawServiceName -Name $enumeratorServiceName
    $gatewayAccount = "NT SERVICE\$GatewayServiceName"
    $gatewayImage = '"{0}"' -f $GatewayPath
    $brokerImage = '"{0}" service --service-name {1} --gateway-service-name {2} --pipe-name {3} --auth-key "{4}" --cmid-library "{5}" --log "{6}"' -f `
        $BrokerPath, $BrokerServiceName, $GatewayServiceName, $BrokerPipeName, `
        $BrokerAuthKeyPath, $ProviderLibraryPath, $BrokerLogPath
    $guardianImage = '"{0}" enterprise hooks watch --manifest "{1}" --interval 1m' -f $GatewayPath, $ManifestPath
    # Spec 005 D1: third SCM service reuses the gateway binary, invoked
    # with the `enterprise windows enumerate` subcommand. Runs as
    # LocalSystem with the same privilege set as the guardian (needs
    # SeImpersonatePrivilege to walk per-user profile trees; SeBackupPrivilege
    # / SeRestorePrivilege for cross-user ACL work); SidType unrestricted so
    # the virtual NT SERVICE\<name> SID is available for future DACL work
    # without shipping a fourth ACE today (targets.yaml's existing AdminFile
    # ACL grants SYSTEM full-control, which covers LocalSystem writes).
    $enumeratorImage = '"{0}" enterprise windows enumerate --manifest "{1}" --interval 5m' -f $GatewayPath, $ManifestPath
    # Transaction-created or reconfigured services remain disabled while
    # protected state and binaries are being mutated. Demand start is not
    # sufficient: SCM may still execute an already queued failure restart.
    $configuredStart = if ($DeferAutomaticStart) { 'disabled' } else { 'auto' }

    Assert-DefenseClawCMIDBrokerServiceOrAbsent `
        -Name $BrokerServiceName `
        -ExpectedImage $brokerImage `
        -AllowArgumentUpgrade
    if (Test-DefenseClawServiceExists -Name $BrokerServiceName) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $BrokerServiceName,
            'binPath=', $brokerImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Credential Broker'
        ))
    }
    else {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $BrokerServiceName,
            'binPath=', $brokerImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Credential Broker'
        ))
    }
    Assert-DefenseClawServiceImagePath -Name $BrokerServiceName -ExpectedImage $brokerImage

    if (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $GatewayServiceName,
            'binPath=', $gatewayImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', $BrokerServiceName,
            'obj=', $gatewayAccount,
            'DisplayName=', 'DefenseClaw Enterprise Gateway'
        ))
    }
    else {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $GatewayServiceName,
            'binPath=', $gatewayImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', $BrokerServiceName,
            'obj=', $gatewayAccount,
            'DisplayName=', 'DefenseClaw Enterprise Gateway'
        ))
    }
    Assert-DefenseClawServiceImagePath `
        -Name $GatewayServiceName `
        -ExpectedImage $gatewayImage
    if (Test-DefenseClawServiceExists -Name $GuardianServiceName) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $GuardianServiceName,
            'binPath=', $guardianImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Enterprise Hook Guardian'
        ))
    }
    else {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $GuardianServiceName,
            'binPath=', $guardianImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Enterprise Hook Guardian'
        ))
    }
    Assert-DefenseClawServiceImagePath `
        -Name $GuardianServiceName `
        -ExpectedImage $guardianImage
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6atyfV): authenticate an
    # existing enumerator BEFORE reconfiguring it, mirroring the
    # ownership check the uninstall path already does. Without this,
    # a foreign process that pre-registered a service with the exact
    # DefenseClawHookEnumerator name would have its ImagePath +
    # ObjectName silently rewritten. Assert-DefenseClawOwnedService-
    # OrAbsent refuses foreign ownership; a matching or absent
    # service proceeds through the create-or-config branch below.
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $enumeratorServiceName `
        -ExpectedGatewayPath $GatewayPath `
        -ExpectedManifestPath $ManifestPath `
        -Enumerator
    if (Test-DefenseClawServiceExists -Name $enumeratorServiceName) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $enumeratorServiceName,
            'binPath=', $enumeratorImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Enterprise Hook Enumerator'
        ))
    }
    else {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'create', $enumeratorServiceName,
            'binPath=', $enumeratorImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
            'obj=', 'LocalSystem',
            'DisplayName=', 'DefenseClaw Enterprise Hook Enumerator'
        ))
    }
    Assert-DefenseClawServiceImagePath `
        -Name $enumeratorServiceName `
        -ExpectedImage $enumeratorImage

    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $GatewayServiceName, 'restricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $BrokerServiceName, 'unrestricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $GuardianServiceName, 'unrestricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $enumeratorServiceName, 'unrestricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $GatewayServiceName, 'SeChangeNotifyPrivilege'
    ))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $BrokerServiceName, 'SeChangeNotifyPrivilege'
    ))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $GuardianServiceName,
        'SeTcbPrivilege/SeImpersonatePrivilege/SeChangeNotifyPrivilege/SeBackupPrivilege/SeRestorePrivilege'
    ))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $enumeratorServiceName,
        'SeTcbPrivilege/SeImpersonatePrivilege/SeChangeNotifyPrivilege/SeBackupPrivilege/SeRestorePrivilege'
    ))
    foreach ($service in @($BrokerServiceName, $GatewayServiceName, $GuardianServiceName, $enumeratorServiceName)) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'failure', $service,
            'reset=', '86400',
            'actions=', 'restart/5000/restart/15000/restart/60000'
        ))
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('failureflag', $service, '1'))
        Set-DefenseClawExactFailureActions -Name $service
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sdset', $service, $script:ServiceSDDL))
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'description', $service,
            $script:ServiceDescription
        ))
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
        [void](Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $key -Name DelayedAutoStart -PropertyType DWord -Value 0 -Force)
        Set-DefenseClawServiceRegistryAcl -Name $service
    }

    Set-DefenseClawCMIDBrokerAuthKey `
        -Path $BrokerAuthKeyPath `
        -GatewayServiceName $GatewayServiceName
    Microsoft.PowerShell.Management\Remove-ItemProperty `
        -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$BrokerServiceName" `
        -Name Environment `
        -ErrorAction SilentlyContinue

    Set-DefenseClawServiceEnvironment `
        -Name $GatewayServiceName `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $GatewayLogPath `
        -BrokerPipeName $BrokerPipeName `
        -BrokerServiceName $BrokerServiceName `
        -BrokerAuthKeyPath $BrokerAuthKeyPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified
    Set-DefenseClawServiceEnvironment `
        -Name $GuardianServiceName `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $GuardianLogPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified
    # Spec 005 D1: the enumerator shares the guardian's log directory
    # via GuardianLogPath — one hook-guardian log surface holds every
    # guardian + enumerator line, matching macOS's shared
    # hook-enumerator.log convention. A follow-up may split the paths
    # if operator log-scraping needs separate surfaces.
    Set-DefenseClawServiceEnvironment `
        -Name $enumeratorServiceName `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $GuardianLogPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified
}

function Get-DefenseClawServiceStartMode {
    param([Parameter(Mandatory)][string]$Name)
    Assert-DefenseClawServiceName -Name $Name
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        return 0
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $start = [int](
        Microsoft.PowerShell.Management\Get-ItemPropertyValue `
            -LiteralPath $key `
            -Name Start
    )
    if ($start -notin @(2, 3, 4)) {
        throw "service $Name has unsupported startup mode $start"
    }
    return $start
}

function Set-DefenseClawServiceStartMode {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet(2, 3, 4)]
        [int]$StartMode
    )
    Assert-DefenseClawServiceName -Name $Name
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        throw "cannot set startup mode for missing Windows service $Name"
    }
    $token = switch ($StartMode) {
        2 { 'auto' }
        3 { 'demand' }
        4 { 'disabled' }
    }
    [void](Invoke-DefenseClawNative `
        -File $script:ScExe `
        -Arguments @('config', $Name, 'start=', $token))
    $actual = Get-DefenseClawServiceStartMode -Name $Name
    if ($actual -ne $StartMode) {
        throw "service $Name startup mode is $actual, expected $StartMode"
    }
}

function ConvertFrom-DefenseClawServiceQuiescenceTimestamp {
    param([Parameter(Mandatory)]$Value)
    if ($null -eq $Value -or
        [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw 'service quiescence timestamp is missing'
    }
    if ($Value -is [DateTime]) {
        # PowerShell 7 may materialize ISO JSON strings as DateTime values.
        # Preserve Kind before any culture-sensitive string conversion.
        $timestamp = ([DateTime]$Value).ToUniversalTime()
    }
    else {
        try {
            $timestamp = [DateTime]::Parse(
                [string]$Value,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).ToUniversalTime()
        }
        catch {
            throw "service quiescence timestamp is invalid: $Value"
        }
    }
    if ($timestamp -gt [DateTime]::UtcNow.AddSeconds(5)) {
        throw "service quiescence timestamp is unexpectedly in the future: $Value"
    }
    return $timestamp
}

function Get-DefenseClawGuardianGeneration {
    # Returns state.updated_at, or $null when the report carries no state.
    # StrictMode throws on a missing property, so absence is probed on the
    # property set. PowerShell 7 materializes the ISO string as a DateTime, whose
    # [string] form is local-culture and drops the UTC designator.
    param($Report)
    if ($null -eq $Report -or $null -eq $Report.PSObject.Properties['state']) {
        return $null
    }
    $state = $Report.state
    if ($null -eq $state -or $null -eq $state.PSObject.Properties['updated_at']) {
        return $null
    }
    $value = $state.updated_at
    if ($null -eq $value) {
        return $null
    }
    if ($value -is [DateTime]) {
        return ([DateTime]$value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return [string]$value
}

function Wait-DefenseClawServiceFailureRestartQuiescence {
    param(
        [Parameter(Mandatory)][string]$ServicesQuiescedAt,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $quiescedAt = ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
        -Value $ServicesQuiescedAt
    $deadline = $quiescedAt.AddSeconds(
        $script:ServiceFailureRestartQuiescenceSeconds
    )
    $remainingMilliseconds = [Math]::Min(
        $script:ServiceFailureRestartQuiescenceSeconds * 1000,
        [Math]::Max(
            0,
            [int64][Math]::Ceiling(
                ($deadline - [DateTime]::UtcNow).TotalMilliseconds
            )
        )
    )
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $remainingMilliseconds) {
        $remaining = (
            $remainingMilliseconds - $stopwatch.ElapsedMilliseconds
        )
        $milliseconds = [Math]::Min(
            250,
            [Math]::Max(1, [int]$remaining)
        )
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $milliseconds
    }
    $stopwatch.Stop()
    # Reassert the fail-closed state after the full 60-second canonical
    # failure-action window plus safety margin. Every restart queued before
    # quiescence has now attempted against a disabled service and drained.
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    foreach ($name in @($GatewayServiceName, $BrokerServiceName, $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($GuardianServiceName, $GatewayServiceName, $brokerServiceName)) {
        Stop-DefenseClawService -Name $name
    }
}

function Set-DefenseClawServiceActivationPhase {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [ValidateSet('quiesced', 'activating')]
        [string]$Phase,
        [string]$ServicesQuiescedAt
    )
    $phaseProperty = $State.PSObject.Properties[
        'service_activation_phase'
    ]
    if ($null -eq $phaseProperty) {
        $State |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name service_activation_phase `
                -Value $Phase
    }
    else {
        $phaseProperty.Value = $Phase
    }
    $timestampValue = if ($Phase -eq 'activating') {
        # Invalidate durable elapsed-time credit before the first startable
        # transition. A crash in this phase must establish a fresh barrier.
        ''
    }
    else {
        [void](ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
            -Value $ServicesQuiescedAt)
        $ServicesQuiescedAt
    }
    $timestampProperty = $State.PSObject.Properties[
        'services_disabled_and_stopped_at'
    ]
    if ($null -eq $timestampProperty) {
        $State |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name services_disabled_and_stopped_at `
                -Value $timestampValue
    }
    else {
        $timestampProperty.Value = $timestampValue
    }
    Write-DefenseClawJsonAtomic -Value $State -Path $Path
}

function Get-DefenseClawTransactionServiceStartMode {
    param([Parameter(Mandatory)]$Service)
    $existed = $Service.PSObject.Properties['existed']
    $startMode = $Service.PSObject.Properties['start_mode']
    if ($null -eq $existed -or $existed.Value -isnot [bool]) {
        throw 'transaction service has invalid existence state'
    }
    if (-not [bool]$existed.Value) {
        if ($null -ne $startMode -and (
                $startMode.Value -is [bool] -or
                [Convert]::ToInt32($startMode.Value) -ne 0
            )) {
            throw 'transaction records a startup mode for an absent service'
        }
        return 0
    }
    $mode = if ($null -eq $startMode) {
        # Backward compatibility for snapshots created before explicit
        # boot-safety state was recorded; canonical managed services were
        # required to be automatic at transaction entry.
        2
    }
    else {
        if ($startMode.Value -is [bool]) {
            throw 'transaction service has invalid startup mode'
        }
        [Convert]::ToInt32($startMode.Value)
    }
    if ($mode -notin @(2, 3, 4)) {
        throw "transaction service has unsupported startup mode $mode"
    }
    return $mode
}

function Get-DefenseClawTransactionServiceStates {
    param(
        [Parameter(Mandatory)]$Services,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6atyfZ): derive the enumerator's
    # service name from the guardian's — same shape as the
    # transaction-open snapshot builder above. Transaction snapshots
    # written by pre-spec-005 psm1 versions have only 2 services;
    # loading such a snapshot on a post-spec-005 host is expected
    # during an upgrade window, so the "missing enumerator state"
    # check below is a WARN (rather than throw) that treats the
    # enumerator as absent. Post-upgrade transactions always carry
    # all 3.
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    $states = @{}
    foreach ($service in @($Services)) {
        $nameProperty = $service.PSObject.Properties['name']
        $runningProperty = $service.PSObject.Properties['running']
        if ($null -eq $nameProperty -or
            $null -eq $runningProperty -or
            $runningProperty.Value -isnot [bool]) {
            throw 'transaction service has invalid identity or running state'
        }
        $name = [string]$nameProperty.Value
        $canonicalName = @(
            $GatewayServiceName,
            $brokerServiceName,
            $GuardianServiceName,
            $enumeratorServiceName
        ) | Microsoft.PowerShell.Core\Where-Object {
            [string]::Equals(
                $_,
                $name,
                [StringComparison]::OrdinalIgnoreCase
            )
        }
        if (@($canonicalName).Count -ne 1 -or $states.ContainsKey($name)) {
            throw 'transaction contains an unexpected or duplicate service state'
        }
        $mode = Get-DefenseClawTransactionServiceStartMode -Service $service
        if ([bool]$runningProperty.Value -and $mode -eq 0) {
            throw "transaction marks absent service $name as running"
        }
        $states[[string]@($canonicalName)[0]] = [pscustomobject]@{
            service = $service
            existed = ($mode -ne 0)
            running = [bool]$runningProperty.Value
            start_mode = [int]$mode
        }
    }
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if (-not $states.ContainsKey($name)) {
            throw "transaction is missing service state for $name"
        }
    }
    # Enumerator is spec-005-new. A pre-spec-005 transaction snapshot
    # will not carry it; synthesise an "absent" entry so callers
    # (Restore-DefenseClawTransactionServiceStartModes) can iterate
    # all three service names uniformly. Post-spec-005 snapshots
    # always contain the entry, and Get-DefenseClawTransactionService-
    # StartMode's absence guard already rejects a running-but-absent
    # combination.
    if (-not $states.ContainsKey($enumeratorServiceName)) {
        $states[$enumeratorServiceName] = [pscustomobject]@{
            service = [pscustomobject]@{
                name = $enumeratorServiceName
                existed = $false
                running = $false
                start_mode = 0
            }
            existed = $false
            running = $false
            start_mode = 0
        }
    }
    if (-not $states.ContainsKey($brokerServiceName)) {
        $states[$brokerServiceName] = [pscustomobject]@{
            service = [pscustomobject]@{
                name = $brokerServiceName
                existed = $false
                running = $false
                start_mode = 0
            }
            existed = $false
            running = $false
            start_mode = 0
        }
    }
    return $states
}

function Restore-DefenseClawTransactionServiceStartModes {
    param(
        [Parameter(Mandatory)]$Services,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $states = Get-DefenseClawTransactionServiceStates `
        -Services $Services `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6atyfZ): restore the enumerator's
    # recorded start mode too, so a rollback returns all three
    # services to their pre-transaction posture. Order: guardian →
    # gateway (existing, preserves the boot-safety invariant that
    # gateway cannot be automatic while guardian is demand-start)
    # → enumerator LAST because enumerator's readiness depends on
    # gateway + guardian being back to their target boot mode; a
    # crash mid-restore leaves enumerator disabled which is a safe
    # posture (no targets.yaml writes until the next transaction).
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    foreach ($name in @($brokerServiceName, $GuardianServiceName, $GatewayServiceName, $enumeratorServiceName)) {
        $state = $states[$name]
        if ($null -ne $state -and [bool]$state.existed) {
            Set-DefenseClawServiceStartMode `
                -Name $name `
                -StartMode ([int]$state.start_mode)
        }
    }
}

function Initialize-DefenseClawManagedIPCDirectory {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    $gatewaySID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    $expectedIPCDirectory = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw',
        'ipc'
    ).TrimEnd('\')
    $ipcDirectory = Assert-DefenseClawCanonicalVolumePath `
        -Path ([IO.Path]::GetFullPath([string]$Layout.ManagedIPCDirectory).TrimEnd('\')) `
        -Label 'managed IPC directory'
    if (-not [string]::Equals(
            $ipcDirectory,
            $expectedIPCDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "managed IPC directory must use the fixed AVC contract path: $expectedIPCDirectory"
    }
    Assert-DefenseClawNoReparsePath -Path $ipcDirectory -AllowMissingLeaf
    $parent = [IO.Path]::GetDirectoryName($ipcDirectory)
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $parent `
            -PathType Container)) {
        Initialize-DefenseClawManagedRoot `
            -Path $parent `
            -Label 'managed IPC parent' `
            -RequiredBase $script:ProgramData
    }
    else {
        Assert-DefenseClawTrustedAncestors `
            -Path $parent `
            -RequiredBase $script:ProgramData
    }

    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $ipcDirectory) {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $ipcDirectory `
                -PathType Container)) {
            throw "managed IPC path is occupied by a non-directory: $ipcDirectory"
        }
        # The fixed AVC path is a single-listener contract. Validate before
        # replacement so a certification service cannot seize a directory
        # owned by another live gateway SID. The current service is accepted
        # as owner for migration from a directory it created itself.
        Assert-DefenseClawPathAcl `
            -Path $ipcDirectory `
            -AllowedWriterSIDs @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID,
                $gatewaySID
            ) `
            -AllowedReaderSIDs @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID,
                $gatewaySID,
                $script:AuthenticatedUsersSID
            ) `
            -AllowedOwnerSIDs @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID,
                $gatewaySID
            ) `
            -RejectUntrustedRead
    }
    else {
        [void](New-DefenseClawProtectedDirectory -Path $ipcDirectory)
    }
    Set-DefenseClawPathAcl `
        -Path $ipcDirectory `
        -Kind ManagedIPCDirectory `
        -GatewayServiceSID $gatewaySID
}

# Remove only ACEs that name the retired gateway SID. The shared IPC path can
# carry permissions owned by another product or deployment, so reconstructing
# it from this installation's canonical ACL would incorrectly discard foreign
# state. Work on a raw descriptor to preserve every non-matching ACE byte for
# byte, including ACE types that FileSystemSecurity does not project cleanly.
function Remove-DefenseClawSIDFromRawDACL {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory)][string]$SID
    )
    try {
        $targetSID = [Security.Principal.SecurityIdentifier]::new($SID)
    }
    catch {
        throw "managed IPC cleanup received an invalid service SID: $SID"
    }
    if (-not $targetSID.Value.StartsWith(
            'S-1-5-80-',
            [StringComparison]::Ordinal
        )) {
        throw "managed IPC cleanup SID is outside the NT SERVICE authority: $SID"
    }
    if ($null -eq $Descriptor.DiscretionaryAcl) {
        throw 'managed IPC directory has an absent or null DACL'
    }
    $bytes = [byte[]]::new($Descriptor.BinaryLength)
    $Descriptor.GetBinaryForm($bytes, 0)
    $updated = [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
    $matchingIndexes = [Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $updated.DiscretionaryAcl.Count; $index++) {
        $ace = $updated.DiscretionaryAcl[$index]
        if ($ace -isnot [Security.AccessControl.KnownAce] -or
            $null -eq $ace.SecurityIdentifier -or
            $ace.SecurityIdentifier.Value -cne $targetSID.Value) {
            continue
        }
        $matchingIndexes.Add($index)
    }
    if ($matchingIndexes.Count -eq 0) {
        return [pscustomobject]@{
            descriptor = $updated
            removed = 0
        }
    }
    if ($matchingIndexes.Count -ne 1) {
        throw "managed IPC directory has duplicate ACEs for the retired gateway SID: $SID"
    }
    $matchingAce = $updated.DiscretionaryAcl[$matchingIndexes[0]]
    $fullControlMask = [int](
        [Security.AccessControl.FileSystemRights]::FullControl
    )
    if ($matchingAce -isnot [Security.AccessControl.CommonAce] -or
        $matchingAce.AceQualifier -ne
            [Security.AccessControl.AceQualifier]::AccessAllowed -or
        $matchingAce.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
        [int]$matchingAce.AccessMask -ne $fullControlMask -or
        [bool]$matchingAce.IsCallback -or
        [int]$matchingAce.OpaqueLength -ne 0) {
        throw (
            'managed IPC directory has a non-canonical ACE for the retired ' +
            "gateway SID: $SID"
        )
    }
    $updated.DiscretionaryAcl.RemoveAce($matchingIndexes[0])
    return [pscustomobject]@{
        descriptor = $updated
        removed = 1
    }
}

function Assert-DefenseClawTransactionIPCServiceBoundary {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    if ([string]::IsNullOrWhiteSpace($GatewayServiceSID)) {
        throw 'transaction IPC cleanup requires its captured gateway service SID'
    }
    if (-not (Test-DefenseClawServiceExists -Name $GatewayServiceName)) {
        throw (
            'transaction IPC cleanup requires the matching stopped service: ' +
            $GatewayServiceName
        )
    }
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath ([string]$Layout.GatewayPath)
    $actualSID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    if ($actualSID -cne $GatewayServiceSID) {
        throw (
            'transaction IPC cleanup gateway SID changed after capture for ' +
            $GatewayServiceName
        )
    }
    if ((Get-DefenseClawServiceStartMode -Name $GatewayServiceName) -ne 4) {
        throw "transaction IPC cleanup requires a disabled gateway service: $GatewayServiceName"
    }
    $service = Microsoft.PowerShell.Management\Get-Service `
        -Name $GatewayServiceName `
        -ErrorAction Stop
    if ($service.Status -ne
        [ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw "transaction IPC cleanup requires a stopped gateway service: $GatewayServiceName"
    }
    return $actualSID
}

function Resolve-DefenseClawRetiredGatewayServiceSID {
    param(
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [string]$GatewayServiceSID
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    if (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
        throw (
            'refusing retired gateway SID resolution while the matching ' +
            "service exists: $GatewayServiceName"
        )
    }
    $resolvedSID = Get-DefenseClawServiceSIDForRecovery `
        -ServiceName $GatewayServiceName
    if (-not [string]::IsNullOrWhiteSpace($GatewayServiceSID) -and
        $GatewayServiceSID -cne $resolvedSID) {
        throw (
            'captured and deterministic gateway service SIDs disagree during ' +
            "committed cleanup for $GatewayServiceName"
        )
    }
    return $resolvedSID
}

function Assert-DefenseClawManagedIPCRetirementDescriptor {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory)][string]$Path
    )
    $protectedFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    if (([int]$Descriptor.ControlFlags -band $protectedFlag) -eq 0) {
        throw "managed IPC cleanup refused an inherited DACL: $Path"
    }
    $allowedOwners = @(
        $script:SystemSID,
        $script:AdministratorsSID,
        $script:TrustedInstallerSID
    )
    if ($null -eq $Descriptor.Owner -or
        $Descriptor.Owner.Value -notin $allowedOwners) {
        throw "managed IPC cleanup refused an untrusted owner: $Path"
    }
    if ($null -eq $Descriptor.Group -or
        $Descriptor.Group.Value -notin $allowedOwners) {
        throw "managed IPC cleanup refused an untrusted group: $Path"
    }
}

function Revoke-DefenseClawManagedIPCServiceAccess {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [string]$GatewayServiceSID,
        [switch]$TransactionCreatedServicePresent
    )
    $resolvedSID = if ($TransactionCreatedServicePresent) {
        Assert-DefenseClawTransactionIPCServiceBoundary `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GatewayServiceSID $GatewayServiceSID
    }
    else {
        Resolve-DefenseClawRetiredGatewayServiceSID `
            -GatewayServiceName $GatewayServiceName `
            -GatewayServiceSID $GatewayServiceSID
    }

    $expectedIPCDirectory = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw',
        'ipc'
    ).TrimEnd('\')
    $ipcDirectory = Assert-DefenseClawCanonicalVolumePath `
        -Path ([IO.Path]::GetFullPath(
            [string]$Layout.ManagedIPCDirectory
        ).TrimEnd('\')) `
        -Label 'managed IPC directory cleanup'
    if (-not [string]::Equals(
            $ipcDirectory,
            $expectedIPCDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "managed IPC cleanup requires the fixed AVC contract path: $expectedIPCDirectory"
    }
    Assert-DefenseClawNoReparsePath -Path $ipcDirectory -AllowMissingLeaf
    Assert-DefenseClawTrustedAncestors `
        -Path ([IO.Path]::GetDirectoryName($ipcDirectory)) `
        -RequiredBase $script:ProgramData

    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    # This final-component OPEN_REPARSE_POINT call is the sole absence proof.
    # A dangling reparse point opens as an object and is rejected by the native
    # directory validator instead of being mistaken for a missing path.
    $before = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
        $ipcDirectory
    )
    if ($null -eq $before) {
        if ($TransactionCreatedServicePresent) {
            [void](Assert-DefenseClawTransactionIPCServiceBoundary `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GatewayServiceSID $resolvedSID)
        }
        elseif (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
            throw (
                'refusing managed IPC permission cleanup because the matching ' +
                "gateway service reappeared: $GatewayServiceName"
            )
        }
        return $false
    }
    $beforeDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        [byte[]]$before.SecurityDescriptor,
        0
    )
    Assert-DefenseClawManagedIPCRetirementDescriptor `
        -Descriptor $beforeDescriptor `
        -Path $ipcDirectory

    $filtered = Remove-DefenseClawSIDFromRawDACL `
        -Descriptor $beforeDescriptor `
        -SID $resolvedSID
    # Resolve the service boundary again immediately before the pinned-handle
    # update or idempotent return. Normal lifecycle operations are serialized
    # by the global lock; this second check fails closed on an out-of-band SCM
    # recreation.
    if ($TransactionCreatedServicePresent) {
        [void](Assert-DefenseClawTransactionIPCServiceBoundary `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GatewayServiceSID $resolvedSID)
    }
    elseif (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
        throw (
            'refusing managed IPC permission cleanup because the matching ' +
            "gateway service reappeared: $GatewayServiceName"
        )
    }
    if ([int]$filtered.removed -eq 0) {
        return $false
    }
    $expectedDescriptor = [Security.AccessControl.RawSecurityDescriptor](
        $filtered.descriptor
    )
    $expectedBytes = [byte[]]::new($expectedDescriptor.BinaryLength)
    $expectedDescriptor.GetBinaryForm($expectedBytes, 0)
    $after = $nativeSecurity::SetDirectoryDaclNoFollow(
        $ipcDirectory,
        $expectedBytes,
        [string]$before.Identity
    )
    if ([string]$after.Identity -cne [string]$before.Identity) {
        throw "managed IPC directory identity changed during cleanup: $ipcDirectory"
    }
    $afterDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        [byte[]]$after.SecurityDescriptor,
        0
    )
    if ($null -eq $afterDescriptor.Owner -or
        $null -eq $afterDescriptor.Group -or
        $afterDescriptor.Owner.Value -cne $expectedDescriptor.Owner.Value -or
        $afterDescriptor.Group.Value -cne $expectedDescriptor.Group.Value -or
        -not (Test-DefenseClawExactRawDACL `
            -Actual $afterDescriptor `
            -Expected $expectedDescriptor)) {
        throw "managed IPC directory did not retain the exact filtered descriptor: $ipcDirectory"
    }

    # Rebind the path once after releasing the mutation handle. This cannot
    # prevent an administrator from changing it later, but it ensures this
    # successful cleanup result still names the exact inode that was updated.
    $published = $nativeSecurity::GetDirectorySecuritySnapshotNoFollow(
        $ipcDirectory
    )
    if ([string]$published.Identity -cne [string]$before.Identity) {
        throw "managed IPC directory changed after cleanup: $ipcDirectory"
    }
    $publishedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        [byte[]]$published.SecurityDescriptor,
        0
    )
    if ($null -eq $publishedDescriptor.Owner -or
        $null -eq $publishedDescriptor.Group -or
        $publishedDescriptor.Owner.Value -cne $expectedDescriptor.Owner.Value -or
        $publishedDescriptor.Group.Value -cne $expectedDescriptor.Group.Value -or
        -not (Test-DefenseClawExactRawDACL `
            -Actual $publishedDescriptor `
            -Expected $expectedDescriptor)) {
        throw "managed IPC directory descriptor changed after cleanup: $ipcDirectory"
    }
    if ($TransactionCreatedServicePresent) {
        [void](Assert-DefenseClawTransactionIPCServiceBoundary `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GatewayServiceSID $resolvedSID)
    }
    elseif (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
        throw (
            'managed IPC permission cleanup completed while the matching ' +
            "gateway service reappeared: $GatewayServiceName"
        )
    }
    return $true
}

function Set-DefenseClawManagedAcls {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [switch]$SkipCodexMachineState
    )
    $gatewaySID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    Set-DefenseClawPathAcl -Path $Layout.InstallRoot -Kind ServiceInstallDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.BinDirectory -Kind ServiceInstallDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.LibexecDirectory -Kind InstallDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GatewayPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GatewayPath -Kind ServiceInstallFile -GatewayServiceSID $gatewaySID
    }
    foreach ($path in @($Layout.BrokerPath, $Layout.HookPath, $Layout.InstallerPath, $Layout.ModulePath)) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf) {
            Set-DefenseClawPathAcl -Path $path -Kind InstallFile -GatewayServiceSID $gatewaySID
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.CLIPath -Kind InstallFile -GatewayServiceSID $gatewaySID
    }
    foreach ($ancestor in @($Layout.StateRootAncestors)) {
        Grant-DefenseClawStateAncestorTraverse -Path $ancestor -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.ManagedIPCDirectory `
            -PathType Container) {
        Set-DefenseClawPathAcl `
            -Path $Layout.ManagedIPCDirectory `
            -Kind ManagedIPCDirectory `
            -GatewayServiceSID $gatewaySID
    }
    elseif (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.ManagedIPCDirectory) {
        throw "managed IPC path is occupied by a non-directory: $($Layout.ManagedIPCDirectory)"
    }
    Set-DefenseClawPathAcl -Path $Layout.StateRoot -Kind StateDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ConfigDirectory -Kind ConfigDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GuardianDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.InstallStateDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ManifestPath -Kind AdminFile -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.RuntimeDirectory -Kind RuntimeDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.BrokerStateDirectory -Kind AuthorizationDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.AuthorizationDirectory -Kind AuthorizationDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.AuthorizationLedgerPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.AuthorizationLedgerPath -Kind AuthorizationFile -GatewayServiceSID $gatewaySID
    }
    Set-DefenseClawPathAcl -Path $Layout.LogDirectory -Kind LogDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GatewayLogDirectory -Kind GatewayLogDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GuardianLogDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.BrokerLogDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GatewayLogPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GatewayLogPath -Kind RuntimeFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GuardianLogPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GuardianLogPath -Kind AdminFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.BrokerLogPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.BrokerLogPath -Kind AdminFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.MetadataPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.MetadataPath -Kind AdminFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CodexRequirementsOwnershipPath -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexRequirementsOwnershipPath `
            -Kind AdminFile `
            -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CodexRequirementsAclBackupPath -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexRequirementsAclBackupPath `
            -Kind AdminFile `
            -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.AgentApplicationControlAttestationPath -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.AgentApplicationControlAttestationPath `
            -Kind AdminFile `
            -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.ManagedHooksTeardownJournalPath -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.ManagedHooksTeardownJournalPath `
            -Kind AdminFile `
            -GatewayServiceSID $gatewaySID
    }
    if (-not $SkipCodexMachineState -and
        [bool]$Layout.CodexTargetEnabled -and
        (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexMachinePolicyPath `
            -PathType Leaf)) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexMachinePolicyPath `
            -Kind MachinePolicyFile `
            -GatewayServiceSID $gatewaySID
    }
    if (-not $SkipCodexMachineState -and
        [bool]$Layout.CodexTargetEnabled -and
        (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexManagedHooksStatePath `
            -PathType Leaf)) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexManagedHooksStatePath `
            -Kind MachinePolicyFile `
            -GatewayServiceSID $gatewaySID
    }
}

# A non-purge uninstall intentionally retains runtime state with an
# administrator-only DACL. Before the replacement gateway starts, adopt every
# retained runtime object into the exact ACL for the newly registered gateway
# service SID. Preflight the whole tree before the first ACL change so a
# hostile reparse point or hard link cannot redirect, or partially trigger,
# the adoption pass.
function Set-DefenseClawRetainedRuntimeAcls {
    param(
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    $root = [IO.Path]::GetFullPath($RuntimeDirectory).TrimEnd('\')
    $redactionKeyPath = [IO.Path]::Combine(
        $root,
        'redaction-correlation.key'
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $root `
            -PathType Container)) {
        throw "retained runtime directory is missing or not a directory: $root"
    }
    Assert-DefenseClawNoReparsePath -Path $root

    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $directories = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $directories.Add($root)
    $pending.Push($root)
    [void]$seen.Add($root)
    $objectCount = 1
    $maximumObjectCount = 16384

    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        Assert-DefenseClawNoReparsePath -Path $directory
        foreach ($item in @(Microsoft.PowerShell.Management\Get-ChildItem `
                -LiteralPath $directory `
                -Force `
                -ErrorAction Stop)) {
            $full = Assert-DefenseClawDescendant `
                -Path $item.FullName `
                -Root $root `
                -Label 'retained runtime object'
            if (-not $seen.Add($full)) {
                throw "retained runtime tree contains a duplicate path: $full"
            }
            $objectCount++
            if ($objectCount -gt $maximumObjectCount) {
                throw (
                    'retained runtime tree exceeds the bounded adoption limit ' +
                    "of $maximumObjectCount objects"
                )
            }
            Assert-DefenseClawNoReparsePath -Path $full
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "refusing retained runtime reparse point: $full"
            }
            if ($item.PSIsContainer) {
                $directories.Add($full)
                $pending.Push($full)
                continue
            }
            $linkCount = [uint32]$nativeSecurity::GetRegularFileLinkCountNoFollow($full)
            if ($linkCount -ne 1) {
                throw "refusing retained runtime file with $linkCount hard links: $full"
            }
            $isRedactionKey = [string]::Equals(
                $full,
                $redactionKeyPath,
                [StringComparison]::OrdinalIgnoreCase
            )
            if ($isRedactionKey -and [int64]$item.Length -ne 32) {
                throw "retained redaction correlation key has an invalid fixed length: $full"
            }
            $files.Add([pscustomobject]@{
                path = $full
                identity = ([string]$nativeSecurity::GetFileIdentity($full)).ToLowerInvariant()
                kind = $(if ($isRedactionKey) {
                    'RuntimeSecretFile'
                }
                else {
                    'RuntimeFile'
                })
            })
        }
    }

    foreach ($directory in $directories) {
        Assert-DefenseClawNoReparsePath -Path $directory
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $directory `
                -PathType Container)) {
            throw "retained runtime directory changed during ACL adoption: $directory"
        }
        Set-DefenseClawPathAcl `
            -Path $directory `
            -Kind RuntimeDirectory `
            -GatewayServiceSID $GatewayServiceSID
    }
    foreach ($file in $files) {
        $path = [string]$file.path
        Assert-DefenseClawNoReparsePath -Path $path
        $identityBefore = ([string]$nativeSecurity::GetFileIdentity($path)).ToLowerInvariant()
        $linksBefore = [uint32]$nativeSecurity::GetRegularFileLinkCountNoFollow($path)
        if ($identityBefore -cne ([string]$file.identity) -or $linksBefore -ne 1) {
            throw "retained runtime file changed during ACL adoption: $path"
        }
        Set-DefenseClawPathAcl `
            -Path $path `
            -Kind ([string]$file.kind) `
            -GatewayServiceSID $GatewayServiceSID
        Assert-DefenseClawNoReparsePath -Path $path
        $identityAfter = ([string]$nativeSecurity::GetFileIdentity($path)).ToLowerInvariant()
        $linksAfter = [uint32]$nativeSecurity::GetRegularFileLinkCountNoFollow($path)
        if ($identityAfter -cne $identityBefore -or $linksAfter -ne 1) {
            throw "retained runtime file changed while its ACL was adopted: $path"
        }
    }
}

function New-DefenseClawLegacyRedactionKeyAcl {
    param(
        [Parameter(Mandatory)][string]$GatewayServiceSID,
        [string]$GroupSID = $script:AdministratorsSID
    )
    $legacy = [Security.AccessControl.FileSecurity]::new()
    $legacy.SetSecurityDescriptorSddlForm(
        ((
            'O:{0}G:{1}D:P(A;;FA;;;{0})' +
            '(A;;FA;;;SY)(A;;FA;;;BA)'
        ) -f $GatewayServiceSID, $GroupSID),
        [Security.AccessControl.AccessControlSections]::All
    )
    return $legacy
}

function Get-DefenseClawRedactionKeySecurityClass {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Actual,
        [string]$GatewayServiceSID
    )
    if ([string]::IsNullOrWhiteSpace($GatewayServiceSID)) {
        $adminExpected = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $false `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
        if (Test-DefenseClawCanonicalRawPathAcl `
                -Actual $Actual `
                -Expected $adminExpected) {
            return 'inactive_admin'
        }
        throw 'redaction correlation key has an unrecognized inactive ACL'
    }

    $secretExpected = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $false `
        -Kind RuntimeSecretFile `
        -GatewayServiceSID $GatewayServiceSID
    if (Test-DefenseClawCanonicalRawPathAcl `
            -Actual $Actual `
            -Expected $secretExpected) {
        return 'runtime_secret'
    }

    # Releases before the RuntimeSecretFile contract created the key with the
    # service as owner and exactly three FullControl ACEs. Group metadata was
    # not standardized, so it is deliberately excluded from this one strict
    # legacy matcher; it grants no access and is replaced during migration.
    $protectedFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    if ($null -ne $Actual.Owner -and
        $Actual.Owner.Value -ceq $GatewayServiceSID -and
        $null -ne $Actual.Group -and
        (([int]$Actual.ControlFlags -band $protectedFlag) -ne 0)) {
        $legacySecurity = New-DefenseClawLegacyRedactionKeyAcl `
            -GatewayServiceSID $GatewayServiceSID `
            -GroupSID $Actual.Group.Value
        $legacy = [Security.AccessControl.RawSecurityDescriptor]::new(
            $legacySecurity.GetSecurityDescriptorBinaryForm(),
            0
        )
        $legacyIgnoredFlags = [int](
            [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited -bor
            [Security.AccessControl.ControlFlags]::GroupDefaulted
        )
        if (Test-DefenseClawExactRawDACL `
                -Actual $Actual `
                -Expected $legacy `
                -IgnoredControlFlags $legacyIgnoredFlags) {
            return 'legacy_runtime_secret'
        }
    }

    # The repair defect in the immediately preceding builds rewrote this one
    # fixed leaf using the exact generic RuntimeFile contract. Accept only that
    # fully known form, then normalize it; arbitrary trusted-only ACLs remain
    # rejected.
    $brokenExpected = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $false `
        -Kind RuntimeFile `
        -GatewayServiceSID $GatewayServiceSID
    if (Test-DefenseClawCanonicalRawPathAcl `
            -Actual $Actual `
            -Expected $brokenExpected) {
        return 'broken_runtime_file'
    }
    throw 'redaction correlation key has an unrecognized active ACL'
}

function Get-DefenseClawRedactionKeySecuritySnapshot {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [string]$GatewayServiceSID
    )
    $path = [IO.Path]::GetFullPath(
        [string]$Layout.RedactionCorrelationKeyPath
    ).TrimEnd('\')
    $expectedPath = [IO.Path]::Combine(
        [IO.Path]::GetFullPath(
            [string]$Layout.RuntimeDirectory
        ).TrimEnd('\'),
        'redaction-correlation.key'
    )
    if (-not [string]::Equals(
            $path,
            $expectedPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'redaction correlation key path is outside its exact runtime location'
    }
    $restoreKind = if ([string]::IsNullOrWhiteSpace($GatewayServiceSID)) {
        'AdminFile'
    }
    else {
        'RuntimeSecretFile'
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $path `
            -PathType Leaf)) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) {
            throw 'redaction correlation key path is occupied by a non-file'
        }
        return [ordered]@{
            schema_version = 2
            path = $path
            existed = $false
            file_identity = ''
            preimage_class = 'absent'
            security_descriptor = ''
            restore_kind = $restoreKind
        }
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollow(
        $path,
        [uint32]32
    )
    $actual = [Security.AccessControl.RawSecurityDescriptor]::new(
        [byte[]]$captured.SecurityDescriptor,
        0
    )
    $preimageClass = Get-DefenseClawRedactionKeySecurityClass `
        -Actual $actual `
        -GatewayServiceSID $GatewayServiceSID
    return [ordered]@{
        schema_version = 2
        path = $path
        existed = $true
        file_identity = [string]$captured.Identity
        preimage_class = $preimageClass
        security_descriptor = $actual.GetSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
        restore_kind = $restoreKind
    }
}

function Restore-DefenseClawRedactionKeySecuritySnapshot {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $path = [IO.Path]::GetFullPath(
        [string]$Layout.RedactionCorrelationKeyPath
    ).TrimEnd('\')
    $priorGateway = @($Snapshot.services |
        Microsoft.PowerShell.Core\Where-Object {
            [string]::Equals(
                [string]$_.name,
                [string]$Snapshot.gateway_service,
                [StringComparison]::OrdinalIgnoreCase
            )
        })
    if ($priorGateway.Count -ne 1) {
        throw 'pending transaction has invalid prior gateway service metadata'
    }
    $priorGatewayExistedProperty = $priorGateway[0].PSObject.Properties[
        'existed'
    ]
    if ($null -eq $priorGatewayExistedProperty -or
        $priorGatewayExistedProperty.Value -isnot [bool]) {
        throw 'pending transaction has invalid prior gateway service metadata'
    }
    $priorGatewayExisted = [bool]$priorGateway[0].existed
    $priorDeploymentProperty = $Snapshot.PSObject.Properties[
        'prior_deployment_active'
    ]
    $priorDeploymentActive = if ($null -eq $priorDeploymentProperty) {
        # Compatibility for older pending snapshots, which could only
        # distinguish fresh/inactive state through service existence.
        $priorGatewayExisted
    }
    elseif ($priorDeploymentProperty.Value -isnot [bool]) {
        throw 'pending transaction has invalid prior deployment state'
    }
    else {
        [bool]$priorDeploymentProperty.Value
    }
    if ($priorGatewayExisted -and -not $priorDeploymentActive) {
        throw 'pending transaction has a gateway service without an active deployment'
    }
    $property = $Snapshot.PSObject.Properties['redaction_key_security']
    if ($null -eq $property) {
        # Compatibility with pending transactions written before metadata-only
        # key snapshots. Normalize only a present fixed 32-byte leaf while the
        # staged/prior gateway SID still resolves; no key data is opened.
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $path `
                -PathType Leaf)) {
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) {
                throw 'redaction correlation key path is occupied by a non-file'
            }
            return
        }
        $nativeSecurity = Initialize-DefenseClawNativeSecurity
        $current = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollow(
            $path,
            [uint32]32
        )
        $currentRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$current.SecurityDescriptor,
            0
        )
        $compatibilityAdmin = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $false `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
        $currentIsAdmin = Test-DefenseClawCanonicalRawPathAcl `
            -Actual $currentRaw `
            -Expected $compatibilityAdmin
        if (-not $priorDeploymentActive -and $currentIsAdmin) {
            # Crash re-entry after the first rollback already produced the
            # exact retained-admin form and removed the staged service.
            return
        }
        $gatewaySID = Get-DefenseClawServiceSIDForRecovery `
            -ServiceName ([string]$Snapshot.gateway_service)
        if (-not $currentIsAdmin) {
            [void](Get-DefenseClawRedactionKeySecurityClass `
                -Actual $currentRaw `
                -GatewayServiceSID $gatewaySID)
        }
        $compatibilityACL = if ($priorDeploymentActive) {
            # A pre-metadata snapshot can restore an older gateway binary.
            # Recreate the exact legacy contract that binary understands;
            # successful forward repair will migrate it to RuntimeSecretFile.
            New-DefenseClawLegacyRedactionKeyAcl `
                -GatewayServiceSID $gatewaySID
        }
        else {
            $compatibilityAdmin
        }
        $compatibilityResult = $nativeSecurity::SetRegularFileSecurityDescriptorNoFollow(
            $path,
            $compatibilityACL.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ),
            [uint32]32,
            [string]$current.Identity
        )
        Assert-DefenseClawCanonicalRawPathAcl `
            -Path $path `
            -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$compatibilityResult.SecurityDescriptor,
                0
            )) `
            -Expected $compatibilityACL
        return
    }

    $recorded = $property.Value
    $requiredProperties = @(
        'schema_version',
        'path',
        'existed',
        'file_identity',
        'preimage_class',
        'security_descriptor',
        'restore_kind'
    )
    if ($null -eq $recorded) {
        throw 'pending transaction has invalid redaction-key security metadata'
    }
    foreach ($name in $requiredProperties) {
        if ($null -eq $recorded.PSObject.Properties[$name]) {
            throw 'pending transaction has incomplete redaction-key security metadata'
        }
    }
    if ([int]$recorded.schema_version -ne 2 -or
        $recorded.existed -isnot [bool]) {
        throw 'pending transaction has invalid redaction-key security metadata'
    }
    $recordedPath = [IO.Path]::GetFullPath(
        [string]$recorded.path
    ).TrimEnd('\')
    if (-not [string]::Equals(
            $recordedPath,
            $path,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'pending transaction records a different redaction-key path'
    }
    if ($null -eq $priorDeploymentProperty) {
        throw 'pending transaction omits prior deployment state for redaction-key metadata'
    }
    $expectedRestoreKind = if ($priorDeploymentActive) {
        'RuntimeSecretFile'
    }
    else {
        'AdminFile'
    }
    if ([string]$recorded.restore_kind -cne $expectedRestoreKind) {
        throw 'pending transaction has an invalid redaction-key restore class'
    }
    if (-not [bool]$recorded.existed) {
        if ([string]$recorded.preimage_class -cne 'absent' -or
            -not [string]::IsNullOrEmpty([string]$recorded.file_identity) -or
            -not [string]::IsNullOrEmpty(
                [string]$recorded.security_descriptor
            )) {
            throw 'absent redaction-key preimage unexpectedly contains metadata'
        }
    }
    elseif ([string]$recorded.file_identity -cnotmatch
            '^[0-9a-f]{8}:[0-9a-f]{16}$' -or
        [string]::IsNullOrWhiteSpace(
            [string]$recorded.security_descriptor
        )) {
        throw 'pending transaction has malformed redaction-key security metadata'
    }

    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $path `
            -PathType Leaf)) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) {
            throw 'redaction correlation key path is occupied by a non-file'
        }
        if ([bool]$recorded.existed) {
            throw 'redaction correlation key disappeared during lifecycle rollback'
        }
        return
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $current = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollow(
        $path,
        [uint32]32
    )
    $currentRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
        [byte[]]$current.SecurityDescriptor,
        0
    )
    $adminExpected = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $false `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    $currentIsAdmin = Test-DefenseClawCanonicalRawPathAcl `
        -Actual $currentRaw `
        -Expected $adminExpected

    if (-not [bool]$recorded.existed) {
        if (-not $priorDeploymentActive -and $currentIsAdmin) {
            # Crash re-entry after the first rollback already retained the key
            # safely. Runtime/audit state is intentionally retained too, so
            # deleting this key would destroy correlation continuity.
            return
        }
        $gatewaySID = Get-DefenseClawServiceSIDForRecovery `
            -ServiceName ([string]$Snapshot.gateway_service)
        $currentClass = if ($currentIsAdmin) {
            'inactive_admin'
        }
        else {
            Get-DefenseClawRedactionKeySecurityClass `
                -Actual $currentRaw `
                -GatewayServiceSID $gatewaySID
        }
        $allowedCurrentClasses = if ($priorDeploymentActive) {
            @('runtime_secret', 'legacy_runtime_secret')
        }
        else {
            @('runtime_secret')
        }
        if ([string]$currentClass -notin $allowedCurrentClasses) {
            throw 'transaction-created redaction key is not in its exact canonical form'
        }
        $retainedExpected = if ($priorDeploymentActive) {
            # A rollback may reactivate an older gateway binary, so retain the
            # new key in the strict legacy service-readable form it supports.
            New-DefenseClawLegacyRedactionKeyAcl `
                -GatewayServiceSID $gatewaySID
        }
        else {
            $adminExpected
        }
        $retained = $nativeSecurity::SetRegularFileSecurityDescriptorNoFollow(
            $path,
            $retainedExpected.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ),
            [uint32]32,
            [string]$current.Identity
        )
        Assert-DefenseClawCanonicalRawPathAcl `
            -Path $path `
            -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$retained.SecurityDescriptor,
                0
            )) `
            -Expected $retainedExpected
        return
    }

    if ([string]$current.Identity -cne [string]$recorded.file_identity) {
        throw 'redaction correlation key identity changed during lifecycle transaction'
    }
    try {
        $recordedRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
            [string]$recorded.security_descriptor
        )
    }
    catch {
        throw 'pending transaction has an invalid redaction-key security descriptor'
    }
    $gatewaySID = ''
    if ($priorDeploymentActive -or -not $currentIsAdmin) {
        $gatewaySID = Get-DefenseClawServiceSIDForRecovery `
            -ServiceName ([string]$Snapshot.gateway_service)
    }
    if (-not $currentIsAdmin) {
        [void](Get-DefenseClawRedactionKeySecurityClass `
            -Actual $currentRaw `
            -GatewayServiceSID $gatewaySID)
    }
    $recordedClass = if ($priorDeploymentActive) {
        Get-DefenseClawRedactionKeySecurityClass `
            -Actual $recordedRaw `
            -GatewayServiceSID $gatewaySID
    }
    else {
        Get-DefenseClawRedactionKeySecurityClass -Actual $recordedRaw
    }
    if ([string]$recordedClass -cne [string]$recorded.preimage_class) {
        throw 'pending transaction redaction-key preimage class does not match its descriptor'
    }

    # Existing-key rollback restores the exact authenticated descriptor, not
    # merely an equivalent modern form. The one exception is the proven broken
    # BA-owned RuntimeFile form: neither loader can restart with it, so restore
    # the exact older three-ACE service-owned compatibility contract.
    $expected = if ([string]$recordedClass -ceq 'broken_runtime_file') {
        New-DefenseClawLegacyRedactionKeyAcl `
            -GatewayServiceSID $gatewaySID
    }
    else {
        $recordedSecurity = [Security.AccessControl.FileSecurity]::new()
        $recordedSecurity.SetSecurityDescriptorSddlForm(
            [string]$recorded.security_descriptor,
            [Security.AccessControl.AccessControlSections]::All
        )
        $recordedSecurity
    }
    $restoreSDDL = $expected.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All
    )
    $restored = $nativeSecurity::SetRegularFileSecurityDescriptorNoFollow(
        $path,
        $restoreSDDL,
        [uint32]32,
        [string]$recorded.file_identity
    )
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $path `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$restored.SecurityDescriptor,
            0
        )) `
        -Expected $expected
}

function Set-DefenseClawManagedCoreAcls {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    Set-DefenseClawManagedAcls `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -SkipCodexMachineState
}

function Set-DefenseClawManagedServicesForTransaction {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    Set-DefenseClawManagedServices `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -BrokerServiceName $Layout.BrokerServiceName `
        -BrokerPath $Layout.BrokerPath `
        -BrokerPipeName $Layout.BrokerPipeName `
        -BrokerAuthKeyPath $Layout.BrokerAuthKeyPath `
        -ProviderLibraryPath $Layout.ProviderLibraryPath `
        -BrokerLogPath $Layout.BrokerLogPath `
        -GatewayPath $Layout.GatewayPath `
        -ManifestPath $Layout.ManifestPath `
        -RuntimeDirectory $Layout.RuntimeDirectory `
        -ConfigPath $Layout.ConfigPath `
        -AuthorizationDirectory $Layout.AuthorizationDirectory `
        -GatewayLogPath $Layout.GatewayLogPath `
        -GuardianLogPath $Layout.GuardianLogPath `
        -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
        -DeferAutomaticStart
    Initialize-DefenseClawManagedIPCDirectory `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName
    Set-DefenseClawRetainedRuntimeAcls `
        -RuntimeDirectory $Layout.RuntimeDirectory `
        -GatewayServiceSID (Get-DefenseClawServiceSID `
            -ServiceName $GatewayServiceName)
    Set-DefenseClawManagedCoreAcls `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName
}

function Get-DefenseClawLayout {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$StateRoot,
        [string]$GatewayServiceName = 'DefenseClawGateway',
        [string]$GuardianServiceName = 'DefenseClawHookGuardian',
        [string]$CertificationCodexHome,
        [switch]$CoreHardeningCertification,
        [switch]$AgentApplicationControlAttested
    )
    $fullInstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $fullStateRoot = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
    $certificationRunID = ''
    if ($GatewayServiceName -cmatch
        '^DefenseClawCertGateway_([a-f0-9]{10})$') {
        $certificationRunID = [string]$Matches[1]
        if ($GuardianServiceName -cne
            "DefenseClawCertGuardian_$certificationRunID") {
            throw 'certification service names must use the same exact run identifier'
        }
        $expectedInstallRoot = [IO.Path]::Combine(
            $script:ProgramFiles,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw-Cert',
            $certificationRunID
        ).TrimEnd('\')
        $expectedStateRoot = [IO.Path]::Combine(
            $script:ProgramData,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw-Cert',
            $certificationRunID
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $fullInstallRoot,
                $expectedInstallRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $fullStateRoot,
                $expectedStateRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'certification services require exact run-scoped managed ' +
                "roots: $expectedInstallRoot ; $expectedStateRoot"
            )
        }
    }
    elseif ($GuardianServiceName -cmatch
        '^DefenseClawCertGuardian_[a-f0-9]{10}$') {
        throw 'certification guardian service requires its exact certification gateway peer'
    }
    else {
        $expectedGatewayServiceName = 'DefenseClawGateway'
        $expectedGuardianServiceName = 'DefenseClawHookGuardian'
        if ($GatewayServiceName -cne $expectedGatewayServiceName -or
            $GuardianServiceName -cne $expectedGuardianServiceName) {
            throw (
                'non-certification enterprise lifecycle requires exact ' +
                'production service names: DefenseClawGateway ; ' +
                'DefenseClawHookGuardian'
            )
        }
        $expectedInstallRoot = [IO.Path]::Combine(
            $script:ProgramFiles,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw'
        ).TrimEnd('\')
        $expectedStateRoot = [IO.Path]::Combine(
            $script:ProgramData,
            'Cisco',
            'Cisco Secure Client',
            'DefenseClaw'
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $fullInstallRoot,
                $expectedInstallRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $fullStateRoot,
                $expectedStateRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'non-certification enterprise lifecycle requires exact ' +
                "production roots: $expectedInstallRoot ; $expectedStateRoot"
            )
        }
    }
    $bin = Microsoft.PowerShell.Management\Join-Path $InstallRoot 'bin'
    $libexec = Microsoft.PowerShell.Management\Join-Path $InstallRoot 'libexec'
    $configDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'etc'
    $guardianDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian'
    $brokerStateDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'cmid-broker'
    $installState = Microsoft.PowerShell.Management\Join-Path $StateRoot 'install'
    $logDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'logs'
    $gatewayLogDirectory = Microsoft.PowerShell.Management\Join-Path $logDirectory 'gateway'
    $brokerLogDirectory = Microsoft.PowerShell.Management\Join-Path $logDirectory 'cmid-broker'
    $guardianLogDirectory = Microsoft.PowerShell.Management\Join-Path $logDirectory 'guardian'
    $managedIPCDirectory = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw',
        'ipc'
    )
    $lifecycleLockDirectory = Microsoft.PowerShell.Management\Join-Path `
        $script:ProgramData `
        'Cisco\Cisco Secure Client\DefenseClaw-Lifecycle'
    $stateBoundary = $fullStateRoot + '\'
    $lifecycleBoundary = [IO.Path]::GetFullPath(
        $lifecycleLockDirectory
    ).TrimEnd('\') + '\'
    if ($stateBoundary.StartsWith(
            $lifecycleBoundary,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $lifecycleBoundary.StartsWith(
            $stateBoundary,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'StateRoot and the protected lifecycle receipt directory must be ' +
            "distinct non-nested trees: $StateRoot ; $lifecycleLockDirectory"
        )
    }
    $purgeScope = Get-DefenseClawStableScopeSHA256 -Values @(
        [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\'),
        [IO.Path]::GetFullPath($StateRoot).TrimEnd('\'),
        $GatewayServiceName,
        $GuardianServiceName
    )
    $selfUninstallReceiptPath = (
        Microsoft.PowerShell.Management\Join-Path `
            $lifecycleLockDirectory `
            "self-uninstall-$purgeScope.json"
    )
    $selfUninstallHelperPath = (
        Microsoft.PowerShell.Management\Join-Path `
            $lifecycleLockDirectory `
            "self-uninstall-$purgeScope.ps1"
    )
    $selfUninstallEnvironmentRoot = (
        Microsoft.PowerShell.Management\Join-Path `
            $lifecycleLockDirectory `
            "self-uninstall-$purgeScope.environment"
    )
    $codexVendorDirectory = Microsoft.PowerShell.Management\Join-Path $script:ProgramData 'OpenAI'
    $codexMachinePolicyDirectory = Microsoft.PowerShell.Management\Join-Path $codexVendorDirectory 'Codex'
    $runtimeDirectory = Microsoft.PowerShell.Management\Join-Path `
        $StateRoot `
        'runtime'
    return @{
        InstallRoot = $InstallRoot
        StateRoot = $StateRoot
        StateRootAncestors = (Get-DefenseClawManagedRootAncestors `
            -Root $fullStateRoot `
            -RequiredBase $script:ProgramData)
        BinDirectory = $bin
        LibexecDirectory = $libexec
        ConfigDirectory = $configDirectory
        RuntimeDirectory = $runtimeDirectory
        RedactionCorrelationKeyPath = (
            Microsoft.PowerShell.Management\Join-Path `
                $runtimeDirectory `
                'redaction-correlation.key'
        )
        ManagedIPCDirectory = $managedIPCDirectory
        ManagedIPCSocketPath = (Microsoft.PowerShell.Management\Join-Path $managedIPCDirectory 'defenseclaw_ipc.sock')
        BrokerStateDirectory = $brokerStateDirectory
        BrokerAuthKeyPath = (Microsoft.PowerShell.Management\Join-Path $brokerStateDirectory 'broker-auth.key')
        GuardianDirectory = $guardianDirectory
        AuthorizationDirectory = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian-state')
        AuthorizationLedgerPath = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian-state\protected_targets.json')
        LogDirectory = $logDirectory
        GatewayLogDirectory = $gatewayLogDirectory
        BrokerLogDirectory = $brokerLogDirectory
        GuardianLogDirectory = $guardianLogDirectory
        GatewayLogPath = (Microsoft.PowerShell.Management\Join-Path $gatewayLogDirectory 'gateway.log')
        BrokerLogPath = (Microsoft.PowerShell.Management\Join-Path $brokerLogDirectory 'cmid-broker.log')
        GuardianLogPath = (Microsoft.PowerShell.Management\Join-Path $guardianLogDirectory 'hook-guardian.log')
        InstallStateDirectory = $installState
        GatewayPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw-gateway.exe')
        BrokerPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw-cmid-broker.exe')
        BrokerServiceName = (Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName)
        BrokerPipeName = ('\\.\pipe\{0}' -f (Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName))
        ProviderLibraryPath = ''
        HookPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw-hook.exe')
        CLIPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw.exe')
        ConfigPath = (Microsoft.PowerShell.Management\Join-Path $configDirectory 'config.yaml')
        ManifestPath = (Microsoft.PowerShell.Management\Join-Path $guardianDirectory 'targets.yaml')
        InstallerPath = (Microsoft.PowerShell.Management\Join-Path $libexec 'install-enterprise.ps1')
        ModulePath = (Microsoft.PowerShell.Management\Join-Path $libexec 'DefenseClawEnterprise.psm1')
        MetadataPath = (Microsoft.PowerShell.Management\Join-Path $installState 'deployment.json')
        PendingPath = (Microsoft.PowerShell.Management\Join-Path $installState 'pending.json')
        TransactionsDirectory = (Microsoft.PowerShell.Management\Join-Path $installState 'transactions')
        LifecycleLockDirectory = $lifecycleLockDirectory
        LifecycleLockPath = (Microsoft.PowerShell.Management\Join-Path $lifecycleLockDirectory 'lifecycle.lock')
        PurgeScopeSHA256 = $purgeScope
        PurgeIntentPath = (
            Microsoft.PowerShell.Management\Join-Path `
                $lifecycleLockDirectory `
                "purge-$purgeScope.json"
        )
        InstallRollbackIntentPath = (
            Microsoft.PowerShell.Management\Join-Path `
                $lifecycleLockDirectory `
                "install-rollback-$purgeScope.json"
        )
        SelfUninstallReceiptPath = $selfUninstallReceiptPath
        SelfUninstallHelperPath = $selfUninstallHelperPath
        SelfUninstallEnvironmentRoot = $selfUninstallEnvironmentRoot
        CodexVendorDirectory = $codexVendorDirectory
        CodexMachinePolicyDirectory = $codexMachinePolicyDirectory
        CodexMachinePolicyPath = (Microsoft.PowerShell.Management\Join-Path $codexMachinePolicyDirectory 'requirements.toml')
        CodexManagedHooksDirectory = $bin
        CodexManagedHooksStatePath = (Microsoft.PowerShell.Management\Join-Path $codexMachinePolicyDirectory '.defenseclaw-managed-hooks.state')
        CodexManagedHooksLockPath = (Microsoft.PowerShell.Management\Join-Path $codexMachinePolicyDirectory '.defenseclaw-managed-hooks.lock')
        ClaudeManagedHooksLockPath = (
            Microsoft.PowerShell.Management\Join-Path `
                (Microsoft.PowerShell.Management\Join-Path `
                    (Microsoft.PowerShell.Management\Join-Path $script:ProgramFiles 'ClaudeCode') `
                    'managed-settings.d') `
                '.defenseclaw-managed-hooks.lock'
        )
        CodexRequirementsOwnershipPath = (Microsoft.PowerShell.Management\Join-Path $installState 'codex-requirements-ownership.json')
        CodexRequirementsAclBackupPath = (Microsoft.PowerShell.Management\Join-Path $installState 'codex-requirements-acl-backup.json')
        AgentApplicationControlAttestationPath = (Microsoft.PowerShell.Management\Join-Path $installState 'agent-application-control-attestation.json')
        ManagedHooksTeardownJournalPath = (Microsoft.PowerShell.Management\Join-Path $installState 'managed-hooks-teardown-journal.json')
        ManagedHooksLifecycleJournalPath = (Microsoft.PowerShell.Management\Join-Path $installState 'managed-hooks-lifecycle-journal.json')
        CoreHardeningCertification = [bool]$CoreHardeningCertification
        AgentApplicationControlAttested = [bool]$AgentApplicationControlAttested
        ClaudeEffectivePolicyVerified = $false
        ClaudeTargetEnabled = $false
        CodexTargetEnabled = $false
        CursorTargetEnabled = $false
        CertificationCodexHome = [string]$CertificationCodexHome
    }
}

function Assert-DefenseClawLayoutVolumeIdentity {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$AllowMissingCertificationCodexHome
    )
    $installRoot = Assert-DefenseClawSafeRoot `
        -Path ([string]$Layout.InstallRoot) `
        -Label 'InstallRoot' `
        -RequiredBase $script:ProgramFiles
    $stateRoot = Assert-DefenseClawSafeRoot `
        -Path ([string]$Layout.StateRoot) `
        -Label 'StateRoot' `
        -RequiredBase $script:ProgramData
    if (-not [string]::Equals(
            $installRoot,
            [string]$Layout.InstallRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $stateRoot,
            [string]$Layout.StateRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'managed layout roots changed during volume identity revalidation'
    }
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        $certificationHome = Resolve-DefenseClawCertificationCodexHome `
            -Path ([string]$Layout.CertificationCodexHome) `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -AllowMissing:$AllowMissingCertificationCodexHome
        if (-not [string]::Equals(
                $certificationHome,
                [string]$Layout.CertificationCodexHome,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'certification CODEX_HOME changed during volume identity revalidation'
        }
    }
}

function New-DefenseClawLayoutDirectories {
    param([Parameter(Mandatory)][hashtable]$Layout)
    foreach ($path in @(
        $Layout.InstallRoot,
        $Layout.BinDirectory,
        $Layout.LibexecDirectory,
        $Layout.StateRoot,
        $Layout.ConfigDirectory,
        $Layout.RuntimeDirectory,
        $Layout.BrokerStateDirectory,
        $Layout.GuardianDirectory,
        $Layout.AuthorizationDirectory,
        $Layout.LogDirectory,
        $Layout.GatewayLogDirectory,
        $Layout.BrokerLogDirectory,
        $Layout.GuardianLogDirectory,
        $Layout.InstallStateDirectory,
        $Layout.TransactionsDirectory
    )) {
        New-DefenseClawDirectory -Path $path
    }
}

function Get-DefenseClawDeploymentMetadata {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [switch]$Required
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.MetadataPath -PathType Leaf)) {
        if ($Required) {
            throw "DefenseClaw enterprise deployment metadata is missing: $($Layout.MetadataPath)"
        }
        return $null
    }
    Assert-DefenseClawNoReparsePath -Path $Layout.MetadataPath
    try {
        $metadata = Microsoft.PowerShell.Management\Get-Content -LiteralPath $Layout.MetadataPath -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse DefenseClaw enterprise deployment metadata: $($_.Exception.Message)"
    }
    if ([int]$metadata.schema_version -ne $script:SchemaVersion) {
        throw "unsupported DefenseClaw enterprise deployment metadata schema: $($metadata.schema_version)"
    }
    foreach ($pair in @(
        @('install_root', $Layout.InstallRoot),
        @('state_root', $Layout.StateRoot)
    )) {
        $recorded = [IO.Path]::GetFullPath([string]$metadata.($pair[0])).TrimEnd('\')
        if (-not [string]::Equals($recorded, [string]$pair[1], [StringComparison]::OrdinalIgnoreCase)) {
            throw "deployment metadata $($pair[0])=$recorded does not match requested $($pair[1])"
        }
    }
    foreach ($pair in @(
        @('codex_machine_policy_path', $Layout.CodexMachinePolicyPath),
        @('codex_managed_hooks_directory', $Layout.CodexManagedHooksDirectory),
        @('codex_managed_hooks_state_path', $Layout.CodexManagedHooksStatePath),
        @('codex_requirements_ownership_path', $Layout.CodexRequirementsOwnershipPath),
        @('codex_requirements_acl_backup_path', $Layout.CodexRequirementsAclBackupPath),
        @('agent_application_control_attestation_path', $Layout.AgentApplicationControlAttestationPath),
        @('managed_hooks_teardown_journal_path', $Layout.ManagedHooksTeardownJournalPath)
    )) {
        $property = $metadata.PSObject.Properties[[string]$pair[0]]
        if ($null -eq $property) {
            # Installed schema-1 deployments from before machine-policy
            # enforcement are migrated by Upgrade or Repair.
            continue
        }
        $recorded = [IO.Path]::GetFullPath([string]$property.Value).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath([string]$pair[1]).TrimEnd('\')
        if (-not [string]::Equals(
            $recorded,
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "deployment metadata $($pair[0])=$recorded does not match the exact managed path"
        }
    }
    $certificationProperty = $metadata.PSObject.Properties['certification_codex_home']
    $recordedCertificationCodexHome = if ($null -eq $certificationProperty -or
        [string]::IsNullOrWhiteSpace([string]$certificationProperty.Value)) {
        ''
    }
    else {
        [IO.Path]::GetFullPath([string]$certificationProperty.Value).TrimEnd('\')
    }
    $recordedCertificationCodexHome =
        Resolve-DefenseClawCertificationCodexHome `
            -Path $recordedCertificationCodexHome `
            -GatewayServiceName ([string]$metadata.gateway_service) `
            -GuardianServiceName ([string]$metadata.guardian_service)
    if ([string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        # Read-only and removal actions intentionally omit certification
        # mutation switches. Protected metadata adopts the exact scope so those
        # actions can authenticate and recover an existing deployment.
        $Layout.CertificationCodexHome = $recordedCertificationCodexHome
    }
    elseif (-not [string]::Equals(
            $recordedCertificationCodexHome,
            [string]$Layout.CertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'deployment metadata certification CODEX_HOME does not match the requested lifecycle scope'
    }
    $coreCertificationProperty = $metadata.PSObject.Properties[
        'core_hardening_certification'
    ]
    if ($null -eq $coreCertificationProperty) {
        if ([bool]$Layout.CoreHardeningCertification) {
            throw 'refusing to convert legacy deployment metadata into core-hardening certification mode'
        }
        $Layout.CoreHardeningCertification = $false
    }
    else {
        if ($coreCertificationProperty.Value -isnot [bool]) {
            throw 'deployment metadata has an invalid core-hardening certification result'
        }
        $recordedCoreCertification = [bool]$coreCertificationProperty.Value
        if ($recordedCoreCertification -and
            [string]::IsNullOrWhiteSpace($recordedCertificationCodexHome)) {
            throw 'deployment metadata enables core-hardening certification outside exact disposable certification scope'
        }
        if ([bool]$Layout.CoreHardeningCertification -and
            -not $recordedCoreCertification) {
            throw 'refusing to convert a production deployment into core-hardening certification mode'
        }
        $Layout.CoreHardeningCertification = $recordedCoreCertification
    }
    foreach ($targetName in @(
        'claude_target_enabled',
        'codex_target_enabled',
        'cursor_target_enabled'
    )) {
        $targetProperty = $metadata.PSObject.Properties[$targetName]
        if ($null -eq $targetProperty) {
            continue
        }
        if ($targetProperty.Value -isnot [bool]) {
            throw "deployment metadata has an invalid $targetName result"
        }
        if ($targetName -eq 'claude_target_enabled') {
            $Layout.ClaudeTargetEnabled = [bool]$targetProperty.Value
        }
        elseif ($targetName -eq 'codex_target_enabled') {
            $Layout.CodexTargetEnabled = [bool]$targetProperty.Value
        }
        else {
            $Layout.CursorTargetEnabled = [bool]$targetProperty.Value
        }
    }
    if ([bool]$Layout.CoreHardeningCertification -and
        ([bool]$Layout.CodexTargetEnabled -or
            [bool]$Layout.CursorTargetEnabled)) {
        throw 'core-hardening certification metadata cannot enable Codex or Cursor targets'
    }
    $providerLibraryProperty = $metadata.PSObject.Properties['provider_library_path']
    if ($null -ne $providerLibraryProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$providerLibraryProperty.Value)) {
        $Layout.ProviderLibraryPath = Resolve-DefenseClawFullPath `
            -Path ([string]$providerLibraryProperty.Value)
    }
    return $metadata
}

function New-DefenseClawDeploymentMetadata {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [bool]$Installed = $true
    )
    $hashes = [ordered]@{}
    foreach ($entry in @(
        @('broker', $Layout.BrokerPath),
        @('gateway', $Layout.GatewayPath),
        @('hook', $Layout.HookPath),
        @('cli', $Layout.CLIPath),
        @('installer', $Layout.InstallerPath),
        @('module', $Layout.ModulePath)
    )) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $entry[1] -PathType Leaf) {
            $hashes[$entry[0]] = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $uninstalledAt = if ($Installed) { $null } else { [DateTime]::UtcNow.ToString('o') }
    $codexMachinePolicySha256 = ''
    $agentApplicationControlAttestationSha256 = ''
    if ($Installed) {
        if ([bool]$Layout.CodexTargetEnabled) {
            foreach ($entry in @(
                @($Layout.CodexMachinePolicyPath, 'policy'),
                @($Layout.CodexManagedHooksStatePath, 'managed hooks state')
            )) {
                if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $entry[0] `
                    -PathType Leaf)) {
                    throw "cannot record installed metadata without Codex $($entry[1]): $($entry[0])"
                }
            }
            $codexMachinePolicySha256 = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Layout.CodexMachinePolicyPath `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
        if ([bool]$Layout.CoreHardeningCertification) {
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath) {
                throw 'core-hardening certification cannot retain external application-control attestation evidence'
            }
        }
        else {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $Layout)
            $agentApplicationControlAttestationSha256 = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Layout.AgentApplicationControlAttestationPath `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
    }
    $metadata = [ordered]@{
        schema_version = $script:SchemaVersion
        deployment_mode = 'managed_enterprise'
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        installed = $Installed
        install_root = $Layout.InstallRoot
        state_root = $Layout.StateRoot
        gateway_service = $GatewayServiceName
        guardian_service = $GuardianServiceName
        gateway_account = "NT SERVICE\$GatewayServiceName"
        guardian_account = 'LocalSystem'
        broker_service = $Layout.BrokerServiceName
        broker_account = 'LocalSystem'
        broker_pipe = $Layout.BrokerPipeName
        broker_auth_key_path = $Layout.BrokerAuthKeyPath
        provider_library_path = $Layout.ProviderLibraryPath
        codex_machine_policy_parent = $Layout.CodexMachinePolicyDirectory
        codex_machine_policy_parent_preserved_on_uninstall = $true
        codex_machine_policy_path = $Layout.CodexMachinePolicyPath
        codex_managed_hooks_directory = $Layout.CodexManagedHooksDirectory
        codex_managed_hooks_state_path = $Layout.CodexManagedHooksStatePath
        codex_requirements_ownership_path = $Layout.CodexRequirementsOwnershipPath
        codex_requirements_acl_backup_path = $Layout.CodexRequirementsAclBackupPath
        agent_application_control_attestation_path = $Layout.AgentApplicationControlAttestationPath
        managed_hooks_teardown_journal_path = $Layout.ManagedHooksTeardownJournalPath
        codex_machine_policy_sha256 = $codexMachinePolicySha256
        agent_application_control_attestation_sha256 = $agentApplicationControlAttestationSha256
        codex_machine_policy_managed = [bool](
            $Installed -and $Layout.CodexTargetEnabled
        )
        codex_approved_client_enforced = [bool](
            $Installed -and $Layout.AgentApplicationControlAttested
        )
        codex_target_enabled = [bool](
            $Installed -and $Layout.CodexTargetEnabled
        )
        claude_target_enabled = [bool](
            $Installed -and $Layout.ClaudeTargetEnabled
        )
        cursor_target_enabled = [bool](
            $Installed -and $Layout.CursorTargetEnabled
        )
        claude_approved_client_enforced = [bool](
            $Installed -and $Layout.AgentApplicationControlAttested
        )
        claude_minimum_client_version = '2.1.152'
        approved_agent_clients_enforced = [bool](
            $Installed -and $Layout.AgentApplicationControlAttested
        )
        claude_effective_policy_verified = [bool](
            $Installed -and $Layout.ClaudeEffectivePolicyVerified
        )
        agent_application_control_enforced = [bool](
            $Installed -and $Layout.AgentApplicationControlAttested
        )
        agent_application_control_prerequisite = $script:AgentApplicationControlPrerequisite
        external_security_prerequisites_satisfied = [bool](
            $Installed -and
            ($Layout.ClaudeTargetEnabled -or
                $Layout.CodexTargetEnabled -or
                $Layout.CursorTargetEnabled) -and
            (-not $Layout.ClaudeTargetEnabled -or
                $Layout.ClaudeEffectivePolicyVerified)
        )
        security_complete = [bool](
            $Installed -and
            ($Layout.ClaudeTargetEnabled -or
                $Layout.CodexTargetEnabled -or
                $Layout.CursorTargetEnabled) -and
            (-not $Layout.ClaudeTargetEnabled -or
                $Layout.ClaudeEffectivePolicyVerified)
        )
        updated_at = [DateTime]::UtcNow.ToString('o')
        uninstalled_at = $uninstalledAt
        hashes = $hashes
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Layout.CertificationCodexHome)) {
        $metadata['certification_codex_home'] = [string]$Layout.CertificationCodexHome
    }
    return $metadata
}

function Test-DefenseClawMetadataInstalled {
    param([Parameter(Mandatory)]$Metadata)
    if ($null -eq $Metadata.PSObject.Properties['installed']) {
        # Backward compatibility for schema-1 metadata written before the
        # explicit uninstall tombstone was introduced.
        return $true
    }
    return [bool]$Metadata.installed
}

function Remove-DefenseClawInactiveDeploymentMetadataForInstall {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)][string]$SnapshotPath
    )
    if (Test-DefenseClawMetadataInstalled -Metadata $Metadata) {
        throw 'refusing to adopt active deployment metadata during Install'
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.MetadataPath `
            -PathType Leaf)) {
        throw 'inactive deployment metadata disappeared before transactional adoption'
    }
    Assert-DefenseClawNoReparsePath -Path $Layout.MetadataPath
    Assert-DefenseClawDescendant `
        -Path $SnapshotPath `
        -Root $Layout.StateRoot `
        -Label 'inactive-metadata adoption snapshot' |
        Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $metadataPath = [IO.Path]::GetFullPath(
        [string]$Layout.MetadataPath
    ).TrimEnd('\')
    $metadataEntries = @(
        @($snapshot.files) |
            Microsoft.PowerShell.Core\Where-Object {
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_.path).TrimEnd('\'),
                    $metadataPath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($metadataEntries.Count -ne 1) {
        throw 'transaction snapshot does not contain exactly one inactive metadata preimage'
    }
    $entry = $metadataEntries[0]
    $existedProperty = $entry.PSObject.Properties['existed']
    $backupProperty = $entry.PSObject.Properties['backup']
    if ($null -eq $existedProperty -or
        $existedProperty.Value -isnot [bool] -or
        -not [bool]$existedProperty.Value -or
        $null -eq $backupProperty -or
        [string]::IsNullOrWhiteSpace([string]$backupProperty.Value)) {
        throw 'transaction snapshot did not preserve the inactive metadata preimage'
    }
    $backupPath = Assert-DefenseClawDescendant `
        -Path ([string]$backupProperty.Value) `
        -Root ([IO.Path]::GetDirectoryName($SnapshotPath)) `
        -Label 'inactive metadata transaction preimage'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $backupPath `
            -PathType Leaf)) {
        throw 'inactive metadata transaction preimage is missing'
    }
    Assert-DefenseClawNoReparsePath -Path $backupPath
    $currentHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $Layout.MetadataPath `
            -Algorithm SHA256
    ).Hash
    $backupHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $backupPath `
            -Algorithm SHA256
    ).Hash
    if (-not [string]::Equals(
            $currentHash,
            $backupHash,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'inactive deployment metadata changed after its transaction snapshot'
    }
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $Layout.MetadataPath `
        -Force
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.MetadataPath) {
        throw 'inactive deployment metadata remained after transactional adoption'
    }
}

function Assert-DefenseClawMetadataIdentity {
    param(
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    if (-not [string]::Equals(
        [string]$Metadata.gateway_service,
        $GatewayServiceName,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "deployment metadata belongs to gateway service $($Metadata.gateway_service), not $GatewayServiceName"
    }
    if (-not [string]::Equals(
        [string]$Metadata.guardian_service,
        $GuardianServiceName,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "deployment metadata belongs to guardian service $($Metadata.guardian_service), not $GuardianServiceName"
    }
    $brokerProperty = $Metadata.PSObject.Properties['broker_service']
    if ($null -ne $brokerProperty -and
        -not [string]::Equals(
            [string]$brokerProperty.Value,
            (Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'deployment metadata belongs to a different credential broker service'
    }
}

function Assert-DefenseClawOwnedServiceOrAbsent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedGatewayPath,
        [string]$ExpectedManifestPath,
        [switch]$Guardian,
        # Spec 005 D1: mirrors -Guardian for the third SCM service.
        # Its ImagePath is the gateway binary invoked with
        # `enterprise windows enumerate --manifest X --interval 5m`;
        # its ObjectName is LocalSystem (same as guardian, matching
        # the account-model choice recorded in the Stage 1 commit).
        [switch]$Enumerator
    )
    if ($Guardian -and $Enumerator) {
        throw '-Guardian and -Enumerator are mutually exclusive'
    }
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        return
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $image = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue -LiteralPath $key -Name ImagePath)
    $expectedImage = if ($Guardian) {
        if ([string]::IsNullOrWhiteSpace($ExpectedManifestPath)) {
            throw 'guardian service ownership validation requires its exact manifest path'
        }
        '"{0}" enterprise hooks watch --manifest "{1}" --interval 1m' -f $ExpectedGatewayPath, $ExpectedManifestPath
    }
    elseif ($Enumerator) {
        if ([string]::IsNullOrWhiteSpace($ExpectedManifestPath)) {
            throw 'enumerator service ownership validation requires its exact manifest path'
        }
        '"{0}" enterprise windows enumerate --manifest "{1}" --interval 5m' -f $ExpectedGatewayPath, $ExpectedManifestPath
    }
    else {
        '"{0}"' -f $ExpectedGatewayPath
    }
    $ownedImage = [string]::Equals($image, $expectedImage, [StringComparison]::OrdinalIgnoreCase)
    if (-not $ownedImage) {
        throw "refusing to replace foreign Windows service $Name with ImagePath $image"
    }
    $objectName = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue -LiteralPath $key -Name ObjectName)
    $expectedAccount = if ($Guardian -or $Enumerator) { 'LocalSystem' } else { "NT SERVICE\$Name" }
    if (-not [string]::Equals($objectName, $expectedAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to replace service $Name owned by unexpected account $objectName"
    }
}

function Assert-DefenseClawCMIDBrokerServiceOrAbsent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedImage,
        [switch]$AllowArgumentUpgrade
    )
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        return
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $image = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue `
        -LiteralPath $key `
        -Name ImagePath)
    $ownedImage = [string]::Equals(
            $image,
            $ExpectedImage,
            [StringComparison]::OrdinalIgnoreCase
        )
    if (-not $ownedImage -and $AllowArgumentUpgrade) {
        $closingQuote = $ExpectedImage.IndexOf('"', 1)
        if ($ExpectedImage.Length -gt 2 -and $ExpectedImage[0] -eq '"' -and
            $closingQuote -gt 1) {
            $expectedPrefix = $ExpectedImage.Substring(0, $closingQuote + 1) + ' service '
            $ownedImage = $image.StartsWith(
                $expectedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    }
    if (-not $ownedImage) {
        throw "refusing to replace foreign credential broker service $Name with ImagePath $image"
    }
    $account = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue `
        -LiteralPath $key `
        -Name ObjectName)
    if (-not [string]::Equals(
            $account,
            'LocalSystem',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "refusing to replace credential broker service $Name owned by unexpected account $account"
    }
}

function Assert-DefenseClawServiceImagePath {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedImage
    )
    Assert-DefenseClawServiceName -Name $Name
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        throw "SCM did not publish the managed service after configuration: $Name"
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $actual = [string](
        Microsoft.PowerShell.Management\Get-ItemPropertyValue `
            -LiteralPath $key `
            -Name ImagePath `
            -ErrorAction Stop
    )
    if (-not [string]::Equals(
        $actual,
        $ExpectedImage,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "SCM published an unexpected ImagePath for $Name`: $actual"
    }
}

function New-DefenseClawTransaction {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$PriorDeploymentActive,
        [switch]$IncludeCodexMachineState,
        [switch]$ManagedHooksTeardownPrepared,
        [switch]$PreserveManagedHooksTeardownJournal,
        [switch]$InstallRootCreatedForTransaction,
        [switch]$StateRootCreatedForTransaction
    )
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath) {
        throw 'refusing to open a lifecycle transaction while protected recovery state already exists'
    }
    if ($PriorDeploymentActive -and
        ($InstallRootCreatedForTransaction -or
            $StateRootCreatedForTransaction)) {
        throw 'an active deployment cannot have a transaction-created managed root'
    }
    $id = [Guid]::NewGuid().ToString('N')
    $directory = Assert-DefenseClawDescendant `
        -Path (Microsoft.PowerShell.Management\Join-Path $Layout.TransactionsDirectory $id) `
        -Root $Layout.StateRoot `
        -Label 'transaction directory'
    New-DefenseClawDirectory -Path $directory
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $installRootIdentity = [string](
        $nativeSecurity::GetDirectorySecuritySnapshotNoFollow(
            [string]$Layout.InstallRoot
        ).Identity
    )
    $stateRootIdentity = [string](
        $nativeSecurity::GetDirectorySecuritySnapshotNoFollow(
            [string]$Layout.StateRoot
        ).Identity
    )
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6atyfZ): transaction snapshots
    # must record all THREE managed services. The enumerator's
    # start-mode + running state travel with gateway + guardian so
    # rollback restores them together — otherwise a failed transaction
    # could leave the enumerator disabled while gateway + guardian are
    # restored to auto-start, and new user profiles would stop getting
    # picked up. Derive the enumerator's service name from the guardian's
    # via the same helper Set-DefenseClawManagedServices uses so a
    # certification-run cross-check is enforced.
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    $services = [Collections.Generic.List[object]]::new()
    foreach ($name in @($BrokerServiceName, $GatewayServiceName, $GuardianServiceName, $enumeratorServiceName)) {
        $service = Get-DefenseClawServiceChecked -Name $name
        $startMode = if ($null -eq $service) {
            0
        }
        else {
            Get-DefenseClawServiceStartMode -Name $name
        }
        $services.Add([ordered]@{
            name = $name
            existed = ($null -ne $service)
            running = (
                $null -ne $service -and
                $service.Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Running
            )
            start_mode = [int]$startMode
        })
    }
    $quiescingIntentPublished = $false
    $servicesQuiescedAt = ''
    try {
        # Publish prior service state before the first explicit stop. If this
        # process is terminated after either stop or while copying preimages,
        # recovery can restore enforcement without requiring snapshot.json to
        # have been completed.
        $quiescingIntent = [ordered]@{
            schema_version = 1
            phase = 'quiescing'
            id = $id
            directory = $directory
            install_root = $Layout.InstallRoot
            state_root = $Layout.StateRoot
            gateway_service = $GatewayServiceName
            guardian_service = $GuardianServiceName
            provider_library_path = [string]$Layout.ProviderLibraryPath
            services = $services
            service_activation_phase = 'quiesced'
            certification_codex_home = [string]$Layout.CertificationCodexHome
            core_hardening_certification = [bool](
                $Layout.CoreHardeningCertification
            )
            prior_deployment_active = [bool]$PriorDeploymentActive
            install_root_created = [bool]$InstallRootCreatedForTransaction
            install_root_identity = $installRootIdentity
            state_root_created = [bool]$StateRootCreatedForTransaction
            state_root_identity = $stateRootIdentity
            created_at = [DateTime]::UtcNow.ToString('o')
        }
        Write-DefenseClawJsonAtomic `
            -Value $quiescingIntent `
            -Path $Layout.PendingPath
        $quiescingIntentPublished = $true

        # Disabled start neutralizes boot activation and any failure restart
        # already queued by SCM. Gateway is disabled first so a crash cannot
        # leave it boot-active while guardian was demoted by this transaction.
        # Spec 005 D1 (CR PRRT_kwDORuAK-s6atyfZ): disable all THREE
        # services during the quiesce phase. Enumerator disabled last
        # so its final cycle (already in flight) can complete and drop
        # a coherent targets.yaml before the transaction reads it as
        # a preimage.
        foreach ($name in @($GatewayServiceName, $brokerServiceName, $GuardianServiceName, $enumeratorServiceName)) {
            $service = $services |
                Microsoft.PowerShell.Core\Where-Object {
                    [string]::Equals(
                        [string]$_.name,
                        $name,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                } |
                Microsoft.PowerShell.Utility\Select-Object -First 1
            if ($null -ne $service -and [bool]$service.existed) {
                Set-DefenseClawServiceStartMode -Name $name -StartMode 4
            }
        }

        # Quiesce every LocalSystem writer before reading any shared or
        # managed file preimage. Stop-Service waits for process exit, so an
        # in-flight guardian reconciliation cannot straddle the snapshot.
        # Enumerator first — it's the targets.yaml writer, stopping it
        # first freezes the file the guardian's final reconcile pass reads.
        Stop-DefenseClawService -Name $enumeratorServiceName
        Stop-DefenseClawService -Name $GuardianServiceName
        Stop-DefenseClawService -Name $GatewayServiceName
        Stop-DefenseClawService -Name $brokerServiceName
        $servicesQuiescedAt = [DateTime]::UtcNow.ToString('o')
        $quiescingIntent['services_disabled_and_stopped_at'] =
            $servicesQuiescedAt
        # This second durable intent is the only authority for amortizing the
        # canonical 60-second SCM failure-restart drain window.
        Write-DefenseClawJsonAtomic `
            -Value $quiescingIntent `
            -Path $Layout.PendingPath

        $gatewayServiceEntry = $services |
            Microsoft.PowerShell.Core\Where-Object {
                [string]::Equals(
                    [string]$_.name,
                    $GatewayServiceName,
                    [StringComparison]::OrdinalIgnoreCase
                )
            } |
            Microsoft.PowerShell.Utility\Select-Object -First 1
        $redactionKeyGatewaySID = if ($null -ne $gatewayServiceEntry -and
            [bool]$gatewayServiceEntry.existed) {
            Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
        }
        elseif ($PriorDeploymentActive) {
            Get-DefenseClawDeterministicServiceSID `
                -ServiceName $GatewayServiceName
        }
        else {
            ''
        }
        $redactionKeySecurity =
            Get-DefenseClawRedactionKeySecuritySnapshot `
                -Layout $Layout `
                -GatewayServiceSID $redactionKeyGatewaySID

        $files = [Collections.Generic.List[object]]::new()
    $destinations = [Collections.Generic.List[string]]::new()
    foreach ($destination in @(
        $Layout.BrokerPath,
        $Layout.GatewayPath,
        $Layout.HookPath,
        $Layout.CLIPath,
        $Layout.ConfigPath,
        $Layout.ManifestPath,
        $Layout.InstallerPath,
        $Layout.ModulePath,
        $Layout.BrokerAuthKeyPath,
        $Layout.MetadataPath,
        $Layout.AgentApplicationControlAttestationPath
    )) {
        $destinations.Add([string]$destination)
    }
    # Uninstall creates its teardown journal only after this transaction has
    # stopped the guardian. Excluding that live journal is what makes every
    # crash phase recoverable: generic restore may restore a deleted gateway
    # binary and machine state, but it can never replace/remove the captured
    # Claude preimage before the hidden rollback command consumes it.
    if (-not $PreserveManagedHooksTeardownJournal) {
        $destinations.Add(
            [string]$Layout.ManagedHooksTeardownJournalPath
        )
    }
    if ($IncludeCodexMachineState) {
        foreach ($destination in @(
            $Layout.CodexMachinePolicyPath,
            $Layout.CodexManagedHooksStatePath,
            $Layout.CodexRequirementsOwnershipPath,
            $Layout.CodexRequirementsAclBackupPath
        )) {
            $destinations.Add([string]$destination)
        }
    }
    $index = 0
    foreach ($destination in $destinations) {
        $exists = Microsoft.PowerShell.Management\Test-Path -LiteralPath $destination -PathType Leaf
        $backup = $null
        $securityDescriptor = ''
        if ($exists) {
            Assert-DefenseClawNoReparsePath -Path $destination
            $isSharedCodexFile = [string]::Equals(
                [IO.Path]::GetFullPath($destination).TrimEnd('\'),
                [IO.Path]::GetFullPath($Layout.CodexMachinePolicyPath).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            ) -or [string]::Equals(
                [IO.Path]::GetFullPath($destination).TrimEnd('\'),
                [IO.Path]::GetFullPath($Layout.CodexManagedHooksStatePath).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )
            if ($isSharedCodexFile) {
                $item = Microsoft.PowerShell.Management\Get-Item `
                    -LiteralPath $destination `
                    -Force
                if ([int64]$item.Length -gt 4194304) {
                    throw "shared Codex enterprise file exceeds the 4194304-byte transaction limit: $destination"
                }
                $securityDescriptor = (
                    Microsoft.PowerShell.Security\Get-Acl -LiteralPath $destination
                ).GetSecurityDescriptorSddlForm(
                    [Security.AccessControl.AccessControlSections]::All
                )
            }
            $backup = Microsoft.PowerShell.Management\Join-Path $directory ("file-{0:D2}.bak" -f $index)
            Microsoft.PowerShell.Management\Copy-Item -LiteralPath $destination -Destination $backup -Force
        }
        $files.Add([ordered]@{
            path = $destination
            existed = [bool]$exists
            backup = $backup
            security_descriptor = $securityDescriptor
        })
        $index++
    }
    $priorAttestationExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.AgentApplicationControlAttestationPath `
        -PathType Leaf
    $priorApplicationControlAttested = $false
    $priorClaudeEffectivePolicyVerified = $false
    if ($priorAttestationExists) {
        $priorAttestation = Get-DefenseClawAgentApplicationControlAttestation `
            -Layout $Layout
        $priorApplicationControlAttested = [bool](
            $priorAttestation.agent_application_control_enforced
        )
        $priorClaudeEffectivePolicyVerified = [bool](
            $priorAttestation.claude_effective_policy_verified
        )
    }
    $teardownJournalPreimageExisted = $false
    $teardownJournalPreimageSHA256 = ''
    if ($PreserveManagedHooksTeardownJournal -and
        (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
            -PathType Leaf)) {
        Assert-DefenseClawNoReparsePath `
            -Path $Layout.ManagedHooksTeardownJournalPath
        $teardownJournalPreimageExisted = $true
        $teardownJournalPreimageSHA256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    $snapshot = [ordered]@{
        schema_version = 1
        id = $id
        directory = $directory
        install_root = $Layout.InstallRoot
        state_root = $Layout.StateRoot
        gateway_service = $GatewayServiceName
        guardian_service = $GuardianServiceName
        provider_library_path = [string]$Layout.ProviderLibraryPath
        service_activation_phase = 'quiesced'
        services_disabled_and_stopped_at = $servicesQuiescedAt
        certification_codex_home = [string]$Layout.CertificationCodexHome
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        prior_deployment_active = [bool]$PriorDeploymentActive
        install_root_created = [bool]$InstallRootCreatedForTransaction
        install_root_identity = $installRootIdentity
        state_root_created = [bool]$StateRootCreatedForTransaction
        state_root_identity = $stateRootIdentity
        agent_application_control_attested = [bool]$priorApplicationControlAttested
        claude_effective_policy_verified = [bool]$priorClaudeEffectivePolicyVerified
        codex_machine_state_included = [bool]$IncludeCodexMachineState
        managed_hooks_teardown_prepared = [bool]$ManagedHooksTeardownPrepared
        managed_hooks_teardown_journal_preserved = [bool](
            $PreserveManagedHooksTeardownJournal
        )
        managed_hooks_teardown_journal_preimage_existed = [bool](
            $teardownJournalPreimageExisted
        )
        managed_hooks_teardown_journal_preimage_sha256 = [string](
            $teardownJournalPreimageSHA256
        )
        redaction_key_security = $redactionKeySecurity
        files = $files
        services = $services
        created_shared_directories = @()
        created_target_runtime_roots = @()
    }
    $snapshotPath = Microsoft.PowerShell.Management\Join-Path $directory 'snapshot.json'
    Write-DefenseClawJsonAtomic -Value $snapshot -Path $snapshotPath
    Write-DefenseClawJsonAtomic -Value ([ordered]@{
        schema_version = 1
        snapshot = $snapshotPath
        created_at = [DateTime]::UtcNow.ToString('o')
    }) -Path $Layout.PendingPath
    return $snapshotPath
    }
    catch {
        $snapshotError = $_
        if (-not $quiescingIntentPublished -and
            (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.PendingPath)) {
            # Move-Item is the last publication operation. If an exceptional
            # finally path ran after the move, treat the durable intent as
            # authoritative and perform normal protected recovery below.
            $quiescingIntentPublished = $true
        }
        if (-not $quiescingIntentPublished) {
            # No service mode or runtime mutation occurs before intent
            # publication. Avoid perturbing healthy services when the atomic
            # write itself failed (for example, disk full).
            try {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $directory `
                    -PathType Container) {
                    Assert-DefenseClawNoReparsePath -Path $directory
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $directory `
                        -Recurse `
                        -Force
                }
            }
            catch {
                throw "transaction intent publication failed ($($snapshotError.Exception.Message)); empty transaction-directory cleanup also failed: $($_.Exception.Message)"
            }
            throw $snapshotError
        }
        $restartErrors = [Collections.Generic.List[string]]::new()
        try {
            if ([string]::IsNullOrWhiteSpace($servicesQuiescedAt)) {
                foreach ($name in @(
                    $GatewayServiceName,
                    $brokerServiceName,
                    $GuardianServiceName,
                    $enumeratorServiceName
                )) {
                    $service = $services |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]::Equals(
                                [string]$_.name,
                                $name,
                                [StringComparison]::OrdinalIgnoreCase
                            )
                        } |
                        Microsoft.PowerShell.Utility\Select-Object -First 1
                    if ($null -ne $service -and [bool]$service.existed) {
                        Set-DefenseClawServiceStartMode `
                            -Name $name `
                            -StartMode 4
                    }
                }
                Stop-DefenseClawService -Name $GuardianServiceName
                Stop-DefenseClawService -Name $GatewayServiceName
                Stop-DefenseClawService -Name $brokerServiceName
                $servicesQuiescedAt = [DateTime]::UtcNow.ToString('o')
                Set-DefenseClawServiceActivationPhase `
                    -State $quiescingIntent `
                    -Path $Layout.PendingPath `
                    -Phase quiesced `
                    -ServicesQuiescedAt $servicesQuiescedAt
            }
            else {
                [void](ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
                    -Value $servicesQuiescedAt)
            }
            Set-DefenseClawServiceActivationPhase `
                -State $quiescingIntent `
                -Path $Layout.PendingPath `
                -Phase activating
            Start-DefenseClawTransactionServices `
                -Services $services `
                -Layout $Layout `
                -ServicesQuiescedAt $servicesQuiescedAt `
                -TrustInProcessQuiescence `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }
        catch {
            $restartErrors.Add($_.Exception.Message)
        }
        if ($restartErrors.Count -gt 0) {
            throw "transaction snapshot failed ($($snapshotError.Exception.Message)); restoring prior service state also failed and protected quiescing recovery was retained: $($restartErrors -join '; ')"
        }
        $cleanupErrors = [Collections.Generic.List[string]]::new()
        $rollbackIntent = $null
        try {
            # A failed initial transaction can own the managed roots even when
            # snapshot.json was never published. Move those exact identity
            # claims to the protected lifecycle-lock namespace before either
            # the pending record or its StateRoot transaction directory is
            # retired. The external receipt is then sufficient authority to
            # finish cleanup after a process crash or reboot.
            $rollbackIntent = Publish-DefenseClawInstallRollbackIntent `
                -Snapshot ([pscustomobject]$quiescingIntent) `
                -Layout $Layout
        }
        catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
        try {
            # Remove partial preimages first. If pending cleanup then fails, a
            # retained quiescing intent or authenticated external receipt can
            # safely tolerate an already-absent transaction directory.
            if ($cleanupErrors.Count -eq 0) {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $directory `
                    -PathType Container) {
                    Assert-DefenseClawNoReparsePath -Path $directory
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $directory `
                        -Recurse `
                        -Force
                }
            }
        }
        catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
        if ($cleanupErrors.Count -eq 0) {
            try {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.PendingPath `
                    -PathType Leaf) {
                    Microsoft.PowerShell.Management\Remove-Item `
                        -LiteralPath $Layout.PendingPath `
                        -Force
                }
            }
            catch {
                $cleanupErrors.Add($_.Exception.Message)
            }
        }
        if ($cleanupErrors.Count -eq 0 -and $null -ne $rollbackIntent) {
            try {
                Complete-DefenseClawInstallRollbackIntent `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
            }
            catch {
                $cleanupErrors.Add($_.Exception.Message)
            }
        }
        if ($cleanupErrors.Count -gt 0) {
            throw "transaction snapshot failed ($($snapshotError.Exception.Message)); prior service state was restored but authenticated rollback cleanup failed and recovery evidence was retained: $($cleanupErrors -join '; ')"
        }
        throw $snapshotError
    }
}

function Set-DefenseClawTransactionManagedHooksTeardownPrepared {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    Assert-DefenseClawDescendant `
        -Path $SnapshotPath `
        -Root $Layout.StateRoot `
        -Label 'managed-hook teardown transaction snapshot' |
        Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    Assert-DefenseClawNoReparsePath -Path $Layout.PendingPath
    Assert-DefenseClawNoReparsePath `
        -Path $Layout.ManagedHooksTeardownJournalPath
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -PathType Leaf)) {
        throw 'cannot mark managed-hook teardown prepared without its live rollback journal'
    }
    $pending = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $Layout.PendingPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath([string]$pending.snapshot),
        [IO.Path]::GetFullPath($SnapshotPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'pending lifecycle record does not identify the managed-hook teardown transaction'
    }
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $prepared = $snapshot.PSObject.Properties[
        'managed_hooks_teardown_prepared'
    ]
    $preserved = $snapshot.PSObject.Properties[
        'managed_hooks_teardown_journal_preserved'
    ]
    if ($null -eq $prepared -or $prepared.Value -isnot [bool] -or
        $null -eq $preserved -or $preserved.Value -isnot [bool] -or
        -not [bool]$preserved.Value) {
        throw 'managed-hook teardown transaction has invalid recovery markers'
    }
    $snapshot.managed_hooks_teardown_prepared = $true
    Write-DefenseClawJsonAtomic -Value $snapshot -Path $SnapshotPath
}

function Add-DefenseClawCodexTransactionSnapshot {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    Assert-DefenseClawDescendant `
        -Path $SnapshotPath `
        -Root $Layout.StateRoot `
        -Label 'transaction snapshot' | Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    foreach ($name in @($GuardianServiceName, $GatewayServiceName)) {
        $service = Get-DefenseClawServiceChecked -Name $name
        if ($null -ne $service -and
            $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw "cannot extend a transaction snapshot while service $name is not stopped"
        }
    }
    Assert-DefenseClawNoReparsePath -Path $Layout.PendingPath
    $pending = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $Layout.PendingPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath([string]$pending.snapshot),
        [IO.Path]::GetFullPath($SnapshotPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'pending lifecycle record does not identify the transaction being extended'
    }
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $included = $snapshot.PSObject.Properties[
        'codex_machine_state_included'
    ]
    if ($null -eq $included -or $included.Value -isnot [bool]) {
        throw 'transaction snapshot has an invalid Codex inclusion state'
    }
    if ([bool]$included.Value) {
        return
    }

    Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
    Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
    $files = [Collections.Generic.List[object]]::new()
    $recordedPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($file in @($snapshot.files)) {
        $files.Add($file)
        [void]$recordedPaths.Add(
            [IO.Path]::GetFullPath([string]$file.path).TrimEnd('\')
        )
    }
    $index = $files.Count
    foreach ($destination in @(
        $Layout.CodexMachinePolicyPath,
        $Layout.CodexManagedHooksStatePath,
        $Layout.CodexRequirementsOwnershipPath,
        $Layout.CodexRequirementsAclBackupPath
    )) {
        $full = [IO.Path]::GetFullPath([string]$destination).TrimEnd('\')
        if ($recordedPaths.Contains($full)) {
            throw "transaction snapshot already contains Codex path without its inclusion marker: $full"
        }
        $exists = Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $full `
            -PathType Leaf
        $backup = $null
        $securityDescriptor = ''
        if ($exists) {
            Assert-DefenseClawNoReparsePath -Path $full
            $item = Microsoft.PowerShell.Management\Get-Item `
                -LiteralPath $full `
                -Force
            if ([int64]$item.Length -gt 4194304) {
                throw "Codex enterprise file exceeds the 4194304-byte transaction limit: $full"
            }
            if ($full -in @(
                [IO.Path]::GetFullPath($Layout.CodexMachinePolicyPath).TrimEnd('\'),
                [IO.Path]::GetFullPath($Layout.CodexManagedHooksStatePath).TrimEnd('\')
            )) {
                $securityDescriptor = (
                    Microsoft.PowerShell.Security\Get-Acl -LiteralPath $full
                ).GetSecurityDescriptorSddlForm(
                    [Security.AccessControl.AccessControlSections]::All
                )
            }
            $backup = Microsoft.PowerShell.Management\Join-Path `
                ([string]$snapshot.directory) `
                ("file-{0:D2}.bak" -f $index)
            Microsoft.PowerShell.Management\Copy-Item `
                -LiteralPath $full `
                -Destination $backup `
                -Force
        }
        $files.Add([ordered]@{
            path = $full
            existed = [bool]$exists
            backup = $backup
            security_descriptor = $securityDescriptor
        })
        $index++
    }
    $snapshot.files = @($files)
    $snapshot.codex_machine_state_included = $true
    Write-DefenseClawJsonAtomic -Value $snapshot -Path $SnapshotPath
}

function Test-DefenseClawOwnedCodexSharedDirectoryPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($allowed in @(
        $Layout.CodexVendorDirectory,
        $Layout.CodexMachinePolicyDirectory
    )) {
        if ([string]::Equals(
            $full,
            [IO.Path]::GetFullPath([string]$allowed).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }
    return $false
}

function Add-DefenseClawTransactionCreatedSharedDirectory {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    Assert-DefenseClawDescendant `
        -Path $SnapshotPath `
        -Root $Layout.StateRoot `
        -Label 'transaction snapshot' | Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    if (-not (Test-DefenseClawOwnedCodexSharedDirectoryPath -Path $Path -Layout $Layout)) {
        throw "refusing to record an unowned shared directory in the lifecycle transaction: $Path"
    }
    $snapshot = Microsoft.PowerShell.Management\Get-Content -LiteralPath $SnapshotPath -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $created = @($snapshot.created_shared_directories)
    foreach ($existing in $created) {
        if ([string]::Equals(
            [IO.Path]::GetFullPath([string]$existing).TrimEnd('\'),
            [IO.Path]::GetFullPath($Path).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            return
        }
    }
    $snapshot.created_shared_directories = @($created + [IO.Path]::GetFullPath($Path).TrimEnd('\'))
    Write-DefenseClawJsonAtomic -Value $snapshot -Path $SnapshotPath
}

function Assert-DefenseClawCodexMachinePolicyDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Codex machine-policy directory is missing or is not a directory: $Path"
    }
    $required = @{}
    $required[$script:SystemSID] = [Security.AccessControl.FileSystemRights]::FullControl
    $required[$script:AdministratorsSID] = [Security.AccessControl.FileSystemRights]::FullControl
    $required[$script:UsersSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    Assert-DefenseClawPathAcl `
        -Path $Path `
        -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID,
            $script:UsersSID
        ) `
        -RequiredRights $required `
        -AllowUsersRead `
        -AllowInheritance `
        -RejectUntrustedRead
}

function Assert-DefenseClawCodexMachinePolicyFilePreflight {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = [IO.Path]::GetFullPath($Layout.CodexMachinePolicyPath).TrimEnd('\')
    $expected = [IO.Path]::GetFullPath(
        [IO.Path]::Combine(
            $script:ProgramData,
            'OpenAI',
            'Codex',
            'requirements.toml'
        )
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $path,
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Codex machine-policy path is not the exact Windows requirements path: $path"
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path)) {
        return
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Codex machine requirements are not a regular file: $path"
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ([int64]$item.Length -gt 4194304) {
        throw "Codex machine requirements exceed the 4194304-byte limit: $path"
    }
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowUsersRead `
        -AllowInheritance
}

function Assert-DefenseClawCodexMachinePolicyFile {
    param([Parameter(Mandatory)][hashtable]$Layout)
    Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexMachinePolicyPath `
        -PathType Leaf)) {
        throw "Codex machine requirements are missing: $($Layout.CodexMachinePolicyPath)"
    }
    $required = New-DefenseClawRequiredRights -Kind MachinePolicy
    Assert-DefenseClawPathAcl `
        -Path $Layout.CodexMachinePolicyPath `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID,
            $script:UsersSID
        ) `
        -RequiredRights $required `
        -AllowUsersRead `
        -RejectUntrustedRead
}

function Assert-DefenseClawCodexManagedHooksStateFilePreflight {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = [IO.Path]::GetFullPath(
        $Layout.CodexManagedHooksStatePath
    ).TrimEnd('\')
    $expected = [IO.Path]::GetFullPath(
        [IO.Path]::Combine(
            $script:ProgramData,
            'OpenAI',
            'Codex',
            '.defenseclaw-managed-hooks.state'
        )
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $path,
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "DefenseClaw Codex managed-hooks state path is not exact: $path"
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path)) {
        return
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "DefenseClaw Codex managed-hooks state is not a regular file: $path"
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ([int64]$item.Length -gt 4194304) {
        throw "DefenseClaw Codex managed-hooks state exceeds the 4194304-byte limit: $path"
    }
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowUsersRead `
        -AllowInheritance
}

function Assert-DefenseClawCodexManagedHooksStateFile {
    param([Parameter(Mandatory)][hashtable]$Layout)
    Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexManagedHooksStatePath `
        -PathType Leaf)) {
        throw "DefenseClaw Codex managed-hooks state is missing: $($Layout.CodexManagedHooksStatePath)"
    }
    $required = New-DefenseClawRequiredRights -Kind MachinePolicy
    Assert-DefenseClawPathAcl `
        -Path $Layout.CodexManagedHooksStatePath `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID,
            $script:UsersSID
        ) `
        -RequiredRights $required `
        -AllowUsersRead `
        -RejectUntrustedRead
}

function Get-DefenseClawCodexRequirementsAclBackup {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = $Layout.CodexRequirementsAclBackupPath
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Codex requirements ACL preimage is missing: $path"
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ([int64]$item.Length -gt 262144) {
        throw "Codex requirements ACL preimage exceeds the 262144-byte limit: $path"
    }
    $adminRights = New-DefenseClawRequiredRights -Kind Admin
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights $adminRights `
        -AllowInheritance `
        -RejectUntrustedRead
    try {
        $backup = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $path `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse Codex requirements ACL preimage: $($_.Exception.Message)"
    }
    if ([int]$backup.schema_version -ne 1) {
        throw "unsupported Codex requirements ACL preimage schema: $($backup.schema_version)"
    }
    $recordedPath = [IO.Path]::GetFullPath([string]$backup.path).TrimEnd('\')
    $expectedPath = [IO.Path]::GetFullPath(
        $Layout.CodexMachinePolicyPath
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $recordedPath,
        $expectedPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Codex requirements ACL preimage records a different path: $recordedPath"
    }
    $existedProperty = $backup.PSObject.Properties['existed']
    if ($null -eq $existedProperty -or $existedProperty.Value -isnot [bool]) {
        throw 'Codex requirements ACL preimage has a non-Boolean existed value'
    }
    $sha256 = [string]$backup.sha256
    $securityDescriptor = [string]$backup.security_descriptor
    if ([bool]$existedProperty.Value) {
        if ($sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Codex requirements ACL preimage has an invalid SHA-256'
        }
        if ([string]::IsNullOrWhiteSpace($securityDescriptor)) {
            throw 'Codex requirements ACL preimage is missing its security descriptor'
        }
        try {
            $security = [Security.AccessControl.FileSecurity]::new()
            $security.SetSecurityDescriptorSddlForm(
                $securityDescriptor,
                [Security.AccessControl.AccessControlSections]::All
            )
        }
        catch {
            throw "Codex requirements ACL preimage contains invalid SDDL: $($_.Exception.Message)"
        }
    }
    elseif (-not [string]::IsNullOrEmpty($sha256) -or
        -not [string]::IsNullOrEmpty($securityDescriptor)) {
        throw 'absent Codex requirements ACL preimage unexpectedly contains file state'
    }
    return $backup
}

function Initialize-DefenseClawCodexRequirementsAclBackup {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        $ExistingMetadata
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexRequirementsAclBackupPath `
        -PathType Leaf) {
        [void](Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout)
        return
    }
    if ($null -ne $ExistingMetadata) {
        $managedProperty = $ExistingMetadata.PSObject.Properties[
            'codex_machine_policy_managed'
        ]
        if ($null -ne $managedProperty -and [bool]$managedProperty.Value) {
            throw 'Codex requirements ACL preimage is missing from an already managed deployment'
        }
    }

    $exists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexMachinePolicyPath `
        -PathType Leaf
    $securityDescriptor = ''
    $sha256 = ''
    if ($exists) {
        Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
        $securityDescriptor = (
            Microsoft.PowerShell.Security\Get-Acl `
                -LiteralPath $Layout.CodexMachinePolicyPath
        ).GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
        $sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.CodexMachinePolicyPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    Write-DefenseClawJsonAtomic -Value ([ordered]@{
        schema_version = 1
        path = $Layout.CodexMachinePolicyPath
        existed = [bool]$exists
        sha256 = $sha256
        security_descriptor = $securityDescriptor
    }) -Path $Layout.CodexRequirementsAclBackupPath
    [void](Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout)
}

function Get-DefenseClawAgentApplicationControlAttestation {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = [IO.Path]::GetFullPath(
        $Layout.AgentApplicationControlAttestationPath
    ).TrimEnd('\')
    $expected = [IO.Path]::GetFullPath(
        (Microsoft.PowerShell.Management\Join-Path `
            $Layout.InstallStateDirectory `
            'agent-application-control-attestation.json')
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $path,
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "agent application-control attestation path is not exact: $path"
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "agent application-control attestation is missing: $path"
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ([int64]$item.Length -gt 65536) {
        throw "agent application-control attestation exceeds the 65536-byte limit: $path"
    }
    $adminRights = New-DefenseClawRequiredRights -Kind Admin
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights $adminRights `
        -AllowInheritance `
        -RejectUntrustedRead
    try {
        $attestation = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $path `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse agent application-control attestation: $($_.Exception.Message)"
    }
    if ([int]$attestation.schema_version -ne
        $script:AgentApplicationControlAttestationSchemaVersion) {
        throw "unsupported agent application-control attestation schema: $($attestation.schema_version)"
    }
    $enforced = $attestation.PSObject.Properties[
        'agent_application_control_enforced'
    ]
    if ($null -eq $enforced -or
        $enforced.Value -isnot [bool]) {
        throw 'agent application-control evidence has an invalid enforcement result'
    }
    if ([string]$attestation.prerequisite -cne
        $script:AgentApplicationControlPrerequisite) {
        throw 'agent application-control attestation records an unknown application-control prerequisite'
    }
    $approvedClient = $attestation.PSObject.Properties[
        'approved_agent_clients_enforced'
    ]
    if ($null -eq $approvedClient -or
        $approvedClient.Value -isnot [bool] -or
        [bool]$approvedClient.Value -ne [bool]$enforced.Value -or
        [string]$attestation.minimum_claude_version -cne '2.1.152') {
        throw 'agent application-control evidence has an invalid approved-client result or Claude version floor'
    }
    $claudeEffective = $attestation.PSObject.Properties[
        'claude_effective_policy_verified'
    ]
    if ($null -eq $claudeEffective -or
        $claudeEffective.Value -isnot [bool]) {
        throw 'agent application-control evidence is missing the independent live Claude effective-policy result'
    }
    $claudeManifestHash = $attestation.PSObject.Properties[
        'claude_effective_policy_manifest_sha256'
    ]
    if ([bool]$claudeEffective.Value) {
        if ($null -eq $claudeManifestHash -or
            [string]$claudeManifestHash.Value -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManifestPath `
                -PathType Leaf)) {
            throw 'Claude effective-policy evidence is not bound to an installed manifest'
        }
        $actualManifestHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.ManifestPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualManifestHash -cne [string]$claudeManifestHash.Value) {
            throw 'Claude effective-policy evidence is stale for the installed manifest'
        }
    }
    elseif ($null -ne $claudeManifestHash -and
        -not [string]::IsNullOrEmpty([string]$claudeManifestHash.Value)) {
        throw 'unverified Claude effective-policy evidence unexpectedly records a manifest binding'
    }
    if ([string]$attestation.attested_by_sid -notmatch '^S-\d-\d+(?:-\d+)+$') {
        throw 'agent application-control attestation contains an invalid administrator SID'
    }
    try {
        # PowerShell 7 materializes this as a DateTime, whose [string] form is
        # local-culture and drops the UTC designator.
        $attestedAtValue = $attestation.attested_at
        $attestedAt = if ($attestedAtValue -is [DateTime]) {
            [DateTime]$attestedAtValue
        }
        else {
            [DateTime]::Parse(
                [string]$attestedAtValue,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
        }
        if ($attestedAt.Kind -eq [DateTimeKind]::Unspecified) {
            throw 'timestamp has no timezone'
        }
    }
    catch {
        throw "agent application-control attestation contains an invalid timestamp: $($_.Exception.Message)"
    }
    return $attestation
}

function Write-DefenseClawAgentApplicationControlAttestation {
    param([Parameter(Mandatory)][hashtable]$Layout)
    if ([bool]$Layout.CoreHardeningCertification) {
        throw 'core-hardening certification must not publish external application-control attestation evidence'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $claudeManifestHash = ''
    if ([bool]$Layout.ClaudeEffectivePolicyVerified) {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.ManifestPath `
            -PathType Leaf)) {
            throw 'cannot attest Claude effective policy without an installed protected manifest'
        }
        $claudeManifestHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.ManifestPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    Write-DefenseClawJsonAtomic -Value ([ordered]@{
        schema_version = $script:AgentApplicationControlAttestationSchemaVersion
        agent_application_control_enforced = [bool]$Layout.AgentApplicationControlAttested
        prerequisite = $script:AgentApplicationControlPrerequisite
        approved_agent_clients_enforced = [bool]$Layout.AgentApplicationControlAttested
        minimum_claude_version = '2.1.152'
        claude_effective_policy_verified = [bool]$Layout.ClaudeEffectivePolicyVerified
        claude_effective_policy_manifest_sha256 = $claudeManifestHash
        attested_by_sid = [string]$identity.User.Value
        attested_at = [DateTime]::UtcNow.ToString('o')
        certification_required = $true
    }) -Path $Layout.AgentApplicationControlAttestationPath
    [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $Layout)
}

function Initialize-DefenseClawCodexMachinePolicyParent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$SnapshotPath
    )
    # This prerequisite is intentionally scoped to explicit enterprise
    # Install/Upgrade/Repair. Ordinary per-user mode never calls this module.
    # Users receive read/traverse only so an impersonated Codex target can
    # distinguish an absent requirements.toml from an inaccessible parent.
    [void](Assert-DefenseClawSafeRoot `
        -Path $Layout.CodexMachinePolicyDirectory `
        -Label 'Codex machine-policy parent' `
        -RequiredBase $script:ProgramData)
    foreach ($directory in @(
        $Layout.CodexVendorDirectory,
        $Layout.CodexMachinePolicyDirectory
    )) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory) {
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory -PathType Container)) {
                throw "Codex machine-policy ancestor is occupied by a non-directory: $directory"
            }
            # Existing shared directories are validation-only. Never take
            # ownership or rewrite their ACLs, even when elevated.
            Assert-DefenseClawCodexMachinePolicyDirectory -Path $directory
            continue
        }
        $created = New-DefenseClawProtectedDirectory `
            -Path $directory `
            -AllowUsersRead
        Assert-DefenseClawCodexMachinePolicyDirectory -Path $directory
        if ($created) {
            Add-DefenseClawTransactionCreatedSharedDirectory `
                -SnapshotPath $SnapshotPath `
                -Path $directory `
                -Layout $Layout
        }
    }
}

# Only the exact lock path is removed, and only as a regular file no untrusted
# principal can write; anything else fails closed.
function Remove-DefenseClawManagedHooksSerializationLock {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path)) {
        return
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is not a regular file: $Path"
    }
    Assert-DefenseClawNoReparsePath -Path $Path
    Assert-DefenseClawPathAcl `
        -Path $Path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowUsersRead `
        -AllowInheritance
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Path -Force
}

# The Codex policy serialization lock outlives the policy files it guards, so it
# is cleared before the emptiness check that follows.
function Remove-DefenseClawCodexPolicySerializationLock {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    if (-not $Layout.ContainsKey('CodexManagedHooksLockPath')) {
        return
    }
    $lockPath = [string]$Layout.CodexManagedHooksLockPath
    if ([string]::IsNullOrWhiteSpace($lockPath)) {
        return
    }
    $lockPath = [IO.Path]::GetFullPath($lockPath)
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($lockPath).TrimEnd('\'),
            $Directory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        return
    }
    Remove-DefenseClawManagedHooksSerializationLock `
        -Path $lockPath `
        -Label 'Codex policy serialization lock'
}

# Both locks sit in shared vendor directories the lifecycle never claims, so the
# lock files are dropped and the directories left as found.
function Remove-DefenseClawCommittedManagedHooksSerializationLocks {
    param([Parameter(Mandatory)][hashtable]$Layout)
    foreach ($lock in @(
        @{ Key = 'CodexManagedHooksLockPath'; Label = 'Codex policy serialization lock' },
        @{ Key = 'ClaudeManagedHooksLockPath'; Label = 'Claude Code policy serialization lock' }
    )) {
        if (-not $Layout.ContainsKey($lock.Key)) {
            continue
        }
        $path = [string]$Layout[$lock.Key]
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }
        Remove-DefenseClawManagedHooksSerializationLock `
            -Path ([IO.Path]::GetFullPath($path)) `
            -Label $lock.Label
    }
}

function Remove-DefenseClawTransactionCreatedSharedDirectories {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $property = $Snapshot.PSObject.Properties['created_shared_directories']
    if ($null -eq $property) {
        return
    }
    $directories = @($property.Value)
    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        $directory = [IO.Path]::GetFullPath([string]$directories[$index]).TrimEnd('\')
        if (-not (Test-DefenseClawOwnedCodexSharedDirectoryPath -Path $directory -Layout $Layout)) {
            throw "transaction contains an unowned shared directory: $directory"
        }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory)) {
            continue
        }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory -PathType Container)) {
            throw "refusing rollback through a replaced Codex machine-policy directory: $directory"
        }
        Assert-DefenseClawCodexMachinePolicyDirectory -Path $directory
        Remove-DefenseClawCodexPolicySerializationLock `
            -Directory $directory `
            -Layout $Layout
        $child = Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $directory -Force | Microsoft.PowerShell.Utility\Select-Object -First 1
        if ($null -ne $child) {
            throw "refusing to remove non-empty transaction-created shared directory: $directory"
        }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $directory -Force
    }
}

function Restore-DefenseClawTransaction {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [switch]$DeferServiceRestart
    )
    Assert-DefenseClawDescendant -Path $SnapshotPath -Root $Layout.StateRoot -Label 'transaction snapshot' | Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $snapshot = Microsoft.PowerShell.Management\Get-Content -LiteralPath $SnapshotPath -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $snapshotCertificationProperty = $snapshot.PSObject.Properties['certification_codex_home']
    $snapshotCertificationCodexHome = if ($null -eq $snapshotCertificationProperty) {
        ''
    }
    else {
        [string]$snapshotCertificationProperty.Value
    }
    $snapshotCertificationCodexHome = Resolve-DefenseClawCertificationCodexHome `
        -Path $snapshotCertificationCodexHome `
        -GatewayServiceName ([string]$snapshot.gateway_service) `
        -GuardianServiceName ([string]$snapshot.guardian_service)
    if ([string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        $Layout.CertificationCodexHome = $snapshotCertificationCodexHome
    }
    elseif (-not [string]::Equals(
            [string]$Layout.CertificationCodexHome,
            $snapshotCertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'pending transaction certification CODEX_HOME does not match the requested lifecycle scope'
    }
    $snapshotCoreCertificationProperty = $snapshot.PSObject.Properties[
        'core_hardening_certification'
    ]
    if ($null -eq $snapshotCoreCertificationProperty -or
        $snapshotCoreCertificationProperty.Value -isnot [bool] -or
        ([bool]$Layout.CoreHardeningCertification -and
            -not [bool]$snapshotCoreCertificationProperty.Value)) {
        throw 'pending transaction core-hardening certification mode does not match the requested lifecycle scope'
    }
    if ([bool]$snapshotCoreCertificationProperty.Value -and
        [string]::IsNullOrWhiteSpace($snapshotCertificationCodexHome)) {
        throw 'pending transaction enables core-hardening certification outside exact disposable scope'
    }
    $Layout.CoreHardeningCertification = [bool](
        $snapshotCoreCertificationProperty.Value
    )
    $snapshotProviderProperty = $snapshot.PSObject.Properties['provider_library_path']
    if ($null -ne $snapshotProviderProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$snapshotProviderProperty.Value)) {
        $Layout.ProviderLibraryPath = Resolve-DefenseClawFullPath `
            -Path ([string]$snapshotProviderProperty.Value) `
            -MustExist `
            -Leaf
    }
    Assert-DefenseClawServiceName -Name ([string]$snapshot.gateway_service)
    Assert-DefenseClawServiceName -Name ([string]$snapshot.guardian_service)
    if ([string]::Equals(
        [string]$snapshot.gateway_service,
        [string]$snapshot.guardian_service,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'pending transaction aliases its gateway and guardian service names'
    }
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name ([string]$snapshot.gateway_service) `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name ([string]$snapshot.guardian_service) `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    if (-not [string]::IsNullOrWhiteSpace([string]$Layout.ProviderLibraryPath)) {
        Assert-DefenseClawCMIDBrokerServiceOrAbsent `
            -Name $Layout.BrokerServiceName `
            -ExpectedImage (Get-DefenseClawCMIDBrokerImage `
                -Layout $Layout `
                -GatewayServiceName ([string]$snapshot.gateway_service))
    }
    # A retained snapshot may be recovered after a reboot or after the final
    # validated activation step. Disable every live owned service before the
    # first stop or file restore. Besides preventing boot activation, disabled
    # start makes any already queued SCM failure restart fail closed.
    foreach ($name in @(
        [string]$snapshot.gateway_service,
        [string]$Layout.BrokerServiceName,
        [string]$snapshot.guardian_service,
        (Get-DefenseClawEnumeratorServiceName -GuardianServiceName ([string]$snapshot.guardian_service))
    )) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @(
        (Get-DefenseClawEnumeratorServiceName -GuardianServiceName ([string]$snapshot.guardian_service)),
        [string]$snapshot.guardian_service,
        [string]$snapshot.gateway_service,
        [string]$Layout.BrokerServiceName
    )) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Stop-DefenseClawService -Name $name
        }
    }
    $restoreQuiescedAt = [DateTime]::UtcNow.ToString('o')
    # Recovery starts a fresh durable drain window. Never reuse a timestamp
    # from a prior process/boot or from an interrupted activation attempt.
    Set-DefenseClawServiceActivationPhase `
        -State $snapshot `
        -Path $SnapshotPath `
        -Phase quiesced `
        -ServicesQuiescedAt $restoreQuiescedAt
    if ($Layout.ContainsKey('ManagedHooksLifecycleJournalPath') -and
        (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
            -PathType Leaf)) {
        # Restore the authenticated machine-policy preimage while the staged
        # gateway still implements this transaction's hidden command. Generic
        # file rollback may replace that gateway with an older release.
        [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
            -Layout $Layout `
            -GatewayServiceName ([string]$snapshot.gateway_service) `
            -Action restore)
        # Retire while the staged gateway still implements this command. The
        # Claude preimage is already exact and services remain disabled, so a
        # crash after retirement resumes safely through the generic pending
        # transaction without requiring this journal again.
        [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
            -Layout $Layout `
            -GatewayServiceName ([string]$snapshot.gateway_service) `
            -Action retire)
    }
    # The staged gateway is still present and every scope-local writer is
    # stopped. Remove any transaction-created per-user runtime roots now,
    # before generic file restoration can replace/delete the helper binary.
    # The cross-scope gate prevents cleanup of the shared user inode while a
    # production or another certification scope could still own it.
    $snapshot = Invoke-DefenseClawTargetRuntimeRollbackCleanup `
        -SnapshotPath $SnapshotPath `
        -Layout $Layout `
        -GatewayServiceName ([string]$snapshot.gateway_service) `
        -GuardianServiceName ([string]$snapshot.guardian_service)
    foreach ($file in $snapshot.files) {
        $destination = [IO.Path]::GetFullPath([string]$file.path)
        $inInstall = $destination.StartsWith($Layout.InstallRoot + '\', [StringComparison]::OrdinalIgnoreCase)
        $inState = $destination.StartsWith($Layout.StateRoot + '\', [StringComparison]::OrdinalIgnoreCase)
        $isCodexMachinePolicy = [string]::Equals(
            $destination.TrimEnd('\'),
            [IO.Path]::GetFullPath($Layout.CodexMachinePolicyPath).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )
        $isCodexManagedState = [string]::Equals(
            $destination.TrimEnd('\'),
            [IO.Path]::GetFullPath($Layout.CodexManagedHooksStatePath).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )
        $isSharedCodexFile = $isCodexMachinePolicy -or $isCodexManagedState
        if (-not $inInstall -and -not $inState -and -not $isSharedCodexFile) {
            throw "transaction contains path outside managed roots: $destination"
        }
        if ($isSharedCodexFile) {
            $policyDirectoryExists = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.CodexMachinePolicyDirectory `
                -PathType Container
            $destinationExists = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $destination `
                -PathType Leaf
            if ([bool]$file.existed -or $destinationExists -or $policyDirectoryExists) {
                Assert-DefenseClawCodexMachinePolicyDirectory `
                    -Path $Layout.CodexMachinePolicyDirectory
            }
        }
        Assert-DefenseClawNoReparsePath -Path $destination -AllowMissingLeaf
        if ([bool]$file.existed) {
            $backup = [string]$file.backup
            Assert-DefenseClawDescendant -Path $backup -Root $Layout.StateRoot -Label 'transaction backup' | Microsoft.PowerShell.Core\Out-Null
            Install-DefenseClawFileAtomic `
                -Source $backup `
                -Destination $destination `
                -SkipIfContentMatches
            $securityProperty = $file.PSObject.Properties['security_descriptor']
            if ($isSharedCodexFile -and
                $null -ne $securityProperty -and
                -not [string]::IsNullOrWhiteSpace([string]$securityProperty.Value)) {
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm(
                    [string]$securityProperty.Value,
                    [Security.AccessControl.AccessControlSections]::All
                )
                Microsoft.PowerShell.Security\Set-Acl `
                    -LiteralPath $destination `
                    -AclObject $security
            }
        }
        elseif (Microsoft.PowerShell.Management\Test-Path -LiteralPath $destination -PathType Leaf) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $destination -Force
        }
    }
    $snapshotApplicationControl = $snapshot.PSObject.Properties[
        'agent_application_control_attested'
    ]
    $snapshotClaudeEffective = $snapshot.PSObject.Properties[
        'claude_effective_policy_verified'
    ]
    if ($null -eq $snapshotApplicationControl -or
        $snapshotApplicationControl.Value -isnot [bool] -or
        $null -eq $snapshotClaudeEffective -or
        $snapshotClaudeEffective.Value -isnot [bool]) {
        throw 'pending transaction has invalid application-control or Claude-policy evidence state'
    }
    $Layout.AgentApplicationControlAttested = [bool](
        $snapshotApplicationControl.Value
    )
    $Layout.ClaudeEffectivePolicyVerified = [bool](
        $snapshotClaudeEffective.Value
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.AgentApplicationControlAttestationPath `
        -PathType Leaf) {
        $restoredAttestation = Get-DefenseClawAgentApplicationControlAttestation `
            -Layout $Layout
        if ([bool]$restoredAttestation.agent_application_control_enforced -ne
            [bool]$Layout.AgentApplicationControlAttested) {
            throw 'restored application-control evidence does not match the transaction snapshot'
        }
        if ([bool]$restoredAttestation.claude_effective_policy_verified -ne
            [bool]$Layout.ClaudeEffectivePolicyVerified) {
            throw 'restored Claude effective-policy evidence does not match the transaction snapshot'
        }
    }
    $previousServices = @($snapshot.services | Microsoft.PowerShell.Core\Where-Object { [bool]$_.existed })
    if ($previousServices.Count -gt 0) {
        Set-DefenseClawManagedServices `
            -GatewayServiceName ([string]$snapshot.gateway_service) `
            -GuardianServiceName ([string]$snapshot.guardian_service) `
            -BrokerServiceName $Layout.BrokerServiceName `
            -BrokerPath $Layout.BrokerPath `
            -BrokerPipeName $Layout.BrokerPipeName `
            -BrokerAuthKeyPath $Layout.BrokerAuthKeyPath `
            -ProviderLibraryPath $Layout.ProviderLibraryPath `
            -BrokerLogPath $Layout.BrokerLogPath `
            -GatewayPath $Layout.GatewayPath `
            -ManifestPath $Layout.ManifestPath `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayLogPath $Layout.GatewayLogPath `
            -GuardianLogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -DeferAutomaticStart
        Set-DefenseClawManagedAcls -Layout $Layout -GatewayServiceName ([string]$snapshot.gateway_service)
    }
    # The fixed 32-byte correlation key is intentionally excluded from the
    # generic file-copy snapshot. Restore only its authenticated metadata on
    # the same inode while the staged/prior gateway service SID still resolves
    # and before any service can be removed or restarted.
    Restore-DefenseClawRedactionKeySecuritySnapshot `
        -Snapshot $snapshot `
        -Layout $Layout
    # An NT SERVICE principal stops resolving once its service is deleted.
    $rolledBackGatewaySID = ''
    foreach ($service in $snapshot.services) {
        if ([bool]$service.existed -or -not [string]::Equals(
                [string]$service.name,
                [string]$snapshot.gateway_service,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            continue
        }
        if (Test-DefenseClawServiceExists -Name ([string]$service.name)) {
            $rolledBackGatewaySID = Get-DefenseClawServiceSID `
                -ServiceName ([string]$service.name)
        }
    }
    # The fixed shared IPC directory is intentionally outside this scope's
    # StateRoot, so generic file rollback cannot remove the gateway ACE that a
    # fresh install published there. The authenticated transaction snapshot is
    # the authority for both the exact service name and its absent preimage.
    # Revoke while the transaction-created service is still authenticated,
    # disabled, and stopped; a crash re-entry where SCM deletion already won
    # uses the deterministic expected-absent lane. Only after that exact ACE is
    # gone may the service row and pending recovery evidence be retired.
    $gatewayServiceSnapshot = @(
        $snapshot.services |
            Microsoft.PowerShell.Core\Where-Object {
                [string]::Equals(
                    [string]$_.name,
                    [string]$snapshot.gateway_service,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($gatewayServiceSnapshot.Count -ne 1) {
        throw 'pending transaction has an invalid gateway service preimage'
    }
    if (-not [bool]$gatewayServiceSnapshot[0].existed) {
        if ([string]::IsNullOrWhiteSpace($rolledBackGatewaySID)) {
            [void](Revoke-DefenseClawManagedIPCServiceAccess `
                -Layout $Layout `
                -GatewayServiceName ([string]$snapshot.gateway_service))
        }
        else {
            [void](Revoke-DefenseClawManagedIPCServiceAccess `
                -Layout $Layout `
                -GatewayServiceName ([string]$snapshot.gateway_service) `
                -GatewayServiceSID $rolledBackGatewaySID `
                -TransactionCreatedServicePresent)
        }
    }
    foreach ($service in $snapshot.services) {
        if (-not [bool]$service.existed) {
            Remove-DefenseClawService -Name ([string]$service.name)
        }
    }
    # Shared ancestors outlive the transaction, so a deleted gateway gives its
    # traverse grant back. A surviving one keeps it.
    if (-not [string]::IsNullOrWhiteSpace($rolledBackGatewaySID)) {
        foreach ($ancestor in @($Layout.StateRootAncestors)) {
            Revoke-DefenseClawStateAncestorTraverse `
                -Path $ancestor `
                -GatewayServiceSID $rolledBackGatewaySID
        }
    }
    Remove-DefenseClawTransactionCreatedSharedDirectories `
        -Snapshot $snapshot `
        -Layout $Layout
    if (-not $DeferServiceRestart) {
        $activationRequired =
            Assert-DefenseClawRestoredTransactionReadyForActivation `
                -Snapshot $snapshot `
                -Layout $Layout
        if ($activationRequired) {
            Set-DefenseClawServiceActivationPhase `
                -State $snapshot `
                -Path $SnapshotPath `
                -Phase activating
            Start-DefenseClawTransactionServices `
                -Services $snapshot.services `
                -Layout $Layout `
                -ServicesQuiescedAt $restoreQuiescedAt `
                -TrustInProcessQuiescence `
                -GatewayServiceName ([string]$snapshot.gateway_service) `
                -GuardianServiceName ([string]$snapshot.guardian_service)
        }
    }
}

function Assert-DefenseClawRestoredTransactionReadyForActivation {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $states = Get-DefenseClawTransactionServiceStates `
        -Services $Snapshot.services `
        -GatewayServiceName ([string]$Snapshot.gateway_service) `
        -GuardianServiceName ([string]$Snapshot.guardian_service)
    $existing = @(
        $states.Values |
            Microsoft.PowerShell.Core\Where-Object { [bool]$_.existed }
    )
    if ($existing.Count -eq 0) {
        # Initial-install rollback has no prior service to reactivate. Files
        # and any transaction-created services were already removed above.
        return $false
    }
    $gatewayState = $states[[string]$Snapshot.gateway_service]
    $guardianState = $states[[string]$Snapshot.guardian_service]
    if (-not [bool]$gatewayState.existed -or -not [bool]$guardianState.existed) {
        throw 'refusing to reactivate a partially restored managed service set'
    }
    Assert-DefenseClawEnterpriseDeployment `
        -Layout $Layout `
        -GatewayServiceName ([string]$Snapshot.gateway_service) `
        -GuardianServiceName ([string]$Snapshot.guardian_service) `
        -ServicingTransaction
    return $true
}

function Start-DefenseClawTransactionServices {
    param(
        [Parameter(Mandatory)]$Services,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$ServicesQuiescedAt,
        [switch]$TrustInProcessQuiescence,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $states = Get-DefenseClawTransactionServiceStates `
        -Services $Services `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    # Reassert disabled and stopped before activation so a queued SCM failure
    # action cannot race recovery. Running+disabled is a valid pre-repair
    # snapshot, so services that must run are temporarily demand-started,
    # started guardian-first, and only then returned to exact recorded modes.
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    foreach ($name in @($GatewayServiceName, $brokerServiceName, $GuardianServiceName)) {
        if ([bool]$states[$name].existed) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($GuardianServiceName, $GatewayServiceName, $brokerServiceName)) {
        if ([bool]$states[$name].existed) {
            Stop-DefenseClawService -Name $name
        }
    }
    if (-not $TrustInProcessQuiescence) {
        # Direct/helper reuse and process-recovery paths cannot prove that the
        # supplied wall-clock timestamp predates no interrupted activation.
        # Their callers persist the fresh disabled+stopped point; waiting from
        # now is the conservative bounded fallback.
        $ServicesQuiescedAt = [DateTime]::UtcNow.ToString('o')
    }
    Wait-DefenseClawServiceFailureRestartQuiescence `
        -ServicesQuiescedAt $ServicesQuiescedAt `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $gateway = $states[$GatewayServiceName]
    $broker = $states[$brokerServiceName]
    $guardian = $states[$GuardianServiceName]
    $gatewayNeedsProtection = (
        [bool]$gateway.existed -and (
            [bool]$gateway.running -or
            [int]$gateway.start_mode -eq 2
        )
    )
    if ($gatewayNeedsProtection -and -not [bool]$guardian.existed) {
        throw 'refusing to reactivate gateway without its recorded guardian service'
    }
    if ($gatewayNeedsProtection -and [bool]$broker.existed -and
        -not ([bool]$broker.running -or [int]$broker.start_mode -eq 2)) {
        throw 'refusing to reactivate a broker-backed gateway without its recorded credential broker'
    }
    $brokerTemporarilyRequired = [bool]$broker.existed -and (
        [bool]$broker.running -or $gatewayNeedsProtection
    )
    if ($brokerTemporarilyRequired) {
        Set-DefenseClawServiceStartMode -Name $brokerServiceName -StartMode 3
        Start-DefenseClawService -Name $brokerServiceName
    }
    $guardianTemporarilyRequired = (
        [bool]$guardian.running -or $gatewayNeedsProtection
    )
    if ($guardianTemporarilyRequired) {
        Set-DefenseClawServiceStartMode `
            -Name $GuardianServiceName `
            -StartMode 3
        # A running SCM state is insufficient. Require a newly published
        # successful LocalSystem reconciliation while gateway is still
        # disabled, so a queued gateway restart cannot beat auto-heal.
        [void](Wait-DefenseClawFreshGuardianReconcile `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName)
    }
    if ([bool]$gateway.running) {
        Set-DefenseClawServiceStartMode `
            -Name $GatewayServiceName `
            -StartMode 3
        Start-DefenseClawService -Name $GatewayServiceName
        Wait-DefenseClawEnterpriseReadiness `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    if ([bool]$guardian.running) {
        # Guardian remains live while both exact boot policies are restored.
        Restore-DefenseClawTransactionServiceStartModes `
            -Services $Services `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    elseif ($guardianTemporarilyRequired) {
        # Preserve temporary protection until gateway runtime and boot policy
        # are exact, then return guardian to its recorded stopped state.
        if ([bool]$gateway.existed) {
            Set-DefenseClawServiceStartMode `
                -Name $GatewayServiceName `
                -StartMode ([int]$gateway.start_mode)
        }
        Stop-DefenseClawService -Name $GuardianServiceName
        Set-DefenseClawServiceStartMode `
            -Name $GuardianServiceName `
            -StartMode ([int]$guardian.start_mode)
    }
    else {
        Restore-DefenseClawTransactionServiceStartModes `
            -Services $Services `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6aunSc): reactivate the enumerator
    # too. Restore-DefenseClawTransactionServiceStartModes only restores
    # `existed=true` services from the pre-transaction snapshot; on a
    # fresh install the enumerator was `existed=false`, so it stays
    # disabled without this explicit start. On a snapshot rollback with
    # an existing enumerator, the Restore call above has already put it
    # back to its recorded start mode — the block below just brings it
    # LIVE if the recorded posture had it running.
    #
    # Edge case (CR PRRT_kwDORuAK-s6au6lY): a snapshot with
    # `running=true, start_mode=4` (running-while-disabled — legal
    # in Windows: sc.exe config can change start mode without
    # stopping the process) must ROUND-TRIP back to running-while-
    # disabled after rollback. Set-DefenseClawServiceStartMode 4
    # doesn't stop the process; but Start-DefenseClawService on a
    # disabled service throws. So the sequence is:
    #   1. Temporarily set demand-start (mode 3).
    #   2. Start-Service.
    #   3. Set disabled (mode 4) — SCM allows this while running.
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $enumeratorState = $states[$enumeratorServiceName]
    $enumeratorService = Get-DefenseClawServiceChecked `
        -Name $enumeratorServiceName
    if ($null -ne $enumeratorService) {
        $enumeratorRecordedExisted = $null -ne $enumeratorState -and [bool]$enumeratorState.existed
        $enumeratorTargetStartMode = if ($enumeratorRecordedExisted) {
            [int]$enumeratorState.start_mode
        }
        else {
            # Fresh install: promote to auto-start.
            2
        }
        # `should run` = recorded-running OR fresh install (we just
        # created the service and want it live now).
        $enumeratorShouldRun = if (-not $enumeratorRecordedExisted) {
            $true
        }
        else {
            [bool]$enumeratorState.running
        }
        if ($enumeratorShouldRun -and $enumeratorTargetStartMode -eq 4) {
            # Running-while-disabled round-trip: demand-start,
            # start, disable while running.
            Set-DefenseClawServiceStartMode `
                -Name $enumeratorServiceName `
                -StartMode 3
            Start-DefenseClawService -Name $enumeratorServiceName
            Set-DefenseClawServiceStartMode `
                -Name $enumeratorServiceName `
                -StartMode 4
        }
        else {
            Set-DefenseClawServiceStartMode `
                -Name $enumeratorServiceName `
                -StartMode $enumeratorTargetStartMode
            if ($enumeratorShouldRun -and $enumeratorTargetStartMode -in @(2, 3)) {
                Start-DefenseClawService -Name $enumeratorServiceName
            }
        }
    }
}

function Restore-DefenseClawTransactionWithManagedHooksRollback {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    # Read the recovery markers before generic restore. New uninstall
    # transactions exclude the live journal from snapshot.files, so a full
    # restore can safely recover a deleted gateway binary without destroying
    # the captured/prepared Claude preimage. Services remain stopped until the
    # hidden rollback verifies the original machine enrollment.
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $prepared = $snapshot.PSObject.Properties[
        'managed_hooks_teardown_prepared'
    ]
    if ($null -eq $prepared -or $prepared.Value -isnot [bool]) {
        throw 'pending transaction has an invalid managed-hook teardown state'
    }
    $preservedProperty = $snapshot.PSObject.Properties[
        'managed_hooks_teardown_journal_preserved'
    ]
    $journalPreserved = (
        $null -ne $preservedProperty -and
        $preservedProperty.Value -is [bool] -and
        [bool]$preservedProperty.Value
    )
    $journalExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -PathType Leaf
    if ($journalPreserved -and $journalExists) {
        Assert-DefenseClawNoReparsePath `
            -Path $Layout.ManagedHooksTeardownJournalPath
    }
    $journalChanged = $false
    if ($journalPreserved) {
        $preimageExistedProperty = $snapshot.PSObject.Properties[
            'managed_hooks_teardown_journal_preimage_existed'
        ]
        $preimageHashProperty = $snapshot.PSObject.Properties[
            'managed_hooks_teardown_journal_preimage_sha256'
        ]
        if ($null -eq $preimageExistedProperty -or
            $preimageExistedProperty.Value -isnot [bool] -or
            $null -eq $preimageHashProperty) {
            throw 'pending transaction has invalid managed-hook journal preimage markers'
        }
        $preimageExisted = [bool]$preimageExistedProperty.Value
        $preimageHash = [string]$preimageHashProperty.Value
        if ($preimageExisted -ne [bool]$journalExists) {
            $journalChanged = $true
        }
        elseif ($journalExists) {
            $currentHash = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $journalChanged = -not [string]::Equals(
                $currentHash,
                $preimageHash,
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    }
    # A preexisting prepared journal can remain byte-identical when hidden
    # prepare verifies its already-clean state and returns idempotently. A
    # crash before the PowerShell prepared marker is then indistinguishable by
    # hash alone. Treat every preserved live journal as rollback work; also
    # retain the changed check so journal deletion fails closed. Hidden
    # rollback authenticates the journal and is idempotent for rolled_back.
    $rollbackRequired = [bool]$prepared.Value -or (
        $journalPreserved -and ($journalExists -or $journalChanged)
    )
    Restore-DefenseClawTransaction `
        -SnapshotPath $SnapshotPath `
        -Layout $Layout `
        -DeferServiceRestart:$rollbackRequired
    if ($rollbackRequired) {
        [void](Invoke-DefenseClawManagedHooksTeardownCommand `
            -Layout $Layout `
            -GatewayServiceName ([string]$snapshot.gateway_service) `
            -Action rollback)
        $snapshot = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $SnapshotPath `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $quiescenceProperty = $snapshot.PSObject.Properties[
            'services_disabled_and_stopped_at'
        ]
        if ($null -eq $quiescenceProperty) {
            throw 'restored transaction did not retain its service quiescence barrier'
        }
        $restoreQuiescedAt = (
            ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
                -Value $quiescenceProperty.Value
        ).ToString('o')
        $activationRequired =
            Assert-DefenseClawRestoredTransactionReadyForActivation `
                -Snapshot $snapshot `
                -Layout $Layout
        if ($activationRequired) {
            Set-DefenseClawServiceActivationPhase `
                -State $snapshot `
                -Path $SnapshotPath `
                -Phase activating
            Start-DefenseClawTransactionServices `
                -Services $snapshot.services `
                -Layout $Layout `
                -ServicesQuiescedAt $restoreQuiescedAt `
                -TrustInProcessQuiescence `
                -GatewayServiceName ([string]$snapshot.gateway_service) `
                -GuardianServiceName ([string]$snapshot.guardian_service)
        }
    }
    return $snapshot
}

function Get-DefenseClawInstallRollbackIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Required
    )
    $path = Assert-DefenseClawDescendant `
        -Path ([string]$Layout.InstallRollbackIntentPath) `
        -Root ([string]$Layout.LifecycleLockDirectory) `
        -Label 'fresh-install rollback intent'
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $path
    )
    if ($null -eq $captured) {
        if ($Required) {
            throw 'authenticated fresh-install rollback intent is missing'
        }
        return $null
    }
    $capturedIdentity = [string]$captured.Identity
    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $path `
        -Force
    if ([int64]$item.Length -gt 3145728) {
        throw 'fresh-install rollback intent exceeds the 3145728-byte limit'
    }
    $expectedAcl = New-DefenseClawCanonicalPathAcl `
        -IsDirectory:$false `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $path `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$captured.SecurityDescriptor,
            0
        )) `
        -Expected $expectedAcl
    try {
        $intent = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $path `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse authenticated fresh-install rollback intent: $($_.Exception.Message)"
    }
    $after = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $path
    )
    if ($null -eq $after -or
        [string]$after.Identity -cne $capturedIdentity) {
        throw 'fresh-install rollback intent identity changed while it was authenticated'
    }
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $path `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$after.SecurityDescriptor,
            0
        )) `
        -Expected $expectedAcl
    $schema = $intent.PSObject.Properties['schema_version']
    if ($null -eq $schema -or
        $schema.Value -is [bool] -or
        [Convert]::ToInt64($schema.Value) -ne 2 -or
        [string]$intent.phase -notin @(
            'preparing_layout',
            'rollback',
            'committed'
        ) -or
        [string]$intent.scope_sha256 -cne
            [string]$Layout.PurgeScopeSHA256) {
        throw 'authenticated fresh-install rollback intent has invalid schema, phase, or scope'
    }
    foreach ($binding in @(
        @('install_root', $Layout.InstallRoot),
        @('state_root', $Layout.StateRoot),
        @('gateway_service', $GatewayServiceName),
        @('guardian_service', $GuardianServiceName)
    )) {
        $property = $intent.PSObject.Properties[[string]$binding[0]]
        if ($null -eq $property -or
            -not [string]::Equals(
                [string]$property.Value,
                [string]$binding[1],
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "authenticated fresh-install rollback intent does not match $($binding[0])"
        }
    }
    $createdAny = $false
    foreach ($prefix in @('install_root', 'state_root')) {
        $created = $intent.PSObject.Properties["${prefix}_created"]
        $identity = $intent.PSObject.Properties["${prefix}_identity"]
        $baselineAbsent = $intent.PSObject.Properties[
            "${prefix}_baseline_absent"
        ]
        $creationState = $intent.PSObject.Properties[
            "${prefix}_creation_state"
        ]
        if ($null -eq $created -or
            $created.Value -isnot [bool] -or
            $null -eq $baselineAbsent -or
            $baselineAbsent.Value -isnot [bool] -or
            $null -eq $creationState -or
            [string]$creationState.Value -notin @(
                'planned',
                'staged',
                'canonical',
                'existing'
            ) -or
            $null -eq $identity -or
            (-not [string]::IsNullOrWhiteSpace([string]$identity.Value) -and
                [string]$identity.Value -cnotmatch
                    '^[0-9a-f]{8}:[0-9a-f]{16}$')) {
            throw "authenticated fresh-install rollback intent has invalid $prefix state"
        }
        if ([bool]$created.Value -ne
            ([string]$creationState.Value -in @('staged', 'canonical')) -or
            ([string]$creationState.Value -ceq 'planned' -and
                -not [bool]$baselineAbsent.Value) -or
            ([string]$creationState.Value -ceq 'existing' -and
                ([bool]$created.Value -or
                    [bool]$baselineAbsent.Value))) {
            throw "authenticated fresh-install rollback intent has inconsistent $prefix creation state"
        }
        if (([string]$creationState.Value -ceq 'planned') -ne
            [string]::IsNullOrWhiteSpace([string]$identity.Value)) {
            throw "authenticated fresh-install rollback intent has an invalid $prefix identity transition"
        }
        $marker = $intent.PSObject.Properties["${prefix}_marker_sid"]
        if ($null -eq $marker -or
            ([bool]$baselineAbsent.Value -and
                [string]$marker.Value -cnotmatch
                    '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') -or
            (-not [bool]$baselineAbsent.Value -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$marker.Value
                ))) {
            throw "authenticated fresh-install rollback intent has invalid $prefix marker authority"
        }
        $createdAny = $createdAny -or [bool]$created.Value
    }
    $runtimeClaims = $intent.PSObject.Properties[
        'created_target_runtime_roots'
    ]
    if ($null -eq $runtimeClaims) {
        throw 'authenticated fresh-install rollback intent is missing target runtime claims'
    }
    $runtimePlan = $intent.PSObject.Properties['target_runtime_plan']
    if ($null -ne $runtimePlan) {
        [void](Assert-DefenseClawTargetRuntimePlan `
            -Plan $runtimePlan.Value `
            -Layout $Layout)
        $runtimePlanPath = $intent.PSObject.Properties[
            'target_runtime_plan_path'
        ]
        if ($null -eq $runtimePlanPath -or
            [string]::IsNullOrWhiteSpace([string]$intent.snapshot_path)) {
            throw 'authenticated install receipt lost target runtime plan binding'
        }
        [void](Assert-DefenseClawDescendant `
            -Path ([string]$runtimePlanPath.Value) `
            -Root ([IO.Path]::GetDirectoryName(
                [string]$intent.snapshot_path
            )) `
            -Label 'target runtime plan receipt binding')
    }
    if (@($runtimeClaims.Value).Count -gt 128 -or
        (@($runtimeClaims.Value).Count -gt 0 -and $null -eq $runtimePlan)) {
        throw 'authenticated install receipt has invalid target runtime claims'
    }
    [void](Assert-DefenseClawTargetRuntimeReport `
        -Report ([pscustomobject]@{
            schema_version = 1
            action = 'stage'
            ok = $true
            claims = @($runtimeClaims.Value)
        }) `
        -Action stage `
        -Plan $(if ($null -eq $runtimePlan) {
            $null
        }
        else {
            $runtimePlan.Value
        }) `
        -JournalProjection)
    $snapshotPath = $intent.PSObject.Properties['snapshot_path']
    if ($null -eq $snapshotPath) {
        throw 'authenticated fresh-install rollback intent is missing its transaction binding'
    }
    if ([string]$intent.phase -in @('rollback', 'committed') -and
        [string]::IsNullOrWhiteSpace([string]$snapshotPath.Value)) {
        throw 'authenticated fresh-install rollback intent phase requires a transaction binding'
    }
    foreach ($name in @('snapshot_identity', 'snapshot_sha256')) {
        if ($null -eq $intent.PSObject.Properties[$name]) {
            throw "authenticated fresh-install rollback intent is missing $name"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$intent.snapshot_identity) -and
        [string]$intent.snapshot_identity -cnotmatch
            '^[0-9a-f]{8}:[0-9a-f]{16}$') {
        throw 'authenticated fresh-install rollback intent has invalid snapshot identity'
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$intent.snapshot_sha256) -and
        [string]$intent.snapshot_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'authenticated fresh-install rollback intent has invalid snapshot digest'
    }
    $gatewaySID = $intent.PSObject.Properties['gateway_service_sid']
    if ($null -eq $gatewaySID -or
        (-not [string]::IsNullOrWhiteSpace([string]$gatewaySID.Value) -and
            [string]$gatewaySID.Value -cnotmatch '^S-1-5-80-(?:[0-9]+-){4}[0-9]+$')) {
        throw 'authenticated fresh-install rollback intent has invalid gateway service SID'
    }
    if ([string]$intent.phase -ceq 'committed' -and
        ([string]::IsNullOrWhiteSpace([string]$intent.snapshot_identity) -or
            [string]::IsNullOrWhiteSpace([string]$intent.snapshot_sha256) -or
            [string]::IsNullOrWhiteSpace([string]$gatewaySID.Value))) {
        throw 'committed install receipt lacks exact transaction or service authority'
    }
    return $intent
}

function ConvertTo-DefenseClawInstallRollbackIntentJson {
    param([Parameter(Mandatory)]$Intent)
    # The external receipt embeds at most one 1 MiB runtime plan and the
    # claims projection of at most one 1 MiB report. Keep the representation
    # compressed and enforce the same byte bound before publication and on
    # every authenticated read, so a valid journal update cannot publish a
    # receipt that crash recovery subsequently refuses to consume.
    $json = $Intent |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 24 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 3145728) {
        throw 'fresh-install rollback intent exceeds the 3145728-byte limit'
    }
    return $json
}

function Write-DefenseClawInstallRollbackIntent {
    param(
        [Parameter(Mandatory)]$Intent,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $json = ConvertTo-DefenseClawInstallRollbackIntentJson -Intent $Intent
    Write-DefenseClawProtectedTextAtomic `
        -Value $json `
        -Path ([string]$Layout.InstallRollbackIntentPath) `
        -RequiredRoot ([string]$Layout.LifecycleLockDirectory)
    return Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
}

function New-DefenseClawManagedRootMarkerSID {
    $bytes = [byte[]]::new(16)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $parts = [Collections.Generic.List[string]]::new()
    for ($offset = 0; $offset -lt $bytes.Length; $offset += 4) {
        $value = [BitConverter]::ToUInt32($bytes, $offset)
        if ($value -eq 0) {
            $value = 1
        }
        $parts.Add($value.ToString(
            [Globalization.CultureInfo]::InvariantCulture
        ))
    }
    return 'S-1-5-21-' + ($parts -join '-')
}

function New-DefenseClawInstallPreparationIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        $InstallRootBaseline,
        $StateRootBaseline
    )
    $existing = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -ne $existing) {
        throw 'refusing to replace an authenticated install preparation receipt'
    }
    $intent = [ordered]@{
        schema_version = 2
        phase = 'preparing_layout'
        scope_sha256 = [string]$Layout.PurgeScopeSHA256
        install_root = [string]$Layout.InstallRoot
        state_root = [string]$Layout.StateRoot
        gateway_service = $GatewayServiceName
        guardian_service = $GuardianServiceName
        install_root_created = $false
        install_root_baseline_absent = [bool]($null -eq $InstallRootBaseline)
        install_root_creation_state = $(if ($null -eq $InstallRootBaseline) {
            'planned'
        }
        else {
            'existing'
        })
        install_root_marker_sid = $(if ($null -eq $InstallRootBaseline) {
            New-DefenseClawManagedRootMarkerSID
        }
        else {
            ''
        })
        install_root_identity = $(if ($null -eq $InstallRootBaseline) {
            ''
        }
        else {
            [string]$InstallRootBaseline.Identity
        })
        state_root_created = $false
        state_root_baseline_absent = [bool]($null -eq $StateRootBaseline)
        state_root_creation_state = $(if ($null -eq $StateRootBaseline) {
            'planned'
        }
        else {
            'existing'
        })
        state_root_marker_sid = $(if ($null -eq $StateRootBaseline) {
            New-DefenseClawManagedRootMarkerSID
        }
        else {
            ''
        })
        state_root_identity = $(if ($null -eq $StateRootBaseline) {
            ''
        }
        else {
            [string]$StateRootBaseline.Identity
        })
        snapshot_path = ''
        snapshot_identity = ''
        snapshot_sha256 = ''
        gateway_service_sid = ''
        created_target_runtime_roots = @()
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    return Write-DefenseClawInstallRollbackIntent `
        -Intent $intent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
}

function Set-DefenseClawInstallPreparationRootIdentity {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)]
        [ValidateSet('install_root', 'state_root')]
        [string]$Root,
        [Parameter(Mandatory)]
        [ValidateSet('staged', 'canonical', 'existing')]
        [string]$State
    )
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    if ([string]$intent.phase -cne 'preparing_layout') {
        throw "cannot record $Root identity after install preparation ended"
    }
    $path = if ($Root -eq 'install_root') {
        [string]$Layout.InstallRoot
    }
    else {
        [string]$Layout.StateRoot
    }
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
        $path
    )
    if ($null -eq $captured) {
        throw "install preparation did not create $Root"
    }
    $recorded = [string]$intent."${Root}_identity"
    if (-not [string]::IsNullOrWhiteSpace($recorded) -and
        $recorded -cne [string]$captured.Identity) {
        throw "install preparation $Root identity changed"
    }
    $baselineAbsent = [bool]$intent."${Root}_baseline_absent"
    $created = $State -in @('staged', 'canonical')
    if (($created -and -not $baselineAbsent) -or
        (-not $created -and $baselineAbsent)) {
        throw "install preparation $Root state disagrees with its absence baseline"
    }
    $intent."${Root}_identity" = [string]$captured.Identity
    $intent."${Root}_created" = [bool]$created
    $intent."${Root}_creation_state" = $State
    return Write-DefenseClawInstallRollbackIntent `
        -Intent $intent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
}

function Set-DefenseClawInstallPreparationTransactionBinding {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)][string]$SnapshotPath
    )
    $snapshot = Assert-DefenseClawDescendant `
        -Path $SnapshotPath `
        -Root ([string]$Layout.TransactionsDirectory) `
        -Label 'install preparation transaction binding'
    Assert-DefenseClawNoReparsePath -Path $snapshot
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -eq $intent) {
        return $null
    }
    if ([string]$intent.phase -cne 'preparing_layout') {
        throw 'cannot bind a transaction after install preparation ended'
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$intent.snapshot_path) -and
        -not [string]::Equals(
            [string]$intent.snapshot_path,
            $snapshot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'install preparation is already bound to another transaction'
    }
    $intent.snapshot_path = $snapshot
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $snapshot
    )
    if ($null -eq $captured) {
        throw 'install preparation transaction snapshot disappeared before binding'
    }
    $digest = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $snapshot `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $after = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $snapshot
    )
    if ($null -eq $after -or
        [string]$after.Identity -cne [string]$captured.Identity) {
        throw 'install preparation transaction snapshot changed while binding'
    }
    $intent.snapshot_identity = [string]$captured.Identity
    $intent.snapshot_sha256 = $digest
    return Write-DefenseClawInstallRollbackIntent `
        -Intent $intent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
}

function Publish-DefenseClawInstallRollbackIntent {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $baselineProperties = @(
        $Snapshot.PSObject.Properties['install_root_created'],
        $Snapshot.PSObject.Properties['install_root_identity'],
        $Snapshot.PSObject.Properties['state_root_created'],
        $Snapshot.PSObject.Properties['state_root_identity']
    )
    if (@($baselineProperties | Microsoft.PowerShell.Core\Where-Object {
                $null -ne $_
            }).Count -eq 0) {
        # Transactions written by a prior release did not claim the managed
        # roots. Preserve their historical rollback behavior rather than infer
        # destructive ownership from mere path presence.
        return $null
    }
    if (@($baselineProperties | Microsoft.PowerShell.Core\Where-Object {
                $null -ne $_
            }).Count -ne $baselineProperties.Count) {
        throw 'pending transaction has incomplete managed-root baseline state'
    }
    $claims = [ordered]@{}
    $createdAny = $false
    foreach ($prefix in @('install_root', 'state_root')) {
        $created = $Snapshot.PSObject.Properties["${prefix}_created"]
        $identity = $Snapshot.PSObject.Properties["${prefix}_identity"]
        if ($null -eq $created -or
            $created.Value -isnot [bool] -or
            $null -eq $identity -or
            [string]$identity.Value -cnotmatch
                '^[0-9a-f]{8}:[0-9a-f]{16}$') {
            throw "pending transaction has invalid $prefix baseline state"
        }
        $claims["${prefix}_created"] = [bool]$created.Value
        $claims["${prefix}_identity"] = [string]$identity.Value
        $createdAny = $createdAny -or [bool]$created.Value
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames `
            -GatewayServiceName ([string]$Snapshot.gateway_service) `
            -GuardianServiceName ([string]$Snapshot.guardian_service))) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "refusing fresh-install root cleanup while service exists: $name"
        }
    }
    $runtimeRootsProperty = $Snapshot.PSObject.Properties[
        'created_target_runtime_roots'
    ]
    $runtimeRoots = if ($null -eq $runtimeRootsProperty) {
        @()
    }
    else {
        @($runtimeRootsProperty.Value)
    }
    $createdAny = $createdAny -or $runtimeRoots.Count -gt 0
    $existing = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName ([string]$Snapshot.gateway_service) `
        -GuardianServiceName ([string]$Snapshot.guardian_service)
    if (-not $createdAny -and $null -eq $existing) {
        return $null
    }
    $snapshotPath = if ($null -ne $existing -and
        -not [string]::IsNullOrWhiteSpace([string]$existing.snapshot_path)) {
        [string]$existing.snapshot_path
    }
    else {
        Microsoft.PowerShell.Management\Join-Path `
            ([string]$Snapshot.directory) `
            'snapshot.json'
    }
    $intent = [ordered]@{
        schema_version = 2
        phase = 'rollback'
        scope_sha256 = [string]$Layout.PurgeScopeSHA256
        install_root = [string]$Layout.InstallRoot
        state_root = [string]$Layout.StateRoot
        gateway_service = [string]$Snapshot.gateway_service
        guardian_service = [string]$Snapshot.guardian_service
        install_root_created = [bool]$claims.install_root_created
        install_root_baseline_absent = $(if ($null -ne $existing) {
            [bool]$existing.install_root_baseline_absent
        }
        else {
            [bool]$claims.install_root_created
        })
        install_root_creation_state = $(if ([bool]$claims.install_root_created) {
            'canonical'
        }
        else {
            'existing'
        })
        install_root_marker_sid = $(if ($null -ne $existing) {
            [string]$existing.install_root_marker_sid
        }
        elseif ([bool]$claims.install_root_created) {
            New-DefenseClawManagedRootMarkerSID
        }
        else {
            ''
        })
        install_root_identity = [string]$claims.install_root_identity
        state_root_created = [bool]$claims.state_root_created
        state_root_baseline_absent = $(if ($null -ne $existing) {
            [bool]$existing.state_root_baseline_absent
        }
        else {
            [bool]$claims.state_root_created
        })
        state_root_creation_state = $(if ([bool]$claims.state_root_created) {
            'canonical'
        }
        else {
            'existing'
        })
        state_root_marker_sid = $(if ($null -ne $existing) {
            [string]$existing.state_root_marker_sid
        }
        elseif ([bool]$claims.state_root_created) {
            New-DefenseClawManagedRootMarkerSID
        }
        else {
            ''
        })
        state_root_identity = [string]$claims.state_root_identity
        snapshot_path = $snapshotPath
        snapshot_identity = $(if ($null -ne $existing) {
            [string]$existing.snapshot_identity
        }
        else {
            ''
        })
        snapshot_sha256 = $(if ($null -ne $existing) {
            [string]$existing.snapshot_sha256
        }
        else {
            ''
        })
        gateway_service_sid = ''
        created_target_runtime_roots = @($runtimeRoots)
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    if ($null -ne $existing) {
        if ([string]$existing.phase -ceq 'committed') {
            throw 'refusing to replace committed install authority with rollback'
        }
        foreach ($name in @(
            'install_root_created',
            'install_root_baseline_absent',
            'install_root_identity',
            'install_root_marker_sid',
            'state_root_created',
            'state_root_baseline_absent',
            'state_root_identity',
            'state_root_marker_sid'
        )) {
            if ([string]$existing.$name -cne [string]$intent[$name]) {
                throw "existing fresh-install rollback intent disagrees on $name"
            }
        }
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$existing.snapshot_path
            ) -and
            -not [string]::Equals(
                [string]$existing.snapshot_path,
                [string]$intent.snapshot_path,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'existing fresh-install rollback intent disagrees on transaction binding'
        }
    }
    return Write-DefenseClawInstallRollbackIntent `
        -Intent $intent `
        -Layout $Layout `
        -GatewayServiceName ([string]$Snapshot.gateway_service) `
        -GuardianServiceName ([string]$Snapshot.guardian_service)
}

function Assert-DefenseClawInstallRollbackRootDescriptor {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Current,
        [Parameter(Mandatory)]
        [ValidateSet('planned', 'staged', 'canonical')]
        [string]$CreationState,
        [Parameter(Mandatory)][string]$MarkerSID,
        [Parameter(Mandatory)]
        [ValidateSet('InstallDirectory', 'AdminDirectory')]
        [string]$ExpectedKind
    )
    if ($CreationState -ceq 'planned') {
        [void](Assert-DefenseClawManagedRootStagingAcl `
            -Path $Path `
            -MarkerSID $MarkerSID)
        return
    }
    if ($CreationState -ceq 'staged') {
        try {
            [void](Assert-DefenseClawManagedRootStagingAcl `
                -Path $Path `
                -MarkerSID $MarkerSID)
            return
        }
        catch {
            # A crash may occur after the exact inode is canonicalized but
            # before the receipt advances from staged to canonical. The
            # recorded identity is already durable, so accept only the exact
            # final root descriptor as the alternate crash state.
        }
    }
    $expectedAcl = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $true `
        -Kind $ExpectedKind `
        -GatewayServiceSID $script:AdministratorsSID
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $Path `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$Current.SecurityDescriptor,
            0
        )) `
        -Expected $expectedAcl
}

function Complete-DefenseClawInstallRollbackIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    if ([string]$intent.phase -ceq 'committed') {
        throw 'refusing to roll back a committed install receipt'
    }
    if (@($intent.created_target_runtime_roots |
            Microsoft.PowerShell.Core\Where-Object {
                [bool]$_.created -and [string]$_.state -cne 'absent'
            }).Count -ne 0) {
        throw (
            'target runtime cleanup must complete through the protected ' +
            'pending transaction before machine-root cleanup'
        )
    }
    $managedServiceNames = @(Get-DefenseClawManagedServiceNames `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName)
    Assert-DefenseClawServicesAbsentChecked `
        -Names $managedServiceNames `
        -Operation 'refusing fresh-install root cleanup'
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    foreach ($claim in @(
        @(
            'InstallRoot',
            'install_root_created',
            'install_root_identity',
            $script:ProgramFiles
        ),
        @(
            'StateRoot',
            'state_root_created',
            'state_root_identity',
            $script:ProgramData
        )
    )) {
        $creationState = [string]$intent.(
            ([string]$claim[1]).Replace('_created', '_creation_state')
        )
        if ($creationState -ceq 'planned') {
            $plannedPath = [string]$Layout[[string]$claim[0]]
            $planned =
                $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                    $plannedPath
                )
            if ($null -eq $planned) {
                continue
            }
            [void](Assert-DefenseClawManagedRootStagingAcl `
                -Path $plannedPath `
                -MarkerSID ([string]$intent.(
                    ([string]$claim[1]).Replace(
                        '_created',
                        '_marker_sid'
                    )
                )))
            $intent.([string]$claim[1]) = $true
            $intent.([string]$claim[2]) = [string]$planned.Identity
        }
        if (-not [bool]$intent.([string]$claim[1])) {
            continue
        }
        $path = [string]$Layout[[string]$claim[0]]
        $current = $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
            $path
        )
        if ($null -eq $current) {
            continue
        }
        if ([string]$current.Identity -cne
            [string]$intent.([string]$claim[2])) {
            throw "transaction-created $($claim[0]) identity changed before rollback cleanup"
        }
        $expectedKind = if ([string]$claim[0] -ceq 'InstallRoot') {
            'InstallDirectory'
        }
        else {
            'AdminDirectory'
        }
        Assert-DefenseClawInstallRollbackRootDescriptor `
            -Path $path `
            -Current $current `
            -CreationState $creationState `
            -MarkerSID ([string]$intent.(
                ([string]$claim[1]).Replace(
                    '_created',
                    '_marker_sid'
                )
            )) `
            -ExpectedKind $expectedKind
        Assert-DefenseClawManagedTreeNoReparse -Root $path
        Remove-DefenseClawManagedTree `
            -Path $path `
            -RequiredBase ([string]$claim[3]) `
            -Label ([string]$claim[0])
        if ($null -ne
            $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                $path
            )) {
            throw "transaction-created $($claim[0]) survived rollback cleanup"
        }
    }
    Assert-DefenseClawServicesAbsentChecked `
        -Names $managedServiceNames `
        -Operation 'fresh-install root cleanup completed'
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath ([string]$Layout.InstallRollbackIntentPath) `
        -Force
    if ($null -ne
        $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
            [string]$Layout.InstallRollbackIntentPath
        )) {
        throw 'fresh-install rollback intent survived completed cleanup'
    }
}

function Set-DefenseClawInstallRollbackIntentCommitted {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)][string]$SnapshotPath
    )
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -eq $intent) {
        return $null
    }
    if ([string]$intent.phase -cne 'preparing_layout') {
        throw 'install preparation receipt cannot enter committed phase'
    }
    if (-not [string]::Equals(
            [string]$intent.snapshot_path,
            [IO.Path]::GetFullPath($SnapshotPath),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'install preparation receipt is bound to another transaction'
    }
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        [string]$intent.snapshot_path
    )
    if ($null -eq $captured) {
        throw 'install transaction disappeared before commit'
    }
    $digest = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath ([string]$intent.snapshot_path) `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    # The protected transaction snapshot is intentionally republished as its
    # lifecycle phase and rollback claims advance. Bind the final verified
    # inode+digest at the commit point; earlier identities remain useful only
    # for detecting races inside each individual authenticated read/update.
    $intent.snapshot_identity = [string]$captured.Identity
    $intent.snapshot_sha256 = $digest
    $gatewaySID = Get-DefenseClawServiceSID `
        -ServiceName $GatewayServiceName
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    $gatewayMode = Get-DefenseClawServiceStartMode -Name $GatewayServiceName
    if ($gatewayMode -eq 2) {
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -RequireReadiness
    }
    elseif ($gatewayMode -eq 4) {
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ServicingTransaction
    }
    else {
        throw 'install commit requires either verified auto-start or disabled servicing state'
    }
    $intent.gateway_service_sid = $gatewaySID
    $intent.phase = 'committed'
    $intent.committed_at = [DateTime]::UtcNow.ToString('o')
    return Write-DefenseClawInstallRollbackIntent `
        -Intent $intent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
}

function Complete-DefenseClawCommittedInstallIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    if ([string]$intent.phase -cne 'committed') {
        throw 'install receipt is not committed'
    }
    if (-not (Test-DefenseClawServiceExists -Name $GatewayServiceName) -or
        (Get-DefenseClawServiceSID -ServiceName $GatewayServiceName) -cne
            [string]$intent.gateway_service_sid) {
        throw 'committed install gateway service identity changed'
    }
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    $gatewayMode = Get-DefenseClawServiceStartMode -Name $GatewayServiceName
    if ($gatewayMode -eq 2) {
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -RequireReadiness
    }
    elseif ($gatewayMode -eq 4) {
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ServicingTransaction
    }
    else {
        throw 'committed install has an invalid gateway start mode'
    }
    $snapshot = [string]$intent.snapshot_path
    $directory = [IO.Path]::GetDirectoryName($snapshot)
    [void](Assert-DefenseClawDescendant `
        -Path $snapshot `
        -Root ([string]$Layout.TransactionsDirectory) `
        -Label 'committed install transaction snapshot')
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $captured = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $snapshot
    )
    if ($null -ne $captured) {
        if ([string]$captured.Identity -cne
            [string]$intent.snapshot_identity) {
            throw 'committed install transaction identity changed'
        }
        $digest = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $snapshot `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($digest -cne [string]$intent.snapshot_sha256) {
            throw 'committed install transaction content changed'
        }
    }
    $pending =
        $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
            [string]$Layout.PendingPath
        )
    if ($null -ne $pending) {
        if ($null -eq $captured) {
            throw 'committed install pending record survived without its transaction snapshot'
        }
        $pendingValue = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath ([string]$Layout.PendingPath) `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if (-not [string]::Equals(
                [string]$pendingValue.snapshot,
                $snapshot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'committed install pending record names another transaction'
        }
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath ([string]$Layout.PendingPath) `
            -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $directory `
            -PathType Container) {
        Assert-DefenseClawNoReparsePath -Path $directory
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $directory `
            -Recurse `
            -Force
    }
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath ([string]$Layout.InstallRollbackIntentPath) `
        -Force
    if ($null -ne
        $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
            [string]$Layout.InstallRollbackIntentPath
        )) {
        throw 'committed install receipt survived retirement'
    }
}

function Complete-DefenseClawTransaction {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [switch]$Rollback
    )
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $transactionSnapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $rollbackIntent = $null
    $committedIntent = $null
    if ($Rollback) {
        $rollbackIntent = Publish-DefenseClawInstallRollbackIntent `
            -Snapshot $transactionSnapshot `
            -Layout $Layout
    }
    else {
        $committedIntent = Set-DefenseClawInstallRollbackIntentCommitted `
            -Layout $Layout `
            -GatewayServiceName ([string]$transactionSnapshot.gateway_service) `
            -GuardianServiceName ([string]$transactionSnapshot.guardian_service) `
            -SnapshotPath $SnapshotPath
    }
    if ($null -ne $committedIntent) {
        Complete-DefenseClawCommittedInstallIntent `
            -Layout $Layout `
            -GatewayServiceName ([string]$committedIntent.gateway_service) `
            -GuardianServiceName ([string]$committedIntent.guardian_service)
        return
    }
    $directory = [IO.Path]::GetDirectoryName($SnapshotPath)
    Assert-DefenseClawDescendant -Path $directory -Root $Layout.StateRoot -Label 'completed transaction' | Microsoft.PowerShell.Core\Out-Null
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath -PathType Leaf) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Layout.PendingPath -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory -PathType Container) {
        Assert-DefenseClawNoReparsePath -Path $directory
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $directory -Recurse -Force
    }
    if ($null -ne $rollbackIntent) {
        Complete-DefenseClawInstallRollbackIntent `
            -Layout $Layout `
            -GatewayServiceName ([string]$rollbackIntent.gateway_service) `
            -GuardianServiceName ([string]$rollbackIntent.guardian_service)
    }
}

function Remove-DefenseClawCommittedManagedHooksTeardownJournal {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PendingPath) {
        throw 'refusing to retire the managed-hook teardown journal while a lifecycle transaction is pending'
    }
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
        throw 'refusing to retire the managed-hook teardown journal before uninstall is durably committed'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.HookPath) {
        throw 'refusing to retire the managed-hook teardown journal while the owned hook binary still exists'
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath)) {
        return $false
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -PathType Leaf)) {
        throw 'managed-hook teardown journal is not a regular file'
    }
    Assert-DefenseClawDescendant `
        -Path $Layout.ManagedHooksTeardownJournalPath `
        -Root $Layout.StateRoot `
        -Label 'committed managed-hook teardown journal' |
        Microsoft.PowerShell.Core\Out-Null
    Assert-DefenseClawNoReparsePath `
        -Path $Layout.ManagedHooksTeardownJournalPath
    $journal = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -Force
    if ([int64]$journal.Length -gt 4194304) {
        throw 'managed-hook teardown journal exceeds the 4194304-byte retirement limit'
    }
    Assert-DefenseClawPathAcl `
        -Path $Layout.ManagedHooksTeardownJournalPath `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -AllowInheritance `
        -RejectUntrustedRead
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -Force
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath) {
        throw 'managed-hook teardown journal survived committed retirement'
    }
    return $true
}

function Recover-DefenseClawQuiescingIntent {
    param(
        [Parameter(Mandatory)]$Intent,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $schema = $Intent.PSObject.Properties['schema_version']
    $phase = $Intent.PSObject.Properties['phase']
    $id = [string]$Intent.id
    if ($null -eq $schema -or
        $schema.Value -is [bool] -or
        [Convert]::ToInt64($schema.Value) -ne 1 -or
        $null -eq $phase -or
        [string]$phase.Value -cne 'quiescing' -or
        $id -cnotmatch '^[0-9a-f]{32}$') {
        throw 'pending lifecycle quiescing intent has an invalid schema, phase, or transaction id'
    }
    $activationPhaseProperty = $Intent.PSObject.Properties[
        'service_activation_phase'
    ]
    if ($null -ne $activationPhaseProperty -and
        [string]$activationPhaseProperty.Value -notin @(
            'quiesced',
            'activating'
        )) {
        throw 'pending lifecycle quiescing intent has an invalid service activation phase'
    }
    foreach ($binding in @(
        @('install_root', $Layout.InstallRoot),
        @('state_root', $Layout.StateRoot),
        @('gateway_service', $GatewayServiceName),
        @('guardian_service', $GuardianServiceName)
    )) {
        $property = $Intent.PSObject.Properties[[string]$binding[0]]
        if ($null -eq $property -or
            -not [string]::Equals(
                [string]$property.Value,
                [string]$binding[1],
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "pending lifecycle quiescing intent does not match $($binding[0])"
        }
    }
    $providerProperty = $Intent.PSObject.Properties['provider_library_path']
    if ($null -ne $providerProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$providerProperty.Value)) {
        $Layout.ProviderLibraryPath = Resolve-DefenseClawFullPath `
            -Path ([string]$providerProperty.Value) `
            -MustExist `
            -Leaf
    }
    $certificationProperty = $Intent.PSObject.Properties[
        'certification_codex_home'
    ]
    $coreCertificationProperty = $Intent.PSObject.Properties[
        'core_hardening_certification'
    ]
    if ($null -eq $certificationProperty -or
        $null -eq $coreCertificationProperty -or
        $coreCertificationProperty.Value -isnot [bool]) {
        throw 'pending lifecycle quiescing intent has invalid certification bindings'
    }
    $intentCertificationCodexHome =
        Resolve-DefenseClawCertificationCodexHome `
            -Path ([string]$certificationProperty.Value) `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    if ([bool]$coreCertificationProperty.Value -and
        [string]::IsNullOrWhiteSpace($intentCertificationCodexHome)) {
        throw 'pending lifecycle quiescing intent enables core certification outside its exact scope'
    }
    if ([string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        $Layout.CertificationCodexHome = $intentCertificationCodexHome
    }
    elseif (-not [string]::Equals(
            [string]$Layout.CertificationCodexHome,
            $intentCertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'pending lifecycle quiescing intent certification CODEX_HOME does not match the requested scope'
    }
    if ([bool]$Layout.CoreHardeningCertification -and
        -not [bool]$coreCertificationProperty.Value) {
        throw 'pending lifecycle quiescing intent does not match requested core-certification mode'
    }
    $Layout.CoreHardeningCertification = [bool](
        $coreCertificationProperty.Value
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    if ([string]::Equals(
        $GatewayServiceName,
        $GuardianServiceName,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'pending lifecycle quiescing intent aliases service identities'
    }
    $expectedDirectory = [IO.Path]::GetFullPath(
        (Microsoft.PowerShell.Management\Join-Path $Layout.TransactionsDirectory $id)
    ).TrimEnd('\')
    $recordedDirectory = [IO.Path]::GetFullPath(
        [string]$Intent.directory
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $recordedDirectory,
        $expectedDirectory,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'pending lifecycle quiescing intent has an unexpected transaction directory'
    }
    [void](Assert-DefenseClawDescendant `
        -Path $recordedDirectory `
        -Root $Layout.StateRoot `
        -Label 'quiescing transaction directory')

    $services = @($Intent.services)
    if ($services.Count -lt 2 -or $services.Count -gt 4) {
        throw 'pending lifecycle quiescing intent has an invalid managed service count'
    }
    $brokerServiceName = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayServiceName
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $serviceState = @{}
    foreach ($service in $services) {
        $nameProperty = $service.PSObject.Properties['name']
        $existedProperty = $service.PSObject.Properties['existed']
        $runningProperty = $service.PSObject.Properties['running']
        if ($null -eq $nameProperty -or
            $null -eq $existedProperty -or
            $existedProperty.Value -isnot [bool] -or
            $null -eq $runningProperty -or
            $runningProperty.Value -isnot [bool]) {
            throw 'pending lifecycle quiescing intent has invalid service state'
        }
        $name = [string]$nameProperty.Value
        if ($name -notin @(
                $GatewayServiceName,
                $brokerServiceName,
                $GuardianServiceName,
                $enumeratorServiceName
            ) -or
            $serviceState.ContainsKey($name)) {
            throw 'pending lifecycle quiescing intent contains an unexpected or duplicate service'
        }
        if ([bool]$runningProperty.Value -and
            -not [bool]$existedProperty.Value) {
            throw "pending lifecycle quiescing intent marks absent service $name as running"
        }
        $serviceState[$name] = [pscustomobject]@{
            existed = [bool]$existedProperty.Value
            running = [bool]$runningProperty.Value
        }
    }
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if (-not $serviceState.ContainsKey($name)) {
            throw "pending lifecycle quiescing intent is missing service $name"
        }
    }
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    Assert-DefenseClawCMIDBrokerServiceOrAbsent `
        -Name $Layout.BrokerServiceName `
        -ExpectedImage (Get-DefenseClawCMIDBrokerImage `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName) `
        -AllowArgumentUpgrade
    if ($serviceState.ContainsKey($brokerServiceName)) {
        Assert-DefenseClawCMIDBrokerServiceOrAbsent `
            -Name $brokerServiceName `
            -ExpectedImage (Get-DefenseClawCMIDBrokerImage `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName)
    }
    # A process/reboot recovery never trusts elapsed wall time from the prior
    # process. Reestablish both disabled+stopped, publish a fresh durable
    # quiescence point, and drain the complete failure-action window.
    foreach ($name in @($GatewayServiceName, $brokerServiceName, $GuardianServiceName, $enumeratorServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($enumeratorServiceName, $GuardianServiceName, $GatewayServiceName, $brokerServiceName)) {
        Stop-DefenseClawService -Name $name
    }
    $recoveryQuiescedAt = [DateTime]::UtcNow.ToString('o')
    $quiescenceProperty = $Intent.PSObject.Properties[
        'services_disabled_and_stopped_at'
    ]
    if ($null -eq $quiescenceProperty) {
        $Intent |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name services_disabled_and_stopped_at `
                -Value $recoveryQuiescedAt
    }
    else {
        $retainedQuiescedAt = $quiescenceProperty.Value
        if ($null -ne $retainedQuiescedAt -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$retainedQuiescedAt
            )) {
            # Parse nonlegacy retained evidence before replacing it so
            # malformed protected state cannot be silently normalized.
            [void](ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
                -Value $retainedQuiescedAt)
        }
    }
    Set-DefenseClawServiceActivationPhase `
        -State $Intent `
        -Path $Layout.PendingPath `
        -Phase quiesced `
        -ServicesQuiescedAt $recoveryQuiescedAt
    Set-DefenseClawServiceActivationPhase `
        -State $Intent `
        -Path $Layout.PendingPath `
        -Phase activating
    Start-DefenseClawTransactionServices `
        -Services $services `
        -Layout $Layout `
        -ServicesQuiescedAt $recoveryQuiescedAt `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $rollbackIntent = Publish-DefenseClawInstallRollbackIntent `
        -Snapshot $Intent `
        -Layout $Layout
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $recordedDirectory) {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $recordedDirectory `
            -PathType Container)) {
            throw 'quiescing transaction directory was replaced by a non-directory'
        }
        Assert-DefenseClawNoReparsePath -Path $recordedDirectory
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $recordedDirectory `
            -Recurse `
            -Force
    }
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $Layout.PendingPath `
        -Force
    if ($null -ne $rollbackIntent) {
        Complete-DefenseClawInstallRollbackIntent `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
}

function Recover-DefenseClawPendingTransaction {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath -PathType Leaf)) {
        return [pscustomobject]@{
            recovered = $false
            fresh_install_rollback = $false
            install_root_created = $false
            state_root_created = $false
        }
    }
    Assert-DefenseClawNoReparsePath -Path $Layout.PendingPath
    $pending = Microsoft.PowerShell.Management\Get-Content -LiteralPath $Layout.PendingPath -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $phase = $pending.PSObject.Properties['phase']
    if ($null -ne $phase) {
        if ([string]$phase.Value -cne 'quiescing') {
            throw "pending lifecycle record has unsupported phase $($phase.Value)"
        }
        $installRootCreated = (
            $null -ne $pending.PSObject.Properties['install_root_created'] -and
            [bool]$pending.install_root_created
        )
        $stateRootCreated = (
            $null -ne $pending.PSObject.Properties['state_root_created'] -and
            [bool]$pending.state_root_created
        )
        Recover-DefenseClawQuiescingIntent `
            -Intent $pending `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        return [pscustomobject]@{
            recovered = $true
            fresh_install_rollback = [bool](
                $installRootCreated -or $stateRootCreated
            )
            install_root_created = [bool]$installRootCreated
            state_root_created = [bool]$stateRootCreated
        }
    }
    $snapshotPath = [string]$pending.snapshot
    $restored = Restore-DefenseClawTransactionWithManagedHooksRollback `
        -SnapshotPath $snapshotPath `
        -Layout $Layout
    $installRootCreated = (
        $null -ne $restored.PSObject.Properties['install_root_created'] -and
        [bool]$restored.install_root_created
    )
    $stateRootCreated = (
        $null -ne $restored.PSObject.Properties['state_root_created'] -and
        [bool]$restored.state_root_created
    )
    Complete-DefenseClawTransaction `
        -SnapshotPath $snapshotPath `
        -Layout $Layout `
        -Rollback
    return [pscustomobject]@{
        recovered = $true
        fresh_install_rollback = [bool](
            $installRootCreated -or $stateRootCreated
        )
        install_root_created = [bool]$installRootCreated
        state_root_created = [bool]$stateRootCreated
    }
}

function Invoke-DefenseClawGatewayCommand {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Capture,
        [switch]$AllowFailure
    )
    $gateway = Resolve-DefenseClawFullPath -Path $Layout.GatewayPath -MustExist -Leaf
    Assert-DefenseClawNoReparsePath -Path $gateway
    $keys = @(
        'DEFENSECLAW_HOME',
        'DEFENSECLAW_CONFIG',
        'DEFENSECLAW_DEPLOYMENT_MODE',
        'DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR',
        'DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT',
        'DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME',
        'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED',
        'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED',
        'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED',
        'CODEX_HOME'
    )
    $previous = @{}
    foreach ($key in $keys) {
        $previous[$key] = [ordered]@{
            set = Microsoft.PowerShell.Management\Test-Path -LiteralPath "Env:$key"
            value = [Environment]::GetEnvironmentVariable($key, 'Process')
        }
    }
    try {
        $env:DEFENSECLAW_HOME = $Layout.RuntimeDirectory
        $env:DEFENSECLAW_CONFIG = $Layout.ConfigPath
        $env:DEFENSECLAW_DEPLOYMENT_MODE = 'managed_enterprise'
        $env:DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR = $Layout.AuthorizationDirectory
        $env:DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT = "NT SERVICE\$GatewayServiceName"
        $env:DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME = $GatewayServiceName
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED',
            $(if ([bool]$Layout.AgentApplicationControlAttested) { '1' } else { $null }),
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED',
            $(if ([bool]$Layout.AgentApplicationControlAttested) { '1' } else { $null }),
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED',
            $(if ([bool]$Layout.ClaudeEffectivePolicyVerified) { '1' } else { $null }),
            'Process'
        )
        # The gateway service and every lifecycle helper are deliberately
        # independent of a caller-controlled alternate CODEX_HOME. Machine
        # requirements live at the documented system path under ProgramData.
        [Environment]::SetEnvironmentVariable(
            'CODEX_HOME',
            $null,
            'Process'
        )
        $processResult = Invoke-DefenseClawProcess `
            -File $gateway `
            -Arguments $Arguments
        if ([int]$processResult.exit_code -ne 0 -and -not $AllowFailure) {
            throw "defenseclaw-gateway exited $($processResult.exit_code) for '$($Arguments -join ' ')': $(($processResult.output | Microsoft.PowerShell.Utility\Out-String).Trim())"
        }
        if ($Capture) {
            return [ordered]@{
                exit_code = [int]$processResult.exit_code
                output = @($processResult.output)
            }
        }
        return [int]$processResult.exit_code
    }
    finally {
        foreach ($key in $keys) {
            if ([bool]$previous[$key].set) {
                [Environment]::SetEnvironmentVariable($key, [string]$previous[$key].value, 'Process')
            }
            else {
                [Environment]::SetEnvironmentVariable($key, $null, 'Process')
            }
        }
    }
}

function New-DefenseClawTargetRuntimeExchangeFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TransactionDirectory
    )
    $safe = Assert-DefenseClawDescendant `
        -Path $Path `
        -Root $TransactionDirectory `
        -Label 'target runtime exchange file'
    Write-DefenseClawProtectedTextAtomic `
        -Value '{}' `
        -Path $safe `
        -RequiredRoot $TransactionDirectory
    return $safe
}

function Get-DefenseClawTargetRuntimeExchangeValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TransactionDirectory
    )
    $safe = Assert-DefenseClawDescendant `
        -Path $Path `
        -Root $TransactionDirectory `
        -Label 'target runtime exchange file'
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    $before = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $safe
    )
    if ($null -eq $before) {
        throw 'target runtime exchange file is missing'
    }
    $expected = New-DefenseClawCanonicalPathAcl `
        -IsDirectory:$false `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $safe `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$before.SecurityDescriptor,
            0
        )) `
        -Expected $expected
    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $safe `
        -Force
    if ([int64]$item.Length -gt 1048576) {
        throw 'target runtime exchange file exceeds the 1048576-byte limit'
    }
    try {
        $value = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $safe `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse target runtime exchange file: $($_.Exception.Message)"
    }
    $after = $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
        $safe
    )
    if ($null -eq $after -or
        [string]$after.Identity -cne [string]$before.Identity) {
        throw 'target runtime exchange file identity changed while it was read'
    }
    Assert-DefenseClawCanonicalRawPathAcl `
        -Path $safe `
        -Actual ([Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$after.SecurityDescriptor,
            0
        )) `
        -Expected $expected
    return $value
}

function Assert-DefenseClawTargetRuntimePlan {
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $allowedPlanProperties = @(
        'schema_version',
        'manifest_path',
        'manifest_sha256',
        'roots'
    )
    foreach ($property in @($Plan.PSObject.Properties)) {
        if ([string]$property.Name -notin $allowedPlanProperties) {
            throw 'target runtime plan contains an unexpected property'
        }
    }
    foreach ($required in $allowedPlanProperties) {
        if ($null -eq $Plan.PSObject.Properties[$required]) {
            throw "target runtime plan is missing $required"
        }
    }
    $manifestPath = [string]$Plan.manifest_path
    $manifestFull = [IO.Path]::GetFullPath($manifestPath)
    if ($Plan.schema_version -is [bool] -or
        [Convert]::ToInt64($Plan.schema_version) -ne 1 -or
        -not [string]::Equals(
            $manifestPath,
            $manifestFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $manifestFull,
            [IO.Path]::GetFullPath([string]$Layout.ManifestPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$Plan.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'target runtime plan has invalid schema or manifest binding'
    }
    $roots = @($Plan.roots)
    if ($roots.Count -gt 128) {
        throw 'target runtime plan exceeds the 128-root limit'
    }
    $seenSID = @{}
    $seenHome = @{}
    $seenLeaf = @{}
    $seenMarker = @{}
    foreach ($root in $roots) {
        $allowedRootProperties = @(
            'user_home',
            'data_dir',
            'sid',
            'baseline',
            'baseline_identity',
            'staging_leaf',
            'marker_sid'
        )
        foreach ($property in @($root.PSObject.Properties)) {
            if ([string]$property.Name -notin $allowedRootProperties) {
                throw 'target runtime plan root contains an unexpected property'
            }
        }
        foreach ($required in @(
            'user_home',
            'data_dir',
            'sid',
            'baseline',
            'staging_leaf',
            'marker_sid'
        )) {
            if ($null -eq $root.PSObject.Properties[$required]) {
                throw "target runtime plan root is missing $required"
            }
        }
        $sid = [string]$root.sid
        try {
            $parsedSID = [Security.Principal.SecurityIdentifier]::new($sid)
        }
        catch {
            throw 'target runtime plan contains an invalid target SID'
        }
        if ($parsedSID.Value -cne $sid -or
            $sid.StartsWith('S-1-5-80-', [StringComparison]::Ordinal) -or
            $sid -in @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID
            ) -or
            [string]$root.baseline -notin @('absent', 'canonical')) {
            throw 'target runtime plan contains an invalid SID or baseline'
        }
        $rawHome = [string]$root.user_home
        $rawData = [string]$root.data_dir
        $home = [IO.Path]::GetFullPath($rawHome).TrimEnd('\')
        $data = [IO.Path]::GetFullPath($rawData).TrimEnd('\')
        $expectedData = [IO.Path]::Combine(
            $home,
            '.defenseclaw'
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $rawHome,
                $home,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $rawData,
                $data,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $data,
                $expectedData,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'target runtime plan contains a noncanonical data directory'
        }
        $sidKey = $sid.ToUpperInvariant()
        $homeKey = $home.ToUpperInvariant()
        if ($seenSID.ContainsKey($sidKey) -or
            $seenHome.ContainsKey($homeKey)) {
            throw 'target runtime plan maps a SID or profile root more than once'
        }
        $seenSID[$sidKey] = $true
        $seenHome[$homeKey] = $true
        $leaf = [string]$root.staging_leaf
        $leafKey = $leaf.ToLowerInvariant()
        if ($leaf -cnotmatch '^\.defenseclaw\.setup-[0-9a-f]{32}$' -or
            $seenLeaf.ContainsKey($leafKey)) {
            throw 'target runtime plan contains an invalid or duplicate staging leaf'
        }
        $seenLeaf[$leafKey] = $true
        $markerSID = [string]$root.marker_sid
        try {
            $parsedMarkerSID =
                [Security.Principal.SecurityIdentifier]::new($markerSID)
        }
        catch {
            throw 'target runtime plan contains an invalid marker SID'
        }
        $markerKey = $markerSID.ToUpperInvariant()
        if ($markerSID -cnotmatch
                '^S-1-5-21-(?:[0-9]+-){7}[0-9]+$' -or
            $parsedMarkerSID.Value -cne $markerSID -or
            $markerSID -ceq $sid -or
            $seenMarker.ContainsKey($markerKey)) {
            throw 'target runtime plan contains an invalid or duplicate marker SID'
        }
        $seenMarker[$markerKey] = $true
        $baselineIdentityProperty = $root.PSObject.Properties[
            'baseline_identity'
        ]
        $baselineIdentity = if ($null -eq $baselineIdentityProperty) {
            ''
        }
        else {
            [string]$baselineIdentityProperty.Value
        }
        if ([string]$root.baseline -ceq 'canonical') {
            if ($baselineIdentity -cnotmatch
                '^[0-9a-f]{8}:[0-9a-f]{16}$') {
                throw 'target runtime canonical baseline lacks an exact identity'
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($baselineIdentity)) {
            throw 'target runtime absent baseline unexpectedly has an identity'
        }
    }
    return $Plan
}

function Assert-DefenseClawTargetRuntimeReport {
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)]
        [ValidateSet('stage', 'finalize', 'cleanup')]
        [string]$Action,
        $Plan,
        [switch]$JournalProjection
    )
    $allowedReportProperties = @(
        'schema_version',
        'action',
        'ok',
        'claims',
        'error'
    )
    foreach ($property in @($Report.PSObject.Properties)) {
        if ([string]$property.Name -notin $allowedReportProperties) {
            throw "target runtime $Action report contains an unexpected property"
        }
    }
    foreach ($required in @('schema_version', 'action', 'ok', 'claims')) {
        if ($null -eq $Report.PSObject.Properties[$required]) {
            throw "target runtime $Action report is missing $required"
        }
    }
    if ($Report.schema_version -is [bool] -or
        [Convert]::ToInt64($Report.schema_version) -ne 1 -or
        [string]$Report.action -cne $Action -or
        $Report.ok -isnot [bool]) {
        throw "target runtime $Action report has an invalid schema"
    }
    $claims = @($Report.claims)
    if ($claims.Count -gt 128) {
        throw "target runtime $Action report exceeds the 128-claim limit"
    }
    $planRoots = @{}
    if ($null -ne $Plan) {
        foreach ($root in @($Plan.roots)) {
            $planKey = (
                [string]$root.sid + "`0" + [string]$root.user_home
            ).ToUpperInvariant()
            $planRoots[$planKey] = $root
        }
    }
    $seenClaims = @{}
    foreach ($claim in $claims) {
        $allowedClaimProperties = @(
            'user_home',
            'data_dir',
            'sid',
            'identity',
            'created',
            'state'
        )
        foreach ($property in @($claim.PSObject.Properties)) {
            if ([string]$property.Name -notin $allowedClaimProperties) {
                throw "target runtime $Action report claim contains an unexpected property"
            }
        }
        foreach ($required in @(
            'user_home',
            'data_dir',
            'sid',
            'created',
            'state'
        )) {
            if ($null -eq $claim.PSObject.Properties[$required]) {
                throw "target runtime $Action report claim is missing $required"
            }
        }
        $claimSID = [string]$claim.sid
        try {
            $parsedClaimSID =
                [Security.Principal.SecurityIdentifier]::new($claimSID)
        }
        catch {
            throw "target runtime $Action report contains an invalid target SID"
        }
        if ($parsedClaimSID.Value -cne $claimSID -or
            $claimSID.StartsWith(
                'S-1-5-80-',
                [StringComparison]::Ordinal
            ) -or
            $claimSID -in @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID
            ) -or
            $claim.created -isnot [bool] -or
            [string]$claim.state -notin @(
                'staged',
                'canonical',
                'absent'
            )) {
            throw "target runtime $Action report contains an invalid claim"
        }
        $claimHome = [IO.Path]::GetFullPath(
            [string]$claim.user_home
        ).TrimEnd('\')
        $claimData = [IO.Path]::GetFullPath(
            [string]$claim.data_dir
        ).TrimEnd('\')
        if (-not [string]::Equals(
                [string]$claim.user_home,
                $claimHome,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                [string]$claim.data_dir,
                $claimData,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $claimData,
                [IO.Path]::Combine(
                    $claimHome,
                    '.defenseclaw'
                ).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "target runtime $Action report contains a noncanonical claim path"
        }
        $claimKey = ($claimSID + "`0" + $claimHome).ToUpperInvariant()
        if ($seenClaims.ContainsKey($claimKey)) {
            throw "target runtime $Action report contains a duplicate claim"
        }
        $seenClaims[$claimKey] = $true
        $identityProperty = $claim.PSObject.Properties['identity']
        $identity = if ($null -eq $identityProperty) {
            ''
        }
        else {
            [string]$identityProperty.Value
        }
        if ([string]$claim.state -ceq 'absent') {
            if (-not [string]::IsNullOrWhiteSpace($identity)) {
                throw "target runtime $Action absent claim retained an identity"
            }
        }
        elseif ($identity -cnotmatch '^[0-9a-f]{8}:[0-9a-f]{16}$') {
            throw "target runtime $Action report claim lacks an exact identity"
        }
        if ($JournalProjection) {
            if (-not [bool]$claim.created -or
                [string]$claim.state -notin @('staged', 'canonical')) {
                throw 'target runtime receipt contains a non-live root claim'
            }
        }
        elseif ($Action -ceq 'stage' -and
            (([bool]$claim.created -and
                    [string]$claim.state -cne 'staged') -or
                (-not [bool]$claim.created -and
                    [string]$claim.state -cne 'canonical'))) {
            throw 'target runtime stage report contains an impossible transition'
        }
        elseif ($Action -ceq 'finalize' -and
            [string]$claim.state -cne 'canonical') {
            throw 'target runtime final report contains a noncanonical claim'
        }
        elseif ($Action -ceq 'cleanup' -and
            ([bool]$claim.created -or
                [string]$claim.state -notin @('absent', 'canonical'))) {
            throw 'target runtime cleanup report contains an impossible transition'
        }
        if ($null -ne $Plan) {
            if (-not $planRoots.ContainsKey($claimKey)) {
                throw "target runtime $Action report claim is outside its plan"
            }
            $root = $planRoots[$claimKey]
            if (-not [string]::Equals(
                    [string]$claim.data_dir,
                    [string]$root.data_dir,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    $claimSID,
                    [string]$root.sid,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "target runtime $Action report claim disagrees with its plan"
            }
            if ([string]$root.baseline -ceq 'canonical') {
                if ([bool]$claim.created -or
                    [string]$claim.state -cne 'canonical' -or
                    $identity -cne [string]$root.baseline_identity) {
                    throw "target runtime $Action report changed an existing baseline"
                }
            }
            elseif ($JournalProjection) {
                if (-not [bool]$claim.created -or
                    [string]$claim.state -notin @('staged', 'canonical')) {
                    throw 'target runtime receipt claim does not own an absent baseline'
                }
            }
            elseif ($Action -ceq 'cleanup') {
                if ([bool]$claim.created -or
                    [string]$claim.state -cne 'absent') {
                    throw 'target runtime cleanup did not restore an absent baseline'
                }
            }
            elseif (-not [bool]$claim.created) {
                throw "target runtime $Action report lost created-root ownership"
            }
        }
    }
    if ($null -ne $Plan -and -not $JournalProjection -and
        [bool]$Report.ok -and
        $claims.Count -ne @($Plan.roots).Count) {
        throw "target runtime $Action success report is incomplete"
    }
    return $Report
}

function Test-DefenseClawTargetRuntimeReportComplete {
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Report
    )
    return [bool](
        $Report.ok -is [bool] -and
        [bool]$Report.ok -and
        @($Report.claims).Count -eq @($Plan.roots).Count
    )
}

function Set-DefenseClawTargetRuntimeTransactionState {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        $Plan,
        [string]$PlanPath,
        $StageReport,
        [string]$StageReportPath,
        $FinalReport,
        [string]$FinalReportPath,
        $CleanupReport,
        [string]$CleanupReportPath
    )
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    foreach ($binding in @(
        @('target_runtime_plan', $Plan),
        @('target_runtime_plan_path', $PlanPath),
        @('target_runtime_stage_report', $StageReport),
        @('target_runtime_stage_report_path', $StageReportPath),
        @('target_runtime_final_report', $FinalReport),
        @('target_runtime_final_report_path', $FinalReportPath),
        @('target_runtime_cleanup_report', $CleanupReport),
        @('target_runtime_cleanup_report_path', $CleanupReportPath)
    )) {
        if ($null -ne $binding[1] -and
            -not [string]::IsNullOrWhiteSpace([string]$binding[1])) {
            $snapshot |
                Microsoft.PowerShell.Utility\Add-Member `
                    -MemberType NoteProperty `
                    -Name ([string]$binding[0]) `
                    -Value $binding[1] `
                    -Force
        }
    }
    $latest = if ($null -ne $CleanupReport) {
        $CleanupReport
    }
    elseif ($null -ne $FinalReport) {
        $FinalReport
    }
    elseif ($null -ne $StageReport) {
        $StageReport
    }
    else {
        $null
    }
    if ($null -ne $latest) {
        $created = @($latest.claims |
            Microsoft.PowerShell.Core\Where-Object {
                [bool]$_.created -and [string]$_.state -cne 'absent'
            })
        # JSON-restored legacy and lifecycle-test snapshots can predate this
        # field. Upsert it through the same schema-safe writer used for the
        # plan/report bindings instead of assigning a missing NoteProperty.
        $snapshot |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name created_target_runtime_roots `
                -Value @($created) `
                -Force
    }
    Write-DefenseClawJsonAtomic -Value $snapshot -Path $SnapshotPath
    $intent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -ne $intent) {
        if ([string]$intent.phase -cne 'preparing_layout') {
            throw 'target runtime state cannot update a closed install receipt'
        }
        # Keep external crash authority bounded: the plan contains the marker
        # identities and the latest deduped claims contain the only live root
        # identities. Full stage/final/cleanup reports remain inside the
        # protected transaction directory referenced by pending.json.
        foreach ($name in @(
            'target_runtime_plan',
            'target_runtime_plan_path',
            'created_target_runtime_roots'
        )) {
            $property = $snapshot.PSObject.Properties[$name]
            if ($null -ne $property) {
                $intent |
                    Microsoft.PowerShell.Utility\Add-Member `
                        -MemberType NoteProperty `
                        -Name $name `
                        -Value $property.Value `
                        -Force
            }
        }
        [void](Write-DefenseClawInstallRollbackIntent `
            -Intent $intent `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName)
    }
    return $snapshot
}

function Invoke-DefenseClawTargetRuntimePreparation {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$ValidationOnly
    )
    $transactionDirectory = [IO.Path]::GetDirectoryName($SnapshotPath)
    $planPath = New-DefenseClawTargetRuntimeExchangeFile `
        -Path (Microsoft.PowerShell.Management\Join-Path `
            $transactionDirectory `
            'target-runtime-plan.json') `
        -TransactionDirectory $transactionDirectory
    $planProbe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise', 'windows', 'target-runtime', 'plan',
            '--manifest', [string]$Layout.ManifestPath,
            '--output', $planPath
        ) `
        -Capture `
        -AllowFailure
    if ([int]$planProbe.exit_code -ne 0) {
        throw "target runtime planning failed with exit $($planProbe.exit_code)"
    }
    $plan = Assert-DefenseClawTargetRuntimePlan `
        -Plan (Get-DefenseClawTargetRuntimeExchangeValue `
            -Path $planPath `
            -TransactionDirectory $transactionDirectory) `
        -Layout $Layout
    if ($ValidationOnly) {
        if (@($plan.roots |
                Microsoft.PowerShell.Core\Where-Object {
                    [string]$_.baseline -ceq 'absent'
                }).Count -gt 0) {
            throw (
                'Upgrade/Repair refuses an enabled target with an absent ' +
                'managed runtime root; add the target through a fresh Install'
            )
        }
        # No user object was mutated, so no rollback ownership is journaled.
        # Every canonical baseline was nevertheless authenticated by the
        # protected helper before services can become startable.
        return $plan
    }
    [void](Set-DefenseClawTargetRuntimeTransactionState `
        -SnapshotPath $SnapshotPath `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Plan $plan `
        -PlanPath $planPath)

    $stagePath = New-DefenseClawTargetRuntimeExchangeFile `
        -Path (Microsoft.PowerShell.Management\Join-Path `
            $transactionDirectory `
            'target-runtime-stage.json') `
        -TransactionDirectory $transactionDirectory
    $stageProbe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise', 'windows', 'target-runtime', 'stage',
            '--request', $planPath,
            '--output', $stagePath
        ) `
        -Capture `
        -AllowFailure
    $stage = $null
    try {
        $stage = Assert-DefenseClawTargetRuntimeReport `
            -Report (Get-DefenseClawTargetRuntimeExchangeValue `
                -Path $stagePath `
                -TransactionDirectory $transactionDirectory) `
            -Action stage `
            -Plan $plan
        [void](Set-DefenseClawTargetRuntimeTransactionState `
            -SnapshotPath $SnapshotPath `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -StageReport $stage `
            -StageReportPath $stagePath)
    }
    catch {
        if ([int]$stageProbe.exit_code -eq 0) {
            throw
        }
    }
    if ([int]$stageProbe.exit_code -ne 0 -or
        $null -eq $stage -or -not [bool]$stage.ok) {
        throw "target runtime staging failed with exit $($stageProbe.exit_code)"
    }

    $finalPath = New-DefenseClawTargetRuntimeExchangeFile `
        -Path (Microsoft.PowerShell.Management\Join-Path `
            $transactionDirectory `
            'target-runtime-final.json') `
        -TransactionDirectory $transactionDirectory
    $finalProbe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise', 'windows', 'target-runtime', 'finalize',
            '--request', $planPath,
            '--claims', $stagePath,
            '--output', $finalPath
        ) `
        -Capture `
        -AllowFailure
    $final = $null
    try {
        $final = Assert-DefenseClawTargetRuntimeReport `
            -Report (Get-DefenseClawTargetRuntimeExchangeValue `
                -Path $finalPath `
                -TransactionDirectory $transactionDirectory) `
            -Action finalize `
            -Plan $plan
    }
    catch {
        if ([int]$finalProbe.exit_code -eq 0) {
            throw
        }
    }
    if ([int]$finalProbe.exit_code -ne 0 -or
        $null -eq $final -or
        -not (Test-DefenseClawTargetRuntimeReportComplete `
            -Plan $plan `
            -Report $final)) {
        throw "target runtime finalization failed with exit $($finalProbe.exit_code)"
    }
    foreach ($claim in @($final.claims)) {
        if ([bool]$claim.created -and
            [string]$claim.state -cne 'canonical') {
            throw 'target runtime finalization did not publish every created root canonically'
        }
    }
    # A partial final report may omit a later marker-staged root. Preserve the
    # complete stage identity journal as rollback authority until finalization
    # has succeeded for the full plan.
    [void](Set-DefenseClawTargetRuntimeTransactionState `
        -SnapshotPath $SnapshotPath `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -FinalReport $final `
        -FinalReportPath $finalPath)
    return $final
}

function Assert-DefenseClawTargetRuntimeProductionChildrenExclusive {
    param(
        [Parameter(Mandatory)][string]$ProductionState,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Children
    )
    $expectedSharedIPC = [IO.Path]::Combine(
        $ProductionState,
        'ipc'
    )
    foreach ($child in $Children) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath(
                    [string]$child.FullName
                ).TrimEnd('\'),
                [IO.Path]::GetFullPath(
                    $expectedSharedIPC
                ).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'refusing shared target runtime cleanup while a ' +
                'production state-root child exists'
            )
        }
    }
}

function Assert-DefenseClawTargetRuntimeCleanupScopeExclusive {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $excluded = @{}
    foreach ($name in @(
        $GatewayServiceName,
        [string]$Layout.BrokerServiceName,
        $GuardianServiceName,
        (Get-DefenseClawEnumeratorServiceName `
            -GuardianServiceName $GuardianServiceName)
    )) {
        $excluded[$name.ToUpperInvariant()] = $true
    }
    $allServices = @(Microsoft.PowerShell.Management\Get-Service `
        -ErrorAction Stop)
    foreach ($service in @($allServices |
            Microsoft.PowerShell.Core\Where-Object {
                ([string]$_.Name).StartsWith(
                    'DefenseClaw',
                    [StringComparison]::OrdinalIgnoreCase
                )
            })) {
        $name = [string]$service.Name
        if (-not $excluded.ContainsKey($name.ToUpperInvariant())) {
            throw (
                'refusing shared target runtime cleanup while another ' +
                "managed DefenseClaw scope exists: $name"
            )
        }
    }
    foreach ($receipt in @(Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath ([string]$Layout.LifecycleLockDirectory) `
            -Filter 'install-rollback-*.json' `
            -File `
            -Force `
            -ErrorAction Stop)) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$receipt.FullName),
                [IO.Path]::GetFullPath(
                    [string]$Layout.InstallRollbackIntentPath
                ),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'refusing shared target runtime cleanup while another ' +
                'install rollback receipt exists'
            )
        }
    }
    $vendorRoot = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client'
    )
    $productionState = [IO.Path]::Combine(
        $vendorRoot,
        'DefenseClaw'
    )
    $nativeSecurity = Initialize-DefenseClawNativeSecurity
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath([string]$Layout.StateRoot).TrimEnd('\'),
            [IO.Path]::GetFullPath($productionState).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $productionSnapshot =
            $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                $productionState
            )
        if ($null -ne $productionSnapshot) {
            Assert-DefenseClawNoReparsePath -Path $productionState
            Assert-DefenseClawTrustedAncestor -Path $productionState
            $productionChildren = @(
                Microsoft.PowerShell.Management\Get-ChildItem `
                    -LiteralPath $productionState `
                    -Force `
                    -ErrorAction Stop
            )
            Assert-DefenseClawTargetRuntimeProductionChildrenExclusive `
                -ProductionState $productionState `
                -Children $productionChildren
            if ($productionChildren.Count -gt 0) {
                $expectedSharedIPC = [IO.Path]::Combine(
                    $productionState,
                    'ipc'
                )
                Assert-DefenseClawNoReparsePath -Path $expectedSharedIPC
                $ipcSnapshot =
                    $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                        $expectedSharedIPC
                    )
                if ($null -eq $ipcSnapshot) {
                    throw 'shared production IPC child is not a no-follow directory'
                }
                $ipcRecheck =
                    $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                        $expectedSharedIPC
                    )
                if ($null -eq $ipcRecheck -or
                    [string]$ipcRecheck.Identity -cne
                        [string]$ipcSnapshot.Identity) {
                    throw 'shared production IPC child changed during scope validation'
                }
            }
            $productionRecheck =
                $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                    $productionState
                )
            if ($null -eq $productionRecheck -or
                [string]$productionRecheck.Identity -cne
                    [string]$productionSnapshot.Identity) {
                throw 'production state root changed during cleanup scope validation'
            }
        }
        foreach ($authority in @(
            [IO.Path]::Combine(
                $productionState,
                'install',
                'deployment.json'
            ),
            [IO.Path]::Combine(
                $productionState,
                'install',
                'pending.json'
            )
        )) {
            Assert-DefenseClawNoReparsePath `
                -Path $authority `
                -AllowMissingLeaf
            $authoritySnapshot =
                $nativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                    $authority
                )
            if ($null -ne $authoritySnapshot) {
                throw (
                    'refusing shared target runtime cleanup while production ' +
                    'deployment authority exists'
                )
            }
        }
    }
    $certificationParent = [IO.Path]::Combine(
        $vendorRoot,
        'DefenseClaw-Cert'
    )
    $certificationSnapshot =
        $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
            $certificationParent
        )
    if ($null -ne $certificationSnapshot) {
        Assert-DefenseClawNoReparsePath -Path $certificationParent
        foreach ($scopeDirectory in @(
            Microsoft.PowerShell.Management\Get-ChildItem `
                -LiteralPath $certificationParent `
                -Directory `
                -Force `
                -ErrorAction Stop
        )) {
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath(
                        [string]$scopeDirectory.FullName
                    ).TrimEnd('\'),
                    [IO.Path]::GetFullPath(
                        [string]$Layout.StateRoot
                    ).TrimEnd('\'),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw (
                    'refusing shared target runtime cleanup while another ' +
                    'certification scope root exists'
                )
            }
        }
    }
}

function Test-DefenseClawTargetRuntimePlanRequiresExclusiveCleanup {
    param([Parameter(Mandatory)]$Plan)
    return [bool](@($Plan.roots |
        Microsoft.PowerShell.Core\Where-Object {
            [string]$_.baseline -ceq 'absent'
        }).Count -gt 0)
}

function Invoke-DefenseClawTargetRuntimeRollbackCleanup {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    Assert-DefenseClawNoReparsePath -Path $SnapshotPath
    $snapshot = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $planProperty = $snapshot.PSObject.Properties['target_runtime_plan']
    if ($null -eq $planProperty) {
        return $snapshot
    }
    $recordedPlanValue = Assert-DefenseClawTargetRuntimePlan `
        -Plan $planProperty.Value `
        -Layout $Layout
    $completedCleanup = $snapshot.PSObject.Properties[
        'target_runtime_cleanup_report'
    ]
    if ($null -ne $completedCleanup) {
        $verifiedCleanup = Assert-DefenseClawTargetRuntimeReport `
            -Report $completedCleanup.Value `
            -Action cleanup `
            -Plan $recordedPlanValue
        if (-not [bool]$verifiedCleanup.ok -or
            @($verifiedCleanup.claims |
                Microsoft.PowerShell.Core\Where-Object {
                    [bool]$_.created -and
                    [string]$_.state -cne 'absent'
                }).Count -ne 0) {
            throw 'journaled target runtime cleanup is incomplete'
        }
        return $snapshot
    }
    # Existing-baseline plans are validation-only and cannot remove a shared
    # user root. Apply the conservative cross-scope coexistence gate only when
    # an absent-baseline root may have been created (including the crash window
    # before its first identity report reached PowerShell).
    if (Test-DefenseClawTargetRuntimePlanRequiresExclusiveCleanup `
            -Plan $recordedPlanValue) {
        Assert-DefenseClawTargetRuntimeCleanupScopeExclusive `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    $transactionDirectory = [IO.Path]::GetDirectoryName($SnapshotPath)
    $planPath = [string]$snapshot.target_runtime_plan_path
    $plan = Assert-DefenseClawTargetRuntimePlan `
        -Plan (Get-DefenseClawTargetRuntimeExchangeValue `
            -Path $planPath `
            -TransactionDirectory $transactionDirectory) `
        -Layout $Layout
    $recordedPlan = $planProperty.Value |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 24 -Compress
    $publishedPlan = $plan |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 24 -Compress
    if ($recordedPlan -cne $publishedPlan) {
        throw 'target runtime cleanup plan disagrees with pending authority'
    }
    $claimsPath = ''
    foreach ($propertyName in @(
        'target_runtime_final_report_path',
        'target_runtime_stage_report_path'
    )) {
        $property = $snapshot.PSObject.Properties[$propertyName]
        if ($null -ne $property -and
            -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            $claimsPath = [string]$property.Value
            break
        }
    }
    $cleanupPath = New-DefenseClawTargetRuntimeExchangeFile `
        -Path (Microsoft.PowerShell.Management\Join-Path `
            $transactionDirectory `
            'target-runtime-cleanup.json') `
        -TransactionDirectory $transactionDirectory
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        'enterprise', 'windows', 'target-runtime', 'cleanup',
        '--request', $planPath
    )) {
        $arguments.Add([string]$value)
    }
    if (-not [string]::IsNullOrWhiteSpace($claimsPath)) {
        $arguments.Add('--claims')
        $arguments.Add($claimsPath)
    }
    $arguments.Add('--output')
    $arguments.Add($cleanupPath)
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @($arguments) `
        -Capture `
        -AllowFailure
    $cleanup = $null
    try {
        $cleanup = Assert-DefenseClawTargetRuntimeReport `
            -Report (Get-DefenseClawTargetRuntimeExchangeValue `
                -Path $cleanupPath `
                -TransactionDirectory $transactionDirectory) `
            -Action cleanup `
            -Plan $plan
    }
    catch {
        if ([int]$probe.exit_code -eq 0) {
            throw
        }
    }
    if ([int]$probe.exit_code -ne 0 -or
        $null -eq $cleanup -or
        -not (Test-DefenseClawTargetRuntimeReportComplete `
            -Plan $plan `
            -Report $cleanup)) {
        throw "target runtime rollback cleanup failed with exit $($probe.exit_code)"
    }
    foreach ($claim in @($cleanup.claims)) {
        if ([bool]$claim.created -and [string]$claim.state -cne 'absent') {
            throw 'target runtime rollback left a transaction-created root'
        }
    }
    # Publish terminal cleanup only after the protected report proves the full
    # plan succeeded. A partial ok:false report can omit later live roots; it
    # must never replace the prior stage/final claims or make re-entry terminal.
    [void](Set-DefenseClawTargetRuntimeTransactionState `
        -SnapshotPath $SnapshotPath `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -CleanupReport $cleanup `
        -CleanupReportPath $cleanupPath)
    return Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $SnapshotPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
}

function Invoke-DefenseClawCodexRequirementsCommand {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)]
        [ValidateSet('inspect', 'reconcile', 'verify', 'remove')]
        [string]$Action
    )
    Assert-DefenseClawAdministrator
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise',
            'windows',
            'codex-requirements',
            $Action,
            '--json'
        ) `
        -Capture `
        -AllowFailure

    $reports = [Collections.Generic.List[object]]::new()
    foreach ($line in @($probe.output)) {
        $text = ([string]$line).Trim()
        if (-not $text.StartsWith('{', [StringComparison]::Ordinal)) {
            continue
        }
        try {
            $reports.Add(
                ($text | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            )
        }
        catch {
            throw "Codex requirements command emitted malformed JSON: $text"
        }
    }
    if ($reports.Count -ne 1) {
        throw "Codex requirements command emitted $($reports.Count) JSON reports; expected exactly one"
    }
    $report = $reports[0]
    if ([int]$report.schema_version -ne 2) {
        throw "unsupported Codex requirements report schema: $($report.schema_version)"
    }
    if (-not [string]::Equals(
        [string]$report.action,
        $Action,
        [StringComparison]::Ordinal
    )) {
        throw "Codex requirements report action mismatch: $($report.action)"
    }
    if ([int]$probe.exit_code -ne 0 -or -not [bool]$report.ok) {
        $detail = if (-not [string]::IsNullOrWhiteSpace([string]$report.error)) {
            [string]$report.error
        }
        else {
            (($probe.output | Microsoft.PowerShell.Utility\Out-String).Trim())
        }
        throw "Codex requirements $Action failed: $detail"
    }
    foreach ($pair in @(
        @('requirements_path', $Layout.CodexMachinePolicyPath),
        @('ownership_path', $Layout.CodexRequirementsOwnershipPath),
        @('managed_state_path', $Layout.CodexManagedHooksStatePath),
        @('managed_dir', $Layout.CodexManagedHooksDirectory),
        @('hook_binary', $Layout.HookPath)
    )) {
        $property = $report.PSObject.Properties[[string]$pair[0]]
        if ($null -eq $property -or
            [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            throw "Codex requirements report is missing $($pair[0])"
        }
        $actual = [IO.Path]::GetFullPath([string]$property.Value).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath([string]$pair[1]).TrimEnd('\')
        if (-not [string]::Equals(
            $actual,
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Codex requirements report $($pair[0]) is outside the exact installed layout: $actual"
        }
    }
    foreach ($hashName in @('preimage_sha256', 'postimage_sha256')) {
        $property = $report.PSObject.Properties[$hashName]
        if ($null -ne $property -and
            -not [string]::IsNullOrEmpty([string]$property.Value) -and
            [string]$property.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw "Codex requirements report contains an invalid $hashName"
        }
    }
    if ($Action -in @('inspect', 'reconcile', 'verify')) {
        if ([string]$report.agent_application_control_prerequisite -cne
            $script:AgentApplicationControlPrerequisite) {
            throw "Codex requirements $Action reported an unknown agent application-control prerequisite"
        }
        foreach ($booleanName in @(
            'agent_application_control_enforced',
            'approved_client_enforced',
            'approved_agent_clients_enforced',
            'claude_target_enabled',
            'claude_effective_policy_verified',
            'codex_target_enabled',
            'cursor_target_enabled',
            'security_complete'
        )) {
            $property = $report.PSObject.Properties[$booleanName]
            if ($null -eq $property -or
                $property.Value -isnot [bool]) {
                throw "Codex requirements $Action did not report boolean $booleanName"
            }
        }
        if ([bool]$report.agent_application_control_enforced -ne
                [bool]$Layout.AgentApplicationControlAttested -or
            [bool]$report.approved_client_enforced -ne
                [bool]$Layout.AgentApplicationControlAttested -or
            [bool]$report.approved_agent_clients_enforced -ne
                [bool]$Layout.AgentApplicationControlAttested) {
            throw "Codex requirements $Action approved-agent application-control result disagrees with protected deployment evidence"
        }
        if ([bool]$report.claude_effective_policy_verified -ne
            [bool]$Layout.ClaudeEffectivePolicyVerified) {
            throw "Codex requirements $Action Claude effective-policy evidence does not match the protected live verification result"
        }
        $expectedSecurityComplete = [bool](
            ([bool]$report.claude_target_enabled -or
                [bool]$report.codex_target_enabled -or
                [bool]$report.cursor_target_enabled) -and
            (-not [bool]$report.claude_target_enabled -or
                [bool]$Layout.ClaudeEffectivePolicyVerified)
        )
        if ([bool]$report.security_complete -ne $expectedSecurityComplete) {
            throw "Codex requirements $Action aggregate security result disagrees with protected evidence"
        }
        $Layout.ClaudeTargetEnabled = [bool]$report.claude_target_enabled
        $Layout.CodexTargetEnabled = [bool]$report.codex_target_enabled
        $Layout.CursorTargetEnabled = [bool]$report.cursor_target_enabled
        if ([bool]$Layout.CodexTargetEnabled) {
            if ($Action -in @('reconcile', 'verify')) {
                if (@($report.managed_events).Count -ne 10) {
                    throw "Codex requirements $Action did not attest all 10 managed hook groups"
                }
                Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
                Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
            }
        }
        elseif ($Action -in @('reconcile', 'verify')) {
            foreach ($booleanName in @(
                'safe_to_remove_binary',
                'managed_state_removed_or_absent'
            )) {
                $property = $report.PSObject.Properties[$booleanName]
                if ($null -eq $property -or
                    $property.Value -isnot [bool] -or
                    -not [bool]$property.Value) {
                    throw "disabled Codex requirements $Action did not attest $booleanName"
                }
            }
            $references = $report.PSObject.Properties[
                'surviving_owned_path_references'
            ]
            if ($null -eq $references -or
                $references.Value -is [bool] -or
                $references.Value -isnot [ValueType] -or
                [Convert]::ToInt64($references.Value) -ne 0) {
                throw "disabled Codex requirements $Action did not prove zero owned-path references"
            }
        }
    }
    return $report
}

function Complete-DefenseClawCodexRequirementsRemoval {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)]$Report
    )
    foreach ($booleanName in @(
        'safe_to_remove_binary',
        'managed_state_existed',
        'managed_state_removed',
        'managed_state_removed_or_absent'
    )) {
        $property = $Report.PSObject.Properties[$booleanName]
        if ($null -eq $property -or $property.Value -isnot [bool]) {
            throw "Codex requirements removal did not report boolean $booleanName"
        }
    }
    if (-not [bool]$Report.safe_to_remove_binary -or
        -not [bool]$Report.managed_state_removed_or_absent -or
        ([bool]$Report.managed_state_existed -and
            -not [bool]$Report.managed_state_removed)) {
        throw 'Codex requirements removal did not prove managed runtime state was removed or already absent'
    }
    $survivingReferences = $Report.PSObject.Properties[
        'surviving_owned_path_references'
    ]
    if ($null -eq $survivingReferences -or
        $survivingReferences.Value -is [bool] -or
        $survivingReferences.Value -isnot [ValueType] -or
        [Convert]::ToInt64($survivingReferences.Value) -ne 0) {
        throw 'Codex requirements removal did not prove zero surviving references to the owned binary tree'
    }
    $disposition = [string]$Report.disposition
    $ownedRemovalDisposition = $disposition -in @(
        'restored_preimage',
        'surgical_preservation',
        'disabled_restored_preimage',
        'disabled_surgical_preservation'
    )
    $verifiedAbsentDisposition = $disposition -in @(
        'ownership_absent',
        'disabled_ownership_absent',
        'disabled_noop',
        'disabled_verified'
    )
    if (-not $ownedRemovalDisposition -and -not $verifiedAbsentDisposition) {
        throw "managed uninstall refuses unexplained Codex requirements removal disposition: $disposition"
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexRequirementsOwnershipPath) {
        throw 'Codex requirements ownership record remains after managed removal'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexManagedHooksStatePath) {
        throw 'DefenseClaw Codex managed-hooks state remains after managed removal'
    }

    if ($verifiedAbsentDisposition) {
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexRequirementsAclBackupPath) {
            # A preimage that recorded no prior file names no foreign ACL to
            # restore, so it leaves with the deployment. One that recorded a
            # file now missing is state this teardown cannot explain.
            $absentBackup = Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout
            if ([bool]$absentBackup.existed) {
                throw (
                    'verified-absent Codex removal retains an ACL preimage for ' +
                    "$($Layout.CodexMachinePolicyPath), which existed before this deployment; " +
                    'restore or remove that file, then run Uninstall again'
                )
            }
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $Layout.CodexRequirementsAclBackupPath `
                -Force
        }
        return
    }

    $backup = Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout
    if ($disposition -in @(
        'restored_preimage',
        'disabled_restored_preimage'
    )) {
        if ([bool]$backup.existed) {
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.CodexMachinePolicyPath `
                -PathType Leaf)) {
                throw 'Codex requirements preimage was not restored'
            }
            $actualHash = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Layout.CodexMachinePolicyPath `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            if ($actualHash -cne [string]$backup.sha256 -or
                -not [string]::Equals(
                    [string]$Report.preimage_sha256,
                    [string]$backup.sha256,
                    [StringComparison]::Ordinal
                )) {
                throw 'restored Codex requirements do not match the authenticated preimage'
            }
            $security = [Security.AccessControl.FileSecurity]::new()
            $security.SetSecurityDescriptorSddlForm(
                [string]$backup.security_descriptor,
                [Security.AccessControl.AccessControlSections]::All
            )
            Microsoft.PowerShell.Security\Set-Acl `
                -LiteralPath $Layout.CodexMachinePolicyPath `
                -AclObject $security
            Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
        }
        elseif (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexMachinePolicyPath) {
            throw 'Codex requirements were created by DefenseClaw but remain after removal'
        }
    }
    else {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexMachinePolicyPath `
            -PathType Leaf)) {
            throw 'surgically preserved Codex requirements are unexpectedly missing'
        }
        $gatewaySID = Get-DefenseClawServiceSID `
            -ServiceName $GatewayServiceName
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexMachinePolicyPath `
            -Kind MachinePolicyFile `
            -GatewayServiceSID $gatewaySID
        Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout
    }

    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $Layout.CodexRequirementsAclBackupPath `
        -Force
}

function Invoke-DefenseClawManagedHooksTeardownCommand {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)]
        [ValidateSet('prepare', 'verify', 'rollback')]
        [string]$Action
    )
    Assert-DefenseClawAdministrator
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise',
            'windows',
            'teardown-managed-hooks',
            $Action,
            '--json'
        ) `
        -Capture `
        -AllowFailure
    $reports = [Collections.Generic.List[object]]::new()
    foreach ($line in @($probe.output)) {
        $text = ([string]$line).Trim()
        if (-not $text.StartsWith('{', [StringComparison]::Ordinal)) {
            continue
        }
        try {
            $reports.Add(
                ($text | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            )
        }
        catch {
            throw "managed-hook teardown command emitted malformed JSON: $text"
        }
    }
    if ($reports.Count -ne 1) {
        throw "managed-hook teardown command emitted $($reports.Count) JSON reports; expected exactly one"
    }
    $report = $reports[0]
    if ([int]$report.schema_version -ne 3) {
        throw "unsupported managed-hook teardown report schema: $($report.schema_version)"
    }
    if ([string]$report.action -cne $Action) {
        throw "managed-hook teardown report action mismatch: $($report.action)"
    }
    $reportOK = $report.PSObject.Properties['ok']
    if ($null -eq $reportOK -or $reportOK.Value -isnot [bool]) {
        throw 'managed-hook teardown report is missing boolean ok'
    }
    # Failure reports cannot safely attest success-only paths or counts. Surface
    # their bounded original diagnostic before validating those fields so a
    # bootstrap/layout failure is not replaced by a secondary schema complaint.
    if ([int]$probe.exit_code -ne 0 -or -not [bool]$reportOK.Value) {
        $detail = if (-not [string]::IsNullOrWhiteSpace([string]$report.error)) {
            [string]$report.error
        }
        else {
            $probe.output
        }
        $detail = ConvertTo-DefenseClawBoundedDiagnostic -Value $detail
        throw "managed-hook teardown $Action failed: $detail"
    }
    foreach ($pair in @(
        @('manifest_path', $Layout.ManifestPath),
        @('journal_path', $Layout.ManagedHooksTeardownJournalPath)
    )) {
        $property = $report.PSObject.Properties[[string]$pair[0]]
        if ($null -eq $property -or
            [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            throw "managed-hook teardown report is missing $($pair[0])"
        }
        $actual = [IO.Path]::GetFullPath([string]$property.Value).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath([string]$pair[1]).TrimEnd('\')
        if (-not [string]::Equals(
            $actual,
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "managed-hook teardown report $($pair[0]) is outside the exact protected layout: $actual"
        }
    }
    $counts = @{}
    foreach ($name in @(
        'target_count',
        'enrollment_target_count',
        'succeeded_count',
        'verified_clean_count',
        'verified_installed_count',
        'failed_count',
        'surviving_owned_path_references'
    )) {
        $property = $report.PSObject.Properties[$name]
        if ($null -eq $property -or
            $property.Value -is [bool] -or
            $property.Value -isnot [ValueType]) {
            throw "managed-hook teardown report is missing numeric $name"
        }
        try {
            $value = [Convert]::ToInt64(
                $property.Value,
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        catch {
            throw "managed-hook teardown report contains invalid $name"
        }
        if ($value -lt 0 -or $value -gt 100000) {
            throw "managed-hook teardown report contains out-of-range $name"
        }
        $counts[$name] = $value
    }
    $results = @($report.results)
    if ($results.Count -ne [int64]$counts.target_count) {
        throw 'managed-hook teardown result count does not match target_count'
    }
    foreach ($row in $results) {
        if ([string]$row.connector -cnotmatch '^[a-z0-9][a-z0-9_-]{0,63}$' -or
            [string]$row.sid -cnotmatch '^S-\d-\d+(?:-\d+)+$') {
            throw 'managed-hook teardown report contains an invalid connector or target SID'
        }
        $okProperty = $row.PSObject.Properties['ok']
        if ($null -eq $okProperty -or
            $okProperty.Value -isnot [bool] -or
            -not [bool]$okProperty.Value) {
            # The cause sits on the row, or on the report when the failure came
            # before row attribution. Control characters are folded so one row
            # cannot restructure the message.
            $rowError = [string]$row.error
            if ([string]::IsNullOrWhiteSpace($rowError)) {
                $rowError = [string]$report.error
            }
            $rowDetail = ''
            if (-not [string]::IsNullOrWhiteSpace($rowError)) {
                $rowDetail = ': ' + ($rowError -replace '[\x00-\x1f\x7f]', ' ')
            }
            throw "managed-hook teardown did not complete target $($row.connector)@$($row.sid)$rowDetail"
        }
    }
    if ($counts.failed_count -ne 0 -or
        $counts.succeeded_count -ne $counts.target_count) {
        throw "managed-hook teardown $Action did not complete every manifest target"
    }
    if ($Action -in @('prepare', 'verify')) {
        foreach ($booleanName in @('rollback_ready', 'safe_to_remove_binary')) {
            $property = $report.PSObject.Properties[$booleanName]
            if ($null -eq $property -or
                $property.Value -isnot [bool] -or
                -not [bool]$property.Value) {
                throw "managed-hook teardown $Action did not attest $booleanName"
            }
        }
        if ($counts.verified_clean_count -ne $counts.target_count -or
            $counts.surviving_owned_path_references -ne 0) {
            throw "managed-hook teardown $Action left an unverified target or owned binary reference"
        }
    }
    else {
        $rollbackCompleted = $report.PSObject.Properties[
            'rollback_completed'
        ]
        $verifiedInstalled = $report.PSObject.Properties[
            'verified_installed_count'
        ]
        if ($null -eq $rollbackCompleted -or
            $rollbackCompleted.Value -isnot [bool] -or
            -not [bool]$rollbackCompleted.Value -or
            $null -eq $verifiedInstalled -or
            [int64]$counts.verified_installed_count -ne
                $counts.enrollment_target_count) {
            throw 'managed-hook teardown rollback did not restore and verify the exact pre-teardown enrollment'
        }
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -PathType Leaf)) {
        throw "managed-hook teardown $Action did not preserve its protected rollback journal"
    }
    Assert-DefenseClawNoReparsePath `
        -Path $Layout.ManagedHooksTeardownJournalPath
    $journal = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -Force
    if ([int64]$journal.Length -gt 4194304) {
        throw 'managed-hook teardown rollback journal exceeds the 4194304-byte limit'
    }
    Assert-DefenseClawPathAcl `
        -Path $Layout.ManagedHooksTeardownJournalPath `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -AllowInheritance `
        -RejectUntrustedRead
    return $report
}

function Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)]
        [ValidateSet('capture', 'restore', 'retire')]
        [string]$Action
    )
    Assert-DefenseClawAdministrator
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise',
            'windows',
            'managed-hooks-lifecycle-snapshot',
            $Action,
            '--json'
        ) `
        -Capture `
        -AllowFailure
    $reports = [Collections.Generic.List[object]]::new()
    foreach ($line in @($probe.output)) {
        $text = ([string]$line).Trim()
        if (-not $text.StartsWith('{', [StringComparison]::Ordinal)) {
            continue
        }
        try {
            $reports.Add(
                ($text | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            )
        }
        catch {
            throw "managed-hook lifecycle snapshot emitted malformed JSON: $text"
        }
    }
    if ($reports.Count -ne 1) {
        throw "managed-hook lifecycle snapshot emitted $($reports.Count) JSON reports; expected exactly one"
    }
    $report = $reports[0]
    if ([int]$report.schema_version -ne 2) {
        throw "unsupported managed-hook lifecycle snapshot schema: $($report.schema_version)"
    }
    if ([string]$report.action -cne $Action) {
        throw "managed-hook lifecycle snapshot action mismatch: $($report.action)"
    }
    $ok = $report.PSObject.Properties['ok']
    if ($null -eq $ok -or $ok.Value -isnot [bool]) {
        throw 'managed-hook lifecycle snapshot is missing boolean ok'
    }
    if ([int]$probe.exit_code -ne 0 -or -not [bool]$ok.Value) {
        $detail = if (-not [string]::IsNullOrWhiteSpace([string]$report.error)) {
            [string]$report.error
        }
        else {
            $probe.output
        }
        $detail = ConvertTo-DefenseClawBoundedDiagnostic -Value $detail
        throw "managed-hook lifecycle snapshot $Action failed: $detail"
    }
    $journal = $report.PSObject.Properties['journal_path']
    if ($null -eq $journal -or
        [string]::IsNullOrWhiteSpace([string]$journal.Value)) {
        throw 'managed-hook lifecycle snapshot is missing journal_path'
    }
    $actual = [IO.Path]::GetFullPath([string]$journal.Value).TrimEnd('\')
    $expected = [IO.Path]::GetFullPath(
        [string]$Layout.ManagedHooksLifecycleJournalPath
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $actual,
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "managed-hook lifecycle snapshot journal is outside the exact protected layout: $actual"
    }
    $expectedPhase = switch ($Action) {
        'capture' { 'captured' }
        'restore' { 'restored' }
        'retire' { @('absent', 'retired') }
    }
    if ([string]$report.phase -notin @($expectedPhase)) {
        throw "managed-hook lifecycle snapshot $Action returned invalid phase: $($report.phase)"
    }
    return $report
}

function Assert-DefenseClawInstalledConfig {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    [void](Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @(
            'enterprise', 'windows', 'validate-service-config',
            '--config', $Layout.ConfigPath,
            '--data-dir', $Layout.RuntimeDirectory,
            '--service-account', "NT SERVICE\$GatewayServiceName",
            '--json'
        ))
}

function Test-DefenseClawGatewayReady {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    $service = Microsoft.PowerShell.Management\Get-Service -Name $GatewayServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service -or
        $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        return $false
    }
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @('status') `
        -Capture `
        -AllowFailure
    return ([int]$probe.exit_code -eq 0)
}

function Test-DefenseClawGuardianReady {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$LiveVerify
    )
    $service = Microsoft.PowerShell.Management\Get-Service -Name $GuardianServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service -or
        $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        return $false
    }
    $verb = if ($LiveVerify) { 'verify' } else { 'status' }
    $probe = Invoke-DefenseClawGatewayCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Arguments @('enterprise', 'hooks', $verb, '--manifest', $Layout.ManifestPath, '--json') `
        -Capture `
        -AllowFailure
    return ([int]$probe.exit_code -eq 0)
}

function Wait-DefenseClawEnterpriseReadiness {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [int]$TimeoutSeconds = 90
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $brokerReady = $false
    $gatewayReady = $false
    $guardianReady = $false
    do {
        $broker = Microsoft.PowerShell.Management\Get-Service `
            -Name $Layout.BrokerServiceName `
            -ErrorAction SilentlyContinue
        $brokerReady = $null -ne $broker -and
            $broker.Status -eq [ServiceProcess.ServiceControllerStatus]::Running
        $gatewayReady = $brokerReady -and (Test-DefenseClawGatewayReady -Layout $Layout -GatewayServiceName $GatewayServiceName)
        if ($gatewayReady) {
            $guardianReady = Test-DefenseClawGuardianReady `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }
        if ($gatewayReady -and $guardianReady) {
            return
        }
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "enterprise readiness timed out: broker_ready=$brokerReady gateway_ready=$gatewayReady guardian_ready=$guardianReady"
}

function Get-DefenseClawOptionalPropertyValues {
    param(
        [Parameter(Mandatory)][object]$Properties,
        [Parameter(Mandatory)][string]$Name
    )
    $property = $Properties.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return
    }
    return @($property.Value)
}

function Assert-DefenseClawServiceConfiguration {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedImage,
        [Parameter(Mandatory)][string]$ExpectedAccount,
        [Parameter(Mandatory)][string]$ExpectedDisplayName,
        [Parameter(Mandatory)][int]$ExpectedSidType,
        [Parameter(Mandatory)][string[]]$ExpectedPrivileges,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedEnvironment,
        [string[]]$ExpectedDependencies = @(),
        [ValidateSet(2, 3, 4)]
        [int[]]$ExpectedStartMode = @(2)
    )
    if (-not (Test-DefenseClawServiceExists -Name $Name)) {
        throw "required Windows service is missing: $Name"
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $properties = Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $key
    if (-not [string]::Equals([string]$properties.ImagePath, $ExpectedImage, [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name ImagePath drift: $($properties.ImagePath)"
    }
    if (-not [string]::Equals([string]$properties.ObjectName, $ExpectedAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name account drift: $($properties.ObjectName)"
    }
    if (-not [string]::Equals([string]$properties.DisplayName, $ExpectedDisplayName, [StringComparison]::Ordinal)) {
        throw "service $Name display name drift: $($properties.DisplayName)"
    }
    if (-not [string]::Equals([string]$properties.Description, $script:ServiceDescription, [StringComparison]::Ordinal)) {
        throw "service $Name description drift: $($properties.Description)"
    }
    if ([int]$properties.Type -ne 0x10) {
        throw "service $Name is not a Win32 own-process service: Type=$($properties.Type)"
    }
    if ([int]$properties.Start -notin $ExpectedStartMode) {
        throw "service $Name startup mode drift: $($properties.Start), expected $($ExpectedStartMode -join ' or ')"
    }
    if ([int]$properties.ErrorControl -ne 1) {
        throw "service $Name ErrorControl drift: $($properties.ErrorControl)"
    }
    if ([int]$properties.DelayedAutoStart -ne 0) {
        throw "service $Name DelayedAutoStart drift: $($properties.DelayedAutoStart)"
    }
    foreach ($dependencyProperty in @('DependOnGroup', 'Group')) {
        $dependency = $properties.PSObject.Properties[$dependencyProperty]
        if ($null -ne $dependency -and
            @($dependency.Value | Microsoft.PowerShell.Core\Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            throw "service $Name has an unexpected $dependencyProperty dependency"
        }
    }
    $actualDependencies = @(
        Get-DefenseClawOptionalPropertyValues -Properties $properties -Name 'DependOnService' |
            Microsoft.PowerShell.Core\Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } |
            Microsoft.PowerShell.Core\ForEach-Object { [string]$_ } |
            Microsoft.PowerShell.Utility\Sort-Object
    )
    $wantedDependencies = @($ExpectedDependencies | Microsoft.PowerShell.Utility\Sort-Object)
    if (($actualDependencies -join "`n") -cne ($wantedDependencies -join "`n")) {
        throw "service $Name dependency drift"
    }
    if ([int]$properties.ServiceSidType -ne $ExpectedSidType) {
        throw "service $Name ServiceSidType drift: $($properties.ServiceSidType), expected $ExpectedSidType"
    }
    $actualPrivileges = @($properties.RequiredPrivileges | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ } | Microsoft.PowerShell.Utility\Sort-Object)
    $wantedPrivileges = @($ExpectedPrivileges | Microsoft.PowerShell.Utility\Sort-Object)
    if (($actualPrivileges -join "`n") -cne ($wantedPrivileges -join "`n")) {
        throw "service $Name required privileges drift: actual=$($actualPrivileges -join ',') expected=$($wantedPrivileges -join ',')"
    }
    $actualFailureActions = [byte[]]$properties.FailureActions
    $expectedFailureActions = Get-DefenseClawFailureActionsBytes
    if ($null -eq $actualFailureActions -or
        [BitConverter]::ToString($actualFailureActions) -cne
            [BitConverter]::ToString($expectedFailureActions)) {
        throw "service $Name failure recovery must repeat restart after 5s/15s/60s with daily reset"
    }
    if ([int]$properties.FailureActionsOnNonCrashFailures -ne 1) {
        throw "service $Name does not recover non-crash failures"
    }
    $actualEnvironment = @(
        Get-DefenseClawOptionalPropertyValues -Properties $properties -Name 'Environment' |
            Microsoft.PowerShell.Core\ForEach-Object { [string]$_ } |
            Microsoft.PowerShell.Utility\Sort-Object
    )
    $wantedEnvironment = @($ExpectedEnvironment | Microsoft.PowerShell.Utility\Sort-Object)
    if (($actualEnvironment -join "`n") -cne ($wantedEnvironment -join "`n")) {
        throw "service $Name environment pin drift"
    }
    Assert-DefenseClawServiceRegistryAcl -Name $Name
    $sddlOutput = Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sdshow', $Name) -Capture
    $sddlLine = $sddlOutput | Microsoft.PowerShell.Core\Where-Object { [string]$_ -like 'D:*' } | Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($null -eq $sddlLine) {
        throw "service $Name has no readable SCM security descriptor"
    }
    $actualSDDL = ([string]$sddlLine).Trim()
    # sdshow returns the whole descriptor including the SCM-maintained audit
    # section. ServiceSDDL is a DACL, so only the DACL portion is comparable.
    $saclIndex = $actualSDDL.IndexOf('S:', [StringComparison]::OrdinalIgnoreCase)
    $actualDACL = if ($saclIndex -ge 0) { $actualSDDL.Substring(0, $saclIndex) } else { $actualSDDL }
    if (-not [string]::Equals($actualDACL, $script:ServiceSDDL, [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name DACL drift: $actualDACL"
    }
}

function Assert-DefenseClawManagedServiceConfigurations {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$PendingTransaction,
        [switch]$ServicingTransaction,
        [switch]$AnyStartMode
    )
    if ($PendingTransaction -and $ServicingTransaction) {
        throw 'service configuration assertion cannot be both pending-live and servicing'
    }
    if ($AnyStartMode -and ($PendingTransaction -or $ServicingTransaction)) {
        throw 'service configuration assertion cannot accept any start mode inside a transaction'
    }
    # Boot policy is not part of the authorization contract; ImagePath, account,
    # SID type, privileges, environment, and the ACL surfaces are. Teardown
    # accepts any supported mode so a disabled or manually started deployment
    # stays removable.
    $expectedStartMode = if ($ServicingTransaction) {
        @(4)
    }
    elseif ($PendingTransaction) {
        @(3)
    }
    elseif ($AnyStartMode) {
        @(2, 3, 4)
    }
    else {
        @(2)
    }
    $gatewayEnvironment = [string[]]@(
        Get-DefenseClawServiceEnvironmentValues `
            -Name $GatewayServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GatewayLogPath `
            -BrokerPipeName $Layout.BrokerPipeName `
            -BrokerServiceName $Layout.BrokerServiceName `
            -BrokerAuthKeyPath $Layout.BrokerAuthKeyPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified
    )
    $guardianEnvironment = [string[]]@(
        Get-DefenseClawServiceEnvironmentValues `
            -Name $GuardianServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified
    )
    $brokerImage = Get-DefenseClawCMIDBrokerImage `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName
    Assert-DefenseClawServiceConfiguration `
        -Name $Layout.BrokerServiceName `
        -ExpectedImage $brokerImage `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Credential Broker' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment @() `
        -ExpectedStartMode $expectedStartMode
    Assert-DefenseClawServiceConfiguration `
        -Name $GatewayServiceName `
        -ExpectedImage ('"{0}"' -f $Layout.GatewayPath) `
        -ExpectedAccount "NT SERVICE\$GatewayServiceName" `
        -ExpectedDisplayName 'DefenseClaw Enterprise Gateway' `
        -ExpectedSidType 3 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment $gatewayEnvironment `
        -ExpectedDependencies @($Layout.BrokerServiceName) `
        -ExpectedStartMode $expectedStartMode
    Assert-DefenseClawServiceConfiguration `
        -Name $GuardianServiceName `
        -ExpectedImage ('"{0}" enterprise hooks watch --manifest "{1}" --interval 1m' -f $Layout.GatewayPath, $Layout.ManifestPath) `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Enterprise Hook Guardian' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @(
            'SeTcbPrivilege',
            'SeImpersonatePrivilege',
            'SeChangeNotifyPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege'
        ) `
        -ExpectedEnvironment $guardianEnvironment `
        -ExpectedStartMode $expectedStartMode
    # Spec 005 D1: third service. Same account model + privilege set
    # as the guardian (needs SeImpersonate + SeBackup + SeRestore for
    # per-user profile walks). Shares the guardian's log path — the
    # enumerator writes one line per cycle to hook-guardian.log rather
    # than a separate hook-enumerator.log, matching what LocalSystem
    # can chown without touching a third log-file ACL surface. ImagePath
    # differs from guardian's watch command: `enterprise windows
    # enumerate --manifest <path> --interval 5m`.
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $enumeratorEnvironment = [string[]]@(
        Get-DefenseClawServiceEnvironmentValues `
            -Name $enumeratorServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified
    )
    Assert-DefenseClawServiceConfiguration `
        -Name $enumeratorServiceName `
        -ExpectedImage ('"{0}" enterprise windows enumerate --manifest "{1}" --interval 5m' -f $Layout.GatewayPath, $Layout.ManifestPath) `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Enterprise Hook Enumerator' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @(
            'SeTcbPrivilege',
            'SeImpersonatePrivilege',
            'SeChangeNotifyPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege'
        ) `
        -ExpectedEnvironment $enumeratorEnvironment `
        -ExpectedStartMode $expectedStartMode
}

function New-DefenseClawRequiredRights {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Admin', 'Install', 'ServiceInstall', 'State', 'ConfigDirectory', 'Config', 'MachinePolicy', 'AuthorizationDirectory', 'AuthorizationFile', 'Runtime', 'RuntimeSecret', 'ManagedIPCDirectory')]
        [string]$Kind,
        [string]$GatewayServiceSID
    )
    $required = @{}
    $required[$script:SystemSID] = [Security.AccessControl.FileSystemRights]::FullControl
    $required[$script:AdministratorsSID] = [Security.AccessControl.FileSystemRights]::FullControl
    switch ($Kind) {
        'Install' {
            $required[$script:UsersSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        'ServiceInstall' {
            $required[$script:UsersSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        'State' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        'ConfigDirectory' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        'Config' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::Read
        }
        'MachinePolicy' {
            $required[$script:UsersSID] = [Security.AccessControl.FileSystemRights]::Read
        }
        'AuthorizationDirectory' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        'AuthorizationFile' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::Read
        }
        'Runtime' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::Modify
        }
        'RuntimeSecret' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::Read
        }
        'ManagedIPCDirectory' {
            $required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::FullControl
            $required[$script:AuthenticatedUsersSID] = (
                [Security.AccessControl.FileSystemRights]::ListDirectory -bor
                [Security.AccessControl.FileSystemRights]::Traverse
            )
        }
    }
    return $required
}

function Assert-DefenseClawEnterpriseDeployment {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$RequireReadiness,
        [switch]$PendingTransaction,
        [switch]$ServicingTransaction
    )
    if ($PendingTransaction -and $ServicingTransaction) {
        throw 'deployment assertion cannot be both pending-live and servicing'
    }
    if ($RequireReadiness -and $ServicingTransaction) {
        throw 'disabled servicing state cannot satisfy live readiness'
    }
    $expectedServiceStartMode = if ($ServicingTransaction) {
        4
    }
    elseif ($PendingTransaction) {
        3
    }
    else {
        2
    }
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    if (-not (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        throw 'DefenseClaw enterprise deployment is recorded as uninstalled'
    }
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $recordedCodexParent = $metadata.PSObject.Properties['codex_machine_policy_parent']
    if ($null -eq $recordedCodexParent -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$recordedCodexParent.Value).TrimEnd('\'),
            [IO.Path]::GetFullPath($Layout.CodexMachinePolicyDirectory).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'deployment metadata does not pin the exact Codex machine-policy parent'
    }
    foreach ($pair in @(
        @('codex_machine_policy_path', $Layout.CodexMachinePolicyPath),
        @('codex_managed_hooks_directory', $Layout.CodexManagedHooksDirectory),
        @('codex_managed_hooks_state_path', $Layout.CodexManagedHooksStatePath),
        @('codex_requirements_ownership_path', $Layout.CodexRequirementsOwnershipPath),
        @('codex_requirements_acl_backup_path', $Layout.CodexRequirementsAclBackupPath),
        @('agent_application_control_attestation_path', $Layout.AgentApplicationControlAttestationPath)
    )) {
        $property = $metadata.PSObject.Properties[[string]$pair[0]]
        if ($null -eq $property -or
            [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            throw "deployment metadata is missing $($pair[0])"
        }
        $recorded = [IO.Path]::GetFullPath([string]$property.Value).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath([string]$pair[1]).TrimEnd('\')
        if (-not [string]::Equals(
            $recorded,
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "deployment metadata $($pair[0]) does not pin the exact installed layout"
        }
    }
    $codexTargetProperty = $metadata.PSObject.Properties[
        'codex_target_enabled'
    ]
    $managedProperty = $metadata.PSObject.Properties[
        'codex_machine_policy_managed'
    ]
    if ($null -eq $codexTargetProperty -or
        $codexTargetProperty.Value -isnot [bool] -or
        $null -eq $managedProperty -or
        $managedProperty.Value -isnot [bool] -or
        [bool]$managedProperty.Value -ne [bool]$codexTargetProperty.Value) {
        throw 'deployment metadata Codex target and machine-policy ownership state disagree'
    }
    $codexTargetEnabled = [bool]$codexTargetProperty.Value
    $cursorTargetProperty = $metadata.PSObject.Properties[
        'cursor_target_enabled'
    ]
    # Schema-1 deployments created before native Cursor support do not carry
    # this field. Their only safe interpretation is Cursor disabled.
    if ($null -ne $cursorTargetProperty -and
        $cursorTargetProperty.Value -isnot [bool]) {
        throw 'deployment metadata has an invalid Cursor target result'
    }
    $cursorTargetEnabled = [bool](
        $null -ne $cursorTargetProperty -and
        [bool]$cursorTargetProperty.Value
    )
    if ($codexTargetEnabled) {
        if ([string]$metadata.codex_machine_policy_sha256 -cnotmatch
            '^[0-9a-f]{64}$') {
            throw 'deployment metadata contains an invalid Codex machine-policy SHA-256'
        }
    }
    elseif (-not [string]::IsNullOrEmpty(
        [string]$metadata.codex_machine_policy_sha256
    )) {
        throw 'Claude-only deployment metadata unexpectedly authenticates a DefenseClaw-managed Codex policy'
    }
    $applicationControlProperty = $metadata.PSObject.Properties[
        'agent_application_control_enforced'
    ]
    $coreCertificationProperty = $metadata.PSObject.Properties[
        'core_hardening_certification'
    ]
    if ($null -eq $applicationControlProperty -or
        $applicationControlProperty.Value -isnot [bool] -or
        $null -eq $coreCertificationProperty -or
        $coreCertificationProperty.Value -isnot [bool] -or
        [bool]$coreCertificationProperty.Value -ne
            [bool]$Layout.CoreHardeningCertification -or
        [string]$metadata.agent_application_control_prerequisite -cne
            $script:AgentApplicationControlPrerequisite) {
        throw 'deployment metadata does not attest the approved-agent application-control prerequisite'
    }
    $approvedClientProperty = $metadata.PSObject.Properties[
        'codex_approved_client_enforced'
    ]
    if ($null -eq $approvedClientProperty -or
        $approvedClientProperty.Value -isnot [bool] -or
        [bool]$approvedClientProperty.Value -ne
            [bool]$applicationControlProperty.Value) {
        throw 'deployment metadata does not attest approved Codex client application control'
    }
    $approvedAgentsProperty = $metadata.PSObject.Properties[
        'approved_agent_clients_enforced'
    ]
    if ($null -eq $approvedAgentsProperty -or
        $approvedAgentsProperty.Value -isnot [bool] -or
        [bool]$approvedAgentsProperty.Value -ne
            [bool]$applicationControlProperty.Value -or
        [string]$metadata.claude_minimum_client_version -cne '2.1.152') {
        throw 'deployment metadata does not attest approved Claude clients at version 2.1.152 or newer'
    }
    $claudeTargetProperty = $metadata.PSObject.Properties[
        'claude_target_enabled'
    ]
    $claudeEffectiveProperty = $metadata.PSObject.Properties[
        'claude_effective_policy_verified'
    ]
    if ($null -eq $claudeTargetProperty -or
        $claudeTargetProperty.Value -isnot [bool] -or
        $null -eq $claudeEffectiveProperty -or
        $claudeEffectiveProperty.Value -isnot [bool]) {
        throw 'deployment metadata has an invalid Claude target or effective-policy result'
    }
    $securityCompleteProperty = $metadata.PSObject.Properties[
        'security_complete'
    ]
    $externalPrerequisitesProperty = $metadata.PSObject.Properties[
        'external_security_prerequisites_satisfied'
    ]
    $expectedSecurityComplete = [bool](
        ([bool]$claudeTargetProperty.Value -or
            $codexTargetEnabled -or
            $cursorTargetEnabled) -and
        (-not [bool]$claudeTargetProperty.Value -or
            [bool]$claudeEffectiveProperty.Value)
    )
    if ($null -eq $securityCompleteProperty -or
        $securityCompleteProperty.Value -isnot [bool] -or
        $null -eq $externalPrerequisitesProperty -or
        $externalPrerequisitesProperty.Value -isnot [bool] -or
        [bool]$externalPrerequisitesProperty.Value -ne
            $expectedSecurityComplete -or
        [bool]$securityCompleteProperty.Value -ne $expectedSecurityComplete -or
        ([bool]$securityCompleteProperty.Value -and
            [bool]$Layout.CoreHardeningCertification)) {
        throw 'deployment metadata has an invalid aggregate Windows enterprise security result'
    }
    $Layout.AgentApplicationControlAttested = [bool](
        $applicationControlProperty.Value
    )
    $Layout.ClaudeTargetEnabled = [bool]$claudeTargetProperty.Value
    $Layout.CodexTargetEnabled = $codexTargetEnabled
    $Layout.CursorTargetEnabled = $cursorTargetEnabled
    $recordedAttestationHash = [string]$metadata.agent_application_control_attestation_sha256
    if ([bool]$Layout.CoreHardeningCertification) {
        if ((Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath) -or
            -not [string]::IsNullOrEmpty($recordedAttestationHash)) {
            throw 'core-hardening deployment retains false external application-control evidence'
        }
        $Layout.ClaudeEffectivePolicyVerified = [bool](
            $metadata.claude_effective_policy_verified
        )
    }
    else {
        $attestation = Get-DefenseClawAgentApplicationControlAttestation -Layout $Layout
        if ([bool]$attestation.agent_application_control_enforced -ne
            [bool]$metadata.agent_application_control_enforced) {
            throw 'protected application-control evidence disagrees with deployment metadata'
        }
        if ([bool]$attestation.claude_effective_policy_verified -ne
            [bool]$metadata.claude_effective_policy_verified) {
            throw 'protected Claude effective-policy evidence disagrees with deployment metadata'
        }
        $Layout.ClaudeEffectivePolicyVerified = [bool](
            $attestation.claude_effective_policy_verified
        )
        if ($recordedAttestationHash -cnotmatch '^[0-9a-f]{64}$') {
            throw 'deployment metadata contains an invalid agent application-control attestation SHA-256'
        }
        $actualAttestationHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualAttestationHash -cne $recordedAttestationHash) {
            throw 'agent application-control attestation hash drift'
        }
    }
    if ($codexTargetEnabled) {
        Assert-DefenseClawCodexMachinePolicyDirectory `
            -Path $Layout.CodexVendorDirectory
        Assert-DefenseClawCodexMachinePolicyDirectory `
            -Path $Layout.CodexMachinePolicyDirectory
        Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout
        Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout
        [void](Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout)
    }
    else {
        foreach ($ownedPath in @(
            $Layout.CodexRequirementsOwnershipPath,
            $Layout.CodexRequirementsAclBackupPath
        )) {
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $ownedPath) {
                throw "Claude-only deployment retains stale DefenseClaw Codex ownership state: $ownedPath"
            }
        }
    }
    $gatewaySID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    $adminWriters = @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)
    $runtimeWriters = @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID, $gatewaySID)
    $adminReaders = $adminWriters
    $gatewayReaders = $runtimeWriters
    $adminRights = New-DefenseClawRequiredRights -Kind Admin
    $installRights = New-DefenseClawRequiredRights -Kind Install
    $serviceInstallRights = New-DefenseClawRequiredRights `
        -Kind ServiceInstall `
        -GatewayServiceSID $gatewaySID
    $stateRights = New-DefenseClawRequiredRights -Kind State -GatewayServiceSID $gatewaySID
    $configDirectoryRights = New-DefenseClawRequiredRights `
        -Kind ConfigDirectory `
        -GatewayServiceSID $gatewaySID
    $configRights = New-DefenseClawRequiredRights -Kind Config -GatewayServiceSID $gatewaySID
    $authorizationDirectoryRights = New-DefenseClawRequiredRights `
        -Kind AuthorizationDirectory `
        -GatewayServiceSID $gatewaySID
    $authorizationFileRights = New-DefenseClawRequiredRights `
        -Kind AuthorizationFile `
        -GatewayServiceSID $gatewaySID
    $runtimeRights = New-DefenseClawRequiredRights -Kind Runtime -GatewayServiceSID $gatewaySID
    $managedIPCDirectoryRights = New-DefenseClawRequiredRights `
        -Kind ManagedIPCDirectory `
        -GatewayServiceSID $gatewaySID

    foreach ($path in @($Layout.InstallRoot, $Layout.BinDirectory)) {
        Assert-DefenseClawPathAcl `
            -Path $path `
            -AllowedWriterSIDs $adminWriters `
            -RequiredRights $serviceInstallRights `
            -AllowUsersRead
    }
    Assert-DefenseClawPathAcl `
        -Path $Layout.LibexecDirectory `
        -AllowedWriterSIDs $adminWriters `
        -RequiredRights $installRights `
        -AllowUsersRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.GatewayPath `
        -AllowedWriterSIDs $adminWriters `
        -RequiredRights $serviceInstallRights `
        -AllowUsersRead
    foreach ($path in @($Layout.BrokerPath, $Layout.HookPath, $Layout.InstallerPath, $Layout.ModulePath)) {
        Assert-DefenseClawPathAcl `
            -Path $path `
            -AllowedWriterSIDs $adminWriters `
            -RequiredRights $installRights `
            -AllowUsersRead
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.CLIPath `
            -AllowedWriterSIDs $adminWriters `
            -RequiredRights $installRights `
            -AllowUsersRead
    }
    $adminOnlyPaths = [Collections.Generic.List[string]]::new()
    foreach ($path in @(
        $Layout.BrokerLogDirectory,
        $Layout.GuardianDirectory,
        $Layout.InstallStateDirectory,
        $Layout.ManifestPath,
        $Layout.LogDirectory,
        $Layout.GuardianLogDirectory,
        $Layout.MetadataPath
    )) {
        $adminOnlyPaths.Add([string]$path)
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.AgentApplicationControlAttestationPath `
        -PathType Leaf) {
        $adminOnlyPaths.Add(
            [string]$Layout.AgentApplicationControlAttestationPath
        )
    }
    if ($codexTargetEnabled) {
        $adminOnlyPaths.Add([string]$Layout.CodexRequirementsOwnershipPath)
        $adminOnlyPaths.Add([string]$Layout.CodexRequirementsAclBackupPath)
    }
    foreach ($path in $adminOnlyPaths) {
        Assert-DefenseClawPathAcl `
            -Path $path `
            -AllowedWriterSIDs $adminWriters `
            -AllowedReaderSIDs $adminReaders `
            -RequiredRights $adminRights `
            -RejectUntrustedRead
    }
    foreach ($journalPath in @(
        $Layout.ManagedHooksLifecycleJournalPath,
        $Layout.ManagedHooksTeardownJournalPath
    )) {
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $journalPath `
            -PathType Leaf) {
            Assert-DefenseClawPathAcl `
                -Path $journalPath `
                -AllowedWriterSIDs $adminWriters `
                -AllowedReaderSIDs $adminReaders `
                -RequiredRights $adminRights `
                -RejectUntrustedRead
        }
    }
    foreach ($ancestor in @($Layout.StateRootAncestors)) {
        Assert-DefenseClawStateAncestorTraverse `
            -Path $ancestor `
            -GatewayServiceSID $gatewaySID
    }
    Assert-DefenseClawPathAcl `
        -Path $Layout.ManagedIPCDirectory `
        -AllowedWriterSIDs $runtimeWriters `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID,
            $gatewaySID,
            $script:AuthenticatedUsersSID
        ) `
        -RequiredRights $managedIPCDirectoryRights `
        -RejectUntrustedRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.StateRoot `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $stateRights `
        -RejectUntrustedRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.ConfigDirectory `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $configDirectoryRights `
        -RejectUntrustedRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.ConfigPath `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $configRights `
        -RejectUntrustedRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.AuthorizationDirectory `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $authorizationDirectoryRights `
        -RejectUntrustedRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.BrokerStateDirectory `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $authorizationDirectoryRights `
        -RejectUntrustedRead
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.AuthorizationLedgerPath -PathType Leaf) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.AuthorizationLedgerPath `
            -AllowedWriterSIDs $adminWriters `
            -AllowedReaderSIDs $gatewayReaders `
            -RequiredRights $authorizationFileRights `
            -RejectUntrustedRead
    }
    foreach ($path in @($Layout.RuntimeDirectory, $Layout.GatewayLogDirectory)) {
        Assert-DefenseClawPathAcl `
            -Path $path `
            -AllowedWriterSIDs $runtimeWriters `
            -AllowedReaderSIDs $gatewayReaders `
            -RequiredRights $runtimeRights `
            -RejectUntrustedRead
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GatewayLogPath -PathType Leaf) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.GatewayLogPath `
            -AllowedWriterSIDs $runtimeWriters `
            -AllowedReaderSIDs $gatewayReaders `
            -RequiredRights $runtimeRights `
            -RejectUntrustedRead
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GuardianLogPath -PathType Leaf) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.GuardianLogPath `
            -AllowedWriterSIDs $adminWriters `
            -AllowedReaderSIDs $adminReaders `
            -RequiredRights $adminRights `
            -RejectUntrustedRead
    }

    foreach ($requiredHash in @('broker', 'gateway', 'hook', 'installer', 'module')) {
        if ($null -eq $metadata.hashes.PSObject.Properties[$requiredHash]) {
            throw "deployment metadata is missing required artifact hash: $requiredHash"
        }
    }
    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) -and
        $null -eq $metadata.hashes.PSObject.Properties['cli']) {
        throw 'deployment metadata is missing the installed CLI artifact hash'
    }
    foreach ($property in $metadata.hashes.PSObject.Properties) {
        # Must cover every key the hash writer emits.
        $path = switch ($property.Name) {
            'broker' { $Layout.BrokerPath }
            'gateway' { $Layout.GatewayPath }
            'hook' { $Layout.HookPath }
            'cli' { $Layout.CLIPath }
            'installer' { $Layout.InstallerPath }
            'module' { $Layout.ModulePath }
            default { $null }
        }
        if ($null -eq $path -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "installed artifact recorded in metadata is missing: $($property.Name)"
        }
        $actualHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne ([string]$property.Value).ToLowerInvariant()) {
            throw "installed artifact hash drift: $($property.Name)"
        }
    }

    $gatewayEnvironment = [string[]]@(
        "DEFENSECLAW_HOME=$($Layout.RuntimeDirectory)",
        "DEFENSECLAW_CONFIG=$($Layout.ConfigPath)",
        'DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise',
        "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$($Layout.AuthorizationDirectory)",
        "DEFENSECLAW_WINDOWS_SERVICE_NAME=$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME=$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT=NT SERVICE\$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_LOG=$($Layout.GatewayLogPath)",
        "DEFENSECLAW_CMID_BROKER_PIPE=$($Layout.BrokerPipeName)",
        "DEFENSECLAW_CMID_BROKER_SERVICE_NAME=$($Layout.BrokerServiceName)",
        "DEFENSECLAW_CMID_BROKER_AUTH_KEY=$($Layout.BrokerAuthKeyPath)"
    )
    $guardianEnvironment = [string[]]@(
        "DEFENSECLAW_HOME=$($Layout.RuntimeDirectory)",
        "DEFENSECLAW_CONFIG=$($Layout.ConfigPath)",
        'DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise',
        "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$($Layout.AuthorizationDirectory)",
        "DEFENSECLAW_WINDOWS_SERVICE_NAME=$GuardianServiceName",
        "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME=$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT=NT SERVICE\$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_LOG=$($Layout.GuardianLogPath)"
    )
    if ([bool]$Layout.AgentApplicationControlAttested) {
        $gatewayEnvironment = [string[]]@(
            $gatewayEnvironment + @(
                'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1',
                'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1'
            )
        )
        $guardianEnvironment = [string[]]@(
            $guardianEnvironment + @(
                'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1',
                'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1'
            )
        )
    }
    if ([bool]$Layout.ClaudeEffectivePolicyVerified) {
        $gatewayEnvironment = [string[]]@(
            $gatewayEnvironment +
                'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1'
        )
        $guardianEnvironment = [string[]]@(
            $guardianEnvironment +
                'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1'
        )
    }
    # Spec 005 D1 (CR PRRT_kwDORuAK-s6aunSc): the enumerator is a
    # third managed SCM service. Its expected env vars mirror the
    # guardian's (DEFENSECLAW_WINDOWS_SERVICE_NAME differs; everything
    # else including the shared GuardianLogPath is identical), and
    # its expected start mode + running state get validated here so
    # -RequireReadiness catches the case where the enumerator got
    # left disabled during activation.
    $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
    $enumeratorEnvironment = [string[]]@(
        "DEFENSECLAW_HOME=$($Layout.RuntimeDirectory)",
        "DEFENSECLAW_CONFIG=$($Layout.ConfigPath)",
        'DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise',
        "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$($Layout.AuthorizationDirectory)",
        "DEFENSECLAW_WINDOWS_SERVICE_NAME=$enumeratorServiceName",
        "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME=$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT=NT SERVICE\$GatewayServiceName",
        "DEFENSECLAW_WINDOWS_SERVICE_LOG=$($Layout.GuardianLogPath)"
    )
    if ([bool]$Layout.AgentApplicationControlAttested) {
        $enumeratorEnvironment = [string[]]@(
            $enumeratorEnvironment + @(
                'DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1',
                'DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1'
            )
        )
    }
    if ([bool]$Layout.ClaudeEffectivePolicyVerified) {
        $enumeratorEnvironment = [string[]]@(
            $enumeratorEnvironment +
                'DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1'
        )
    }
    Assert-DefenseClawServiceConfiguration `
        -Name $Layout.BrokerServiceName `
        -ExpectedImage (Get-DefenseClawCMIDBrokerImage -Layout $Layout -GatewayServiceName $GatewayServiceName) `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Credential Broker' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment @() `
        -ExpectedStartMode $expectedServiceStartMode
    Assert-DefenseClawServiceConfiguration `
        -Name $GatewayServiceName `
        -ExpectedImage ('"{0}"' -f $Layout.GatewayPath) `
        -ExpectedAccount "NT SERVICE\$GatewayServiceName" `
        -ExpectedDisplayName 'DefenseClaw Enterprise Gateway' `
        -ExpectedSidType 3 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment $gatewayEnvironment `
        -ExpectedDependencies @($Layout.BrokerServiceName) `
        -ExpectedStartMode $expectedServiceStartMode
    Assert-DefenseClawServiceConfiguration `
        -Name $GuardianServiceName `
        -ExpectedImage ('"{0}" enterprise hooks watch --manifest "{1}" --interval 1m' -f $Layout.GatewayPath, $Layout.ManifestPath) `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Enterprise Hook Guardian' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @(
            'SeTcbPrivilege',
            'SeImpersonatePrivilege',
            'SeChangeNotifyPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege'
        ) `
        -ExpectedEnvironment $guardianEnvironment `
        -ExpectedStartMode $expectedServiceStartMode
    Assert-DefenseClawServiceConfiguration `
        -Name $enumeratorServiceName `
        -ExpectedImage ('"{0}" enterprise windows enumerate --manifest "{1}" --interval 5m' -f $Layout.GatewayPath, $Layout.ManifestPath) `
        -ExpectedAccount 'LocalSystem' `
        -ExpectedDisplayName 'DefenseClaw Enterprise Hook Enumerator' `
        -ExpectedSidType 1 `
        -ExpectedPrivileges @(
            'SeTcbPrivilege',
            'SeImpersonatePrivilege',
            'SeChangeNotifyPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege'
        ) `
        -ExpectedEnvironment $enumeratorEnvironment `
        -ExpectedStartMode $expectedServiceStartMode
    Assert-DefenseClawInstalledConfig -Layout $Layout -GatewayServiceName $GatewayServiceName
    [void](Invoke-DefenseClawCodexRequirementsCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))

    if ($RequireReadiness) {
        $brokerService = Microsoft.PowerShell.Management\Get-Service `
            -Name $Layout.BrokerServiceName `
            -ErrorAction SilentlyContinue
        if ($null -eq $brokerService -or
            $brokerService.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
            throw 'credential broker SCM process is not running'
        }
        if (-not (Test-DefenseClawGatewayReady -Layout $Layout -GatewayServiceName $GatewayServiceName)) {
            throw 'gateway SCM process is running but authenticated health is not ready'
        }
        if (-not (Test-DefenseClawGuardianReady `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -LiveVerify)) {
            throw 'guardian SCM process is running but protected target coverage is not verified'
        }
        # Spec 005 D1: readiness check for the enumerator SCM
        # process. Uses the same lightweight "service is running"
        # probe as Test-DefenseClawGatewayReady rather than a
        # deeper liveness call — the enumerator has no readiness
        # RPC of its own; its per-cycle stderr goes to the
        # guardian's log surface and the sidecar's
        # SidecarHealth.Enumerator field (spec 005 Stage 9)
        # carries the per-cycle state. A missing-or-stopped SCM
        # process here is caught; a hung enumerator loop is a
        # follow-up to add a health probe for.
        $enumeratorService = Microsoft.PowerShell.Management\Get-Service `
            -Name $enumeratorServiceName `
            -ErrorAction SilentlyContinue
        if ($null -eq $enumeratorService -or
            $enumeratorService.Status -ne
                [ServiceProcess.ServiceControllerStatus]::Running) {
            throw 'enumerator SCM process is not running; targets.yaml will not refresh for new user profiles'
        }
    }
}

function Get-DefenseClawArtifactPath {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$Name
    )
    $path = switch ($Name) {
        'broker' { $Layout.BrokerPath }
        'gateway' { $Layout.GatewayPath }
        'hook' { $Layout.HookPath }
        'cli' { $Layout.CLIPath }
        'installer' { $Layout.InstallerPath }
        'module' { $Layout.ModulePath }
        'config' { $Layout.ConfigPath }
        'manifest' { $Layout.ManifestPath }
        default { throw "unknown managed artifact: $Name" }
    }
    return $path
}

function Assert-DefenseClawRecordedArtifactHashes {
    param(
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)][hashtable]$Layout,
        [string[]]$ReplacedArtifacts = @(),
        # Names the caller in drift errors. Every lifecycle action shares this
        # gate, and the only way out is an Upgrade that replaces the artifact.
        [string]$Action = 'this action'
    )
    foreach ($required in @('broker', 'gateway', 'hook', 'installer', 'module')) {
        if ($required -notin $ReplacedArtifacts -and
            $null -eq $Metadata.hashes.PSObject.Properties[$required]) {
            throw "deployment metadata is missing required artifact hash: $required"
        }
    }
    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) -and
        'cli' -notin $ReplacedArtifacts -and
        $null -eq $Metadata.hashes.PSObject.Properties['cli']) {
        throw 'deployment metadata does not authenticate the installed CLI'
    }
    foreach ($property in $Metadata.hashes.PSObject.Properties) {
        if ($property.Name -in $ReplacedArtifacts) {
            continue
        }
        $path = Get-DefenseClawArtifactPath -Layout $Layout -Name $property.Name
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "recorded managed artifact is missing before lifecycle mutation: $($property.Name)"
        }
        Assert-DefenseClawNoReparsePath -Path $path
        $actual = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if (-not [string]::Equals(
            $actual,
            [string]$property.Value,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw (
                "$Action refuses unrecorded artifact hash drift: $($property.Name) " +
                "at $path does not match deployment metadata; run Upgrade with " +
                "the replacement for $($property.Name) to re-record it"
            )
        }
    }
}

function Get-DefenseClawLifecycleSources {
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$BrokerBinary,
        [string]$ProviderLibrary,
        [string]$GatewayBinary,
        [string]$HookBinary,
        [string]$CLIBinary,
        [string]$Config,
        [string]$Manifest,
        [string]$InstallerSource,
        [string]$ModuleSource,
        [switch]$AllowUnsigned,
        # Retained only for internal call-shape compatibility. The public
        # lifecycle entry point rejects deferred configuration before layout
        # resolution, so this legacy source-selection branch is unreachable.
        [switch]$DeferredConfig
    )
    $sources = @{}
    if ($Action -notin @('Install', 'Upgrade', 'Repair')) {
        return $sources
    }
    if ([string]::IsNullOrWhiteSpace($InstallerSource) -or
        [string]::IsNullOrWhiteSpace($ModuleSource)) {
        throw "$Action requires the installer and adjacent module source paths"
    }
    if ($Action -eq 'Install') {
        $required = @(
            @('BrokerBinary', $BrokerBinary),
            @('ProviderLibrary', $ProviderLibrary),
            @('GatewayBinary', $GatewayBinary),
            @('HookBinary', $HookBinary)
        )
        # Legacy compatibility scaffolding: direct callers of this internal
        # helper can still describe the old source shape, but the lifecycle
        # gate rejects that mode before this function is reached.
        if (-not $DeferredConfig) {
            $required += @(
                @('Config', $Config),
                @('Manifest', $Manifest)
            )
        }
        foreach ($req in $required) {
            if ([string]::IsNullOrWhiteSpace([string]$req[1])) {
                throw "Install requires -$($req[0])"
            }
        }
    }
    if ($Action -eq 'Upgrade' -and
        ([string]::IsNullOrWhiteSpace($BrokerBinary) -or
        [string]::IsNullOrWhiteSpace($ProviderLibrary) -or
        [string]::IsNullOrWhiteSpace($GatewayBinary) -or
        [string]::IsNullOrWhiteSpace($HookBinary))) {
        throw 'Upgrade requires -BrokerBinary, -ProviderLibrary, -GatewayBinary, and -HookBinary'
    }

    foreach ($entry in @(
        @('broker', $BrokerBinary, 'credential broker executable', $true),
        @('provider_library', $ProviderLibrary, 'managed credential provider library', $true),
        @('gateway', $GatewayBinary, 'gateway executable', $true),
        @('hook', $HookBinary, 'hook executable', $true),
        @('cli', $CLIBinary, 'CLI executable', $true),
        @('config', $Config, 'managed config', $false),
        @('manifest', $Manifest, 'guardian manifest', $false),
        @('installer', $InstallerSource, 'enterprise installer', $true),
        @('module', $ModuleSource, 'enterprise installer module', $true)
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$entry[1])) {
            continue
        }
        $sources[[string]$entry[0]] = Get-DefenseClawSourceDescriptor `
            -Path ([string]$entry[1]) `
            -Label ([string]$entry[2]) `
            -Authenticode:([bool]$entry[3]) `
            -AllowUnsigned:$AllowUnsigned
    }
    return $sources
}

function Assert-DefenseClawLifecycleSourcesCurrent {
    param([Parameter(Mandatory)][hashtable]$Sources)
    foreach ($name in @(
        $Sources.Keys | Microsoft.PowerShell.Utility\Sort-Object
    )) {
        [void](Assert-DefenseClawSourceDescriptorCurrent `
            -Source $Sources[[string]$name])
    }
}

function Get-DefenseClawServiceState {
    param([Parameter(Mandatory)][string]$Name)
    $service = Microsoft.PowerShell.Management\Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return 'absent'
    }
    return $service.Status.ToString().ToLowerInvariant()
}

function ConvertTo-DefenseClawBoundedDiagnostic {
    param(
        [AllowNull()]$Value,
        [ValidateRange(64, 4096)][int]$MaxLength = 2048
    )
    $text = (($Value | Microsoft.PowerShell.Utility\Out-String).Trim())
    if ([string]::IsNullOrWhiteSpace($text)) {
        return 'unavailable'
    }
    $text = $text -replace '[\x00-\x1f\x7f]+', ' '
    $text = $text -replace '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer <redacted>'
    $text = $text -replace '(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|''[^'']*''|[^,;\s]+)', '$1=<redacted>'
    $text = $text.Trim()
    if ($text.Length -gt $MaxLength) {
        return $text.Substring(0, $MaxLength - 3) + '...'
    }
    return $text
}

function Get-DefenseClawGuardianStatusReport {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName
    )
    try {
        $probe = Invoke-DefenseClawGatewayCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Arguments @('enterprise', 'hooks', 'status', '--manifest', $Layout.ManifestPath, '--json') `
            -Capture `
            -AllowFailure
        foreach ($line in @($probe.output)) {
            $text = ([string]$line).Trim()
            if (-not $text.StartsWith('{')) {
                continue
            }
            try {
                return $text | Microsoft.PowerShell.Utility\ConvertFrom-Json
            }
            catch {
                continue
            }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            ok = $false
            errors = @(
                "guardian status command failed: $(ConvertTo-DefenseClawBoundedDiagnostic -Value $_.Exception.Message)"
            )
        }
    }
    return [pscustomobject][ordered]@{
        ok = $false
        errors = @(
            "guardian status command exited $($probe.exit_code) without a valid JSON report: $(ConvertTo-DefenseClawBoundedDiagnostic -Value $probe.output)"
        )
    }
}

function Get-DefenseClawLifecycleStatus {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $errors = [Collections.Generic.List[string]]::new()
    $metadata = $null
    try {
        $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout
        if ($null -ne $metadata) {
            Assert-DefenseClawMetadataIdentity `
                -Metadata $metadata `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }
    }
    catch {
        $errors.Add($_.Exception.Message)
    }
    $installed = $null -ne $metadata -and (Test-DefenseClawMetadataInstalled -Metadata $metadata)
    $pending = Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath -PathType Leaf
    $gatewayState = Get-DefenseClawServiceState -Name $GatewayServiceName
    $brokerState = Get-DefenseClawServiceState -Name $Layout.BrokerServiceName
    $guardianState = Get-DefenseClawServiceState -Name $GuardianServiceName
    $gatewayReady = $false
    $guardianReady = $false
    $codexRequirementsReady = $false
    $codexRequirementsDisposition = $null
    $codexTargetEnabled = $false
    $cursorTargetEnabled = [bool]$Layout.CursorTargetEnabled
    $claudeTargetEnabled = [bool]$Layout.ClaudeTargetEnabled
    $claudeEffectivePolicyVerified = [bool](
        $Layout.ClaudeEffectivePolicyVerified
    )
    $generation = $null
    if ($installed -and -not $pending) {
        try {
            $gatewayReady = Test-DefenseClawGatewayReady `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName
        }
        catch {
            $errors.Add($_.Exception.Message)
        }
        try {
            $guardianReady = Test-DefenseClawGuardianReady `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            $guardianReport = Get-DefenseClawGuardianStatusReport `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName
            $generation = Get-DefenseClawGuardianGeneration -Report $guardianReport
            if ($null -ne $guardianReport -and
                $null -ne $guardianReport.PSObject.Properties['errors']) {
                foreach ($issue in @($guardianReport.PSObject.Properties['errors'].Value)) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$issue)) {
                        $errors.Add(
                            "guardian status: $(ConvertTo-DefenseClawBoundedDiagnostic -Value $issue)"
                        )
                    }
                }
            }
        }
        catch {
            $errors.Add($_.Exception.Message)
        }
        if (Test-DefenseClawAdministrator) {
            try {
                $codexReport = Invoke-DefenseClawCodexRequirementsCommand `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -Action $(if ([bool]$Layout.CodexTargetEnabled) {
                        'verify'
                    } else {
                        'inspect'
                    })
                $codexRequirementsReady = [bool]$codexReport.ok
                $codexRequirementsDisposition = [string]$codexReport.disposition
                $codexTargetEnabled = [bool]$codexReport.codex_target_enabled
                $cursorTargetEnabled = [bool]$codexReport.cursor_target_enabled
                $claudeTargetEnabled = [bool]$codexReport.claude_target_enabled
                $claudeEffectivePolicyVerified = [bool](
                    $codexReport.claude_effective_policy_verified
                )
            }
            catch {
                $errors.Add($_.Exception.Message)
            }
        }
        else {
            $errors.Add(
                'Codex machine requirements verification requires an elevated administrator token'
            )
        }
    }
    $healthy = if ($installed) {
        $gatewayState -eq 'running' -and
            $brokerState -eq 'running' -and
            $guardianState -eq 'running' -and
            $gatewayReady -and
            $guardianReady -and
            $codexRequirementsReady -and
            -not $pending -and
            $errors.Count -eq 0
    }
    else {
        $gatewayState -eq 'absent' -and
            $brokerState -eq 'absent' -and
            $guardianState -eq 'absent' -and
            -not $pending -and
            $errors.Count -eq 0
    }
    # Cursor uses the same protected Guardian/runtime readiness lane but does
    # not require Codex machine policy or application-control proof.
    $externalSecuritySatisfied = [bool](
        $installed -and
        ($claudeTargetEnabled -or $codexTargetEnabled -or $cursorTargetEnabled) -and
        (-not $claudeTargetEnabled -or
            $claudeEffectivePolicyVerified)
    )
    return [pscustomobject][ordered]@{
        schema_version = 1
        ok = [bool]$healthy
        action = $Action.ToLowerInvariant()
        installed = [bool]$installed
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        core_hardening_complete = [bool]($installed -and $healthy)
        external_security_prerequisites_satisfied = [bool]$externalSecuritySatisfied
        install_root = $Layout.InstallRoot
        state_root = $Layout.StateRoot
        transaction_pending = [bool]$pending
        gateway_service = $GatewayServiceName
        broker_service = $Layout.BrokerServiceName
        guardian_service = $GuardianServiceName
        gateway_service_state = $gatewayState
        broker_service_state = $brokerState
        guardian_service_state = $guardianState
        gateway_ready = [bool]$gatewayReady
        guardian_ready = [bool]$guardianReady
        codex_machine_requirements_ready = [bool]$codexRequirementsReady
        codex_machine_requirements_disposition = $codexRequirementsDisposition
        codex_machine_policy_path = $Layout.CodexMachinePolicyPath
        codex_managed_hooks_state_path = $Layout.CodexManagedHooksStatePath
        agent_application_control_enforced = [bool]$Layout.AgentApplicationControlAttested
        agent_application_control_prerequisite = $script:AgentApplicationControlPrerequisite
        codex_approved_client_enforced = [bool]$Layout.AgentApplicationControlAttested
        codex_target_enabled = [bool]$codexTargetEnabled
        cursor_target_enabled = [bool]$cursorTargetEnabled
        claude_target_enabled = [bool]$claudeTargetEnabled
        claude_approved_client_enforced = [bool]$Layout.AgentApplicationControlAttested
        claude_minimum_client_version = '2.1.152'
        approved_agent_clients_enforced = [bool]$Layout.AgentApplicationControlAttested
        claude_effective_policy_verified = [bool]$claudeEffectivePolicyVerified
        security_complete = [bool](
            $healthy -and
            $externalSecuritySatisfied
        )
        guardian_generation = $generation
        errors = @($errors)
    }
}

function Wait-DefenseClawFreshGuardianReconcile {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [int]$TimeoutSeconds = 90
    )
    $priorReport = Get-DefenseClawGuardianStatusReport `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName
    $priorGeneration = [string](Get-DefenseClawGuardianGeneration -Report $priorReport)
    # Guardian generation timestamps have one-second precision. Avoid
    # restarting in the same encoded second, which would make a genuinely new
    # LocalSystem reconcile look stale.
    if (-not [string]::IsNullOrWhiteSpace($priorGeneration)) {
        $boundaryDeadline = [DateTime]::UtcNow.AddSeconds(2)
        while ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') -eq $priorGeneration -and
            [DateTime]::UtcNow -lt $boundaryDeadline) {
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 100
        }
    }
    $startedAfter = [DateTime]::UtcNow.AddSeconds(-1)
    Stop-DefenseClawService -Name $GuardianServiceName
    Start-DefenseClawService -Name $GuardianServiceName

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastStatus = 'guardian status report unavailable'
    do {
        $report = Get-DefenseClawGuardianStatusReport `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName
        $reportOK = $null -ne $report -and
            $null -ne $report.PSObject.Properties['ok'] -and
            [bool]$report.ok
        $generation = if ($reportOK) { Get-DefenseClawGuardianGeneration -Report $report } else { $null }
        if (-not $reportOK) {
            $issues = [Collections.Generic.List[string]]::new()
            if ($null -ne $report -and $null -ne $report.PSObject.Properties['errors']) {
                foreach ($issue in @($report.PSObject.Properties['errors'].Value)) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$issue)) {
                        $issues.Add([string]$issue)
                    }
                }
            }
            if ($issues.Count -eq 0) {
                $issues.Add('guardian status reported ok=false without an error')
            }
            $lastStatus = ConvertTo-DefenseClawBoundedDiagnostic -Value ($issues -join '; ')
        }
        elseif ($null -eq $generation) {
            $lastStatus = 'guardian status reported ok=true without a generation'
        }
        else {
            $lastStatus = "guardian status generation '$generation' is not fresh"
        }
        if ($null -ne $generation) {
            try {
                $generationTime = [DateTime]::Parse(
                    $generation,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).ToUniversalTime()
                if (($generation -ne $priorGeneration -or [string]::IsNullOrWhiteSpace($priorGeneration)) -and
                    $generationTime -ge $startedAfter) {
                    return $generation
                }
            }
            catch {
                # Keep waiting for a complete, parseable guardian record.
                $lastStatus = ConvertTo-DefenseClawBoundedDiagnostic `
                    -Value "guardian status generation '$generation' is invalid: $($_.Exception.Message)"
            }
        }
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "LocalSystem guardian restarted but did not publish a fresh reconcile within $TimeoutSeconds seconds; last_status=$lastStatus"
}

function Assert-DefenseClawManagedInstallTree {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $allowedDirectories = @(
        $Layout.BinDirectory,
        $Layout.LibexecDirectory
    )
    $allowedFiles = @(
        $Layout.BrokerPath,
        $Layout.GatewayPath,
        $Layout.HookPath,
        $Layout.CLIPath,
        $Layout.InstallerPath,
        $Layout.ModulePath
    )
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Layout.InstallRoot -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "refusing to remove managed install tree containing a reparse point: $($item.FullName)"
        }
        $full = [IO.Path]::GetFullPath($item.FullName)
        if ($item.PSIsContainer) {
            if ($full -notin $allowedDirectories) {
                throw "refusing to remove unexpected directory from managed install root: $full"
            }
        }
        elseif ($full -notin $allowedFiles) {
            throw "refusing to remove unexpected file from managed install root: $full"
        }
    }
}

function Assert-DefenseClawManagedTreeNoReparse {
    param([Parameter(Mandatory)][string]$Root)
    Assert-DefenseClawNoReparsePath -Path $Root
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Root -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "managed tree contains a reparse point: $($item.FullName)"
        }
    }
}

function Set-DefenseClawPreservedStateAcls {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )
    $items = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Layout.StateRoot -Recurse -Force)
    Set-DefenseClawPathAcl `
        -Path $Layout.StateRoot `
        -Kind AdminDirectory `
        -GatewayServiceSID $GatewayServiceSID
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "refusing preserved-state ACL rewrite through reparse point: $($item.FullName)"
        }
        $kind = if ($item.PSIsContainer) { 'AdminDirectory' } else { 'AdminFile' }
        Set-DefenseClawPathAcl `
            -Path $item.FullName `
            -Kind $kind `
            -GatewayServiceSID $GatewayServiceSID
    }
}

function Remove-DefenseClawManagedTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RequiredBase,
        [Parameter(Mandatory)][string]$Label
    )
    $safe = Assert-DefenseClawSafeRoot -Path $Path -Label $Label -RequiredBase $RequiredBase
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $safe)) {
        return
    }
    Assert-DefenseClawManagedTreeNoReparse -Root $safe
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}

function Get-DefenseClawFileIdentity {
    param([Parameter(Mandatory)][string]$Path)
    $full = Resolve-DefenseClawFullPath -Path $Path -MustExist -Leaf
    Assert-DefenseClawNoReparsePath -Path $full
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    return ([string]$nativeSecurityType::GetFileIdentity($full)).ToLowerInvariant()
}

function Get-DefenseClawSelfUninstallCallerIdentity {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][int]$CallerPID
    )
    if ($CallerPID -le 0) {
        throw '-SelfUninstallCallerPID must be a positive process identifier'
    }
    $expectedImage = Resolve-DefenseClawFullPath `
        -Path $Layout.CLIPath `
        -MustExist `
        -Leaf
    Assert-DefenseClawNoReparsePath -Path $expectedImage
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    try {
        $actualImage = [IO.Path]::GetFullPath(
            [string]$nativeSecurityType::GetProcessImagePath(
                [uint32]$CallerPID
            )
        ).TrimEnd('\')
        $creationFileTime = [int64](
            $nativeSecurityType::GetProcessCreationFileTime(
                [uint32]$CallerPID
            )
        )
    }
    catch {
        throw (
            'cannot authenticate the installed CLI self-uninstall caller ' +
            "$CallerPID`: $($_.Exception.Message)"
        )
    }
    if (-not [string]::Equals(
            $actualImage,
            $expectedImage,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            '-SelfUninstallCallerPID does not identify the exact installed ' +
            "DefenseClaw CLI: $actualImage"
        )
    }
    if ($creationFileTime -le 0) {
        throw 'installed CLI self-uninstall caller has an invalid process creation FILETIME'
    }
    return [ordered]@{
        pid = [int64]$CallerPID
        creation_filetime = $creationFileTime
        image_path = $expectedImage
        file_identity = Get-DefenseClawFileIdentity -Path $expectedImage
        sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $expectedImage `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
}

function Assert-DefenseClawSelfUninstallRetiredRoot {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissing
    )
    $canonical = [IO.Path]::GetFullPath($Layout.InstallRoot).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $canonicalParent = [IO.Path]::GetDirectoryName($canonical)
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full),
            $canonicalParent,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "self-uninstall retired root is not an exact same-parent sibling: $full"
    }
    $expectedPattern = '^' +
        [Text.RegularExpressions.Regex]::Escape(
            [IO.Path]::GetFileName($canonical)
        ) +
        '\.retired-[0-9a-f]{32}$'
    if ([IO.Path]::GetFileName($full) -cnotmatch $expectedPattern) {
        throw "self-uninstall retired root has invalid 128-bit sibling grammar: $full"
    }
    if (-not [string]::Equals(
            [IO.Path]::GetPathRoot($canonical),
            [IO.Path]::GetPathRoot($full),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "self-uninstall retired root is not on the InstallRoot volume: $full"
    }
    [void](Assert-DefenseClawSafeRoot `
        -Path $full `
        -Label 'self-uninstall retired InstallRoot' `
        -RequiredBase $script:ProgramFiles)
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $full) {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $full `
                -PathType Container)) {
            throw "self-uninstall retired root is not a directory: $full"
        }
        Assert-DefenseClawNoReparsePath -Path $full
    }
    elseif (-not $AllowMissing) {
        throw "self-uninstall retired root is missing: $full"
    }
    return $full
}

function New-DefenseClawSelfUninstallRetiredRoot {
    param([Parameter(Mandatory)][hashtable]$Layout)
    for ($attempt = 0; $attempt -lt 16; $attempt++) {
        $candidate = (
            [IO.Path]::GetFullPath($Layout.InstallRoot).TrimEnd('\') +
            '.retired-' +
            [Guid]::NewGuid().ToString('N')
        )
        [void](Assert-DefenseClawSelfUninstallRetiredRoot `
            -Layout $Layout `
            -Path $candidate `
            -AllowMissing)
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $candidate)) {
            return $candidate
        }
    }
    throw 'cannot allocate a nonexisting 128-bit self-uninstall retirement sibling'
}

function Get-DefenseClawRetiredInstallTreeAllowlist {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$RetiredRoot
    )
    $directories = @(
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'bin'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'agents'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'libexec')
    )
    $files = @(
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'bin\defenseclaw-cmid-broker.exe'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'bin\defenseclaw-gateway.exe'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'bin\defenseclaw-hook.exe'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'bin\defenseclaw.exe'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'agents\codex.exe'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'libexec\install-enterprise.ps1'),
        (Microsoft.PowerShell.Management\Join-Path $RetiredRoot 'libexec\DefenseClawEnterprise.psm1')
    )
    return @{
        directories = @(
            $directories |
                Microsoft.PowerShell.Core\ForEach-Object {
                    [IO.Path]::GetFullPath($_).TrimEnd('\')
                }
        )
        files = @(
            $files |
                Microsoft.PowerShell.Core\ForEach-Object {
                    [IO.Path]::GetFullPath($_).TrimEnd('\')
                }
        )
    }
}

function Assert-DefenseClawRetiredInstallTree {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$RetiredRoot,
        [switch]$SkipAclValidation
    )
    $retired = Assert-DefenseClawSelfUninstallRetiredRoot `
        -Layout $Layout `
        -Path $RetiredRoot
    $allowlist = Get-DefenseClawRetiredInstallTreeAllowlist `
        -Layout $Layout `
        -RetiredRoot $retired
    Assert-DefenseClawManagedTreeNoReparse -Root $retired
    $objects = @(
        Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $retired `
            -Force
    ) + @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $retired `
            -Recurse `
            -Force
    )
    foreach ($item in $objects) {
        $full = [IO.Path]::GetFullPath($item.FullName).TrimEnd('\')
        if (-not [string]::Equals(
                $full,
                $retired,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            if ($item.PSIsContainer) {
                if ($full -notin $allowlist.directories) {
                    throw "self-uninstall retired tree contains unexpected directory: $full"
                }
            }
            elseif ($full -notin $allowlist.files) {
                throw "self-uninstall retired tree contains unexpected file: $full"
            }
        }
        if (-not $SkipAclValidation) {
            Assert-DefenseClawPathAcl `
                -Path $full `
                -AllowedWriterSIDs @(
                    $script:SystemSID,
                    $script:AdministratorsSID,
                    $script:TrustedInstallerSID
                ) `
                -AllowedReaderSIDs @(
                    $script:SystemSID,
                    $script:AdministratorsSID,
                    $script:TrustedInstallerSID
                ) `
                -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
                -AllowInheritance `
                -RejectUntrustedRead
        }
    }
}

function Set-DefenseClawRetiredInstallTreeAcls {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$RetiredRoot
    )
    $retired = Assert-DefenseClawSelfUninstallRetiredRoot `
        -Layout $Layout `
        -Path $RetiredRoot
    # Remove traversal at the root before enumerating descendants. Otherwise a
    # standard user watching the sibling rename could race this enumeration
    # and open a new executable handle from the retired tree.
    Set-DefenseClawPathAcl `
        -Path $retired `
        -Kind AdminDirectory `
        -GatewayServiceSID $script:AdministratorsSID
    $items = @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $retired `
            -Recurse `
            -Force
    )
    foreach ($item in $items) {
        $kind = if ($item.PSIsContainer) { 'AdminDirectory' } else { 'AdminFile' }
        Set-DefenseClawPathAcl `
            -Path $item.FullName `
            -Kind $kind `
            -GatewayServiceSID $script:AdministratorsSID
    }
    Assert-DefenseClawRetiredInstallTree `
        -Layout $Layout `
        -RetiredRoot $retired
}

function Set-DefenseClawInstallTreeRetirementAcls {
    param([Parameter(Mandatory)][hashtable]$Layout)
    Assert-DefenseClawManagedInstallTree -Layout $Layout
    # Strip Users RX from the canonical root before its random sibling name is
    # observable. Existing mapped CLI code continues to run; no standard user
    # can traverse the tree to create a new post-retirement locker.
    Set-DefenseClawPathAcl `
        -Path $Layout.InstallRoot `
        -Kind AdminDirectory `
        -GatewayServiceSID $script:AdministratorsSID
    $items = @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $Layout.InstallRoot `
            -Recurse `
            -Force
    )
    foreach ($item in $items) {
        $kind = if ($item.PSIsContainer) { 'AdminDirectory' } else { 'AdminFile' }
        Set-DefenseClawPathAcl `
            -Path $item.FullName `
            -Kind $kind `
            -GatewayServiceSID $script:AdministratorsSID
    }
}

function Write-DefenseClawProtectedTextAtomic {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RequiredRoot
    )
    $destination = Assert-DefenseClawDescendant `
        -Path $Path `
        -Root $RequiredRoot `
        -Label 'protected text file'
    Assert-DefenseClawNoReparsePath -Path $destination -AllowMissingLeaf
    $temporary = "$destination.new.$([Guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText(
            $temporary,
            $Value,
            [Text.UTF8Encoding]::new($false)
        )
        Set-DefenseClawPathAcl `
            -Path $temporary `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
        Microsoft.PowerShell.Management\Move-Item `
            -LiteralPath $temporary `
            -Destination $destination `
            -Force
        Set-DefenseClawPathAcl `
            -Path $destination `
            -Kind AdminFile `
            -GatewayServiceSID $script:AdministratorsSID
    }
    finally {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $temporary) {
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $temporary `
                -Force
        }
    }
}

function Get-DefenseClawSelfUninstallReceipt {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Required
    )
    $path = Assert-DefenseClawDescendant `
        -Path $Layout.SelfUninstallReceiptPath `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall receipt'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $path `
            -PathType Leaf)) {
        if ($Required) {
            throw 'authenticated DefenseClaw self-uninstall receipt is missing'
        }
        return $null
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $path `
        -Force
    if ([int64]$item.Length -gt 65536) {
        throw 'self-uninstall receipt exceeds the 65536-byte limit'
    }
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -RejectUntrustedRead
    try {
        $receipt = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $path `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse authenticated self-uninstall receipt: $($_.Exception.Message)"
    }
    $schema = $receipt.PSObject.Properties['schema_version']
    $purgeRequested = $receipt.PSObject.Properties['purge_requested']
    $coreCertification = $receipt.PSObject.Properties[
        'core_hardening_certification'
    ]
    $callerPID = $receipt.PSObject.Properties['caller_pid']
    $callerCreation = $receipt.PSObject.Properties[
        'caller_creation_filetime'
    ]
    if ($null -eq $schema -or
        $schema.Value -is [bool] -or
        [Convert]::ToInt64($schema.Value) -ne 1 -or
        [string]$receipt.phase -notin @(
            'prepared_install_retirement',
            'committed_install_retirement'
        ) -or
        [string]$receipt.scope_sha256 -cne
            [string]$Layout.PurgeScopeSHA256 -or
        $null -eq $purgeRequested -or
        $purgeRequested.Value -isnot [bool] -or
        $null -eq $coreCertification -or
        $coreCertification.Value -isnot [bool] -or
        $null -eq $callerPID -or
        $callerPID.Value -is [bool] -or
        [Convert]::ToInt64($callerPID.Value) -le 0 -or
        $null -eq $callerCreation -or
        $callerCreation.Value -is [bool] -or
        [Convert]::ToInt64($callerCreation.Value) -le 0) {
        throw 'authenticated self-uninstall receipt has an invalid schema, phase, or typed binding'
    }
    foreach ($binding in @(
        @('install_root', $Layout.InstallRoot),
        @('state_root', $Layout.StateRoot),
        @('pending_path', $Layout.PendingPath),
        @(
            'helper_environment_root',
            $Layout.SelfUninstallEnvironmentRoot
        )
    )) {
        $property = $receipt.PSObject.Properties[[string]$binding[0]]
        if ($null -eq $property -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath([string]$property.Value).TrimEnd('\'),
                [IO.Path]::GetFullPath([string]$binding[1]).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "authenticated self-uninstall receipt does not match $($binding[0])"
        }
    }
    foreach ($binding in @(
        @('gateway_service', $GatewayServiceName),
        @('guardian_service', $GuardianServiceName)
    )) {
        $property = $receipt.PSObject.Properties[[string]$binding[0]]
        if ($null -eq $property -or
            [string]$property.Value -cne [string]$binding[1]) {
            throw "authenticated self-uninstall receipt does not match $($binding[0])"
        }
    }
    $retiredProperty = $receipt.PSObject.Properties['retired_install_root']
    if ($null -eq $retiredProperty) {
        throw 'authenticated self-uninstall receipt is missing its retired root'
    }
    [void](Assert-DefenseClawSelfUninstallRetiredRoot `
        -Layout $Layout `
        -Path ([string]$retiredProperty.Value) `
        -AllowMissing)
    foreach ($hashName in @(
        'tombstone_sha256',
        'pending_sha256',
        'caller_sha256',
        'retired_installer_sha256',
        'retired_module_sha256'
    )) {
        $property = $receipt.PSObject.Properties[$hashName]
        if ($null -eq $property -or
            [string]$property.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw "authenticated self-uninstall receipt has invalid $hashName"
        }
    }
    $helperHash = $receipt.PSObject.Properties['helper_sha256']
    if ($null -eq $helperHash -or
        ([string]$receipt.phase -ceq 'committed_install_retirement' -and
            [string]$helperHash.Value -cnotmatch '^[0-9a-f]{64}$') -or
        ([string]$receipt.phase -ceq 'prepared_install_retirement' -and
            -not [string]::IsNullOrWhiteSpace([string]$helperHash.Value) -and
            [string]$helperHash.Value -cnotmatch '^[0-9a-f]{64}$')) {
        throw 'authenticated self-uninstall receipt has invalid helper hash'
    }
    $fileIdentity = $receipt.PSObject.Properties['caller_file_identity']
    if ($null -eq $fileIdentity -or
        [string]$fileIdentity.Value -cnotmatch
            '^[0-9a-f]{8}:[0-9a-f]{16}$') {
        throw 'authenticated self-uninstall receipt has invalid caller file identity'
    }
    $callerImage = $receipt.PSObject.Properties['caller_image_path']
    if ($null -eq $callerImage -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$callerImage.Value).TrimEnd('\'),
            [IO.Path]::GetFullPath($Layout.CLIPath).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'authenticated self-uninstall receipt has invalid caller image path'
    }
    $certificationProperty = $receipt.PSObject.Properties[
        'certification_codex_home'
    ]
    if ($null -eq $certificationProperty) {
        throw 'authenticated self-uninstall receipt is missing certification scope'
    }
    $receiptCertificationHome = Resolve-DefenseClawCertificationCodexHome `
        -Path ([string]$certificationProperty.Value) `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ([bool]$coreCertification.Value -and
        [string]::IsNullOrWhiteSpace($receiptCertificationHome)) {
        throw 'authenticated self-uninstall receipt enables core certification outside its exact scope'
    }
    if ([string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        $Layout.CertificationCodexHome = $receiptCertificationHome
    }
    elseif (-not [string]::Equals(
            [string]$Layout.CertificationCodexHome,
            $receiptCertificationHome,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'authenticated self-uninstall receipt certification CODEX_HOME does not match the requested scope'
    }
    if ([bool]$Layout.CoreHardeningCertification -and
        -not [bool]$coreCertification.Value) {
        throw 'authenticated self-uninstall receipt does not match requested core-certification mode'
    }
    $Layout.CoreHardeningCertification = [bool]$coreCertification.Value
    return $receipt
}

function Publish-DefenseClawSelfUninstallReceipt {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)]$CallerIdentity,
        [switch]$Purge
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.PendingPath `
            -PathType Leaf)) {
        throw 'self-uninstall receipt publication requires a pending lifecycle transaction'
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "self-uninstall receipt publication refused while service exists: $name"
        }
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.InstallRoot `
            -PathType Container)) {
        throw 'self-uninstall receipt publication requires the canonical InstallRoot'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.SelfUninstallReceiptPath) {
        throw 'an authenticated self-uninstall receipt already exists'
    }
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
        throw 'self-uninstall receipt publication requires a committed uninstall tombstone'
    }
    foreach ($path in @($Layout.CLIPath, $Layout.InstallerPath, $Layout.ModulePath)) {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $path `
                -PathType Leaf)) {
            throw "self-uninstall receipt publication is missing managed artifact: $path"
        }
        Assert-DefenseClawNoReparsePath -Path $path
    }
    $retiredRoot = New-DefenseClawSelfUninstallRetiredRoot -Layout $Layout
    $receipt = [ordered]@{
        schema_version = 1
        phase = 'prepared_install_retirement'
        scope_sha256 = [string]$Layout.PurgeScopeSHA256
        install_root = $Layout.InstallRoot
        retired_install_root = $retiredRoot
        state_root = $Layout.StateRoot
        pending_path = $Layout.PendingPath
        helper_environment_root = $Layout.SelfUninstallEnvironmentRoot
        gateway_service = $GatewayServiceName
        guardian_service = $GuardianServiceName
        certification_codex_home = [string]$Layout.CertificationCodexHome
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        purge_requested = [bool]$Purge
        tombstone_sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.MetadataPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        pending_sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.PendingPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        caller_pid = [int64]$CallerIdentity.pid
        caller_creation_filetime = [int64]$CallerIdentity.creation_filetime
        caller_image_path = [string]$CallerIdentity.image_path
        caller_file_identity = [string]$CallerIdentity.file_identity
        caller_sha256 = [string]$CallerIdentity.sha256
        retired_installer_sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.InstallerPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        retired_module_sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.ModulePath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        helper_sha256 = ''
        created_at = [DateTime]::UtcNow.ToString('o')
        committed_at = ''
    }
    Write-DefenseClawJsonAtomic `
        -Value $receipt `
        -Path $Layout.SelfUninstallReceiptPath
    Set-DefenseClawPathAcl `
        -Path $Layout.SelfUninstallReceiptPath `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    return Get-DefenseClawSelfUninstallReceipt `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
}

function Initialize-DefenseClawSelfUninstallEnvironment {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $environmentRoot = Assert-DefenseClawDescendant `
        -Path $Layout.SelfUninstallEnvironmentRoot `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall helper environment root'
    Initialize-DefenseClawManagedRoot `
        -Path $environmentRoot `
        -Label 'self-uninstall helper environment root' `
        -RequiredBase $Layout.LifecycleLockDirectory
    Assert-DefenseClawPathAcl `
        -Path $environmentRoot `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -RejectUntrustedRead
    return $environmentRoot
}

function Assert-DefenseClawSelfUninstallEnvironment {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $environmentRoot = Assert-DefenseClawDescendant `
        -Path $Layout.SelfUninstallEnvironmentRoot `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall helper environment root'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $environmentRoot `
            -PathType Container)) {
        throw 'self-uninstall helper environment root is not a directory'
    }
    Assert-DefenseClawManagedTreeNoReparse -Root $environmentRoot
    $objects = @(
        Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $environmentRoot `
            -Force
    ) + @(
        Microsoft.PowerShell.Management\Get-ChildItem `
            -LiteralPath $environmentRoot `
            -Recurse `
            -Force
    )
    foreach ($item in $objects) {
        Assert-DefenseClawPathAcl `
            -Path $item.FullName `
            -AllowedWriterSIDs @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID
            ) `
            -AllowedReaderSIDs @(
                $script:SystemSID,
                $script:AdministratorsSID,
                $script:TrustedInstallerSID
            ) `
            -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
            -AllowInheritance `
            -RejectUntrustedRead
    }
    return $environmentRoot
}

function Remove-DefenseClawSelfUninstallEnvironment {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $environmentRoot = Assert-DefenseClawDescendant `
        -Path $Layout.SelfUninstallEnvironmentRoot `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall helper environment root'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $environmentRoot)) {
        return
    }
    [void](Assert-DefenseClawSelfUninstallEnvironment -Layout $Layout)
    Remove-DefenseClawManagedTree `
        -Path $environmentRoot `
        -RequiredBase $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall helper environment root'
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $environmentRoot) {
        throw 'self-uninstall helper environment root survived cleanup'
    }
}

function Get-DefenseClawSelfUninstallHelperContent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $retiredModulePath = Microsoft.PowerShell.Management\Join-Path `
        ([string]$Receipt.retired_install_root) `
        'libexec\DefenseClawEnterprise.psm1'
    $receiptLiteral = ([string]$Layout.SelfUninstallReceiptPath).Replace(
        "'",
        "''"
    )
    $moduleLiteral = ([string]$retiredModulePath).Replace("'", "''")
    $moduleHashLiteral = ([string]$Receipt.retired_module_sha256).Replace(
        "'",
        "''"
    )
    return @"
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
try {
    `$receiptPath = '$receiptLiteral'
    `$modulePath = '$moduleLiteral'
    `$expectedModuleHash = '$moduleHashLiteral'
    if (-not [IO.File]::Exists(`$modulePath)) {
        throw "retired self-uninstall module is missing: `$modulePath"
    }
    `$moduleItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath `$modulePath -Force
    if ((`$moduleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "retired self-uninstall module is a reparse point: `$modulePath"
    }
    `$actualModuleHash = (
        Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath `$modulePath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (`$actualModuleHash -cne `$expectedModuleHash) {
        throw 'retired self-uninstall module hash does not match its protected receipt'
    }
    Microsoft.PowerShell.Core\Import-Module -Name `$modulePath -Force -ErrorAction Stop
    `$module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
    if (`$null -eq `$module) {
        throw 'retired DefenseClaw enterprise module did not import'
    }
    & `$module {
        param(`$ProtectedReceiptPath)
        Complete-DefenseClawSelfUninstallRetirement `
            -ReceiptPath `$ProtectedReceiptPath `
            -WaitForCallerExit
    } `$receiptPath
}
catch {
    [Console]::Error.WriteLine(
        "DefenseClaw self-uninstall finalizer retained recovery state: {0}",
        `$_.Exception.Message
    )
    exit 1
}
"@
}

function Assert-DefenseClawSelfUninstallHelper {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $helperPath = Assert-DefenseClawDescendant `
        -Path $Layout.SelfUninstallHelperPath `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'self-uninstall finalizer'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $helperPath `
            -PathType Leaf)) {
        throw 'protected self-uninstall finalizer is missing'
    }
    Assert-DefenseClawNoReparsePath -Path $helperPath
    Assert-DefenseClawPathAcl `
        -Path $helperPath `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -RejectUntrustedRead
    $actualHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $helperPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actualHash -cne [string]$Receipt.helper_sha256) {
        throw 'protected self-uninstall finalizer hash does not match its receipt'
    }
    return $helperPath
}

function Ensure-DefenseClawSelfUninstallHelper {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    [void](Initialize-DefenseClawSelfUninstallEnvironment `
        -Layout $Layout)
    $content = Get-DefenseClawSelfUninstallHelperContent `
        -Layout $Layout `
        -Receipt $Receipt
    $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($content)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $expectedHash = (
            [BitConverter]::ToString(
                $algorithm.ComputeHash($expectedBytes)
            ).Replace('-', '').ToLowerInvariant()
        )
    }
    finally {
        $algorithm.Dispose()
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.SelfUninstallHelperPath) {
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$Receipt.helper_sha256
            ) -and
            [string]$Receipt.helper_sha256 -cne $expectedHash) {
            throw 'existing self-uninstall finalizer belongs to different protected receipt content'
        }
        $Receipt.helper_sha256 = $expectedHash
        return Assert-DefenseClawSelfUninstallHelper `
            -Layout $Layout `
            -Receipt $Receipt
    }
    Write-DefenseClawProtectedTextAtomic `
        -Value $content `
        -Path $Layout.SelfUninstallHelperPath `
        -RequiredRoot $Layout.LifecycleLockDirectory
    $Receipt.helper_sha256 = $expectedHash
    return $Layout.SelfUninstallHelperPath
}

function Set-DefenseClawSelfUninstallReceiptCommitted {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $receipt = Get-DefenseClawSelfUninstallReceipt `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PendingPath) {
        throw 'self-uninstall retirement cannot commit while transaction evidence remains'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath) {
        throw 'self-uninstall retirement cannot commit before teardown-journal retirement'
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "self-uninstall retirement cannot commit while service exists: $name"
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.InstallRoot) {
        throw 'self-uninstall retirement cannot commit while canonical InstallRoot exists'
    }
    Assert-DefenseClawRetiredInstallTree `
        -Layout $Layout `
        -RetiredRoot ([string]$receipt.retired_install_root)
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.MetadataPath `
            -PathType Leaf)) {
        throw 'self-uninstall retirement cannot commit without its uninstall tombstone'
    }
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
        throw 'self-uninstall retirement cannot commit against installed metadata'
    }
    $actualTombstoneHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $Layout.MetadataPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actualTombstoneHash -cne [string]$receipt.tombstone_sha256) {
        throw 'self-uninstall tombstone changed after retirement preparation'
    }
    $retiredCLI = Microsoft.PowerShell.Management\Join-Path `
        ([string]$receipt.retired_install_root) `
        'bin\defenseclaw.exe'
    if ([string]$receipt.phase -ceq 'prepared_install_retirement' -and
        -not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $retiredCLI `
            -PathType Leaf)) {
        throw 'prepared self-uninstall retired CLI is missing'
    }
    if ([string]$receipt.phase -ceq 'prepared_install_retirement') {
        foreach ($artifact in @(
            @(
                'installer',
                (
                    Microsoft.PowerShell.Management\Join-Path `
                        ([string]$receipt.retired_install_root) `
                        'libexec\install-enterprise.ps1'
                ),
                [string]$receipt.retired_installer_sha256
            ),
            @(
                'module',
                (
                    Microsoft.PowerShell.Management\Join-Path `
                        ([string]$receipt.retired_install_root) `
                        'libexec\DefenseClawEnterprise.psm1'
                ),
                [string]$receipt.retired_module_sha256
            )
        )) {
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath ([string]$artifact[1]) `
                    -PathType Leaf)) {
                throw "prepared self-uninstall retired $($artifact[0]) is missing"
            }
            $artifactHash = (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath ([string]$artifact[1]) `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            if ($artifactHash -cne [string]$artifact[2]) {
                throw "prepared self-uninstall retired $($artifact[0]) hash changed"
            }
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $retiredCLI `
        -PathType Leaf) {
        if ((Get-DefenseClawFileIdentity -Path $retiredCLI) -cne
                [string]$receipt.caller_file_identity -or
            (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $retiredCLI `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant() -cne [string]$receipt.caller_sha256) {
            throw 'retired CLI file identity or hash changed after atomic rename'
        }
    }
    if ([string]$receipt.phase -ceq 'committed_install_retirement') {
        [void](Ensure-DefenseClawSelfUninstallHelper `
            -Layout $Layout `
            -Receipt $receipt)
        return Get-DefenseClawSelfUninstallReceipt `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Required
    }
    [void](Ensure-DefenseClawSelfUninstallHelper `
        -Layout $Layout `
        -Receipt $receipt)
    $receipt.phase = 'committed_install_retirement'
    $receipt.committed_at = [DateTime]::UtcNow.ToString('o')
    Write-DefenseClawJsonAtomic `
        -Value $receipt `
        -Path $Layout.SelfUninstallReceiptPath
    Set-DefenseClawPathAcl `
        -Path $Layout.SelfUninstallReceiptPath `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    return Get-DefenseClawSelfUninstallReceipt `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
}

function Test-DefenseClawSelfUninstallCallerRunning {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    try {
        $creationFileTime = [int64](
            $nativeSecurityType::GetProcessCreationFileTime(
                [uint32][int64]$Receipt.caller_pid
            )
        )
        $imagePath = [IO.Path]::GetFullPath(
            [string]$nativeSecurityType::GetProcessImagePath(
                [uint32][int64]$Receipt.caller_pid
            )
        ).TrimEnd('\')
    }
    catch {
        return $false
    }
    if ($creationFileTime -ne [int64]$Receipt.caller_creation_filetime) {
        return $false
    }
    $retiredImage = Microsoft.PowerShell.Management\Join-Path `
        ([string]$Receipt.retired_install_root) `
        'bin\defenseclaw.exe'
    return (
        [string]::Equals(
            $imagePath,
            [IO.Path]::GetFullPath($Layout.CLIPath).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]::Equals(
            $imagePath,
            [IO.Path]::GetFullPath($retiredImage).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )
    )
}

function Start-DefenseClawSelfUninstallHelper {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $environmentRoot =
        Initialize-DefenseClawSelfUninstallEnvironment `
            -Layout $Layout
    $helperPath = Assert-DefenseClawSelfUninstallHelper `
        -Layout $Layout `
        -Receipt $Receipt
    $powerShell = [IO.Path]::Combine(
        $script:System32,
        'WindowsPowerShell\v1.0\powershell.exe'
    )
    $powerShell = Resolve-DefenseClawFullPath `
        -Path $powerShell `
        -MustExist `
        -Leaf
    Assert-DefenseClawNoReparsePath -Path $powerShell
    if ($helperPath.Contains('"') -or
        [Text.RegularExpressions.Regex]::IsMatch(
            $helperPath,
            '[\x00-\x1f]'
        )) {
        throw 'protected self-uninstall finalizer path contains unsafe command-line characters'
    }
    $arguments = (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "' + $helperPath + '"'
    )
    $homeDrive = [IO.Path]::GetPathRoot(
        $environmentRoot
    ).TrimEnd('\')
    $homePath = $environmentRoot.Substring($homeDrive.Length)
    if ([string]::IsNullOrWhiteSpace($homeDrive) -or
        -not $homePath.StartsWith(
            '\',
            [StringComparison]::Ordinal
        )) {
        throw 'protected helper environment root does not have a local drive home path'
    }
    $environment = [Collections.Generic.List[string]]::new()
    foreach ($pair in @(
        @('SystemRoot', $script:WindowsDirectory),
        @('windir', $script:WindowsDirectory),
        @('ProgramFiles', $script:ProgramFiles),
        @('ProgramData', $script:ProgramData),
        @('TEMP', $environmentRoot),
        @('TMP', $environmentRoot),
        @('LOCALAPPDATA', $environmentRoot),
        @('APPDATA', $environmentRoot),
        @('USERPROFILE', $environmentRoot),
        @('HOME', $environmentRoot),
        @('HOMEDRIVE', $homeDrive),
        @('HOMEPATH', $homePath),
        @('PSModuleAnalysisCachePath', 'NUL'),
        @('PATH', (
            @(
                $script:System32,
                $script:WindowsDirectory,
                ([IO.Path]::Combine($script:System32, 'Wbem')),
                ([IO.Path]::Combine(
                    $script:System32,
                    'WindowsPowerShell\v1.0'
                ))
            ) -join [IO.Path]::PathSeparator
        )),
        @('PSModulePath', (
            [IO.Path]::Combine(
                $script:System32,
                'WindowsPowerShell\v1.0\Modules'
            )
        ))
    )) {
        $environment.Add(
            ([string]$pair[0]) + '=' + ([string]$pair[1])
        )
    }
    # ProcessStartInfo on Windows PowerShell 5.1 sets bInheritHandles=true
    # whenever streams are redirected and can leak unrelated inheritable
    # caller pipes. The installed CLI would then wait for capture EOF while
    # this helper waits for that CLI to exit. Native CreateProcessW launches
    # the fixed System32 engine with bInheritHandles=false, no standard-handle
    # startup fields, CREATE_NO_WINDOW, an explicit clean Unicode environment,
    # and a fixed trusted working directory.
    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    return [int64]$nativeSecurityType::StartDetachedProcess(
        $powerShell,
        ('"' + $powerShell + '" ' + $arguments),
        $script:System32,
        [string[]]$environment.ToArray()
    )
}

function Remove-DefenseClawRetiredInstallTree {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $retired = [string]$Receipt.retired_install_root
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $retired)) {
        return
    }
    Assert-DefenseClawRetiredInstallTree `
        -Layout $Layout `
        -RetiredRoot $retired
    $allowlist = Get-DefenseClawRetiredInstallTreeAllowlist `
        -Layout $Layout `
        -RetiredRoot $retired
    $modulePath = Microsoft.PowerShell.Management\Join-Path `
        $retired `
        'libexec\DefenseClawEnterprise.psm1'
    foreach ($path in @(
        $allowlist.files |
            Microsoft.PowerShell.Core\Where-Object {
                -not [string]::Equals(
                    [string]$_,
                    $modulePath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )) {
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $path `
            -PathType Leaf) {
            Assert-DefenseClawNoReparsePath -Path $path
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $path `
                -Force
        }
    }
    foreach ($directory in @(
        (Microsoft.PowerShell.Management\Join-Path $retired 'agents'),
        (Microsoft.PowerShell.Management\Join-Path $retired 'bin')
    )) {
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $directory `
            -PathType Container) {
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $directory `
                -Force
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $modulePath `
        -PathType Leaf) {
        $moduleHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $modulePath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($moduleHash -cne [string]$Receipt.retired_module_sha256) {
            throw 'retired module changed before receipt-authorized final deletion'
        }
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $modulePath `
            -Force
    }
    $libexec = Microsoft.PowerShell.Management\Join-Path $retired 'libexec'
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $libexec `
        -PathType Container) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $libexec `
            -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $retired `
        -PathType Container) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $retired `
            -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $retired) {
        throw 'receipt-bound retired InstallRoot survived final cleanup'
    }
}

function Remove-DefenseClawSelfUninstallEvidence {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    # HOME/TEMP/module-analysis state is isolated to this receipt-bound,
    # Admin-only root. Retire it before the launcher and receipt, after every
    # tree object and ACL has been revalidated.
    Remove-DefenseClawSelfUninstallEnvironment -Layout $Layout
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.SelfUninstallHelperPath) {
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$Receipt.helper_sha256
            )) {
            [void](Assert-DefenseClawSelfUninstallHelper `
                -Layout $Layout `
                -Receipt $Receipt)
        }
        else {
            Assert-DefenseClawNoReparsePath `
                -Path $Layout.SelfUninstallHelperPath
            Assert-DefenseClawPathAcl `
                -Path $Layout.SelfUninstallHelperPath `
                -AllowedWriterSIDs @(
                    $script:SystemSID,
                    $script:AdministratorsSID,
                    $script:TrustedInstallerSID
                ) `
                -AllowedReaderSIDs @(
                    $script:SystemSID,
                    $script:AdministratorsSID,
                    $script:TrustedInstallerSID
                ) `
                -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
                -RejectUntrustedRead
        }
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $Layout.SelfUninstallHelperPath `
            -Force
    }
    # The authenticated receipt is always the final object retired. Any crash
    # before this point therefore leaves exact authority for a bounded retry.
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.SelfUninstallReceiptPath) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $Layout.SelfUninstallReceiptPath `
            -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.SelfUninstallReceiptPath) {
        throw 'authenticated self-uninstall receipt survived final cleanup'
    }
}

function Wait-DefenseClawSelfUninstallCallerExit {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt,
        [int]$TimeoutSeconds = 300
    )
    if (-not (Test-DefenseClawSelfUninstallCallerRunning `
            -Layout $Layout `
            -Receipt $Receipt)) {
        return
    }
    $process = Microsoft.PowerShell.Management\Get-Process `
        -Id ([int][int64]$Receipt.caller_pid) `
        -ErrorAction Stop
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            throw (
                'installed CLI did not exit within the bounded ' +
                "$TimeoutSeconds-second self-uninstall cleanup wait"
            )
        }
    }
    finally {
        $process.Dispose()
    }
    if (Test-DefenseClawSelfUninstallCallerRunning `
        -Layout $Layout `
        -Receipt $Receipt) {
        throw 'installed CLI identity still matches after bounded exit wait'
    }
}

function Assert-DefenseClawSelfUninstallCommittedState {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [Parameter(Mandatory)]$Receipt,
        [switch]$AllowPurgedState
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PendingPath) {
        throw 'committed self-uninstall recovery found pending transaction evidence'
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "committed self-uninstall recovery found live service: $name"
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.InstallRoot) {
        throw 'committed self-uninstall recovery found canonical InstallRoot'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.MetadataPath `
        -PathType Leaf) {
        $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
        Assert-DefenseClawMetadataIdentity `
            -Metadata $metadata `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
            throw 'committed self-uninstall recovery found installed metadata'
        }
        $actualTombstoneHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.MetadataPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualTombstoneHash -cne [string]$Receipt.tombstone_sha256) {
            throw 'committed self-uninstall recovery found changed tombstone'
        }
    }
    elseif (-not $AllowPurgedState -or
        -not [bool]$Receipt.purge_requested -or
        (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.StateRoot)) {
        throw 'committed self-uninstall recovery is missing its authenticated tombstone'
    }
}

function Move-DefenseClawRetiredInstallTreeBack {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt
    )
    $retired = [string]$Receipt.retired_install_root
    Assert-DefenseClawRetiredInstallTree `
        -Layout $Layout `
        -RetiredRoot $retired `
        -SkipAclValidation
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.InstallRoot) {
        throw 'cannot restore retired InstallRoot because canonical root already exists'
    }
    [IO.Directory]::Move($retired, $Layout.InstallRoot)
    Assert-DefenseClawNoReparsePath -Path $Layout.InstallRoot
}

function Add-DefenseClawSelfUninstallResult {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)]$Receipt,
        [bool]$CleanupPending
    )
    foreach ($entry in @(
        @('cached_enterprise_clients_require_reload', $true),
        @('self_uninstall_cleanup_pending', [bool]$CleanupPending),
        @('canonical_install_root_absent', [bool](
            -not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.InstallRoot)
        )),
        @('self_uninstall_receipt_path', [string]$Layout.SelfUninstallReceiptPath),
        @('self_uninstall_helper_path', [string]$Layout.SelfUninstallHelperPath),
        @(
            'self_uninstall_environment_root',
            [string]$Layout.SelfUninstallEnvironmentRoot
        ),
        @('retired_install_root', [string]$Receipt.retired_install_root)
    )) {
        $Result |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name ([string]$entry[0]) `
                -Value $entry[1] `
                -Force
    }
    return $Result
}

function Add-DefenseClawUninstallContractResult {
    param([Parameter(Mandatory)]$Result)
    $Result |
        Microsoft.PowerShell.Utility\Add-Member `
            -MemberType NoteProperty `
            -Name cached_enterprise_clients_require_reload `
            -Value $true `
            -Force
    return $Result
}

function Invoke-DefenseClawSelfUninstallRecovery {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Purge
    )
    $receipt = Get-DefenseClawSelfUninstallReceipt `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -eq $receipt) {
        return [pscustomobject]@{
            handled = $false
            result = $null
        }
    }
    $canonicalExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.InstallRoot `
        -PathType Container
    $retiredExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath ([string]$receipt.retired_install_root) `
        -PathType Container
    if ($canonicalExists -and $retiredExists) {
        throw 'self-uninstall recovery found both canonical and retired InstallRoot'
    }
    $pendingExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PendingPath `
        -PathType Leaf
    if ([string]$receipt.phase -ceq 'prepared_install_retirement' -and
        $pendingExists) {
        if ($retiredExists) {
            Move-DefenseClawRetiredInstallTreeBack `
                -Layout $Layout `
                -Receipt $receipt
        }
        elseif ($canonicalExists) {
            Assert-DefenseClawManagedInstallTree -Layout $Layout
        }
        # If neither tree exists, the authenticated transaction snapshot still
        # owns exact file restoration. Retire only the independent rename
        # evidence, then let generic pending recovery recreate its allowlist.
        Remove-DefenseClawSelfUninstallEvidence `
            -Layout $Layout `
            -Receipt $receipt
        return [pscustomobject]@{
            handled = $false
            result = $null
        }
    }
    if ([string]$receipt.phase -ceq 'prepared_install_retirement') {
        if ($canonicalExists) {
            throw 'prepared self-uninstall receipt without pending state found canonical InstallRoot'
        }
        Assert-DefenseClawSelfUninstallCommittedState `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Receipt $receipt
        if ($retiredExists) {
            [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName)
            $receipt = Set-DefenseClawSelfUninstallReceiptCommitted `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }
        else {
            Remove-DefenseClawSelfUninstallEvidence `
                -Layout $Layout `
                -Receipt $receipt
            return [pscustomobject]@{
                handled = $false
                result = $null
            }
        }
    }
    Assert-DefenseClawSelfUninstallCommittedState `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Receipt $receipt `
        -AllowPurgedState
    if ($retiredExists) {
        if (Test-DefenseClawSelfUninstallCallerRunning `
            -Layout $Layout `
            -Receipt $receipt) {
            [void](Ensure-DefenseClawSelfUninstallHelper `
                -Layout $Layout `
                -Receipt $receipt)
            [void](Start-DefenseClawSelfUninstallHelper `
                -Layout $Layout `
                -Receipt $receipt)
            if ($Action -ne 'Uninstall') {
                throw (
                    'an authenticated self-uninstall cleanup is waiting for ' +
                    "the installed CLI to exit; retry $Action after it exits"
                )
            }
            $result = Get-DefenseClawLifecycleStatus `
                -Action 'Uninstall' `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            if ([bool]$receipt.purge_requested -and
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.StateRoot)) {
                $result |
                    Microsoft.PowerShell.Utility\Add-Member `
                        -MemberType NoteProperty `
                        -Name purged `
                        -Value $true `
                        -Force
            }
            $result = Add-DefenseClawSelfUninstallResult `
                -Result $result `
                -Layout $Layout `
                -Receipt $receipt `
                -CleanupPending:$true
            return [pscustomobject]@{
                handled = $true
                result = $result
            }
        }
        Remove-DefenseClawRetiredInstallTree `
            -Layout $Layout `
            -Receipt $receipt
    }
    Remove-DefenseClawSelfUninstallEvidence `
        -Layout $Layout `
        -Receipt $receipt
    if ([bool]$receipt.purge_requested -and
        -not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.StateRoot)) {
        $result = Get-DefenseClawLifecycleStatus `
            -Action 'Uninstall' `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        $result |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name purged `
                -Value $true `
                -Force
        $result = Add-DefenseClawUninstallContractResult -Result $result
        return [pscustomobject]@{
            handled = $true
            result = $result
        }
    }
    return [pscustomobject]@{
        handled = $false
        result = $null
    }
}

function Complete-DefenseClawSelfUninstallRetirement {
    param(
        [Parameter(Mandatory)][string]$ReceiptPath,
        [switch]$WaitForCallerExit,
        [ValidateRange(1, 900)]
        [int]$CleanupTimeoutSeconds = 300
    )
    Assert-DefenseClawAdministrator
    $fullReceiptPath = Assert-DefenseClawCanonicalVolumePath `
        -Path $ReceiptPath `
        -Label 'self-uninstall finalizer receipt'
    $expectedLifecycleDirectory = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
        'Cisco Secure Client',
        'DefenseClaw-Lifecycle'
    ).TrimEnd('\')
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($fullReceiptPath),
            $expectedLifecycleDirectory,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [IO.Path]::GetFileName($fullReceiptPath) -cnotmatch
            '^self-uninstall-[0-9a-f]{64}\.json$') {
        throw 'self-uninstall finalizer receipt path is outside the exact protected lifecycle namespace'
    }
    Assert-DefenseClawNoReparsePath -Path $fullReceiptPath
    [void](Assert-DefenseClawCanonicalVolumePath `
        -Path $fullReceiptPath `
        -Label 'self-uninstall finalizer receipt')
    $bootstrapReceipt = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $fullReceiptPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $layout = Get-DefenseClawLayout `
        -InstallRoot ([string]$bootstrapReceipt.install_root) `
        -StateRoot ([string]$bootstrapReceipt.state_root) `
        -GatewayServiceName ([string]$bootstrapReceipt.gateway_service) `
        -GuardianServiceName ([string]$bootstrapReceipt.guardian_service)
    if (-not [string]::Equals(
            $fullReceiptPath,
            [string]$layout.SelfUninstallReceiptPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'self-uninstall finalizer receipt path does not match its authenticated scope'
    }
    $receipt = Get-DefenseClawSelfUninstallReceipt `
        -Layout $layout `
        -GatewayServiceName ([string]$bootstrapReceipt.gateway_service) `
        -GuardianServiceName ([string]$bootstrapReceipt.guardian_service) `
        -Required
    $loadedModulePath = [IO.Path]::GetFullPath(
        [string]$MyInvocation.MyCommand.Module.Path
    ).TrimEnd('\')
    $expectedModulePath = [IO.Path]::GetFullPath(
        (
            Microsoft.PowerShell.Management\Join-Path `
                ([string]$receipt.retired_install_root) `
                'libexec\DefenseClawEnterprise.psm1'
        )
    ).TrimEnd('\')
    if (-not [string]::Equals(
            $loadedModulePath,
            $expectedModulePath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $loadedModulePath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant() -cne
            [string]$receipt.retired_module_sha256) {
        throw 'self-uninstall finalizer is not running the exact receipt-bound retired module'
    }
    if ($WaitForCallerExit) {
        Wait-DefenseClawSelfUninstallCallerExit `
            -Layout $layout `
            -Receipt $receipt
    }
    $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(
        $CleanupTimeoutSeconds
    )
    $retryDelayMilliseconds = 200
    while ($true) {
        $cleanupFailure = $null
        $lock = Enter-DefenseClawLifecycleLock -Layout $layout
        try {
            Assert-DefenseClawLayoutVolumeIdentity `
                -Layout $layout `
                -GatewayServiceName ([string]$receipt.gateway_service) `
                -GuardianServiceName ([string]$receipt.guardian_service)
            $receipt = Get-DefenseClawSelfUninstallReceipt `
                -Layout $layout `
                -GatewayServiceName ([string]$receipt.gateway_service) `
                -GuardianServiceName ([string]$receipt.guardian_service) `
                -Required
            if (Test-DefenseClawSelfUninstallCallerRunning `
                -Layout $layout `
                -Receipt $receipt) {
                throw 'self-uninstall finalizer refuses cleanup while exact caller identity is running'
            }
            if ([string]$receipt.phase -ceq
                'prepared_install_retirement') {
                $receipt = Set-DefenseClawSelfUninstallReceiptCommitted `
                    -Layout $layout `
                    -GatewayServiceName ([string]$receipt.gateway_service) `
                    -GuardianServiceName ([string]$receipt.guardian_service)
            }
            Assert-DefenseClawSelfUninstallCommittedState `
                -Layout $layout `
                -GatewayServiceName ([string]$receipt.gateway_service) `
                -GuardianServiceName ([string]$receipt.guardian_service) `
                -Receipt $receipt `
                -AllowPurgedState
            try {
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath (
                        [string]$receipt.retired_install_root
                    )) {
                    Remove-DefenseClawRetiredInstallTree `
                        -Layout $layout `
                        -Receipt $receipt
                }
                Remove-DefenseClawSelfUninstallEvidence `
                    -Layout $layout `
                    -Receipt $receipt
                return
            }
            catch {
                $cleanupFailure = $_
                # A sharing violation may leave a valid strict subset of the
                # retired allowlist. Re-authenticate every surviving object
                # while holding the lifecycle lock before allowing a retry.
                # Unexpected content, reparse points, ACL drift, changed
                # receipts, or changed lifecycle state therefore fail closed
                # immediately instead of being treated as transient.
                if (-not (Microsoft.PowerShell.Management\Test-Path `
                        -LiteralPath $layout.SelfUninstallReceiptPath `
                        -PathType Leaf)) {
                    $retiredStillExists =
                        Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath (
                                [string]$receipt.retired_install_root
                            )
                    $helperStillExists =
                        Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath $layout.SelfUninstallHelperPath
                    $environmentStillExists =
                        Microsoft.PowerShell.Management\Test-Path `
                            -LiteralPath (
                                $layout.SelfUninstallEnvironmentRoot
                            )
                    if (-not $retiredStillExists -and
                        -not $helperStillExists -and
                        -not $environmentStillExists) {
                        return
                    }
                    throw (
                        'self-uninstall cleanup lost its authenticated ' +
                        'receipt before all authorized objects were retired'
                    )
                }
                $receipt = Get-DefenseClawSelfUninstallReceipt `
                    -Layout $layout `
                    -GatewayServiceName ([string]$receipt.gateway_service) `
                    -GuardianServiceName (
                        [string]$receipt.guardian_service
                    ) `
                    -Required
                Assert-DefenseClawSelfUninstallCommittedState `
                    -Layout $layout `
                    -GatewayServiceName ([string]$receipt.gateway_service) `
                    -GuardianServiceName (
                        [string]$receipt.guardian_service
                    ) `
                    -Receipt $receipt `
                    -AllowPurgedState
                if (Test-DefenseClawSelfUninstallCallerRunning `
                    -Layout $layout `
                    -Receipt $receipt) {
                    throw (
                        'self-uninstall caller identity reappeared during ' +
                        'bounded final cleanup'
                    )
                }
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath (
                        [string]$receipt.retired_install_root
                    )) {
                    Assert-DefenseClawRetiredInstallTree `
                        -Layout $layout `
                        -RetiredRoot (
                            [string]$receipt.retired_install_root
                        )
                }
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.SelfUninstallHelperPath) {
                    [void](Assert-DefenseClawSelfUninstallHelper `
                        -Layout $layout `
                        -Receipt $receipt)
                }
                if (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $layout.SelfUninstallEnvironmentRoot) {
                    [void](Assert-DefenseClawSelfUninstallEnvironment `
                        -Layout $layout)
                }
            }
        }
        finally {
            Exit-DefenseClawLifecycleLock -Lock $lock
        }
        if ($null -eq $cleanupFailure) {
            return
        }
        if ([DateTime]::UtcNow -ge $cleanupDeadline) {
            throw (
                'self-uninstall cleanup exceeded its bounded ' +
                "$CleanupTimeoutSeconds-second retry window: " +
                $cleanupFailure.Exception.Message
            )
        }
        # Never hold the lifecycle lock while waiting for a pre-existing
        # standard-user file handle or antivirus scanner to release the tree.
        Microsoft.PowerShell.Utility\Start-Sleep `
            -Milliseconds $retryDelayMilliseconds
        $retryDelayMilliseconds = [Math]::Min(
            $retryDelayMilliseconds * 2,
            2000
        )
    }
}

function Get-DefenseClawStatePurgeIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Required
    )
    $path = Assert-DefenseClawDescendant `
        -Path $Layout.PurgeIntentPath `
        -Root $Layout.LifecycleLockDirectory `
        -Label 'state purge intent'
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $path `
            -PathType Leaf)) {
        if ($Required) {
            throw 'authenticated DefenseClaw state-purge intent is missing'
        }
        return $null
    }
    Assert-DefenseClawNoReparsePath -Path $path
    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $path `
        -Force
    if ([int64]$item.Length -gt 65536) {
        throw 'state-purge intent exceeds the 65536-byte limit'
    }
    Assert-DefenseClawPathAcl `
        -Path $path `
        -AllowedWriterSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -AllowedReaderSIDs @(
            $script:SystemSID,
            $script:AdministratorsSID,
            $script:TrustedInstallerSID
        ) `
        -RequiredRights (New-DefenseClawRequiredRights -Kind Admin) `
        -RejectUntrustedRead
    try {
        $intent = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $path `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    catch {
        throw "cannot parse authenticated state-purge intent: $($_.Exception.Message)"
    }
    $schema = $intent.PSObject.Properties['schema_version']
    if ($null -eq $schema -or
        $schema.Value -is [bool] -or
        [Convert]::ToInt64($schema.Value) -ne 1 -or
        [string]$intent.phase -cne 'committed_state_purge' -or
        [string]$intent.scope_sha256 -cne
            [string]$Layout.PurgeScopeSHA256 -or
        [string]$intent.tombstone_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'authenticated state-purge intent has invalid schema, phase, scope, or tombstone hash'
    }
    foreach ($binding in @(
        @('install_root', $Layout.InstallRoot),
        @('state_root', $Layout.StateRoot),
        @('gateway_service', $GatewayServiceName),
        @('guardian_service', $GuardianServiceName)
    )) {
        $property = $intent.PSObject.Properties[[string]$binding[0]]
        if ($null -eq $property -or
            -not [string]::Equals(
                [string]$property.Value,
                [string]$binding[1],
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "authenticated state-purge intent does not match $($binding[0])"
        }
    }
    $certificationProperty = $intent.PSObject.Properties[
        'certification_codex_home'
    ]
    $coreCertificationProperty = $intent.PSObject.Properties[
        'core_hardening_certification'
    ]
    if ($null -eq $certificationProperty -or
        $null -eq $coreCertificationProperty -or
        $coreCertificationProperty.Value -isnot [bool]) {
        throw 'authenticated state-purge intent has invalid certification bindings'
    }
    $intentCertificationCodexHome =
        Resolve-DefenseClawCertificationCodexHome `
            -Path ([string]$certificationProperty.Value) `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    if ([bool]$coreCertificationProperty.Value -and
        [string]::IsNullOrWhiteSpace($intentCertificationCodexHome)) {
        throw 'authenticated state-purge intent enables core certification outside its exact scope'
    }
    if ([string]::IsNullOrWhiteSpace(
            [string]$Layout.CertificationCodexHome
        )) {
        $Layout.CertificationCodexHome = $intentCertificationCodexHome
    }
    elseif (-not [string]::Equals(
            [string]$Layout.CertificationCodexHome,
            $intentCertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'authenticated state-purge intent certification CODEX_HOME does not match the requested scope'
    }
    if ([bool]$Layout.CoreHardeningCertification -and
        -not [bool]$coreCertificationProperty.Value) {
        throw 'authenticated state-purge intent does not match requested core-certification mode'
    }
    $Layout.CoreHardeningCertification = [bool](
        $coreCertificationProperty.Value
    )
    return $intent
}

function Remove-DefenseClawCommittedEmptyInstallRoot {
    param([Parameter(Mandatory)][hashtable]$Layout)
    if (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.InstallRoot)) {
        return
    }
    Assert-DefenseClawManagedTreeNoReparse -Root $Layout.InstallRoot
    $allowed = @(
        [IO.Path]::GetFullPath($Layout.BinDirectory).TrimEnd('\'),
        [IO.Path]::GetFullPath($Layout.LibexecDirectory).TrimEnd('\')
    )
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem `
        -LiteralPath $Layout.InstallRoot `
        -Recurse `
        -Force) {
        $full = [IO.Path]::GetFullPath($item.FullName).TrimEnd('\')
        if (-not $item.PSIsContainer -or $full -notin $allowed) {
            throw "committed uninstall left unexpected InstallRoot content: $full"
        }
    }
    Remove-DefenseClawManagedTree `
        -Path $Layout.InstallRoot `
        -RequiredBase $script:ProgramFiles `
        -Label 'InstallRoot'
}

function Publish-DefenseClawStatePurgeIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath) {
        throw 'refusing state-purge intent publication while a lifecycle transaction is pending'
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "refusing state-purge intent publication while service exists: $name"
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.InstallRoot) {
        throw 'refusing state-purge intent publication while InstallRoot exists'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath) {
        throw 'refusing state-purge intent publication before teardown-journal retirement'
    }
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
        throw 'refusing state-purge intent publication before committed uninstall tombstone'
    }
    $tombstoneHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $Layout.MetadataPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $existing = Get-DefenseClawStatePurgeIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -ne $existing) {
        if ([string]$existing.tombstone_sha256 -cne $tombstoneHash) {
            throw 'existing state-purge intent belongs to a different uninstall tombstone'
        }
        return $existing
    }
    $intent = [ordered]@{
        schema_version = 1
        phase = 'committed_state_purge'
        scope_sha256 = [string]$Layout.PurgeScopeSHA256
        install_root = $Layout.InstallRoot
        state_root = $Layout.StateRoot
        gateway_service = $GatewayServiceName
        guardian_service = $GuardianServiceName
        certification_codex_home = [string]$Layout.CertificationCodexHome
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        tombstone_sha256 = $tombstoneHash
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    Write-DefenseClawJsonAtomic `
        -Value $intent `
        -Path $Layout.PurgeIntentPath
    Set-DefenseClawPathAcl `
        -Path $Layout.PurgeIntentPath `
        -Kind AdminFile `
        -GatewayServiceSID $script:AdministratorsSID
    return Get-DefenseClawStatePurgeIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
}

function Complete-DefenseClawStatePurge {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [string]$GatewayServiceSID
    )
    $intent = Get-DefenseClawStatePurgeIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "refusing authenticated state purge while service exists: $name"
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.InstallRoot) {
        throw 'refusing authenticated state purge after InstallRoot reappeared'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PendingPath) {
        throw 'refusing authenticated state purge while transaction evidence remains'
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.MetadataPath `
        -PathType Leaf) {
        $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
        Assert-DefenseClawMetadataIdentity `
            -Metadata $metadata `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
            throw 'state-purge intent is stale because deployment is installed'
        }
        $actualHash = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.MetadataPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ([string]$intent.tombstone_sha256 -cne $actualHash) {
            throw 'state-purge tombstone changed after intent publication'
        }
    }
    [void](Revoke-DefenseClawManagedIPCServiceAccess `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GatewayServiceSID $GatewayServiceSID)
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "refusing authenticated state purge because service reappeared: $name"
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.StateRoot) {
        Remove-DefenseClawManagedTree `
            -Path $Layout.StateRoot `
            -RequiredBase $script:ProgramData `
            -Label 'StateRoot'
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.StateRoot) {
        throw 'StateRoot survived authenticated purge'
    }
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $Layout.PurgeIntentPath `
        -Force
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.PurgeIntentPath) {
        throw 'state-purge intent survived completed purge'
    }
    $result = Get-DefenseClawLifecycleStatus `
        -Action 'Uninstall' `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $result |
        Microsoft.PowerShell.Utility\Add-Member `
            -MemberType NoteProperty `
            -Name purged `
            -Value $true
    return $result
}

function Invoke-DefenseClawCommittedUninstallCleanup {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Purge,
        # The deleting caller supplies its captured SID. Crash-resumed cleanup
        # recomputes it from the authenticated service name and requires an
        # exact match whenever both forms are available.
        [string]$GatewayServiceSID
    )
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (Test-DefenseClawMetadataInstalled -Metadata $metadata) {
        throw 'committed-uninstall cleanup requires an uninstall tombstone'
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath) {
        throw 'committed-uninstall cleanup requires transaction retirement'
    }
    foreach ($name in @(Get-DefenseClawManagedServiceNames -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "committed-uninstall cleanup refused while service exists: $name"
        }
    }
    $cleanupGatewaySID = Resolve-DefenseClawRetiredGatewayServiceSID `
        -GatewayServiceName $GatewayServiceName `
        -GatewayServiceSID $GatewayServiceSID
    Remove-DefenseClawCommittedEmptyInstallRoot -Layout $Layout
    [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName)
    Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout $Layout
    foreach ($ancestor in @($Layout.StateRootAncestors)) {
        Revoke-DefenseClawStateAncestorTraverse `
            -Path $ancestor `
            -GatewayServiceSID $cleanupGatewaySID
    }
    if ($Purge) {
        [void](Publish-DefenseClawStatePurgeIntent `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName)
        $result = Complete-DefenseClawStatePurge `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -GatewayServiceSID $cleanupGatewaySID
        $result |
            Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name cached_enterprise_clients_require_reload `
                -Value $true `
                -Force
        return $result
    }
    [void](Revoke-DefenseClawManagedIPCServiceAccess `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GatewayServiceSID $cleanupGatewaySID)
    $result = Get-DefenseClawLifecycleStatus `
        -Action 'Uninstall' `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $result |
        Microsoft.PowerShell.Utility\Add-Member `
            -MemberType NoteProperty `
            -Name cached_enterprise_clients_require_reload `
            -Value $true `
            -Force
    return $result
}

function Invoke-DefenseClawPreLayoutRecovery {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Purge,
        [string]$RequestedCertificationCodexHome,
        [switch]$RequestedCoreHardeningCertification
    )
    # A self-uninstall receipt can be the final surviving authority after both
    # canonical InstallRoot retirement and StateRoot purge. Recover it before
    # purge receipts, tombstones, or any fresh canonical directory creation.
    $selfUninstallRecovery = Invoke-DefenseClawSelfUninstallRecovery `
        -Action $Action `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Purge:$Purge
    if ([bool]$selfUninstallRecovery.handled) {
        return $selfUninstallRecovery
    }
    $installRollbackIntent = Get-DefenseClawInstallRollbackIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($null -ne $installRollbackIntent) {
        if ([string]$installRollbackIntent.phase -ceq 'committed') {
            Complete-DefenseClawCommittedInstallIntent `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            $installRollbackIntent = $null
        }
        elseif ([string]$installRollbackIntent.phase -ceq
            'preparing_layout' -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$installRollbackIntent.snapshot_path
            )) {
            $intentNativeSecurity = Initialize-DefenseClawNativeSecurity
            $stateRoot =
                $intentNativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                    [string]$Layout.StateRoot
                )
            if ($null -eq $stateRoot -or
                $null -eq
                    $intentNativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                        [string]$Layout.PendingPath
                    )) {
                throw (
                    'bound install preparation lost its protected pending ' +
                    'transaction; recovery evidence was retained'
                )
            }
            $recovered = Recover-DefenseClawPendingTransaction `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            if (-not [bool]$recovered.recovered) {
                throw 'bound install preparation transaction was not recovered'
            }
            $installRollbackIntent = $null
            if ($Action -eq 'Uninstall' -and $Purge) {
                $result = Get-DefenseClawLifecycleStatus `
                    -Action 'Uninstall' `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
                $result |
                    Microsoft.PowerShell.Utility\Add-Member `
                        -MemberType NoteProperty `
                        -Name purged `
                        -Value $true `
                        -Force
                return [pscustomobject]@{
                    handled = $true
                    result = (Add-DefenseClawUninstallContractResult `
                        -Result $result)
                }
            }
            if ($Action -ne 'Install') {
                throw "$Action recovered a failed initial install; run Install to create a deployment"
            }
        }
    }
    if ($null -ne $installRollbackIntent) {
        if ($Action -notin @('Install', 'Uninstall') -or
            ($Action -eq 'Uninstall' -and -not $Purge)) {
            throw (
                'an authenticated fresh-install rollback is pending; run a ' +
                'fresh Install or Uninstall -Purge for this exact scope'
            )
        }
        Complete-DefenseClawInstallRollbackIntent `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        $installRollbackIntent = $null
        if ($Action -eq 'Uninstall') {
            $result = Get-DefenseClawLifecycleStatus `
                -Action 'Uninstall' `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            $result |
                Microsoft.PowerShell.Utility\Add-Member `
                    -MemberType NoteProperty `
                    -Name purged `
                    -Value $true `
                    -Force
            $result = Add-DefenseClawUninstallContractResult -Result $result
            return [pscustomobject]@{
                handled = $true
                result = $result
            }
        }
    }
    if ($null -eq $installRollbackIntent) {
        # Repair and Upgrade transactions predate and intentionally do not
        # publish fresh-install root authority. Recover their authenticated
        # pending record before a later Install publishes a new preparation
        # receipt; otherwise the unrelated new receipt can be consumed by the
        # old rollback or collide with services restored from its preimage.
        $pendingNativeSecurity = Initialize-DefenseClawNativeSecurity
        $pendingStateRoot =
            $pendingNativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                [string]$Layout.StateRoot
            )
        if ($null -ne $pendingStateRoot) {
            $pendingBeforeLayout =
                $pendingNativeSecurity::GetRegularFileSecuritySnapshotNoFollowIfExists(
                    [string]$Layout.PendingPath
                )
            if ($null -ne $pendingBeforeLayout) {
                $pendingRecovery = Recover-DefenseClawPendingTransaction `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
                if (-not [bool]$pendingRecovery.recovered) {
                    throw 'authenticated pending transaction was not recovered before layout preparation'
                }
                if ([bool]$pendingRecovery.fresh_install_rollback) {
                    if ($Action -eq 'Uninstall' -and $Purge) {
                        $result = Get-DefenseClawLifecycleStatus `
                            -Action 'Uninstall' `
                            -Layout $Layout `
                            -GatewayServiceName $GatewayServiceName `
                            -GuardianServiceName $GuardianServiceName
                        $result |
                            Microsoft.PowerShell.Utility\Add-Member `
                                -MemberType NoteProperty `
                                -Name purged `
                                -Value $true `
                                -Force
                        return [pscustomobject]@{
                            handled = $true
                            result = (Add-DefenseClawUninstallContractResult `
                                -Result $result)
                        }
                    }
                    if ($Action -ne 'Install') {
                        throw "$Action recovered a failed initial install; run Install to create a deployment"
                    }
                }
            }
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.PurgeIntentPath) {
        if ($Action -eq 'Uninstall' -and $Purge) {
            $result = Complete-DefenseClawStatePurge `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            $result = Add-DefenseClawUninstallContractResult -Result $result
            return [pscustomobject]@{
                handled = $true
                result = $result
            }
        }
        if ($Action -eq 'Install') {
            [void](Complete-DefenseClawStatePurge `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName)
            # Receipt recovery adopts the old deployment mode only to
            # authenticate cleanup. A new Install is governed solely by this
            # invocation's explicit certification switches.
            $Layout.CertificationCodexHome =
                [string]$RequestedCertificationCodexHome
            $Layout.CoreHardeningCertification =
                [bool]$RequestedCoreHardeningCertification
        }
        else {
            throw (
                'an authenticated state-purge intent is pending; ' +
                'run Uninstall -Purge or perform a fresh Install'
            )
        }
    }

    if ($Action -eq 'Uninstall') {
        if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.StateRoot `
                -PathType Container)) {
            throw (
                'Uninstall -Purge requires either an existing managed ' +
                'StateRoot or its authenticated state-purge intent'
            )
        }
        if ((Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.MetadataPath `
                -PathType Leaf) -and
            -not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.PendingPath)) {
            $committedMetadata = Get-DefenseClawDeploymentMetadata `
                -Layout $Layout `
                -Required
            Assert-DefenseClawMetadataIdentity `
                -Metadata $committedMetadata `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            if (-not (Test-DefenseClawMetadataInstalled `
                    -Metadata $committedMetadata)) {
                $result = Invoke-DefenseClawCommittedUninstallCleanup `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -Purge:$Purge
                return [pscustomobject]@{
                    handled = $true
                    result = $result
                }
            }
        }
    }
    return [pscustomobject]@{
        handled = $false
        result = $null
    }
}

function Get-DefenseClawTargetRuntimePreparationMode {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Upgrade', 'Repair')]
        [string]$Action,
        [Parameter(Mandatory)][bool]$ManifestPresent
    )
    if (-not $ManifestPresent) {
        throw (
            "$Action requires an authenticated installed targets.yaml " +
            'before target runtime preparation'
        )
    }
    if ($Action -ceq 'Install') { return 'prepare' }
    return 'validate'
}

function Invoke-DefenseClawInstallLikeLifecycle {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][hashtable]$Sources,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$RefreshApplicationControlAttestation,
        [switch]$RefreshClaudeEffectivePolicyAttestation,
        [switch]$InstallRootCreatedForTransaction,
        [switch]$StateRootCreatedForTransaction,
        [switch]$NoStart
    )
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout
    if ($Sources.ContainsKey('provider_library')) {
        $Layout.ProviderLibraryPath = [string]$Sources['provider_library'].path
    }
    if ([string]::IsNullOrWhiteSpace([string]$Layout.ProviderLibraryPath)) {
        throw "$Action requires a validated managed credential provider library"
    }
    Assert-DefenseClawCMIDBrokerServiceOrAbsent `
        -Name $Layout.BrokerServiceName `
        -ExpectedImage (Get-DefenseClawCMIDBrokerImage `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName) `
        -AllowArgumentUpgrade
    if ($null -ne $metadata) {
        Assert-DefenseClawMetadataIdentity `
            -Metadata $metadata `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    if ($Action -eq 'Install') {
        if ($null -ne $metadata -and (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
            throw 'DefenseClaw enterprise mode is already installed; use Upgrade or Repair'
        }
        if ($null -ne $metadata) {
            # A process can die after committed uninstall transaction cleanup
            # but before its protected prepared journal is retired. The trusted
            # uninstall tombstone authorizes exact cleanup before a direct
            # reinstall opens any transaction or mutates services/hooks.
            [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName)
        }
    }
    elseif ($null -eq $metadata -or -not (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        throw "$Action requires an installed DefenseClaw enterprise deployment"
    }

    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    if ($null -ne $metadata -and (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        $replaced = @($Sources.Keys | Microsoft.PowerShell.Core\Where-Object {
            $_ -in @(
                'gateway',
                'broker',
                'hook',
                'cli',
                'installer',
                'module'
            )
        })
        Assert-DefenseClawRecordedArtifactHashes `
            -Metadata $metadata `
            -Layout $Layout `
            -ReplacedArtifacts $replaced `
            -Action $Action
    }

    $priorCodexTargetEnabled = $false
    if ($null -ne $metadata -and
        (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        $priorCodexTargetProperty = $metadata.PSObject.Properties[
            'codex_target_enabled'
        ]
        if ($null -eq $priorCodexTargetProperty) {
            # Legacy enterprise metadata predates target applicability. Include
            # the shared state for safe migration rather than risk an
            # unsnapshotted preimage.
            $priorCodexTargetEnabled = $true
        }
        elseif ($priorCodexTargetProperty.Value -isnot [bool]) {
            throw 'deployment metadata contains an invalid Codex target result'
        }
        else {
            $priorCodexTargetEnabled = [bool]$priorCodexTargetProperty.Value
        }
    }
    if ($priorCodexTargetEnabled) {
        # Authenticate pre-existing shared machine files before the lifecycle
        # snapshot reads them or any managed service/artifact is changed.
        Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
        Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
    }
    $priorDeploymentActive = [bool](
        $null -ne $metadata -and
        (Test-DefenseClawMetadataInstalled -Metadata $metadata)
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
        -PathType Leaf) {
        # A crash after transaction commit but before journal retirement is
        # harmless. Authenticate and retire that stale preimage before a new
        # lifecycle transaction is allowed to replace it.
        [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action retire)
    }
    $snapshot = New-DefenseClawTransaction `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -PriorDeploymentActive:$priorDeploymentActive `
        -IncludeCodexMachineState:$priorCodexTargetEnabled `
        -InstallRootCreatedForTransaction:$InstallRootCreatedForTransaction `
        -StateRootCreatedForTransaction:$StateRootCreatedForTransaction
    [void](Set-DefenseClawInstallPreparationTransactionBinding `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -SnapshotPath $snapshot)
    try {
        if ($Action -eq 'Install' -and $null -ne $metadata) {
            # The inactive uninstall tombstone remains the authority for
            # exact-scope adoption until New-DefenseClawTransaction has
            # durably copied it. Retire it only inside that transaction so
            # the hidden requirements helper sees fresh-install state. A
            # failed reinstall restores the exact tombstone preimage; a
            # successful reinstall publishes new active metadata below.
            Remove-DefenseClawInactiveDeploymentMetadataForInstall `
                -Layout $Layout `
                -Metadata $metadata `
                -SnapshotPath $snapshot
        }
        Stop-DefenseClawService -Name $GuardianServiceName
        Stop-DefenseClawService -Name $GatewayServiceName
        Stop-DefenseClawService -Name $Layout.BrokerServiceName
        # Upgrade/Repair must capture the old machine-policy identity before a
        # replacement config or manifest changes its endpoint/target set. New
        # gateway/hook bytes are staged first so even an upgrade from a release
        # without the snapshot command can open the protected journal.
        $deferredPolicySources = if ($Action -eq 'Install') {
            @()
        }
        else {
            @('config', 'manifest')
        }
        foreach ($name in @($Sources.Keys | Microsoft.PowerShell.Core\Where-Object {
            $_ -notin $deferredPolicySources -and $_ -ne 'provider_library'
        })) {
            $destination = Get-DefenseClawArtifactPath -Layout $Layout -Name $name
            Install-DefenseClawSourceDescriptor `
                -Source $Sources[$name] `
                -Destination $destination
        }
        foreach ($requiredPath in @(
            $Layout.GatewayPath,
            $Layout.BrokerPath,
            $Layout.HookPath,
            $Layout.ConfigPath,
            $Layout.ManifestPath,
            $Layout.InstallerPath,
            $Layout.ModulePath
        )) {
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
                throw "required managed artifact is missing after $Action staging: $requiredPath"
            }
        }
        if ($Action -ne 'Install') {
            [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action capture)
        }
        foreach ($name in @($deferredPolicySources | Microsoft.PowerShell.Core\Where-Object {
            $Sources.ContainsKey($_)
        })) {
            $destination = Get-DefenseClawArtifactPath -Layout $Layout -Name $name
            Install-DefenseClawSourceDescriptor `
                -Source $Sources[$name] `
                -Destination $destination
        }
        # Upgrade and Repair may reuse the installed config and manifest when
        # no replacement source was supplied. Install always supplies both;
        # the public entry point rejects the legacy deferred source shape.
        $requiredArtifacts = @(
            @{Path = $Layout.BrokerPath;    SourceKey = $null},
            @{Path = $Layout.GatewayPath;   SourceKey = $null},
            @{Path = $Layout.HookPath;      SourceKey = $null},
            @{Path = $Layout.ConfigPath;    SourceKey = 'config'},
            @{Path = $Layout.ManifestPath;  SourceKey = 'manifest'},
            @{Path = $Layout.InstallerPath; SourceKey = $null},
            @{Path = $Layout.ModulePath;    SourceKey = $null}
        )
        foreach ($entry in $requiredArtifacts) {
            $requiredPath = $entry.Path
            $skippable = ($null -ne $entry.SourceKey) -and
                (-not $Sources.ContainsKey($entry.SourceKey))
            if ($skippable) {
                continue
            }
            if (-not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $requiredPath `
                -PathType Leaf)) {
                throw "required managed artifact is missing after $Action policy staging: $requiredPath"
            }
        }
        $targetRuntimeManifestPresent = [bool](
            Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManifestPath `
                -PathType Leaf
        )
        $targetRuntimePreparationMode =
            Get-DefenseClawTargetRuntimePreparationMode `
                -Action $Action `
                -ManifestPresent $targetRuntimeManifestPresent
        # Resolve and publish every target root before SCM activation or any
        # gateway/guardian process can write user state. Only a fresh Install
        # may create an absent root; Upgrade/Repair authenticate every
        # canonical baseline and reject any absent enabled target before
        # services become startable. For Install, the helper's plan is
        # journaled before staging; exact created identities are journaled
        # before final publication, and canonical final state is journaled
        # before services become startable.
        [void](Invoke-DefenseClawTargetRuntimePreparation `
            -SnapshotPath $snapshot `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ValidationOnly:($targetRuntimePreparationMode -ceq 'validate'))
        if ($Action -eq 'Install') {
            # A clean install has no NT SERVICE identities until SCM creates
            # the transaction-owned service pair. The snapshot subprocess
            # loads the protected managed config and validates the gateway's
            # virtual-service SID, so register both services disabled and
            # establish the SID-dependent runtime ACL before capture. The
            # transaction already recorded both services as absent and removes
            # them if capture or any later step fails.
            Set-DefenseClawManagedServicesForTransaction `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action capture)
        }

        $attestationNeedsRefresh = [bool]$RefreshApplicationControlAttestation
        $attestationExists = Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.AgentApplicationControlAttestationPath `
            -PathType Leaf
        if ([bool]$Layout.CoreHardeningCertification -and $attestationExists) {
            $staleAttestation =
                Get-DefenseClawAgentApplicationControlAttestation -Layout $Layout
            if ([bool]$staleAttestation.agent_application_control_enforced) {
                throw 'core-hardening migration refuses to discard genuine application-control attestation evidence'
            }
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath `
                -Force
            $attestationExists = $false
        }
        elseif (-not $attestationNeedsRefresh -and $attestationExists) {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $Layout)
        }
        if ($Action -ne 'Install') {
            # Upgrade/Repair deliberately capture the previous hook identity
            # before reconfiguring the existing service pair.
            Set-DefenseClawManagedServicesForTransaction `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }
        $targetReport = Invoke-DefenseClawCodexRequirementsCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action inspect
        if ([bool]$Layout.CoreHardeningCertification -and
            ([bool]$Layout.CodexTargetEnabled -or
                [bool]$Layout.CursorTargetEnabled)) {
            throw (
                'Core-hardening certification is Claude-only and refuses ' +
                'enabled Codex or Cursor targets in the protected manifest'
            )
        }
        if ($Sources.ContainsKey('manifest') -and
            -not $RefreshClaudeEffectivePolicyAttestation -and
            [bool]$Layout.ClaudeEffectivePolicyVerified) {
            # Approved-client evidence is bound to exact manifest bytes. A
            # replacement manifest must be exercised again before the external
            # prerequisite can be re-attested.
            $Layout.ClaudeEffectivePolicyVerified = $false
            $attestationNeedsRefresh = $true
            $targetReport = Invoke-DefenseClawCodexRequirementsCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action inspect
        }
        if ($RefreshClaudeEffectivePolicyAttestation -and
            -not [bool]$Layout.ClaudeTargetEnabled) {
            throw '-AttestClaudeEffectivePolicy requires at least one enabled Claude target in the protected manifest'
        }
        if (-not [bool]$Layout.ClaudeTargetEnabled -and
            [bool]$Layout.ClaudeEffectivePolicyVerified) {
            $Layout.ClaudeEffectivePolicyVerified = $false
            $attestationNeedsRefresh = $true
        }
        if (-not [bool]$Layout.CoreHardeningCertification -and
            ($attestationNeedsRefresh -or -not $attestationExists)) {
            Write-DefenseClawAgentApplicationControlAttestation -Layout $Layout
            Set-DefenseClawManagedCoreAcls `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName
        }
        Set-DefenseClawServiceEnvironment `
            -Name $GatewayServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GatewayLogPath `
            -BrokerPipeName $Layout.BrokerPipeName `
            -BrokerServiceName $Layout.BrokerServiceName `
            -BrokerAuthKeyPath $Layout.BrokerAuthKeyPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified
        Set-DefenseClawServiceEnvironment `
            -Name $GuardianServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified
        if ([bool]$Layout.CodexTargetEnabled) {
            if (-not $priorCodexTargetEnabled) {
                Add-DefenseClawCodexTransactionSnapshot `
                    -SnapshotPath $snapshot `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
            }
            Initialize-DefenseClawCodexMachinePolicyParent `
                -Layout $Layout `
                -SnapshotPath $snapshot
            Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
            Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
            Initialize-DefenseClawCodexRequirementsAclBackup `
                -Layout $Layout `
                -ExistingMetadata $metadata
            Set-DefenseClawManagedAcls `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName
            [void](Invoke-DefenseClawCodexRequirementsCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action reconcile)
            Set-DefenseClawManagedAcls `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName
            Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout
            Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout
        }
        elseif ($priorCodexTargetEnabled) {
            $codexRemoval = Invoke-DefenseClawCodexRequirementsCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action reconcile
            Complete-DefenseClawCodexRequirementsRemoval `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Report $codexRemoval
        }
        Assert-DefenseClawInstalledConfig -Layout $Layout -GatewayServiceName $GatewayServiceName

        $newMetadata = New-DefenseClawDeploymentMetadata `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        Write-DefenseClawJsonAtomic -Value $newMetadata -Path $Layout.MetadataPath
        Set-DefenseClawManagedAcls -Layout $Layout -GatewayServiceName $GatewayServiceName

        # Validate the complete static deployment while both services remain
        # disabled. This is the only state that also blocks a restart already
        # queued by SCM failure actions.
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ServicingTransaction
        if (-not $NoStart) {
            $activationSnapshot =
                Microsoft.PowerShell.Management\Get-Content `
                    -LiteralPath $snapshot `
                    -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
            $priorServiceStates = Get-DefenseClawTransactionServiceStates `
                -Services $activationSnapshot.services `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            $hadPreexistingService = @(
                $priorServiceStates.Values |
                    Microsoft.PowerShell.Core\Where-Object {
                        [bool]$_.existed
                    }
            ).Count -gt 0
            $quiescenceProperty =
                $activationSnapshot.PSObject.Properties[
                    'services_disabled_and_stopped_at'
                ]
            if ($null -eq $quiescenceProperty) {
                throw 'transaction snapshot is missing its service quiescence barrier'
            }
            $activationQuiescedAt = (
                ConvertFrom-DefenseClawServiceQuiescenceTimestamp `
                    -Value $quiescenceProperty.Value
            ).ToString('o')
            Set-DefenseClawServiceActivationPhase `
                -State $activationSnapshot `
                -Path $snapshot `
                -Phase activating
            if ($hadPreexistingService) {
                Wait-DefenseClawServiceFailureRestartQuiescence `
                    -ServicesQuiescedAt $activationQuiescedAt `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
            }
            # The LocalSystem broker must be live before any restricted
            # gateway path can request a credential.
            Set-DefenseClawServiceStartMode `
                -Name $Layout.BrokerServiceName `
                -StartMode 3
            Start-DefenseClawService -Name $Layout.BrokerServiceName
            # The guardian becomes startable, publishes a fresh successful
            # reconcile, and remains live while gateway is still disabled.
            Set-DefenseClawServiceStartMode `
                -Name $GuardianServiceName `
                -StartMode 3
            [void](Wait-DefenseClawFreshGuardianReconcile `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName)
            # Only a freshly reconciling guardian authorizes gateway demand
            # start. A queued gateway failure restart is now safe to run.
            Set-DefenseClawServiceStartMode `
                -Name $GatewayServiceName `
                -StartMode 3
            Start-DefenseClawService -Name $GatewayServiceName
            # Spec 005 D1 (CR PRRT_kwDORuAK-s6au6lZ): the enumerator
            # must be demand-started + RUNNING before the pending-state
            # assertion below, which requires every managed service to
            # be StartMode 3 AND (via -RequireReadiness below) the
            # enumerator SCM process to be Running. Promotion to
            # StartMode 2 happens later alongside gateway + guardian
            # only after full readiness succeeds.
            $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
            Set-DefenseClawServiceStartMode `
                -Name $enumeratorServiceName `
                -StartMode 3
            Start-DefenseClawService -Name $enumeratorServiceName
            Assert-DefenseClawManagedServiceConfigurations `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName `
                -PendingTransaction
            Wait-DefenseClawEnterpriseReadiness `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            # Canonicalize dynamic logs/authorization after the service-created
            # files exist, then verify exact effective rights.
            Set-DefenseClawManagedAcls -Layout $Layout -GatewayServiceName $GatewayServiceName
            Assert-DefenseClawEnterpriseDeployment `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName `
                -RequireReadiness `
                -PendingTransaction
            # Only fully verified live state may become boot-active. A crash
            # before pending cleanup can start only validated services.
            Set-DefenseClawServiceStartMode `
                -Name $GuardianServiceName `
                -StartMode 2
            Set-DefenseClawServiceStartMode `
                -Name $Layout.BrokerServiceName `
                -StartMode 2
            Set-DefenseClawServiceStartMode `
                -Name $GatewayServiceName `
                -StartMode 2
            # Spec 005 D1: promote the (already-running) enumerator
            # from demand-start to auto-start now that readiness has
            # been proven. Without this, boot would leave the
            # enumerator disabled and new user profiles would never
            # get picked up.
            Set-DefenseClawServiceStartMode `
                -Name $enumeratorServiceName `
                -StartMode 2
            Assert-DefenseClawEnterpriseDeployment `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName `
                -RequireReadiness
        }
        # -NoStart intentionally leaves both services disabled. Enabling them
        # without first running a fresh guardian reconcile would let a queued
        # SCM restart violate the guardian-before-gateway invariant.
        Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout
    }
    catch {
        $operationError = $_
        try {
            Restore-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout
            Complete-DefenseClawTransaction `
                -SnapshotPath $snapshot `
                -Layout $Layout `
                -Rollback
        }
        catch {
            throw "$Action failed ($($operationError.Exception.Message)); rollback also failed and pending recovery was retained: $($_.Exception.Message)"
        }
        try {
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
                -PathType Leaf) {
                [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -Action retire)
            }
        }
        catch {
            throw (
                "$Action failed ($($operationError.Exception.Message)); " +
                'the exact prior machine enrollment was restored, but its ' +
                "completed lifecycle journal could not be retired: $($_.Exception.Message)"
            )
        }
        throw $operationError
    }
    try {
        [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action retire)
    }
    catch {
        throw (
            "$Action committed, but its protected managed-hook lifecycle " +
            "journal could not be retired: $($_.Exception.Message)"
        )
    }
    $result = Get-DefenseClawLifecycleStatus `
        -Action $Action `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ($NoStart) {
        $result.ok = $true
    }
    return $result
}

function Invoke-DefenseClawUninstallLifecycle {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$Purge,
        [int]$SelfUninstallCallerPID
    )
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if (-not (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        # Uninstall is idempotent after the durable tombstone. This also
        # finishes the only safe post-commit cleanup if the previous process
        # died after transaction completion but before journal retirement.
        return Invoke-DefenseClawCommittedUninstallCleanup `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Purge:$Purge
    }
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    # ImagePath/ObjectName ownership alone is insufficient authorization for
    # deletion by service name. Authenticate the complete registry/SCM
    # contract before any teardown mutation.
    Assert-DefenseClawManagedServiceConfigurations `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -AnyStartMode
    Assert-DefenseClawManagedInstallTree -Layout $Layout
    Assert-DefenseClawRecordedArtifactHashes `
        -Metadata $metadata `
        -Layout $Layout `
        -Action 'Uninstall'
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksLifecycleJournalPath `
        -PathType Leaf) {
        [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action retire)
    }
    $selfUninstallCallerIdentity = $null
    if ($SelfUninstallCallerPID -gt 0) {
        $selfUninstallCallerIdentity =
            Get-DefenseClawSelfUninstallCallerIdentity `
                -Layout $Layout `
                -CallerPID $SelfUninstallCallerPID
    }
    $gatewaySID = Get-DefenseClawServiceSID -ServiceName $GatewayServiceName
    $snapshot = $null
    $selfUninstallReceipt = $null
    try {
        # New-DefenseClawTransaction records prior service state, then waits
        # for guardian and gateway process exit before snapshotting. The live
        # teardown journal is intentionally excluded: captured/prepared
        # preimages must survive generic restore until hidden rollback consumes
        # them. Therefore no LocalSystem auto-heal can occur after the
        # authoritative prepare+verify boundary.
        $snapshot = New-DefenseClawTransaction `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -PriorDeploymentActive `
            -IncludeCodexMachineState:$Layout.CodexTargetEnabled `
            -PreserveManagedHooksTeardownJournal
        [void](Invoke-DefenseClawManagedHooksTeardownCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action prepare)
        [void](Invoke-DefenseClawManagedHooksTeardownCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action verify)
        Set-DefenseClawTransactionManagedHooksTeardownPrepared `
            -SnapshotPath $snapshot `
            -Layout $Layout
        if ([bool]$Layout.CodexTargetEnabled) {
            $codexRemoval = Invoke-DefenseClawCodexRequirementsCommand `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Action remove
            Complete-DefenseClawCodexRequirementsRemoval `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName `
                -Report $codexRemoval
        }
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.AgentApplicationControlAttestationPath `
            -PathType Leaf) {
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $Layout.AgentApplicationControlAttestationPath `
                -Force
        }
        # Re-authenticate every service field and both ACL surfaces at the
        # deletion boundary. A concurrent administrative drift or same-name
        # takeover fails closed before either sc.exe delete.
        Assert-DefenseClawManagedServiceConfigurations `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ServicingTransaction
        # Spec 005 D1: teardown order enumerator → guardian → gateway.
        # The enumerator writes targets.yaml; removing it first stops
        # further writes so the guardian's final reconcile pass sees a
        # stable file. Guardian teardown after remains unchanged.
        $enumeratorServiceName = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $GuardianServiceName
        Assert-DefenseClawOwnedServiceOrAbsent `
            -Name $enumeratorServiceName `
            -ExpectedGatewayPath $Layout.GatewayPath `
            -ExpectedManifestPath $Layout.ManifestPath `
            -Enumerator
        Remove-DefenseClawService -Name $enumeratorServiceName
        Assert-DefenseClawOwnedServiceOrAbsent `
            -Name $GuardianServiceName `
            -ExpectedGatewayPath $Layout.GatewayPath `
            -ExpectedManifestPath $Layout.ManifestPath `
            -Guardian
        Remove-DefenseClawService -Name $GuardianServiceName
        Assert-DefenseClawOwnedServiceOrAbsent `
            -Name $GatewayServiceName `
            -ExpectedGatewayPath $Layout.GatewayPath
        Remove-DefenseClawService -Name $GatewayServiceName
        Assert-DefenseClawCMIDBrokerServiceOrAbsent `
            -Name $Layout.BrokerServiceName `
            -ExpectedImage (Get-DefenseClawCMIDBrokerImage `
                -Layout $Layout `
                -GatewayServiceName $GatewayServiceName)
        Remove-DefenseClawService -Name $Layout.BrokerServiceName
        $tombstone = New-DefenseClawDeploymentMetadata `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Installed:$false
        $tombstone.hashes = [ordered]@{}
        Write-DefenseClawJsonAtomic -Value $tombstone -Path $Layout.MetadataPath
        Set-DefenseClawPreservedStateAcls `
            -Layout $Layout `
            -GatewayServiceSID $gatewaySID
        if ($null -ne $selfUninstallCallerIdentity) {
            Set-DefenseClawInstallTreeRetirementAcls -Layout $Layout
            $selfUninstallReceipt =
                Publish-DefenseClawSelfUninstallReceipt `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -CallerIdentity $selfUninstallCallerIdentity `
                    -Purge:$Purge
            $retiredRoot = [string]$selfUninstallReceipt.retired_install_root
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $retiredRoot) {
                throw 'fresh self-uninstall retirement sibling unexpectedly exists'
            }
            [IO.Directory]::Move($Layout.InstallRoot, $retiredRoot)
            if ((Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $Layout.InstallRoot) -or
                -not (Microsoft.PowerShell.Management\Test-Path `
                    -LiteralPath $retiredRoot `
                    -PathType Container)) {
                throw 'atomic self-uninstall InstallRoot retirement did not complete exactly'
            }
            # Re-assert the Admin-only retirement ACLs after the rename.
            # Traversal was already removed from the canonical root before
            # receipt publication, so the sibling name is never a new
            # standard-user execution surface.
            Set-DefenseClawRetiredInstallTreeAcls `
                -Layout $Layout `
                -RetiredRoot $retiredRoot
        }
        else {
            Remove-DefenseClawManagedTree `
                -Path $Layout.InstallRoot `
                -RequiredBase $script:ProgramFiles `
                -Label 'InstallRoot'
        }
        Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout
    }
    catch {
        $operationError = $_
        $rollbackErrors = [Collections.Generic.List[string]]::new()
        # Publication writes the protected receipt before returning its
        # authenticated representation. If the post-write authentication
        # check itself fails, discover that exact evidence before rollback.
        # Never silently strand external authority while generic transaction
        # state is retired.
        if ($null -ne $selfUninstallCallerIdentity -and
            $null -eq $selfUninstallReceipt -and
            (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.SelfUninstallReceiptPath `
                -PathType Leaf)) {
            try {
                $selfUninstallReceipt =
                    Get-DefenseClawSelfUninstallReceipt `
                        -Layout $Layout `
                        -GatewayServiceName $GatewayServiceName `
                        -GuardianServiceName $GuardianServiceName `
                        -Required
            }
            catch {
                $rollbackErrors.Add(
                    'published self-uninstall receipt could not be ' +
                    "authenticated for rollback: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $selfUninstallReceipt -and
            -not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.InstallRoot) -and
            (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath ([string]$selfUninstallReceipt.retired_install_root) `
                -PathType Container)) {
            try {
                Move-DefenseClawRetiredInstallTreeBack `
                    -Layout $Layout `
                    -Receipt $selfUninstallReceipt
            }
            catch {
                $rollbackErrors.Add(
                    "retired InstallRoot restore failed: $($_.Exception.Message)"
                )
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$snapshot)) {
            try {
                [void](Restore-DefenseClawTransactionWithManagedHooksRollback `
                    -SnapshotPath $snapshot `
                    -Layout $Layout)
            }
            catch {
                $rollbackErrors.Add(
                    "managed lifecycle/hook restore failed: $($_.Exception.Message)"
                )
            }
        }
        if ($rollbackErrors.Count -eq 0 -and
            $null -ne $selfUninstallReceipt) {
            try {
                Remove-DefenseClawSelfUninstallEvidence `
                    -Layout $Layout `
                    -Receipt $selfUninstallReceipt
            }
            catch {
                $rollbackErrors.Add(
                    "self-uninstall evidence retirement failed: $($_.Exception.Message)"
                )
            }
        }
        if ($rollbackErrors.Count -eq 0 -and
            -not [string]::IsNullOrWhiteSpace([string]$snapshot)) {
            try {
                Complete-DefenseClawTransaction `
                    -SnapshotPath $snapshot `
                    -Layout $Layout `
                    -Rollback
            }
            catch {
                $rollbackErrors.Add(
                    "transaction cleanup failed: $($_.Exception.Message)"
                )
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw (
                "Uninstall failed ($($operationError.Exception.Message)); " +
                'rollback also failed and protected recovery state was retained: ' +
                ($rollbackErrors -join '; ')
            )
        }
        throw $operationError
    }
    try {
        # The authenticated rollback journal remains live through transaction
        # completion. Retire it only after the tombstone, binary deletion, and
        # pending-transaction cleanup are all durable.
        [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName)
    }
    catch {
        throw (
            'Uninstall committed, but protected managed-hook teardown journal ' +
            "retirement failed; retry Uninstall to finish cleanup: $($_.Exception.Message)"
        )
    }
    if ($null -ne $selfUninstallReceipt) {
        try {
            $selfUninstallReceipt =
                Set-DefenseClawSelfUninstallReceiptCommitted `
                    -Layout $Layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
            [void](Start-DefenseClawSelfUninstallHelper `
                -Layout $Layout `
                -Receipt $selfUninstallReceipt)
        }
        catch {
            throw (
                'Uninstall committed and canonical InstallRoot was retired, ' +
                'but detached self-cleanup could not start; protected recovery ' +
                "state was retained: $($_.Exception.Message)"
            )
        }
    }
    # The OpenAI\Codex tree is shared global vendor state. Enterprise
    # uninstall/purge never claims or removes it, including directories
    # DefenseClaw originally provisioned. Purge is authorized by an
    # authenticated receipt outside StateRoot before its first deletion.
    $result = Invoke-DefenseClawCommittedUninstallCleanup `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Purge:$Purge `
        -GatewayServiceSID $gatewaySID
    $result |
        Microsoft.PowerShell.Utility\Add-Member `
            -MemberType NoteProperty `
            -Name cached_enterprise_clients_require_reload `
            -Value $true `
            -Force
    if ($null -ne $selfUninstallReceipt) {
        return Add-DefenseClawSelfUninstallResult `
            -Result $result `
            -Layout $Layout `
            -Receipt $selfUninstallReceipt `
            -CleanupPending:$true
    }
    return $result
}

function Invoke-DefenseClawReconcileLifecycle {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout -Required
    if (-not (Test-DefenseClawMetadataInstalled -Metadata $metadata)) {
        throw 'Reconcile requires an installed DefenseClaw enterprise deployment'
    }
    Assert-DefenseClawMetadataIdentity `
        -Metadata $metadata `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GatewayServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath
    Assert-DefenseClawOwnedServiceOrAbsent `
        -Name $GuardianServiceName `
        -ExpectedGatewayPath $Layout.GatewayPath `
        -ExpectedManifestPath $Layout.ManifestPath `
        -Guardian
    Assert-DefenseClawRecordedArtifactHashes `
        -Metadata $metadata `
        -Layout $Layout `
        -Action 'Reconcile'
    if ([bool]$Layout.CodexTargetEnabled) {
        Assert-DefenseClawCodexMachinePolicyDirectory -Path $Layout.CodexVendorDirectory
        Assert-DefenseClawCodexMachinePolicyDirectory -Path $Layout.CodexMachinePolicyDirectory
        Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout
        Assert-DefenseClawCodexManagedHooksStateFilePreflight -Layout $Layout
        [void](Get-DefenseClawCodexRequirementsAclBackup -Layout $Layout)
        [void](Invoke-DefenseClawCodexRequirementsCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action reconcile)
    }
    else {
        [void](Invoke-DefenseClawCodexRequirementsCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action inspect)
    }
    Set-DefenseClawManagedAcls `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName
    if ([bool]$Layout.CodexTargetEnabled) {
        Assert-DefenseClawCodexMachinePolicyFile -Layout $Layout
        Assert-DefenseClawCodexManagedHooksStateFile -Layout $Layout
        [void](Invoke-DefenseClawCodexRequirementsCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action verify)
    }
    Assert-DefenseClawEnterpriseDeployment `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $generation = Wait-DefenseClawFreshGuardianReconcile `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    Set-DefenseClawManagedAcls -Layout $Layout -GatewayServiceName $GatewayServiceName
    Assert-DefenseClawEnterpriseDeployment `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -RequireReadiness
    $result = Get-DefenseClawLifecycleStatus `
        -Action 'Reconcile' `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    $result.guardian_generation = $generation
    return $result
}

function Invoke-DefenseClawEnterpriseLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Upgrade', 'Repair', 'Reconcile', 'Status', 'Verify', 'Uninstall')]
        [string]$Action,
        [string]$BrokerBinary,
        [string]$ProviderLibrary,
        [string]$GatewayBinary,
        [string]$HookBinary,
        [string]$CLIBinary,
        [string]$Config,
        [string]$Manifest,
        [string]$InstallRoot = (Microsoft.PowerShell.Management\Join-Path $script:ProgramFiles 'Cisco\Cisco Secure Client\DefenseClaw'),
        [string]$StateRoot = (Microsoft.PowerShell.Management\Join-Path $script:ProgramData 'Cisco\Cisco Secure Client\DefenseClaw'),
        [string]$GatewayServiceName = 'DefenseClawGateway',
        [string]$GuardianServiceName = 'DefenseClawHookGuardian',
        [string]$CertificationCodexHome,
        [switch]$CoreHardeningCertification,
        [switch]$NoStart,
        [switch]$Purge,
        [switch]$AllowUnsigned,
        [switch]$AttestAgentApplicationControl,
        [switch]$AttestClaudeEffectivePolicy,
        [string]$InstallerSource,
        [string]$ModuleSource,
        [int]$SelfUninstallCallerPID,
        # Retained for command-line compatibility, but rejected before layout
        # resolution until late config publication has an authenticated target
        # runtime preparation and activation transaction.
        [switch]$DeferredConfig
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    if ([string]::Equals($GatewayServiceName, $GuardianServiceName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'gateway and guardian Windows service names must be distinct'
    }
    # Blocker 039 requires every enabled target runtime to be authenticated
    # and prepared before any managed service can write user state. A
    # deferred-config Install has no targets.yaml from which to derive that
    # authority, and the legacy late-drop path has no transactional activation
    # boundary. Reject it before resolving layout paths, opening the lifecycle
    # lock, creating roots, or touching SCM; a normal Install with an
    # authenticated manifest remains the supported path.
    if ($DeferredConfig) {
        throw (
            '-DeferredConfig is temporarily unavailable: secure target ' +
            'runtime preparation requires authenticated targets.yaml during Install'
        )
    }
    $certificationServiceScope = [Text.RegularExpressions.Regex]::IsMatch(
        $GatewayServiceName,
        '^DefenseClawCertGateway_[a-f0-9]{10}$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($certificationServiceScope -and
        $Action -in @('Install', 'Upgrade', 'Repair') -and
        -not $AllowUnsigned) {
        throw (
            'certification-scoped Install, Upgrade, or Repair requires ' +
            '-AllowUnsigned'
        )
    }
    $resolvedCertificationCodexHome = Resolve-DefenseClawCertificationCodexHome `
        -Path $CertificationCodexHome `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -AllowMissing:($Action -in @('Status', 'Verify'))
    if ($Purge -and $Action -ne 'Uninstall') {
        throw '-Purge is valid only with Uninstall'
    }
    if ($SelfUninstallCallerPID -lt 0 -or
        ($SelfUninstallCallerPID -gt 0 -and $Action -ne 'Uninstall')) {
        throw '-SelfUninstallCallerPID is valid only as a positive PID with Uninstall'
    }
    if ($NoStart -and $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-NoStart is valid only with Install, Upgrade, or Repair'
    }
    if ($CoreHardeningCertification -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-CoreHardeningCertification is valid only with Install, Upgrade, or Repair'
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedCertificationCodexHome) -and
        -not $AllowUnsigned) {
        throw '-CertificationCodexHome requires -AllowUnsigned for every lifecycle action'
    }
    if ($CoreHardeningCertification -and
        (-not $AllowUnsigned -or
            [string]::IsNullOrWhiteSpace($resolvedCertificationCodexHome))) {
        throw '-CoreHardeningCertification requires -AllowUnsigned and -CertificationCodexHome'
    }
    if ($AttestAgentApplicationControl -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-AttestAgentApplicationControl is valid only with Install, Upgrade, or Repair'
    }
    if ($AttestClaudeEffectivePolicy -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-AttestClaudeEffectivePolicy is valid only with Install, Upgrade, or Repair'
    }
    if ($CoreHardeningCertification -and
        ($AttestAgentApplicationControl -or
            $AttestClaudeEffectivePolicy)) {
        throw (
            '-CoreHardeningCertification cannot be combined with production ' +
            'application-control or Claude-policy attestations'
        )
    }
    if ($Action -ne 'Status') {
        Assert-DefenseClawAdministrator
    }

    $resolvedInstallRoot = Assert-DefenseClawSafeRoot `
        -Path $InstallRoot `
        -Label 'InstallRoot' `
        -RequiredBase $script:ProgramFiles
    $resolvedStateRoot = Assert-DefenseClawSafeRoot `
        -Path $StateRoot `
        -Label 'StateRoot' `
        -RequiredBase $script:ProgramData
    Assert-DefenseClawDistinctRoots `
        -InstallRoot $resolvedInstallRoot `
        -StateRoot $resolvedStateRoot
    if ($AllowUnsigned) {
        Assert-DefenseClawUnsignedCertificationScope `
            -Action $Action `
            -InstallRoot $resolvedInstallRoot `
            -StateRoot $resolvedStateRoot `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -CertificationCodexHome $resolvedCertificationCodexHome
    }
    $layout = Get-DefenseClawLayout `
        -InstallRoot $resolvedInstallRoot `
        -StateRoot $resolvedStateRoot `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -CertificationCodexHome $resolvedCertificationCodexHome `
        -CoreHardeningCertification:$CoreHardeningCertification `
        -AgentApplicationControlAttested:$AttestAgentApplicationControl

    # Keep the authoritative current/global/GUID drive identity adjacent to
    # the first managed metadata read, not only to caller argument parsing.
    Assert-DefenseClawLayoutVolumeIdentity `
        -Layout $layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -AllowMissingCertificationCodexHome:($Action -in @('Status', 'Verify'))
    if ((Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $layout.MetadataPath `
            -PathType Leaf) -and
        ($Action -ne 'Status' -or (Test-DefenseClawAdministrator))) {
        # Protected metadata, not a caller-supplied certification path, is the
        # authority for continuing an existing core-hardening certification
        # deployment.
        [void](Get-DefenseClawDeploymentMetadata -Layout $layout)
    }
    $applicationControlAttestationExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $layout.AgentApplicationControlAttestationPath `
        -PathType Leaf
    if ($applicationControlAttestationExists -and
        ($Action -ne 'Status' -or (Test-DefenseClawAdministrator))) {
        $existingApplicationControlAttestation =
            Get-DefenseClawAgentApplicationControlAttestation -Layout $layout
        $layout.AgentApplicationControlAttested = [bool](
            $existingApplicationControlAttestation.agent_application_control_enforced
        )
        $layout.ClaudeEffectivePolicyVerified = [bool](
            $existingApplicationControlAttestation.claude_effective_policy_verified
        )
    }
    if ($AttestAgentApplicationControl) {
        if ([bool]$layout.CoreHardeningCertification) {
            throw '-AttestAgentApplicationControl is forbidden in core-hardening certification mode'
        }
        $layout.AgentApplicationControlAttested = $true
    }
    if ($AttestClaudeEffectivePolicy) {
        if ([bool]$layout.CoreHardeningCertification) {
            throw '-AttestClaudeEffectivePolicy is forbidden in core-hardening certification mode'
        }
        $layout.ClaudeEffectivePolicyVerified = $true
    }
    if ($Action -eq 'Status') {
        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -AllowMissingCertificationCodexHome
        return Get-DefenseClawLifecycleStatus `
            -Action $Action `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }
    if ($Action -eq 'Verify') {
        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -AllowMissingCertificationCodexHome
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.PendingPath -PathType Leaf) {
            throw 'cannot verify while a lifecycle transaction is pending; run Repair'
        }
        Assert-DefenseClawEnterpriseDeployment `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -RequireReadiness
        return Get-DefenseClawLifecycleStatus `
            -Action $Action `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
    }

    Assert-DefenseClawAdministrator
    if ($Action -ne 'Install' -and
        -not ($Action -eq 'Uninstall' -and $Purge) -and
        -not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $resolvedStateRoot `
            -PathType Container)) {
        throw "$Action requires an existing managed StateRoot: $resolvedStateRoot"
    }
    $sources = Get-DefenseClawLifecycleSources `
        -Action $Action `
        -BrokerBinary $BrokerBinary `
        -ProviderLibrary $ProviderLibrary `
        -GatewayBinary $GatewayBinary `
        -HookBinary $HookBinary `
        -CLIBinary $CLIBinary `
        -Config $Config `
        -Manifest $Manifest `
        -InstallerSource $InstallerSource `
        -ModuleSource $ModuleSource `
        -AllowUnsigned:$AllowUnsigned `
        -DeferredConfig:$DeferredConfig

    # Secure creation is race-safe and validates every existing ancestor
    # before the first lifecycle coordination object is opened. The lock then
    # lives in a protected ProgramData directory, so an unprivileged process
    # cannot precreate or hold a competing object as it could with Global\.
    Assert-DefenseClawLayoutVolumeIdentity `
        -Layout $layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    Assert-DefenseClawLifecycleSourcesCurrent -Sources $sources
    Initialize-DefenseClawManagedRoot `
        -Path $layout.LifecycleLockDirectory `
        -Label 'lifecycle lock directory' `
        -RequiredBase $script:ProgramData
    $lifecycleLock = Enter-DefenseClawLifecycleLock -Layout $layout
    try {
        # Revalidate current/global/GUID drive identity after the bounded lock
        # wait, before any filesystem or SCM mutation. Source descriptors are
        # rebound here and again immediately before each atomic source copy.
        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        Assert-DefenseClawLifecycleSourcesCurrent -Sources $sources

        # A purge receipt lives outside StateRoot and is authenticated before
        # any managed layout directory is created. It is therefore sufficient
        # authority to resume a crash-interrupted purge after StateRoot itself
        # has been partially or completely deleted.
        $preLayoutRecovery = Invoke-DefenseClawPreLayoutRecovery `
            -Action $Action `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -Purge:$Purge `
            -RequestedCertificationCodexHome $resolvedCertificationCodexHome `
            -RequestedCoreHardeningCertification:$CoreHardeningCertification
        if ([bool]$preLayoutRecovery.handled) {
            return $preLayoutRecovery.result
        }

        if ($Action -eq 'Reconcile') {
            Assert-DefenseClawLayoutVolumeIdentity `
                -Layout $layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.InstallRoot -PathType Container)) {
                throw 'Reconcile requires an existing managed InstallRoot'
            }
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.PendingPath -PathType Leaf) {
                $reconcileRecovery = Recover-DefenseClawPendingTransaction `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
                if ([bool]$reconcileRecovery.fresh_install_rollback) {
                    throw 'Reconcile recovered a failed initial install; run Install to create a deployment'
                }
            }
            return Invoke-DefenseClawReconcileLifecycle `
                -Layout $layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }

        # Capture the exact absence baseline before the first managed-root
        # mutation. Fresh-install rollback records these booleans together with
        # the no-follow directory identities in its protected snapshot, so it
        # can delete only roots this transaction actually introduced.
        $nativeSecurity = Initialize-DefenseClawNativeSecurity
        $installRootBaseline =
            $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                [string]$layout.InstallRoot
            )
        $stateRootBaseline =
            $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                [string]$layout.StateRoot
            )
        $installRootCreatedForTransaction = $false
        $stateRootCreatedForTransaction = $false
        $installPreparationIntent = $null
        if ($Action -eq 'Install') {
            # Publish protected absence/preimage authority before the first
            # root mutation. If the process dies, the exact-scope receipt is
            # still available outside StateRoot for fail-closed recovery.
            $installPreparationIntent =
                New-DefenseClawInstallPreparationIntent `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -InstallRootBaseline $installRootBaseline `
                    -StateRootBaseline $stateRootBaseline
        }
        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        if ($null -ne $installPreparationIntent) {
            $installRootCreatedForTransaction = [bool](
                Initialize-DefenseClawTransactionManagedRoot `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -Root install_root `
                    -Path $layout.InstallRoot `
                    -Label 'InstallRoot' `
                    -RequiredBase $script:ProgramFiles `
                    -AllowUsersRead
            )
        }
        else {
            [void](Initialize-DefenseClawManagedRoot `
                -Path $layout.InstallRoot `
                -Label 'InstallRoot' `
                -RequiredBase $script:ProgramFiles `
                -AllowUsersRead)
        }
        if ($null -ne $installPreparationIntent) {
            $stateRootCreatedForTransaction = [bool](
                Initialize-DefenseClawTransactionManagedRoot `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -Root state_root `
                    -Path $layout.StateRoot `
                    -Label 'StateRoot' `
                    -RequiredBase $script:ProgramData
            )
        }
        else {
            [void](Initialize-DefenseClawManagedRoot `
                -Path $layout.StateRoot `
                -Label 'StateRoot' `
                -RequiredBase $script:ProgramData)
        }
        New-DefenseClawLayoutDirectories -Layout $layout
        $pendingRecovery = Recover-DefenseClawPendingTransaction `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        if ([bool]$pendingRecovery.fresh_install_rollback) {
            if ($Action -eq 'Uninstall' -and $Purge) {
                $result = Get-DefenseClawLifecycleStatus `
                    -Action 'Uninstall' `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
                $result |
                    Microsoft.PowerShell.Utility\Add-Member `
                        -MemberType NoteProperty `
                        -Name purged `
                        -Value $true `
                        -Force
                return Add-DefenseClawUninstallContractResult -Result $result
            }
            if ($Action -ne 'Install') {
                throw "$Action recovered a failed initial install; run Install or Uninstall -Purge"
            }
            # Recovery retired the earlier exact-scope receipt. Start a new
            # protected preparation transaction before recreating either
            # root, so a second crash cannot reproduce the original gap.
            $recoveredInstallBaseline =
                $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                    [string]$layout.InstallRoot
                )
            $recoveredStateBaseline =
                $nativeSecurity::GetDirectorySecuritySnapshotNoFollowIfExists(
                    [string]$layout.StateRoot
                )
            $installPreparationIntent =
                New-DefenseClawInstallPreparationIntent `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -InstallRootBaseline $recoveredInstallBaseline `
                    -StateRootBaseline $recoveredStateBaseline
            $installRootCreatedForTransaction = [bool](
                Initialize-DefenseClawTransactionManagedRoot `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -Root install_root `
                    -Path $layout.InstallRoot `
                    -Label 'InstallRoot' `
                    -RequiredBase $script:ProgramFiles `
                    -AllowUsersRead
            )
            $stateRootCreatedForTransaction = [bool](
                Initialize-DefenseClawTransactionManagedRoot `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName `
                    -Root state_root `
                    -Path $layout.StateRoot `
                    -Label 'StateRoot' `
                    -RequiredBase $script:ProgramData
            )
            New-DefenseClawLayoutDirectories -Layout $layout
        }

        if ($Action -eq 'Uninstall') {
            return Invoke-DefenseClawUninstallLifecycle `
                -Layout $layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName `
                -Purge:$Purge `
                -SelfUninstallCallerPID $SelfUninstallCallerPID
        }
        return Invoke-DefenseClawInstallLikeLifecycle `
            -Action $Action `
            -Layout $layout `
            -Sources $sources `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -RefreshApplicationControlAttestation:(
                $AttestAgentApplicationControl -or
                $AttestClaudeEffectivePolicy
            ) `
            -RefreshClaudeEffectivePolicyAttestation:$AttestClaudeEffectivePolicy `
            -InstallRootCreatedForTransaction:$installRootCreatedForTransaction `
            -StateRootCreatedForTransaction:$stateRootCreatedForTransaction `
            -NoStart:($NoStart -or $DeferredConfig)
    }
    finally {
        Exit-DefenseClawLifecycleLock -Lock $lifecycleLock
    }
}

Microsoft.PowerShell.Core\Export-ModuleMember -Function Invoke-DefenseClawEnterpriseLifecycle
