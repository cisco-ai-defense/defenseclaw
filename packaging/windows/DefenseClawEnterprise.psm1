# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
$script:AdministratorsSID = 'S-1-5-32-544'
$script:UsersSID = 'S-1-5-32-545'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:ServiceSDDL = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;BU)'
$script:ServiceDescription = 'Administrator-managed DefenseClaw service; standard users have query-only SCM access.'
$script:ServiceFailureRestartQuiescenceSeconds = 65
$script:SchemaVersion = 1
$script:AgentApplicationControlAttestationSchemaVersion = 2
$script:AgentApplicationControlPrerequisite = 'wdac_or_applocker_approved_agent_client_rules'
$script:CodexTrustedHookLauncherPrerequisite = 'approved_fail_closed_fixed_hook_launcher'
$script:ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$script:ProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$script:WindowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
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

function Resolve-DefenseClawCertificationCodexHome {
    param(
        [string]$Path,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
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

    $full = Resolve-DefenseClawFullPath -Path $Path -MustExist
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
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $full -PathType Container)) {
        throw "certification CODEX_HOME must be an existing directory: $full"
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
    Assert-DefenseClawNoReparsePath -Path $full
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
    if ($Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw "$prefix; action must be Install, Upgrade, or Repair"
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
        'DefenseClaw-Cert',
        $runID
    ).TrimEnd('\')
    $expectedState = [IO.Path]::Combine(
        $script:ProgramData,
        'Cisco',
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
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "required System32 tool is missing: $resolved"
    }
    Assert-DefenseClawNoReparsePath -Path $resolved
    $output = & $resolved @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $detail = ($output | Microsoft.PowerShell.Utility\Out-String).Trim()
        throw "$resolved exited $exitCode while running '$($Arguments -join ' ')': $detail"
    }
    if ($Capture) {
        return @($output)
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

function New-DefenseClawCanonicalPathAcl {
    param(
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)]
        [ValidateSet('InstallDirectory', 'InstallFile', 'ServiceInstallDirectory', 'ServiceInstallFile', 'StateDirectory', 'AdminDirectory', 'AdminFile', 'ConfigFile', 'MachinePolicyFile', 'RuntimeDirectory', 'RuntimeFile', 'AuthorizationDirectory', 'AuthorizationFile', 'LogDirectory', 'GatewayLogDirectory')]
        [string]$Kind,
        [Parameter(Mandatory)][string]$GatewayServiceSID
    )

    $directoryKinds = @(
        'InstallDirectory',
        'ServiceInstallDirectory',
        'StateDirectory',
        'AdminDirectory',
        'RuntimeDirectory',
        'AuthorizationDirectory',
        'LogDirectory',
        'GatewayLogDirectory'
    )
    if ($IsDirectory -ne ($Kind -in $directoryKinds)) {
        throw "ACL kind $Kind does not match the managed path object type"
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
    }

    $inheritanceFlags = if ($IsDirectory) {
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
        [Security.AccessControl.RawSecurityDescriptor]$Expected
    )

    # NTFS may persist a protected DACL with the benign AutoInherited (AI)
    # control flag even when Set-Acl received an otherwise identical D:P
    # descriptor. Mask only that metadata bit, then require every other
    # descriptor control flag and the raw DACL bytes to match exactly. RawAcl
    # equality preserves ACE order, revision, type, flags, mask, SID, and
    # duplicates; it cannot hide an unrecognized or inherited ACE.
    $ignoredFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
    )
    $actualFlags = (
        [int]$Actual.ControlFlags -band (-bnot $ignoredFlag)
    )
    $expectedFlags = (
        [int]$Expected.ControlFlags -band (-bnot $ignoredFlag)
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
    $protectedFlag = [int](
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    if (([int]$actualDescriptor.ControlFlags -band $protectedFlag) -eq 0) {
        throw "managed DACL is not protected after exact ACL replacement: $Path"
    }
    $ownerSID = if ($null -eq $actualDescriptor.Owner) {
        ''
    }
    else {
        $actualDescriptor.Owner.Value
    }
    $groupSID = if ($null -eq $actualDescriptor.Group) {
        ''
    }
    else {
        $actualDescriptor.Group.Value
    }
    if ($ownerSID -ne $script:AdministratorsSID -or
        $groupSID -ne $script:AdministratorsSID) {
        throw (
            'managed path owner/group are not the canonical Administrators ' +
            "SID after exact ACL replacement: $Path"
        )
    }
    $expectedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $Expected.GetSecurityDescriptorBinaryForm(),
        0
    )
    if (-not (Test-DefenseClawExactRawDACL `
        -Actual $actualDescriptor `
        -Expected $expectedDescriptor)) {
        throw "managed path does not have the exact canonical DACL: $Path"
    }
}

function Set-DefenseClawPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [ValidateSet('InstallDirectory', 'InstallFile', 'ServiceInstallDirectory', 'ServiceInstallFile', 'StateDirectory', 'AdminDirectory', 'AdminFile', 'ConfigFile', 'MachinePolicyFile', 'RuntimeDirectory', 'RuntimeFile', 'AuthorizationDirectory', 'AuthorizationFile', 'LogDirectory', 'GatewayLogDirectory')]
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
        [switch]$AllowUsersRead
    )
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parent -PathType Container)) {
        throw "protected directory parent must already exist: $parent"
    }
    Assert-DefenseClawTrustedAncestor -Path $parent

    $nativeSecurityType = Initialize-DefenseClawNativeSecurity
    $sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($AllowUsersRead) {
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
        -AllowUsersRead:$AllowUsersRead
    return [bool]$created
}

function Initialize-DefenseClawManagedRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$RequiredBase,
        [switch]$AllowUsersRead
    )
    $base = [IO.Path]::GetFullPath($RequiredBase).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    Assert-DefenseClawTrustedAncestors -Path $full -RequiredBase $base

    $current = $base
    $relative = $full.Substring($base.Length).TrimStart('\')
    $components = @($relative.Split('\') | Microsoft.PowerShell.Core\Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    for ($index = 0; $index -lt $components.Count; $index++) {
        $current = Microsoft.PowerShell.Management\Join-Path $current $components[$index]
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current)) {
            [void](New-DefenseClawProtectedDirectory `
                -Path $current `
                -AllowUsersRead:$AllowUsersRead)
        }
        elseif (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current -PathType Container)) {
            throw "$Label ancestor is occupied by a non-directory: $current"
        }
        else {
            Assert-DefenseClawTrustedAncestor -Path $current
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
    if ($ownerSID -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
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
        [string]$ExpectedSHA256
    )
    Assert-DefenseClawNoReparsePath -Path $Source
    Assert-DefenseClawNoReparsePath -Path $Destination -AllowMissingLeaf
    New-DefenseClawDirectory -Path ([IO.Path]::GetDirectoryName($Destination))
    $temporary = "$Destination.new.$([Guid]::NewGuid().ToString('N'))"
    try {
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $Source -Destination $temporary -Force
        Assert-DefenseClawNoReparsePath -Path $temporary
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSHA256)) {
            $copiedHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
            if (-not [string]::Equals(
                $copiedHash,
                $ExpectedSHA256,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "source changed while staging managed artifact: $Source"
            }
        }
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $temporary -Destination $Destination -Force
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
        $Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 | Microsoft.PowerShell.Management\Set-Content -LiteralPath $temporary -Encoding UTF8
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
    return $null -ne (Microsoft.PowerShell.Management\Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

function Stop-DefenseClawService {
    param([Parameter(Mandatory)][string]$Name)
    $service = Microsoft.PowerShell.Management\Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
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
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified,
        [switch]$CodexTrustedHookLauncherVerified
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
    if ($AgentApplicationControlAttested) {
        $values.Add('DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1')
        $values.Add('DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1')
    }
    if ($ClaudeEffectivePolicyVerified) {
        $values.Add('DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1')
    }
    if ($CodexTrustedHookLauncherVerified) {
        $values.Add('DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1')
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
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified,
        [switch]$CodexTrustedHookLauncherVerified
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
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified `
        -CodexTrustedHookLauncherVerified:$CodexTrustedHookLauncherVerified)
    [void](Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $serviceKey -Name Environment -PropertyType MultiString -Value $values -Force)
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
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $serviceKey -AclObject $security
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

    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
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

    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $serviceKey
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
        [Parameter(Mandatory)][string]$GatewayPath,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$AuthorizationDirectory,
        [Parameter(Mandatory)][string]$GatewayLogPath,
        [Parameter(Mandatory)][string]$GuardianLogPath,
        [switch]$AgentApplicationControlAttested,
        [switch]$ClaudeEffectivePolicyVerified,
        [switch]$CodexTrustedHookLauncherVerified,
        [switch]$DeferAutomaticStart
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    $gatewayAccount = "NT SERVICE\$GatewayServiceName"
    $gatewayImage = '"{0}"' -f $GatewayPath
    $guardianImage = '"{0}" enterprise hooks watch --manifest "{1}" --interval 1m' -f $GatewayPath, $ManifestPath
    # Transaction-created or reconfigured services remain disabled while
    # protected state and binaries are being mutated. Demand start is not
    # sufficient: SCM may still execute an already queued failure restart.
    $configuredStart = if ($DeferAutomaticStart) { 'disabled' } else { 'auto' }

    if (Test-DefenseClawServiceExists -Name $GatewayServiceName) {
        [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
            'config', $GatewayServiceName,
            'binPath=', $gatewayImage,
            'type=', 'own',
            'start=', $configuredStart,
            'error=', 'normal',
            'depend=', '/',
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
            'depend=', '/',
            'obj=', $gatewayAccount,
            'DisplayName=', 'DefenseClaw Enterprise Gateway'
        ))
    }
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

    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $GatewayServiceName, 'restricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @('sidtype', $GuardianServiceName, 'unrestricted'))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $GatewayServiceName, 'SeChangeNotifyPrivilege'
    ))
    [void](Invoke-DefenseClawNative -File $script:ScExe -Arguments @(
        'privs', $GuardianServiceName,
        'SeTcbPrivilege/SeImpersonatePrivilege/SeChangeNotifyPrivilege/SeBackupPrivilege/SeRestorePrivilege'
    ))
    foreach ($service in @($GatewayServiceName, $GuardianServiceName)) {
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

    Set-DefenseClawServiceEnvironment `
        -Name $GatewayServiceName `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $GatewayLogPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified `
        -CodexTrustedHookLauncherVerified:$CodexTrustedHookLauncherVerified
    Set-DefenseClawServiceEnvironment `
        -Name $GuardianServiceName `
        -RuntimeDirectory $RuntimeDirectory `
        -ConfigPath $ConfigPath `
        -AuthorizationDirectory $AuthorizationDirectory `
        -GatewayServiceName $GatewayServiceName `
        -LogPath $GuardianLogPath `
        -AgentApplicationControlAttested:$AgentApplicationControlAttested `
        -ClaudeEffectivePolicyVerified:$ClaudeEffectivePolicyVerified `
        -CodexTrustedHookLauncherVerified:$CodexTrustedHookLauncherVerified
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($GuardianServiceName, $GatewayServiceName)) {
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
            $GuardianServiceName
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
    # Activate the guardian's recorded boot policy first. A power loss during
    # this sequence can therefore never leave the gateway automatic while the
    # guardian is still demand-start because of this transaction.
    foreach ($name in @($GuardianServiceName, $GatewayServiceName)) {
        $state = $states[$name]
        if ([bool]$state.existed) {
            Set-DefenseClawServiceStartMode `
                -Name $name `
                -StartMode ([int]$state.start_mode)
        }
    }
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
    Set-DefenseClawPathAcl -Path $Layout.AgentDirectory -Kind InstallDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.LibexecDirectory -Kind InstallDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GatewayPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GatewayPath -Kind ServiceInstallFile -GatewayServiceSID $gatewaySID
    }
    foreach ($path in @($Layout.HookPath, $Layout.InstallerPath, $Layout.ModulePath)) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf) {
            Set-DefenseClawPathAcl -Path $path -Kind InstallFile -GatewayServiceSID $gatewaySID
        }
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.CLIPath -Kind InstallFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexTrustedHookLauncherPath `
        -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexTrustedHookLauncherPath `
            -Kind InstallFile `
            -GatewayServiceSID $gatewaySID
    }

    Set-DefenseClawPathAcl -Path $Layout.StateRoot -Kind StateDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ConfigDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GuardianDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.InstallStateDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ConfigPath -Kind ConfigFile -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.ManifestPath -Kind AdminFile -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.RuntimeDirectory -Kind RuntimeDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.AuthorizationDirectory -Kind AuthorizationDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.AuthorizationLedgerPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.AuthorizationLedgerPath -Kind AuthorizationFile -GatewayServiceSID $gatewaySID
    }
    Set-DefenseClawPathAcl -Path $Layout.LogDirectory -Kind LogDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GatewayLogDirectory -Kind GatewayLogDirectory -GatewayServiceSID $gatewaySID
    Set-DefenseClawPathAcl -Path $Layout.GuardianLogDirectory -Kind AdminDirectory -GatewayServiceSID $gatewaySID
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GatewayLogPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GatewayLogPath -Kind RuntimeFile -GatewayServiceSID $gatewaySID
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.GuardianLogPath -PathType Leaf) {
        Set-DefenseClawPathAcl -Path $Layout.GuardianLogPath -Kind AdminFile -GatewayServiceSID $gatewaySID
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
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CodexTrustedShellAttestationPath -PathType Leaf) {
        Set-DefenseClawPathAcl `
            -Path $Layout.CodexTrustedShellAttestationPath `
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

function Get-DefenseClawLayout {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$StateRoot,
        [string]$GatewayServiceName = 'DefenseClawGateway',
        [string]$GuardianServiceName = 'DefenseClawHookGuardian',
        [string]$CertificationCodexHome,
        [switch]$CoreHardeningCertification,
        [switch]$AgentApplicationControlAttested,
        [switch]$CodexTrustedHookLauncherVerified
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
            'DefenseClaw-Cert',
            $certificationRunID
        ).TrimEnd('\')
        $expectedStateRoot = [IO.Path]::Combine(
            $script:ProgramData,
            'Cisco',
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
            'DefenseClaw'
        ).TrimEnd('\')
        $expectedStateRoot = [IO.Path]::Combine(
            $script:ProgramData,
            'Cisco',
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
    $agentDirectory = Microsoft.PowerShell.Management\Join-Path $InstallRoot 'agents'
    $libexec = Microsoft.PowerShell.Management\Join-Path $InstallRoot 'libexec'
    $configDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'etc'
    $guardianDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian'
    $installState = Microsoft.PowerShell.Management\Join-Path $StateRoot 'install'
    $logDirectory = Microsoft.PowerShell.Management\Join-Path $StateRoot 'logs'
    $gatewayLogDirectory = Microsoft.PowerShell.Management\Join-Path $logDirectory 'gateway'
    $guardianLogDirectory = Microsoft.PowerShell.Management\Join-Path $logDirectory 'guardian'
    $lifecycleLockDirectory = Microsoft.PowerShell.Management\Join-Path `
        $script:ProgramData `
        'Cisco\DefenseClaw-Lifecycle'
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
    return @{
        InstallRoot = $InstallRoot
        StateRoot = $StateRoot
        BinDirectory = $bin
        AgentDirectory = $agentDirectory
        LibexecDirectory = $libexec
        ConfigDirectory = $configDirectory
        RuntimeDirectory = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'runtime')
        GuardianDirectory = $guardianDirectory
        AuthorizationDirectory = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian-state')
        AuthorizationLedgerPath = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian-state\protected_targets.json')
        LogDirectory = $logDirectory
        GatewayLogDirectory = $gatewayLogDirectory
        GuardianLogDirectory = $guardianLogDirectory
        GatewayLogPath = (Microsoft.PowerShell.Management\Join-Path $gatewayLogDirectory 'gateway.log')
        GuardianLogPath = (Microsoft.PowerShell.Management\Join-Path $guardianLogDirectory 'hook-guardian.log')
        InstallStateDirectory = $installState
        GatewayPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw-gateway.exe')
        HookPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw-hook.exe')
        CLIPath = (Microsoft.PowerShell.Management\Join-Path $bin 'defenseclaw.exe')
        CodexTrustedHookLauncherPath = (Microsoft.PowerShell.Management\Join-Path $agentDirectory 'codex.exe')
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
        SelfUninstallReceiptPath = $selfUninstallReceiptPath
        SelfUninstallHelperPath = $selfUninstallHelperPath
        SelfUninstallEnvironmentRoot = $selfUninstallEnvironmentRoot
        CodexVendorDirectory = $codexVendorDirectory
        CodexMachinePolicyDirectory = $codexMachinePolicyDirectory
        CodexMachinePolicyPath = (Microsoft.PowerShell.Management\Join-Path $codexMachinePolicyDirectory 'requirements.toml')
        CodexManagedHooksDirectory = $bin
        CodexManagedHooksStatePath = (Microsoft.PowerShell.Management\Join-Path $codexMachinePolicyDirectory '.defenseclaw-managed-hooks.state')
        CodexRequirementsOwnershipPath = (Microsoft.PowerShell.Management\Join-Path $installState 'codex-requirements-ownership.json')
        CodexRequirementsAclBackupPath = (Microsoft.PowerShell.Management\Join-Path $installState 'codex-requirements-acl-backup.json')
        CodexTrustedShellAttestationPath = (Microsoft.PowerShell.Management\Join-Path $installState 'agent-application-control-attestation.json')
        ManagedHooksTeardownJournalPath = (Microsoft.PowerShell.Management\Join-Path $installState 'managed-hooks-teardown-journal.json')
        CoreHardeningCertification = [bool]$CoreHardeningCertification
        AgentApplicationControlAttested = [bool]$AgentApplicationControlAttested
        ClaudeEffectivePolicyVerified = $false
        ClaudeTargetEnabled = $false
        CodexTrustedHookLauncherVerified = [bool]$CodexTrustedHookLauncherVerified
        CodexTargetEnabled = $false
        CertificationCodexHome = [string]$CertificationCodexHome
    }
}

function Assert-DefenseClawLayoutVolumeIdentity {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
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
            -GuardianServiceName $GuardianServiceName
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
        $Layout.AgentDirectory,
        $Layout.LibexecDirectory,
        $Layout.StateRoot,
        $Layout.ConfigDirectory,
        $Layout.RuntimeDirectory,
        $Layout.GuardianDirectory,
        $Layout.AuthorizationDirectory,
        $Layout.LogDirectory,
        $Layout.GatewayLogDirectory,
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
        @('agent_application_control_attestation_path', $Layout.CodexTrustedShellAttestationPath),
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
    foreach ($targetName in @('claude_target_enabled', 'codex_target_enabled')) {
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
        else {
            $Layout.CodexTargetEnabled = [bool]$targetProperty.Value
        }
    }
    if ([bool]$Layout.CoreHardeningCertification -and
        [bool]$Layout.CodexTargetEnabled) {
        throw 'core-hardening certification metadata cannot enable the Codex target'
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
        @('gateway', $Layout.GatewayPath),
        @('hook', $Layout.HookPath),
        @('cli', $Layout.CLIPath),
        @('codex_launcher', $Layout.CodexTrustedHookLauncherPath),
        @('installer', $Layout.InstallerPath),
        @('module', $Layout.ModulePath)
    )) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $entry[1] -PathType Leaf) {
            $hashes[$entry[0]] = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $uninstalledAt = if ($Installed) { $null } else { [DateTime]::UtcNow.ToString('o') }
    $codexMachinePolicySha256 = ''
    $codexTrustedShellAttestationSha256 = ''
    $codexLauncherIdentity = [ordered]@{
        path = ''
        sha256 = ''
        signer_thumbprint = ''
        signer_subject = ''
        file_version = ''
    }
    if ($Installed) {
        if (-not [bool]$Layout.AgentApplicationControlAttested -and
            -not [bool]$Layout.CoreHardeningCertification) {
            throw 'cannot record installed enterprise metadata without agent application-control attestation'
        }
        if ([bool]$Layout.CodexTargetEnabled -and
            -not [bool]$Layout.CodexTrustedHookLauncherVerified) {
            throw 'cannot record installed enterprise metadata for an enabled Codex target without a verified fail-closed fixed hook launcher'
        }
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
        [void](Get-DefenseClawCodexTrustedShellAttestation -Layout $Layout)
        if ([bool]$Layout.CodexTrustedHookLauncherVerified) {
            $codexLauncherIdentity =
                Get-DefenseClawCodexTrustedHookLauncherIdentity -Layout $Layout
        }
        $codexTrustedShellAttestationSha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $Layout.CodexTrustedShellAttestationPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
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
        codex_machine_policy_parent = $Layout.CodexMachinePolicyDirectory
        codex_machine_policy_parent_preserved_on_uninstall = $true
        codex_machine_policy_path = $Layout.CodexMachinePolicyPath
        codex_managed_hooks_directory = $Layout.CodexManagedHooksDirectory
        codex_managed_hooks_state_path = $Layout.CodexManagedHooksStatePath
        codex_requirements_ownership_path = $Layout.CodexRequirementsOwnershipPath
        codex_requirements_acl_backup_path = $Layout.CodexRequirementsAclBackupPath
        agent_application_control_attestation_path = $Layout.CodexTrustedShellAttestationPath
        managed_hooks_teardown_journal_path = $Layout.ManagedHooksTeardownJournalPath
        codex_machine_policy_sha256 = $codexMachinePolicySha256
        agent_application_control_attestation_sha256 = $codexTrustedShellAttestationSha256
        codex_machine_policy_managed = [bool](
            $Installed -and $Layout.CodexTargetEnabled
        )
        codex_approved_client_enforced = [bool](
            $Installed -and $Layout.AgentApplicationControlAttested
        )
        codex_target_enabled = [bool](
            $Installed -and $Layout.CodexTargetEnabled
        )
        codex_trusted_hook_launcher_required = [bool](
            $Installed -and $Layout.CodexTargetEnabled
        )
        codex_trusted_hook_launcher_verified = [bool](
            $Installed -and $Layout.CodexTrustedHookLauncherVerified
        )
        codex_trusted_hook_launcher_path = [string]$codexLauncherIdentity.path
        codex_trusted_hook_launcher_sha256 = [string]$codexLauncherIdentity.sha256
        codex_trusted_hook_launcher_signer_thumbprint = [string]$codexLauncherIdentity.signer_thumbprint
        codex_trusted_hook_launcher_signer_subject = [string]$codexLauncherIdentity.signer_subject
        codex_trusted_hook_launcher_file_version = [string]$codexLauncherIdentity.file_version
        codex_launcher_application_control_bound = [bool](
            $Installed -and
            $Layout.AgentApplicationControlAttested -and
            $Layout.CodexTrustedHookLauncherVerified
        )
        stock_codex_client_paths_blocked = [bool](
            $Installed -and
            $Layout.AgentApplicationControlAttested -and
            $Layout.CodexTrustedHookLauncherVerified
        )
        codex_trusted_hook_launcher_prerequisite = $script:CodexTrustedHookLauncherPrerequisite
        stock_codex_supported = $false
        claude_target_enabled = [bool](
            $Installed -and $Layout.ClaudeTargetEnabled
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
            $Layout.AgentApplicationControlAttested -and
            (-not $Layout.ClaudeTargetEnabled -or
                $Layout.ClaudeEffectivePolicyVerified) -and
            (-not $Layout.CodexTargetEnabled -or
                $Layout.CodexTrustedHookLauncherVerified)
        )
        security_complete = [bool](
            $Installed -and
            $Layout.AgentApplicationControlAttested -and
            (-not $Layout.ClaudeTargetEnabled -or
                $Layout.ClaudeEffectivePolicyVerified) -and
            (-not $Layout.CodexTargetEnabled -or
                $Layout.CodexTrustedHookLauncherVerified)
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
}

function Assert-DefenseClawOwnedServiceOrAbsent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedGatewayPath,
        [string]$ExpectedManifestPath,
        [switch]$Guardian
    )
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
    else {
        '"{0}"' -f $ExpectedGatewayPath
    }
    $ownedImage = [string]::Equals($image, $expectedImage, [StringComparison]::OrdinalIgnoreCase)
    if (-not $ownedImage) {
        throw "refusing to replace foreign Windows service $Name with ImagePath $image"
    }
    $objectName = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue -LiteralPath $key -Name ObjectName)
    $expectedAccount = if ($Guardian) { 'LocalSystem' } else { "NT SERVICE\$Name" }
    if (-not [string]::Equals($objectName, $expectedAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to replace service $Name owned by unexpected account $objectName"
    }
}

function New-DefenseClawTransaction {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$IncludeCodexMachineState,
        [switch]$ManagedHooksTeardownPrepared,
        [switch]$PreserveManagedHooksTeardownJournal
    )
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath) {
        throw 'refusing to open a lifecycle transaction while protected recovery state already exists'
    }
    $id = [Guid]::NewGuid().ToString('N')
    $directory = Assert-DefenseClawDescendant `
        -Path (Microsoft.PowerShell.Management\Join-Path $Layout.TransactionsDirectory $id) `
        -Root $Layout.StateRoot `
        -Label 'transaction directory'
    New-DefenseClawDirectory -Path $directory
    $services = [Collections.Generic.List[object]]::new()
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        $service = Microsoft.PowerShell.Management\Get-Service `
            -Name $name `
            -ErrorAction SilentlyContinue
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
            services = $services
            service_activation_phase = 'quiesced'
            certification_codex_home = [string]$Layout.CertificationCodexHome
            core_hardening_certification = [bool](
                $Layout.CoreHardeningCertification
            )
            created_at = [DateTime]::UtcNow.ToString('o')
        }
        Write-DefenseClawJsonAtomic `
            -Value $quiescingIntent `
            -Path $Layout.PendingPath
        $quiescingIntentPublished = $true

        # Disabled start neutralizes boot activation and any failure restart
        # already queued by SCM. Gateway is disabled first so a crash cannot
        # leave it boot-active while guardian was demoted by this transaction.
        foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
            $service = $services |
                Microsoft.PowerShell.Core\Where-Object {
                    [string]::Equals(
                        [string]$_.name,
                        $name,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                } |
                Microsoft.PowerShell.Core\Select-Object -First 1
            if ($null -ne $service -and [bool]$service.existed) {
                Set-DefenseClawServiceStartMode -Name $name -StartMode 4
            }
        }

        # Quiesce the only LocalSystem writer before reading any shared or
        # managed file preimage. Stop-Service waits for process exit, so an
        # in-flight guardian reconciliation cannot straddle the snapshot.
        Stop-DefenseClawService -Name $GuardianServiceName
        Stop-DefenseClawService -Name $GatewayServiceName
        $servicesQuiescedAt = [DateTime]::UtcNow.ToString('o')
        $quiescingIntent['services_disabled_and_stopped_at'] =
            $servicesQuiescedAt
        # This second durable intent is the only authority for amortizing the
        # canonical 60-second SCM failure-restart drain window.
        Write-DefenseClawJsonAtomic `
            -Value $quiescingIntent `
            -Path $Layout.PendingPath

        $files = [Collections.Generic.List[object]]::new()
    $destinations = [Collections.Generic.List[string]]::new()
    foreach ($destination in @(
        $Layout.GatewayPath,
        $Layout.HookPath,
        $Layout.CLIPath,
        $Layout.CodexTrustedHookLauncherPath,
        $Layout.ConfigPath,
        $Layout.ManifestPath,
        $Layout.InstallerPath,
        $Layout.ModulePath,
        $Layout.MetadataPath,
        $Layout.CodexTrustedShellAttestationPath
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
        -LiteralPath $Layout.CodexTrustedShellAttestationPath `
        -PathType Leaf
    $priorApplicationControlAttested = $false
    $priorClaudeEffectivePolicyVerified = $false
    $priorCodexTrustedHookLauncherVerified = $false
    if ($priorAttestationExists) {
        $priorAttestation = Get-DefenseClawCodexTrustedShellAttestation `
            -Layout $Layout
        $priorApplicationControlAttested = [bool](
            $priorAttestation.agent_application_control_enforced
        )
        $priorClaudeEffectivePolicyVerified = [bool](
            $priorAttestation.claude_effective_policy_verified
        )
        $priorCodexTrustedHookLauncherVerified = [bool](
            $priorAttestation.codex_trusted_hook_launcher_verified
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
        service_activation_phase = 'quiesced'
        services_disabled_and_stopped_at = $servicesQuiescedAt
        certification_codex_home = [string]$Layout.CertificationCodexHome
        core_hardening_certification = [bool]$Layout.CoreHardeningCertification
        agent_application_control_attested = [bool]$priorApplicationControlAttested
        claude_effective_policy_verified = [bool]$priorClaudeEffectivePolicyVerified
        codex_trusted_hook_launcher_verified = [bool]$priorCodexTrustedHookLauncherVerified
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
        files = $files
        services = $services
        created_shared_directories = @()
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
                    $GuardianServiceName
                )) {
                    $service = $services |
                        Microsoft.PowerShell.Core\Where-Object {
                            [string]::Equals(
                                [string]$_.name,
                                $name,
                                [StringComparison]::OrdinalIgnoreCase
                            )
                        } |
                        Microsoft.PowerShell.Core\Select-Object -First 1
                    if ($null -ne $service -and [bool]$service.existed) {
                        Set-DefenseClawServiceStartMode `
                            -Name $name `
                            -StartMode 4
                    }
                }
                Stop-DefenseClawService -Name $GuardianServiceName
                Stop-DefenseClawService -Name $GatewayServiceName
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
        try {
            # Remove partial preimages first. If pending cleanup then fails, a
            # retained quiescing intent safely tolerates an already-absent
            # transaction directory and can repeat service restoration.
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
        if ($cleanupErrors.Count -gt 0) {
            throw "transaction snapshot failed ($($snapshotError.Exception.Message)); prior service state was restored but protected quiescing cleanup failed and recovery was retained: $($cleanupErrors -join '; ')"
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
        $service = Microsoft.PowerShell.Management\Get-Service `
            -Name $name `
            -ErrorAction SilentlyContinue
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

function Get-DefenseClawCodexTrustedHookLauncherIdentity {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = Resolve-DefenseClawFullPath `
        -Path $Layout.CodexTrustedHookLauncherPath `
        -MustExist `
        -Leaf
    Assert-DefenseClawNoReparsePath -Path $path
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        [string]::IsNullOrWhiteSpace(
            [string]$signature.SignerCertificate.Thumbprint
        )) {
        throw "protected Codex trusted launcher has no valid Authenticode signer: $path"
    }
    $item = Microsoft.PowerShell.Management\Get-Item `
        -LiteralPath $path `
        -Force
    return [ordered]@{
        path = $path
        sha256 = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $path `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        signer_thumbprint = (
            [string]$signature.SignerCertificate.Thumbprint
        ).ToLowerInvariant()
        signer_subject = [string]$signature.SignerCertificate.Subject
        file_version = [string]$item.VersionInfo.FileVersion
    }
}

function Get-DefenseClawCodexTrustedShellAttestation {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $path = [IO.Path]::GetFullPath(
        $Layout.CodexTrustedShellAttestationPath
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
        $enforced.Value -isnot [bool] -or
        (-not [bool]$enforced.Value -and
            -not [bool]$Layout.CoreHardeningCertification)) {
        throw 'agent application-control evidence does not assert enforcement outside exact core-hardening certification scope'
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
    if ([string]$attestation.codex_trusted_hook_launcher_prerequisite -cne
        $script:CodexTrustedHookLauncherPrerequisite) {
        throw 'agent application-control attestation records an unknown Codex trusted-hook-launcher prerequisite'
    }
    $launcherVerified = $attestation.PSObject.Properties[
        'codex_trusted_hook_launcher_verified'
    ]
    if ($null -eq $launcherVerified -or
        $launcherVerified.Value -isnot [bool]) {
        throw 'agent application-control attestation is missing the Codex trusted-hook-launcher verification result'
    }
    $launcherPath = $attestation.PSObject.Properties[
        'codex_trusted_hook_launcher_path'
    ]
    $launcherHash = $attestation.PSObject.Properties[
        'codex_trusted_hook_launcher_sha256'
    ]
    $launcherSigner = $attestation.PSObject.Properties[
        'codex_trusted_hook_launcher_signer_thumbprint'
    ]
    $launcherVersion = $attestation.PSObject.Properties[
        'codex_trusted_hook_launcher_file_version'
    ]
    if ([bool]$launcherVerified.Value) {
        $launcherAppControl = $attestation.PSObject.Properties[
            'codex_launcher_application_control_bound'
        ]
        $stockPathsBlocked = $attestation.PSObject.Properties[
            'stock_codex_client_paths_blocked'
        ]
        if (-not [bool]$enforced.Value -or
            $null -eq $launcherAppControl -or
            $launcherAppControl.Value -isnot [bool] -or
            -not [bool]$launcherAppControl.Value -or
            $null -eq $stockPathsBlocked -or
            $stockPathsBlocked.Value -isnot [bool] -or
            -not [bool]$stockPathsBlocked.Value) {
            throw 'Codex launcher evidence is not bound to application control that blocks stock client paths'
        }
        if ($null -eq $launcherPath -or
            $null -eq $launcherHash -or
            $null -eq $launcherSigner -or
            $null -eq $launcherVersion -or
            [string]$launcherHash.Value -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$launcherSigner.Value -cnotmatch '^[0-9a-f]{40,128}$') {
            throw 'Codex trusted-hook-launcher evidence has an invalid protected artifact identity'
        }
        $recordedLauncherPath = [IO.Path]::GetFullPath(
            [string]$launcherPath.Value
        ).TrimEnd('\')
        if (-not [string]::Equals(
            $recordedLauncherPath,
            [IO.Path]::GetFullPath(
                $Layout.CodexTrustedHookLauncherPath
            ).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'Codex trusted-hook-launcher evidence points outside the exact protected install path'
        }
        $actualLauncher = Get-DefenseClawCodexTrustedHookLauncherIdentity `
            -Layout $Layout
        if ([string]$actualLauncher.sha256 -cne
                [string]$launcherHash.Value -or
            [string]$actualLauncher.signer_thumbprint -cne
                [string]$launcherSigner.Value -or
            [string]$actualLauncher.file_version -cne
                [string]$launcherVersion.Value) {
            throw 'protected Codex trusted-hook-launcher artifact identity drift'
        }
    }
    else {
        foreach ($property in @(
            $launcherPath,
            $launcherHash,
            $launcherSigner,
            $launcherVersion
        )) {
            if ($null -ne $property -and
                -not [string]::IsNullOrEmpty([string]$property.Value)) {
                throw 'unverified Codex launcher evidence unexpectedly records a protected artifact identity'
            }
        }
        foreach ($booleanName in @(
            'codex_launcher_application_control_bound',
            'stock_codex_client_paths_blocked'
        )) {
            $property = $attestation.PSObject.Properties[$booleanName]
            if ($null -ne $property -and
                ($property.Value -isnot [bool] -or
                    [bool]$property.Value)) {
                throw "unverified Codex launcher evidence has invalid $booleanName"
            }
        }
    }
    $stockCodexSupported = $attestation.PSObject.Properties[
        'stock_codex_supported'
    ]
    if ($null -eq $stockCodexSupported -or
        $stockCodexSupported.Value -isnot [bool] -or
        [bool]$stockCodexSupported.Value) {
        throw 'agent application-control attestation must reject stock Codex clients whose hook-launch failures are non-blocking'
    }
    if ([string]$attestation.attested_by_sid -notmatch '^S-\d-\d+(?:-\d+)+$') {
        throw 'agent application-control attestation contains an invalid administrator SID'
    }
    try {
        $attestedAt = [DateTime]::Parse(
            [string]$attestation.attested_at,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        if ($attestedAt.Kind -eq [DateTimeKind]::Unspecified) {
            throw 'timestamp has no timezone'
        }
    }
    catch {
        throw "agent application-control attestation contains an invalid timestamp: $($_.Exception.Message)"
    }
    return $attestation
}

function Write-DefenseClawCodexTrustedShellAttestation {
    param([Parameter(Mandatory)][hashtable]$Layout)
    if (-not [bool]$Layout.AgentApplicationControlAttested -and
        -not [bool]$Layout.CoreHardeningCertification) {
        throw 'managed-enterprise mode requires explicit agent application-control attestation'
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
    $launcherIdentity = [ordered]@{
        path = ''
        sha256 = ''
        signer_thumbprint = ''
        signer_subject = ''
        file_version = ''
    }
    if ([bool]$Layout.CodexTrustedHookLauncherVerified) {
        $launcherIdentity = Get-DefenseClawCodexTrustedHookLauncherIdentity `
            -Layout $Layout
    }
    Write-DefenseClawJsonAtomic -Value ([ordered]@{
        schema_version = $script:AgentApplicationControlAttestationSchemaVersion
        agent_application_control_enforced = [bool]$Layout.AgentApplicationControlAttested
        prerequisite = $script:AgentApplicationControlPrerequisite
        approved_agent_clients_enforced = [bool]$Layout.AgentApplicationControlAttested
        minimum_claude_version = '2.1.152'
        claude_effective_policy_verified = [bool]$Layout.ClaudeEffectivePolicyVerified
        claude_effective_policy_manifest_sha256 = $claudeManifestHash
        codex_trusted_hook_launcher_prerequisite = $script:CodexTrustedHookLauncherPrerequisite
        codex_trusted_hook_launcher_verified = [bool]$Layout.CodexTrustedHookLauncherVerified
        codex_trusted_hook_launcher_path = [string]$launcherIdentity.path
        codex_trusted_hook_launcher_sha256 = [string]$launcherIdentity.sha256
        codex_trusted_hook_launcher_signer_thumbprint = [string]$launcherIdentity.signer_thumbprint
        codex_trusted_hook_launcher_signer_subject = [string]$launcherIdentity.signer_subject
        codex_trusted_hook_launcher_file_version = [string]$launcherIdentity.file_version
        codex_launcher_application_control_bound = [bool](
            $Layout.AgentApplicationControlAttested -and
            $Layout.CodexTrustedHookLauncherVerified
        )
        stock_codex_client_paths_blocked = [bool](
            $Layout.AgentApplicationControlAttested -and
            $Layout.CodexTrustedHookLauncherVerified
        )
        stock_codex_supported = $false
        attested_by_sid = [string]$identity.User.Value
        attested_at = [DateTime]::UtcNow.ToString('o')
        certification_required = $true
    }) -Path $Layout.CodexTrustedShellAttestationPath
    [void](Get-DefenseClawCodexTrustedShellAttestation -Layout $Layout)
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
    # A retained snapshot may be recovered after a reboot or after the final
    # validated activation step. Disable every live owned service before the
    # first stop or file restore. Besides preventing boot activation, disabled
    # start makes any already queued SCM failure restart fail closed.
    foreach ($name in @(
        [string]$snapshot.gateway_service,
        [string]$snapshot.guardian_service
    )) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @([string]$snapshot.guardian_service, [string]$snapshot.gateway_service)) {
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
            Install-DefenseClawFileAtomic -Source $backup -Destination $destination
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
    $snapshotLauncherVerified = $snapshot.PSObject.Properties[
        'codex_trusted_hook_launcher_verified'
    ]
    if ($null -eq $snapshotApplicationControl -or
        $snapshotApplicationControl.Value -isnot [bool] -or
        $null -eq $snapshotClaudeEffective -or
        $snapshotClaudeEffective.Value -isnot [bool] -or
        $null -eq $snapshotLauncherVerified -or
        $snapshotLauncherVerified.Value -isnot [bool]) {
        throw 'pending transaction has invalid application-control, Claude-policy, or trusted-hook-launcher evidence state'
    }
    $Layout.AgentApplicationControlAttested = [bool](
        $snapshotApplicationControl.Value
    )
    $Layout.ClaudeEffectivePolicyVerified = [bool](
        $snapshotClaudeEffective.Value
    )
    $Layout.CodexTrustedHookLauncherVerified = [bool](
        $snapshotLauncherVerified.Value
    )
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.CodexTrustedShellAttestationPath `
        -PathType Leaf) {
        $restoredAttestation = Get-DefenseClawCodexTrustedShellAttestation `
            -Layout $Layout
        if ([bool]$restoredAttestation.agent_application_control_enforced -ne
            [bool]$Layout.AgentApplicationControlAttested) {
            throw 'restored application-control evidence does not match the transaction snapshot'
        }
        if ([bool]$restoredAttestation.codex_trusted_hook_launcher_verified -ne
            [bool]$Layout.CodexTrustedHookLauncherVerified) {
            throw 'restored trusted-hook-launcher evidence does not match the transaction snapshot'
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
            -GatewayPath $Layout.GatewayPath `
            -ManifestPath $Layout.ManifestPath `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayLogPath $Layout.GatewayLogPath `
            -GuardianLogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified `
            -DeferAutomaticStart
        Set-DefenseClawManagedAcls -Layout $Layout -GatewayServiceName ([string]$snapshot.gateway_service)
    }
    foreach ($service in $snapshot.services) {
        if (-not [bool]$service.existed) {
            Remove-DefenseClawService -Name ([string]$service.name)
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
    if ($existing.Count -ne 2) {
        throw 'refusing to reactivate a partially restored managed service pair'
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if ([bool]$states[$name].existed) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($GuardianServiceName, $GatewayServiceName)) {
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

function Complete-DefenseClawTransaction {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][hashtable]$Layout
    )
    $directory = [IO.Path]::GetDirectoryName($SnapshotPath)
    Assert-DefenseClawDescendant -Path $directory -Root $Layout.StateRoot -Label 'completed transaction' | Microsoft.PowerShell.Core\Out-Null
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath -PathType Leaf) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Layout.PendingPath -Force
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $directory -PathType Container) {
        Assert-DefenseClawNoReparsePath -Path $directory
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $directory -Recurse -Force
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
    if ($services.Count -ne 2) {
        throw 'pending lifecycle quiescing intent must record exactly two services'
    }
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
        if ($name -notin @($GatewayServiceName, $GuardianServiceName) -or
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
    # A process/reboot recovery never trusts elapsed wall time from the prior
    # process. Reestablish both disabled+stopped, publish a fresh durable
    # quiescence point, and drain the complete failure-action window.
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            Set-DefenseClawServiceStartMode -Name $name -StartMode 4
        }
    }
    foreach ($name in @($GuardianServiceName, $GatewayServiceName)) {
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
}

function Recover-DefenseClawPendingTransaction {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.PendingPath -PathType Leaf)) {
        return
    }
    Assert-DefenseClawNoReparsePath -Path $Layout.PendingPath
    $pending = Microsoft.PowerShell.Management\Get-Content -LiteralPath $Layout.PendingPath -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $phase = $pending.PSObject.Properties['phase']
    if ($null -ne $phase) {
        if ([string]$phase.Value -cne 'quiescing') {
            throw "pending lifecycle record has unsupported phase $($phase.Value)"
        }
        Recover-DefenseClawQuiescingIntent `
            -Intent $pending `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        return
    }
    $snapshotPath = [string]$pending.snapshot
    [void](Restore-DefenseClawTransactionWithManagedHooksRollback `
        -SnapshotPath $snapshotPath `
        -Layout $Layout)
    Complete-DefenseClawTransaction -SnapshotPath $snapshotPath -Layout $Layout
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
        'DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED',
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
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED',
            $(if ([bool]$Layout.CodexTrustedHookLauncherVerified) { '1' } else { $null }),
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
        $output = & $gateway @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -and -not $AllowFailure) {
            throw "defenseclaw-gateway exited $exitCode for '$($Arguments -join ' ')': $(($output | Microsoft.PowerShell.Utility\Out-String).Trim())"
        }
        if ($Capture) {
            return [ordered]@{
                exit_code = $exitCode
                output = @($output)
            }
        }
        return $exitCode
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
    if ([int]$probe.exit_code -ne 0 -or -not [bool]$report.ok) {
        $detail = if (-not [string]::IsNullOrWhiteSpace([string]$report.error)) {
            [string]$report.error
        }
        else {
            (($probe.output | Microsoft.PowerShell.Utility\Out-String).Trim())
        }
        throw "Codex requirements $Action failed: $detail"
    }
    if ($Action -in @('inspect', 'reconcile', 'verify')) {
        if ([string]$report.agent_application_control_prerequisite -cne
            $script:AgentApplicationControlPrerequisite) {
            throw "Codex requirements $Action reported an unknown agent application-control prerequisite"
        }
        if ([string]$report.codex_trusted_hook_launcher_prerequisite -cne
            $script:CodexTrustedHookLauncherPrerequisite) {
            throw "Codex requirements $Action reported an unknown trusted-hook-launcher prerequisite"
        }
        foreach ($booleanName in @(
            'agent_application_control_enforced',
            'approved_client_enforced',
            'approved_agent_clients_enforced',
            'claude_target_enabled',
            'claude_effective_policy_verified',
            'codex_target_enabled',
            'codex_trusted_hook_launcher_required',
            'codex_trusted_hook_launcher_verified',
            'stock_codex_supported',
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
                [bool]$Layout.AgentApplicationControlAttested -or
            (-not [bool]$report.agent_application_control_enforced -and
                -not [bool]$Layout.CoreHardeningCertification)) {
            throw "Codex requirements $Action approved-agent application-control result disagrees with protected deployment evidence"
        }
        if ([bool]$report.stock_codex_supported) {
            throw "Codex requirements $Action incorrectly certifies a stock Codex client with non-blocking hook-launch failures"
        }
        if ([bool]$report.codex_trusted_hook_launcher_required -ne
            [bool]$report.codex_target_enabled) {
            throw "Codex requirements $Action trusted-hook-launcher requirement does not match manifest target enablement"
        }
        if ([bool]$report.codex_trusted_hook_launcher_verified -ne
            [bool]$Layout.CodexTrustedHookLauncherVerified) {
            throw "Codex requirements $Action trusted-hook-launcher evidence does not match the protected deployment attestation"
        }
        if ([bool]$report.claude_effective_policy_verified -ne
            [bool]$Layout.ClaudeEffectivePolicyVerified) {
            throw "Codex requirements $Action Claude effective-policy evidence does not match the protected live verification result"
        }
        $expectedSecurityComplete = [bool](
            $Layout.AgentApplicationControlAttested -and
            (-not [bool]$report.claude_target_enabled -or
                [bool]$Layout.ClaudeEffectivePolicyVerified) -and
            (-not [bool]$report.codex_target_enabled -or
                [bool]$Layout.CodexTrustedHookLauncherVerified)
        )
        if ([bool]$report.security_complete -ne $expectedSecurityComplete) {
            throw "Codex requirements $Action aggregate security result disagrees with protected evidence"
        }
        $Layout.ClaudeTargetEnabled = [bool]$report.claude_target_enabled
        $Layout.CodexTargetEnabled = [bool]$report.codex_target_enabled
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
            throw 'verified-absent Codex removal unexpectedly retains a DefenseClaw ACL preimage'
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
    if ([int]$report.schema_version -ne 1) {
        throw "unsupported managed-hook teardown report schema: $($report.schema_version)"
    }
    if ([string]$report.action -cne $Action) {
        throw "managed-hook teardown report action mismatch: $($report.action)"
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
        'succeeded_count',
        'verified_clean_count',
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
            throw "managed-hook teardown did not complete target $($row.connector)@$($row.sid)"
        }
    }
    if ([int]$probe.exit_code -ne 0 -or -not [bool]$report.ok) {
        $detail = if (-not [string]::IsNullOrWhiteSpace([string]$report.error)) {
            [string]$report.error
        }
        else {
            (($probe.output | Microsoft.PowerShell.Utility\Out-String).Trim())
        }
        throw "managed-hook teardown $Action failed: $detail"
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
            $verifiedInstalled.Value -is [bool] -or
            [Convert]::ToInt64($verifiedInstalled.Value) -ne
                $counts.target_count) {
            throw 'managed-hook teardown rollback did not reinstall and verify every original target'
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
    $gatewayReady = $false
    $guardianReady = $false
    do {
        $gatewayReady = Test-DefenseClawGatewayReady -Layout $Layout -GatewayServiceName $GatewayServiceName
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
    throw "enterprise readiness timed out: gateway_ready=$gatewayReady guardian_ready=$guardianReady"
}

function Assert-DefenseClawServiceConfiguration {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedImage,
        [Parameter(Mandatory)][string]$ExpectedAccount,
        [Parameter(Mandatory)][string]$ExpectedDisplayName,
        [Parameter(Mandatory)][int]$ExpectedSidType,
        [Parameter(Mandatory)][string[]]$ExpectedPrivileges,
        [Parameter(Mandatory)][string[]]$ExpectedEnvironment,
        [ValidateSet(2, 3, 4)]
        [int]$ExpectedStartMode = 2
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
    if ([int]$properties.Start -ne $ExpectedStartMode) {
        throw "service $Name startup mode drift: $($properties.Start), expected $ExpectedStartMode"
    }
    if ([int]$properties.ErrorControl -ne 1) {
        throw "service $Name ErrorControl drift: $($properties.ErrorControl)"
    }
    if ([int]$properties.DelayedAutoStart -ne 0) {
        throw "service $Name DelayedAutoStart drift: $($properties.DelayedAutoStart)"
    }
    foreach ($dependencyProperty in @('DependOnService', 'DependOnGroup', 'Group')) {
        $dependency = $properties.PSObject.Properties[$dependencyProperty]
        if ($null -ne $dependency -and
            @($dependency.Value | Microsoft.PowerShell.Core\Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            throw "service $Name has an unexpected $dependencyProperty dependency"
        }
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
    $actualEnvironment = @($properties.Environment | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ } | Microsoft.PowerShell.Utility\Sort-Object)
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
    if (-not [string]::Equals($actualSDDL, $script:ServiceSDDL, [StringComparison]::OrdinalIgnoreCase)) {
        throw "service $Name DACL drift: $actualSDDL"
    }
}

function Assert-DefenseClawManagedServiceConfigurations {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$PendingTransaction,
        [switch]$ServicingTransaction
    )
    if ($PendingTransaction -and $ServicingTransaction) {
        throw 'service configuration assertion cannot be both pending-live and servicing'
    }
    $expectedStartMode = if ($ServicingTransaction) {
        4
    }
    elseif ($PendingTransaction) {
        3
    }
    else {
        2
    }
    $gatewayEnvironment = [string[]]@(
        Get-DefenseClawServiceEnvironmentValues `
            -Name $GatewayServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GatewayLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified
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
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified
    )
    Assert-DefenseClawServiceConfiguration `
        -Name $GatewayServiceName `
        -ExpectedImage ('"{0}"' -f $Layout.GatewayPath) `
        -ExpectedAccount "NT SERVICE\$GatewayServiceName" `
        -ExpectedDisplayName 'DefenseClaw Enterprise Gateway' `
        -ExpectedSidType 3 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment $gatewayEnvironment `
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
}

function New-DefenseClawRequiredRights {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Admin', 'Install', 'ServiceInstall', 'State', 'Config', 'MachinePolicy', 'AuthorizationDirectory', 'AuthorizationFile', 'Runtime')]
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
        @('agent_application_control_attestation_path', $Layout.CodexTrustedShellAttestationPath)
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
        (-not [bool]$applicationControlProperty.Value -and
            -not [bool]$Layout.CoreHardeningCertification) -or
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
    foreach ($booleanName in @(
        'codex_trusted_hook_launcher_verified',
        'stock_codex_supported'
    )) {
        $property = $metadata.PSObject.Properties[$booleanName]
        if ($null -eq $property -or $property.Value -isnot [bool]) {
            throw "deployment metadata is missing boolean $booleanName"
        }
    }
    $launcherRequired = $metadata.PSObject.Properties[
        'codex_trusted_hook_launcher_required'
    ]
    if ($null -eq $launcherRequired -or
        $launcherRequired.Value -isnot [bool] -or
        [bool]$launcherRequired.Value -ne $codexTargetEnabled -or
        [string]$metadata.codex_trusted_hook_launcher_prerequisite -cne
            $script:CodexTrustedHookLauncherPrerequisite -or
        [bool]$metadata.stock_codex_supported) {
        throw 'deployment metadata Codex trusted-hook-launcher requirement does not match target enablement'
    }
    if ($codexTargetEnabled -and
        -not [bool]$metadata.codex_trusted_hook_launcher_verified) {
        throw 'deployment metadata enables Codex without verified fail-closed fixed hook-launcher evidence'
    }
    if ($codexTargetEnabled) {
        $launcherIdentity = Get-DefenseClawCodexTrustedHookLauncherIdentity `
            -Layout $Layout
        $recordedLauncherPath = [IO.Path]::GetFullPath(
            [string]$metadata.codex_trusted_hook_launcher_path
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $recordedLauncherPath,
                [string]$launcherIdentity.path,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [string]$metadata.codex_trusted_hook_launcher_sha256 -cne
                [string]$launcherIdentity.sha256 -or
            [string]$metadata.codex_trusted_hook_launcher_signer_thumbprint -cne
                [string]$launcherIdentity.signer_thumbprint -or
            [string]$metadata.codex_trusted_hook_launcher_file_version -cne
                [string]$launcherIdentity.file_version -or
            $metadata.PSObject.Properties[
                'codex_launcher_application_control_bound'
            ].Value -isnot [bool] -or
            -not [bool]$metadata.codex_launcher_application_control_bound -or
            $metadata.PSObject.Properties[
                'stock_codex_client_paths_blocked'
            ].Value -isnot [bool] -or
            -not [bool]$metadata.stock_codex_client_paths_blocked -or
            $null -eq $metadata.hashes.PSObject.Properties[
                'codex_launcher'
            ] -or
            [string]$metadata.hashes.codex_launcher -cne
                [string]$launcherIdentity.sha256) {
            throw 'deployment metadata does not authenticate the exact protected Codex launcher artifact'
        }
    }
    else {
        foreach ($propertyName in @(
            'codex_trusted_hook_launcher_path',
            'codex_trusted_hook_launcher_sha256',
            'codex_trusted_hook_launcher_signer_thumbprint',
            'codex_trusted_hook_launcher_file_version'
        )) {
            if (-not [string]::IsNullOrEmpty(
                [string]$metadata.$propertyName
            )) {
                throw 'Codex-disabled deployment metadata unexpectedly authenticates a launcher artifact'
            }
        }
        foreach ($propertyName in @(
            'codex_launcher_application_control_bound',
            'stock_codex_client_paths_blocked'
        )) {
            $property = $metadata.PSObject.Properties[$propertyName]
            if ($null -eq $property -or
                $property.Value -isnot [bool] -or
                [bool]$property.Value) {
                throw "Codex-disabled deployment metadata has invalid $propertyName"
            }
        }
        if (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexTrustedHookLauncherPath) {
            throw 'Codex-disabled deployment retains a protected launcher artifact'
        }
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
        [bool]$applicationControlProperty.Value -and
        (-not [bool]$claudeTargetProperty.Value -or
            [bool]$claudeEffectiveProperty.Value) -and
        (-not $codexTargetEnabled -or
            [bool]$metadata.codex_trusted_hook_launcher_verified)
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
    $attestation = Get-DefenseClawCodexTrustedShellAttestation -Layout $Layout
    if ([bool]$attestation.agent_application_control_enforced -ne
        [bool]$metadata.agent_application_control_enforced) {
        throw 'protected application-control evidence disagrees with deployment metadata'
    }
    if ([bool]$attestation.codex_trusted_hook_launcher_verified -ne
        [bool]$metadata.codex_trusted_hook_launcher_verified) {
        throw 'protected Codex trusted-hook-launcher evidence disagrees with deployment metadata'
    }
    if ([bool]$attestation.claude_effective_policy_verified -ne
        [bool]$metadata.claude_effective_policy_verified) {
        throw 'protected Claude effective-policy evidence disagrees with deployment metadata'
    }
    $Layout.AgentApplicationControlAttested = [bool](
        $applicationControlProperty.Value
    )
    $Layout.ClaudeTargetEnabled = [bool]$claudeTargetProperty.Value
    $Layout.ClaudeEffectivePolicyVerified = [bool](
        $attestation.claude_effective_policy_verified
    )
    $Layout.CodexTrustedHookLauncherVerified = [bool](
        $attestation.codex_trusted_hook_launcher_verified
    )
    $Layout.CodexTargetEnabled = $codexTargetEnabled
    $recordedAttestationHash = [string]$metadata.agent_application_control_attestation_sha256
    if ($recordedAttestationHash -cnotmatch '^[0-9a-f]{64}$') {
        throw 'deployment metadata contains an invalid agent application-control attestation SHA-256'
    }
    $actualAttestationHash = (
        Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $Layout.CodexTrustedShellAttestationPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actualAttestationHash -cne $recordedAttestationHash) {
        throw 'agent application-control attestation hash drift'
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
    $configRights = New-DefenseClawRequiredRights -Kind Config -GatewayServiceSID $gatewaySID
    $authorizationDirectoryRights = New-DefenseClawRequiredRights `
        -Kind AuthorizationDirectory `
        -GatewayServiceSID $gatewaySID
    $authorizationFileRights = New-DefenseClawRequiredRights `
        -Kind AuthorizationFile `
        -GatewayServiceSID $gatewaySID
    $runtimeRights = New-DefenseClawRequiredRights -Kind Runtime -GatewayServiceSID $gatewaySID

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
        -Path $Layout.AgentDirectory `
        -AllowedWriterSIDs $adminWriters `
        -RequiredRights $installRights `
        -AllowUsersRead
    Assert-DefenseClawPathAcl `
        -Path $Layout.GatewayPath `
        -AllowedWriterSIDs $adminWriters `
        -RequiredRights $serviceInstallRights `
        -AllowUsersRead
    foreach ($path in @($Layout.HookPath, $Layout.InstallerPath, $Layout.ModulePath)) {
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
    if ($codexTargetEnabled) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.CodexTrustedHookLauncherPath `
            -AllowedWriterSIDs $adminWriters `
            -RequiredRights $installRights `
            -AllowUsersRead
    }
    $adminOnlyPaths = [Collections.Generic.List[string]]::new()
    foreach ($path in @(
        $Layout.ConfigDirectory,
        $Layout.GuardianDirectory,
        $Layout.InstallStateDirectory,
        $Layout.ManifestPath,
        $Layout.LogDirectory,
        $Layout.GuardianLogDirectory,
        $Layout.MetadataPath,
        $Layout.CodexTrustedShellAttestationPath
    )) {
        $adminOnlyPaths.Add([string]$path)
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
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $Layout.ManagedHooksTeardownJournalPath `
        -PathType Leaf) {
        Assert-DefenseClawPathAcl `
            -Path $Layout.ManagedHooksTeardownJournalPath `
            -AllowedWriterSIDs $adminWriters `
            -AllowedReaderSIDs $adminReaders `
            -RequiredRights $adminRights `
            -RejectUntrustedRead
    }
    Assert-DefenseClawPathAcl `
        -Path $Layout.StateRoot `
        -AllowedWriterSIDs $adminWriters `
        -AllowedReaderSIDs $gatewayReaders `
        -RequiredRights $stateRights `
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

    foreach ($requiredHash in @('gateway', 'hook', 'installer', 'module')) {
        if ($null -eq $metadata.hashes.PSObject.Properties[$requiredHash]) {
            throw "deployment metadata is missing required artifact hash: $requiredHash"
        }
    }
    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $Layout.CLIPath -PathType Leaf) -and
        $null -eq $metadata.hashes.PSObject.Properties['cli']) {
        throw 'deployment metadata is missing the installed CLI artifact hash'
    }
    foreach ($property in $metadata.hashes.PSObject.Properties) {
        $path = switch ($property.Name) {
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
        "DEFENSECLAW_WINDOWS_SERVICE_LOG=$($Layout.GatewayLogPath)"
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
    if ([bool]$Layout.CodexTrustedHookLauncherVerified) {
        $gatewayEnvironment = [string[]]@(
            $gatewayEnvironment +
                'DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1'
        )
        $guardianEnvironment = [string[]]@(
            $guardianEnvironment +
                'DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1'
        )
    }
    Assert-DefenseClawServiceConfiguration `
        -Name $GatewayServiceName `
        -ExpectedImage ('"{0}"' -f $Layout.GatewayPath) `
        -ExpectedAccount "NT SERVICE\$GatewayServiceName" `
        -ExpectedDisplayName 'DefenseClaw Enterprise Gateway' `
        -ExpectedSidType 3 `
        -ExpectedPrivileges @('SeChangeNotifyPrivilege') `
        -ExpectedEnvironment $gatewayEnvironment `
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
    Assert-DefenseClawInstalledConfig -Layout $Layout -GatewayServiceName $GatewayServiceName
    [void](Invoke-DefenseClawCodexRequirementsCommand `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))

    if ($RequireReadiness) {
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
    }
}

function Get-DefenseClawArtifactPath {
    param(
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][string]$Name
    )
    $path = switch ($Name) {
        'gateway' { $Layout.GatewayPath }
        'hook' { $Layout.HookPath }
        'cli' { $Layout.CLIPath }
        'codex_launcher' { $Layout.CodexTrustedHookLauncherPath }
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
        [string[]]$ReplacedArtifacts = @()
    )
    foreach ($required in @('gateway', 'hook', 'installer', 'module')) {
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
            throw "refusing to bless pre-existing artifact hash drift during repair/upgrade: $($property.Name)"
        }
    }
}

function Get-DefenseClawLifecycleSources {
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$GatewayBinary,
        [string]$HookBinary,
        [string]$CLIBinary,
        [string]$CodexTrustedHookLauncherBinary,
        [string]$Config,
        [string]$Manifest,
        [string]$InstallerSource,
        [string]$ModuleSource,
        [switch]$AllowUnsigned
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
        foreach ($required in @(
            @('GatewayBinary', $GatewayBinary),
            @('HookBinary', $HookBinary),
            @('Config', $Config),
            @('Manifest', $Manifest)
        )) {
            if ([string]::IsNullOrWhiteSpace([string]$required[1])) {
                throw "Install requires -$($required[0])"
            }
        }
    }
    if ($Action -eq 'Upgrade' -and
        ([string]::IsNullOrWhiteSpace($GatewayBinary) -or
        [string]::IsNullOrWhiteSpace($HookBinary))) {
        throw 'Upgrade requires -GatewayBinary and -HookBinary'
    }

    foreach ($entry in @(
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
    if (-not [string]::IsNullOrWhiteSpace($CodexTrustedHookLauncherBinary)) {
        # The launcher is an upstream agent trust boundary, not a
        # DefenseClaw test build. Certification-mode signature relaxation must
        # never apply to it.
        $sources['codex_launcher'] = Get-DefenseClawSourceDescriptor `
            -Path $CodexTrustedHookLauncherBinary `
            -Label 'approved fail-closed Codex launcher executable' `
            -Authenticode
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
        return $null
    }
    return $null
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
    $guardianState = Get-DefenseClawServiceState -Name $GuardianServiceName
    $gatewayReady = $false
    $guardianReady = $false
    $codexRequirementsReady = $false
    $codexRequirementsDisposition = $null
    $codexTargetEnabled = $false
    $claudeTargetEnabled = [bool]$Layout.ClaudeTargetEnabled
    $claudeEffectivePolicyVerified = [bool](
        $Layout.ClaudeEffectivePolicyVerified
    )
    $codexTrustedHookLauncherVerified = [bool](
        $Layout.CodexTrustedHookLauncherVerified
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
            if ($null -ne $guardianReport -and $null -ne $guardianReport.state) {
                $generation = [string]$guardianReport.state.updated_at
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
                $claudeTargetEnabled = [bool]$codexReport.claude_target_enabled
                $claudeEffectivePolicyVerified = [bool](
                    $codexReport.claude_effective_policy_verified
                )
                $codexTrustedHookLauncherVerified = [bool](
                    $codexReport.codex_trusted_hook_launcher_verified
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
            $guardianState -eq 'running' -and
            $gatewayReady -and
            $guardianReady -and
            $codexRequirementsReady -and
            -not $pending -and
            $errors.Count -eq 0
    }
    else {
        $gatewayState -eq 'absent' -and
            $guardianState -eq 'absent' -and
            -not $pending -and
            $errors.Count -eq 0
    }
    $externalSecuritySatisfied = [bool](
        $installed -and
        $Layout.AgentApplicationControlAttested -and
        (-not $claudeTargetEnabled -or
            $claudeEffectivePolicyVerified) -and
        (-not $codexTargetEnabled -or
            $codexTrustedHookLauncherVerified)
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
        guardian_service = $GuardianServiceName
        gateway_service_state = $gatewayState
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
        codex_trusted_hook_launcher_required = [bool]$codexTargetEnabled
        codex_trusted_hook_launcher_verified = [bool]$codexTrustedHookLauncherVerified
        codex_trusted_hook_launcher_prerequisite = $script:CodexTrustedHookLauncherPrerequisite
        codex_trusted_hook_launcher_path = $Layout.CodexTrustedHookLauncherPath
        stock_codex_supported = $false
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
    $priorGeneration = if ($null -ne $priorReport -and $null -ne $priorReport.state) {
        [string]$priorReport.state.updated_at
    }
    else {
        ''
    }
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
    do {
        $report = Get-DefenseClawGuardianStatusReport `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName
        if ($null -ne $report -and [bool]$report.ok -and $null -ne $report.state) {
            $generation = [string]$report.state.updated_at
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
            }
        }
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "LocalSystem guardian restarted but did not publish a fresh reconcile within $TimeoutSeconds seconds"
}

function Assert-DefenseClawManagedInstallTree {
    param([Parameter(Mandatory)][hashtable]$Layout)
    $allowedDirectories = @(
        $Layout.BinDirectory,
        $Layout.AgentDirectory,
        $Layout.LibexecDirectory
    )
    $allowedFiles = @(
        $Layout.GatewayPath,
        $Layout.HookPath,
        $Layout.CLIPath,
        $Layout.CodexTrustedHookLauncherPath,
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
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
        [IO.Path]::GetFullPath($Layout.AgentDirectory).TrimEnd('\'),
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
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
        [Parameter(Mandatory)][string]$GuardianServiceName
    )
    $intent = Get-DefenseClawStatePurgeIntent `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -Required
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
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
        [switch]$Purge
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
    foreach ($name in @($GatewayServiceName, $GuardianServiceName)) {
        if (Test-DefenseClawServiceExists -Name $name) {
            throw "committed-uninstall cleanup refused while service exists: $name"
        }
    }
    Remove-DefenseClawCommittedEmptyInstallRoot -Layout $Layout
    [void](Remove-DefenseClawCommittedManagedHooksTeardownJournal `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName)
    if ($Purge) {
        [void](Publish-DefenseClawStatePurgeIntent `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName)
        $result = Complete-DefenseClawStatePurge `
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

function Invoke-DefenseClawInstallLikeLifecycle {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Layout,
        [Parameter(Mandatory)][hashtable]$Sources,
        [Parameter(Mandatory)][string]$GatewayServiceName,
        [Parameter(Mandatory)][string]$GuardianServiceName,
        [switch]$RefreshApplicationControlAttestation,
        [switch]$RefreshClaudeEffectivePolicyAttestation,
        [switch]$RefreshCodexTrustedHookLauncherAttestation,
        [switch]$NoStart
    )
    $metadata = Get-DefenseClawDeploymentMetadata -Layout $Layout
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
                'hook',
                'cli',
                'codex_launcher',
                'installer',
                'module'
            )
        })
        Assert-DefenseClawRecordedArtifactHashes `
            -Metadata $metadata `
            -Layout $Layout `
            -ReplacedArtifacts $replaced
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
    $snapshot = New-DefenseClawTransaction `
        -Layout $Layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName `
        -IncludeCodexMachineState:$priorCodexTargetEnabled
    try {
        Stop-DefenseClawService -Name $GuardianServiceName
        Stop-DefenseClawService -Name $GatewayServiceName
        foreach ($name in $Sources.Keys) {
            $destination = Get-DefenseClawArtifactPath -Layout $Layout -Name $name
            Install-DefenseClawSourceDescriptor `
                -Source $Sources[$name] `
                -Destination $destination
        }
        foreach ($requiredPath in @(
            $Layout.GatewayPath,
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

        $attestationNeedsRefresh = [bool]$RefreshApplicationControlAttestation
        $attestationExists = Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $Layout.CodexTrustedShellAttestationPath `
            -PathType Leaf
        if (-not $attestationNeedsRefresh -and $attestationExists) {
            [void](Get-DefenseClawCodexTrustedShellAttestation -Layout $Layout)
        }
        Set-DefenseClawManagedServices `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -GatewayPath $Layout.GatewayPath `
            -ManifestPath $Layout.ManifestPath `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayLogPath $Layout.GatewayLogPath `
            -GuardianLogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified `
            -DeferAutomaticStart
        Set-DefenseClawManagedCoreAcls `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName
        $targetReport = Invoke-DefenseClawCodexRequirementsCommand `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -Action inspect
        if ([bool]$Layout.CoreHardeningCertification -and
            [bool]$Layout.CodexTargetEnabled) {
            throw (
                'Core-hardening certification is Claude-only and refuses an ' +
                'enabled Codex target in the protected manifest'
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
        if ($RefreshCodexTrustedHookLauncherAttestation -and
            -not [bool]$Layout.CodexTargetEnabled) {
            throw '-AttestCodexTrustedHookLauncher requires at least one enabled Codex target in the protected manifest'
        }
        if (-not [bool]$Layout.CodexTargetEnabled) {
            if ([bool]$Layout.CodexTrustedHookLauncherVerified) {
                $Layout.CodexTrustedHookLauncherVerified = $false
                $attestationNeedsRefresh = $true
            }
            if (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $Layout.CodexTrustedHookLauncherPath `
                -PathType Leaf) {
                Assert-DefenseClawNoReparsePath `
                    -Path $Layout.CodexTrustedHookLauncherPath
                Microsoft.PowerShell.Management\Remove-Item `
                    -LiteralPath $Layout.CodexTrustedHookLauncherPath `
                    -Force
            }
        }
        if ($attestationNeedsRefresh -or -not $attestationExists) {
            Write-DefenseClawCodexTrustedShellAttestation -Layout $Layout
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
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified
        Set-DefenseClawServiceEnvironment `
            -Name $GuardianServiceName `
            -RuntimeDirectory $Layout.RuntimeDirectory `
            -ConfigPath $Layout.ConfigPath `
            -AuthorizationDirectory $Layout.AuthorizationDirectory `
            -GatewayServiceName $GatewayServiceName `
            -LogPath $Layout.GuardianLogPath `
            -AgentApplicationControlAttested:$Layout.AgentApplicationControlAttested `
            -ClaudeEffectivePolicyVerified:$Layout.ClaudeEffectivePolicyVerified `
            -CodexTrustedHookLauncherVerified:$Layout.CodexTrustedHookLauncherVerified
        if ([bool]$Layout.CodexTargetEnabled) {
            if (-not [bool]$Layout.AgentApplicationControlAttested) {
                throw 'an enabled Codex target is forbidden in unattested core-hardening certification mode'
            }
            if (-not [bool]$Layout.CodexTrustedHookLauncherVerified) {
                throw 'an enabled Codex target requires a verified protected fail-closed launcher artifact before any Codex machine state is touched'
            }
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
                -Name $GatewayServiceName `
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
            Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout
        }
        catch {
            throw "$Action failed ($($operationError.Exception.Message)); rollback also failed and pending recovery was retained: $($_.Exception.Message)"
        }
        throw $operationError
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
        -GuardianServiceName $GuardianServiceName
    Assert-DefenseClawManagedInstallTree -Layout $Layout
    Assert-DefenseClawRecordedArtifactHashes `
        -Metadata $metadata `
        -Layout $Layout
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
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $Layout.CodexTrustedShellAttestationPath `
            -Force
        # Re-authenticate every service field and both ACL surfaces at the
        # deletion boundary. A concurrent administrative drift or same-name
        # takeover fails closed before either sc.exe delete.
        Assert-DefenseClawManagedServiceConfigurations `
            -Layout $Layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName `
            -ServicingTransaction
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
                    -Layout $Layout
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
        -Purge:$Purge
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
        -Layout $Layout
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
        [string]$GatewayBinary,
        [string]$HookBinary,
        [string]$CLIBinary,
        [string]$CodexTrustedHookLauncherBinary,
        [string]$Config,
        [string]$Manifest,
        [string]$InstallRoot = (Microsoft.PowerShell.Management\Join-Path $script:ProgramFiles 'Cisco\DefenseClaw'),
        [string]$StateRoot = (Microsoft.PowerShell.Management\Join-Path $script:ProgramData 'Cisco\DefenseClaw'),
        [string]$GatewayServiceName = 'DefenseClawGateway',
        [string]$GuardianServiceName = 'DefenseClawHookGuardian',
        [string]$CertificationCodexHome,
        [switch]$CoreHardeningCertification,
        [switch]$NoStart,
        [switch]$Purge,
        [switch]$AllowUnsigned,
        [switch]$AttestAgentApplicationControl,
        [switch]$AttestClaudeEffectivePolicy,
        [switch]$AttestCodexTrustedHookLauncher,
        [string]$InstallerSource,
        [string]$ModuleSource,
        [int]$SelfUninstallCallerPID
    )
    Assert-DefenseClawServiceName -Name $GatewayServiceName
    Assert-DefenseClawServiceName -Name $GuardianServiceName
    if ([string]::Equals($GatewayServiceName, $GuardianServiceName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'gateway and guardian Windows service names must be distinct'
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
        -GuardianServiceName $GuardianServiceName
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
    if ($AllowUnsigned -and $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-AllowUnsigned is valid only with Install, Upgrade, or Repair'
    }
    if ($CoreHardeningCertification -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-CoreHardeningCertification is valid only with Install, Upgrade, or Repair'
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedCertificationCodexHome) -and
        $Action -in @('Install', 'Upgrade', 'Repair') -and
        -not $AllowUnsigned) {
        throw '-CertificationCodexHome requires -AllowUnsigned for every Install, Upgrade, or Repair'
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
    if ($AttestCodexTrustedHookLauncher -and
        $Action -notin @('Install', 'Upgrade', 'Repair')) {
        throw '-AttestCodexTrustedHookLauncher is valid only with Install, Upgrade, or Repair'
    }
    $codexLauncherBinaryProvided = -not [string]::IsNullOrWhiteSpace(
        $CodexTrustedHookLauncherBinary
    )
    if ($Action -in @('Install', 'Upgrade', 'Repair') -and
        [bool]$AttestCodexTrustedHookLauncher -ne
            [bool]$codexLauncherBinaryProvided) {
        throw '-AttestCodexTrustedHookLauncher and -CodexTrustedHookLauncherBinary must be supplied together'
    }
    if ($CoreHardeningCertification -and
        ($AttestAgentApplicationControl -or
            $AttestClaudeEffectivePolicy -or
            $AttestCodexTrustedHookLauncher -or
            $codexLauncherBinaryProvided)) {
        throw (
            '-CoreHardeningCertification cannot be combined with production ' +
            'application-control, Claude-policy, or trusted-launcher attestations'
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
        -AgentApplicationControlAttested:$AttestAgentApplicationControl `
        -CodexTrustedHookLauncherVerified:$AttestCodexTrustedHookLauncher

    # Keep the authoritative current/global/GUID drive identity adjacent to
    # the first managed metadata read, not only to caller argument parsing.
    Assert-DefenseClawLayoutVolumeIdentity `
        -Layout $layout `
        -GatewayServiceName $GatewayServiceName `
        -GuardianServiceName $GuardianServiceName
    if ((Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $layout.MetadataPath `
            -PathType Leaf) -and
        ($Action -ne 'Status' -or (Test-DefenseClawAdministrator))) {
        # Protected metadata, not a caller-supplied certification path, is the
        # authority for continuing an existing core-hardening certification
        # deployment.
        [void](Get-DefenseClawDeploymentMetadata -Layout $layout)
    }
    $trustedShellAttestationExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $layout.CodexTrustedShellAttestationPath `
        -PathType Leaf
    if ($trustedShellAttestationExists -and
        ($Action -ne 'Status' -or (Test-DefenseClawAdministrator))) {
        $existingApplicationControlAttestation =
            Get-DefenseClawCodexTrustedShellAttestation -Layout $layout
        $layout.AgentApplicationControlAttested = [bool](
            $existingApplicationControlAttestation.agent_application_control_enforced
        )
        $layout.ClaudeEffectivePolicyVerified = [bool](
            $existingApplicationControlAttestation.claude_effective_policy_verified
        )
        $layout.CodexTrustedHookLauncherVerified = [bool](
            $existingApplicationControlAttestation.codex_trusted_hook_launcher_verified
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
    if ($AttestCodexTrustedHookLauncher) {
        if ([bool]$layout.CoreHardeningCertification) {
            throw '-AttestCodexTrustedHookLauncher is forbidden in core-hardening certification mode'
        }
        $layout.CodexTrustedHookLauncherVerified = $true
    }
    if ($Action -eq 'Install' -and
        -not $AttestAgentApplicationControl -and
        -not [bool]$layout.CoreHardeningCertification) {
        throw 'Install requires -AttestAgentApplicationControl after WDAC or AppLocker rules block unapproved agent runtimes; this does not certify Codex hook execution'
    }
    if ($Action -in @('Upgrade', 'Repair') -and
        -not $trustedShellAttestationExists -and
        -not $AttestAgentApplicationControl -and
        -not [bool]$layout.CoreHardeningCertification) {
        throw "$Action requires -AttestAgentApplicationControl to migrate this deployment"
    }

    if ($Action -eq 'Status') {
        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
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
            -GuardianServiceName $GuardianServiceName
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
        -GatewayBinary $GatewayBinary `
        -HookBinary $HookBinary `
        -CLIBinary $CLIBinary `
        -CodexTrustedHookLauncherBinary $CodexTrustedHookLauncherBinary `
        -Config $Config `
        -Manifest $Manifest `
        -InstallerSource $InstallerSource `
        -ModuleSource $ModuleSource `
        -AllowUnsigned:$AllowUnsigned

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
                Recover-DefenseClawPendingTransaction `
                    -Layout $layout `
                    -GatewayServiceName $GatewayServiceName `
                    -GuardianServiceName $GuardianServiceName
            }
            return Invoke-DefenseClawReconcileLifecycle `
                -Layout $layout `
                -GatewayServiceName $GatewayServiceName `
                -GuardianServiceName $GuardianServiceName
        }

        Assert-DefenseClawLayoutVolumeIdentity `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName
        Initialize-DefenseClawManagedRoot `
            -Path $layout.InstallRoot `
            -Label 'InstallRoot' `
            -RequiredBase $script:ProgramFiles `
            -AllowUsersRead
        Initialize-DefenseClawManagedRoot `
            -Path $layout.StateRoot `
            -Label 'StateRoot' `
            -RequiredBase $script:ProgramData
        New-DefenseClawLayoutDirectories -Layout $layout
        Recover-DefenseClawPendingTransaction `
            -Layout $layout `
            -GatewayServiceName $GatewayServiceName `
            -GuardianServiceName $GuardianServiceName

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
                $AttestClaudeEffectivePolicy -or
                $AttestCodexTrustedHookLauncher
            ) `
            -RefreshClaudeEffectivePolicyAttestation:$AttestClaudeEffectivePolicy `
            -RefreshCodexTrustedHookLauncherAttestation:$AttestCodexTrustedHookLauncher `
            -NoStart:$NoStart
    }
    finally {
        Exit-DefenseClawLifecycleLock -Lock $lifecycleLock
    }
}

Microsoft.PowerShell.Core\Export-ModuleMember -Function Invoke-DefenseClawEnterpriseLifecycle
