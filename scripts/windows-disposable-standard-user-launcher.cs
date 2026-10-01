// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DefenseClaw
{
    // GitHub-hosted Windows runners deliberately disable UAC. A real local
    // standard-user logon is therefore the only honest way to exercise the
    // user-scope Setup lifecycle without weakening Setup's elevation gate.
    public static class DisposableStandardUserLauncher
    {
        private const uint LOGON_WITH_PROFILE = 0x00000001;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const short SW_HIDE = 0;
        private const uint SEM_FAILCRITICALERRORS = 0x0001;
        private const uint SEM_NOGPFAULTERRORBOX = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int TokenTypeInformation = 8;
        private const int TokenElevation = 20;
        private const int TokenPrimary = 1;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int KEY_QUERY_VALUE = 0x0001;
        private const int KEY_NOTIFY = 0x0010;
        private const int REG_NOTIFY_CHANGE_NAME = 0x00000001;
        private const int REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
        private const int REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000;
        private const string ProfileListPath =
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
        private const int JobObjectAssociateCompletionPortInformation = 7;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
        private const uint INFINITE = 0xFFFFFFFF;

        // Deliberately excludes WINSTA_EXITWINDOWS. The child may enumerate
        // and render on the existing interactive station, but cannot log the
        // runner session off.
        private const int InteractiveWindowStationAccess =
            0x0001 | // WINSTA_ENUMDESKTOPS
            0x0002 | // WINSTA_READATTRIBUTES
            0x0004 | // WINSTA_ACCESSCLIPBOARD
            0x0008 | // WINSTA_CREATEDESKTOP
            0x0010 | // WINSTA_WRITEATTRIBUTES
            0x0020 | // WINSTA_ACCESSGLOBALATOMS
            0x0100 | // WINSTA_ENUMERATE
            0x0200;  // WINSTA_READSCREEN

        // Deliberately excludes journal, hook-control, and switch-desktop
        // rights. Setup and its same-user driver only need to create, inspect,
        // enumerate, and message windows on the existing default desktop.
        private const int InteractiveDesktopAccess =
            0x0001 | // DESKTOP_READOBJECTS
            0x0002 | // DESKTOP_CREATEWINDOW
            0x0004 | // DESKTOP_CREATEMENU
            0x0040 | // DESKTOP_ENUMERATE
            0x0080;  // DESKTOP_WRITEOBJECTS

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CreateProcessWithLogonW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessWithLogon(
            string username,
            string domain,
            IntPtr password,
            uint logonFlags,
            string applicationName,
            StringBuilder commandLine,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "GetTokenInformation",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformationElevation(
            IntPtr token,
            int informationClass,
            out TOKEN_ELEVATION information,
            int informationLength,
            out int returnLength);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "GetTokenInformation",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformationInteger(
            IntPtr token,
            int informationClass,
            out int information,
            int informationLength,
            out int returnLength);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateJobObjectW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            int informationClass,
            out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
            uint informationLength,
            out uint returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT
        {
            public IntPtr CompletionKey;
            public IntPtr CompletionPort;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateIoCompletionPort(
            IntPtr fileHandle,
            IntPtr existingPort,
            UIntPtr completionKey,
            uint concurrentThreads);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetQueuedCompletionStatus(
            IntPtr port,
            out uint bytesTransferred,
            out IntPtr completionKey,
            out IntPtr overlapped,
            uint milliseconds);

        // LUID is two DWORDs natively, so it sits at offset 4, not 8.
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW(string systemName, string name, out long luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr token,
            [MarshalAs(UnmanagedType.Bool)] bool disableAll,
            ref TOKEN_PRIVILEGES newState,
            int bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegOpenKeyExW(
            IntPtr key,
            string subKey,
            int options,
            int desired,
            out IntPtr result);

        [DllImport("advapi32.dll")]
        private static extern int RegNotifyChangeKeyValue(
            IntPtr key,
            [MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
            int filter,
            IntPtr eventHandle,
            [MarshalAs(UnmanagedType.Bool)] bool asynchronous);

        [DllImport("advapi32.dll")]
        private static extern int RegCloseKey(IntPtr key);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint access,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process,
            out long creationTime,
            out long exitTime,
            out long kernelTime,
            out long userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll")]
        private static extern uint SetErrorMode(uint mode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll")]
        private static extern IntPtr GetThreadDesktop(uint threadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetUserObjectSecurity(
            IntPtr userObject,
            ref uint securityInformation,
            [Out] byte[] securityDescriptor,
            uint descriptorLength,
            out uint neededLength);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetUserObjectSecurity(
            IntPtr userObject,
            ref uint securityInformation,
            byte[] securityDescriptor);

        public static InteractiveDesktopGrant GrantInteractiveDesktop(string accountSid)
        {
            if (String.IsNullOrWhiteSpace(accountSid))
            {
                throw new ArgumentException("disposable account SID is required", "accountSid");
            }
            SecurityIdentifier sid = new SecurityIdentifier(accountSid);
            IntPtr station = GetProcessWindowStation();
            IntPtr desktop = GetThreadDesktop(GetCurrentThreadId());
            if (station == IntPtr.Zero || desktop == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "could not resolve the current interactive window station and desktop");
            }

            byte[] originalStation = ReadUserObjectDacl(station, "window station");
            byte[] originalDesktop = ReadUserObjectDacl(desktop, "desktop");
            bool stationChanged = false;
            try
            {
                WriteUserObjectDacl(
                    station,
                    AddAllowAce(originalStation, sid, InteractiveWindowStationAccess),
                    "window station");
                stationChanged = true;
                WriteUserObjectDacl(
                    desktop,
                    AddAllowAce(originalDesktop, sid, InteractiveDesktopAccess),
                    "desktop");
                return new InteractiveDesktopGrant(
                    station,
                    desktop,
                    originalStation,
                    originalDesktop);
            }
            catch
            {
                if (stationChanged)
                {
                    WriteUserObjectDacl(station, originalStation, "window station rollback");
                }
                throw;
            }
        }

        public static DisposableStandardUserProcess Start(
            string username,
            string domain,
            SecureString password,
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string expectedUserSid)
        {
            if (String.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("disposable account name is required", "username");
            }
            if (password == null) throw new ArgumentNullException("password");
            if (String.IsNullOrWhiteSpace(applicationPath) ||
                !System.IO.Path.IsPathRooted(applicationPath))
            {
                throw new ArgumentException("application path must be absolute", "applicationPath");
            }
            if (String.IsNullOrWhiteSpace(workingDirectory) ||
                !System.IO.Path.IsPathRooted(workingDirectory))
            {
                throw new ArgumentException("working directory must be absolute", "workingDirectory");
            }
            SecurityIdentifier expectedSid = new SecurityIdentifier(expectedUserSid);

            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            IntPtr passwordBuffer = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            IntPtr port = IntPtr.Zero;
            Process process = null;
            bool resumed = false;
            try
            {
                passwordBuffer = Marshal.SecureStringToGlobalAllocUnicode(password);
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                // A console-backed PowerShell receives valid CONIN$/CONOUT$
                // standard handles during process initialization. Hide its
                // window, and leave lpDesktop null so the child inherits the
                // exact station/desktop whose ACL GrantInteractiveDesktop
                // updated instead of assuming the hosted runner uses Default.
                startupInfo.dwFlags = STARTF_USESHOWWINDOW;
                startupInfo.wShowWindow = SW_HIDE;
                bool created;
                int createError = 0;
                uint previousErrorMode = SetErrorMode(
                    SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
                try
                {
                    created = CreateProcessWithLogon(
                        username,
                        domain,
                        passwordBuffer,
                        LOGON_WITH_PROFILE,
                        applicationPath,
                        BuildCommandLine(applicationPath, arguments),
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        IntPtr.Zero,
                        workingDirectory,
                        ref startupInfo,
                        out processInfo);
                    if (!created) createError = Marshal.GetLastWin32Error();
                }
                finally
                {
                    SetErrorMode(previousErrorMode);
                }
                if (!created)
                {
                    throw new Win32Exception(
                        createError,
                        "CreateProcessWithLogonW failed for the disposable standard user");
                }

                token = OpenToken(processInfo.hProcess);
                ValidateChildToken(token, processInfo.dwProcessId, expectedSid);
                job = CreateKillOnCloseJob(out port);
                if (!AssignProcessToJobObject(job, processInfo.hProcess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "AssignProcessToJobObject failed for the disposable standard-user harness");
                }
                process = Process.GetProcessById(checked((int)processInfo.dwProcessId));
                uint previousSuspendCount = ResumeThread(processInfo.hThread);
                if (previousSuspendCount == UInt32.MaxValue)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                }
                if (previousSuspendCount != 1)
                {
                    throw new InvalidOperationException(
                        "disposable standard-user primary thread had unexpected suspend count " +
                        previousSuspendCount);
                }
                resumed = true;
                DisposableStandardUserProcess result =
                    new DisposableStandardUserProcess(
                        process,
                        processInfo.hProcess,
                        job,
                        port,
                        previousSuspendCount);
                process = null;
                processInfo.hProcess = IntPtr.Zero;
                job = IntPtr.Zero;
                port = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (!resumed && processInfo.hProcess != IntPtr.Zero)
                {
                    TerminateProcess(processInfo.hProcess, 1603);
                }
                if (token != IntPtr.Zero) CloseHandle(token);
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (port != IntPtr.Zero) CloseHandle(port);
                if (process != null) process.Dispose();
                if (passwordBuffer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer);
                }
            }
        }

        private static IntPtr OpenToken(IntPtr process)
        {
            IntPtr token;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }
            return token;
        }

        private static void ValidateChildToken(
            IntPtr token,
            uint processId,
            SecurityIdentifier expectedSid)
        {
            TOKEN_ELEVATION elevation;
            int returned;
            if (!GetTokenInformationElevation(
                token,
                TokenElevation,
                out elevation,
                Marshal.SizeOf(typeof(TOKEN_ELEVATION)),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetTokenInformation(TokenElevation) failed for disposable user");
            }
            if (elevation.TokenIsElevated != 0)
            {
                throw new InvalidOperationException(
                    "disposable standard-user harness token is elevated");
            }

            int tokenType;
            if (!GetTokenInformationInteger(
                token,
                TokenTypeInformation,
                out tokenType,
                sizeof(int),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetTokenInformation(TokenType) failed for disposable user");
            }
            if (tokenType != TokenPrimary)
            {
                throw new InvalidOperationException(
                    "disposable standard-user harness did not receive a primary token");
            }

            using (WindowsIdentity identity = new WindowsIdentity(token))
            {
                if (identity.User == null || !identity.User.Equals(expectedSid))
                {
                    throw new InvalidOperationException(
                        "disposable standard-user harness token has an unexpected user SID");
                }
                SecurityIdentifier administrators =
                    new SecurityIdentifier("S-1-5-32-544");
                SecurityIdentifier interactive = new SecurityIdentifier("S-1-5-4");
                bool hasAdministratorSid = false;
                bool hasInteractiveSid = false;
                if (identity.Groups != null)
                {
                    foreach (IdentityReference group in identity.Groups)
                    {
                        SecurityIdentifier groupSid = group as SecurityIdentifier;
                        if (groupSid == null)
                        {
                            groupSid = (SecurityIdentifier)group.Translate(
                                typeof(SecurityIdentifier));
                        }
                        if (groupSid.Equals(interactive))
                        {
                            hasInteractiveSid = true;
                        }
                        if (groupSid.Equals(administrators))
                        {
                            hasAdministratorSid = true;
                        }
                    }
                }
                if (hasAdministratorSid)
                {
                    throw new InvalidOperationException(
                        "disposable standard-user harness token is an administrator");
                }
                if (!hasInteractiveSid)
                {
                    throw new InvalidOperationException(
                        "disposable standard-user harness token is not interactive");
                }
            }

            uint childSession;
            uint parentSession;
            if (!ProcessIdToSessionId(processId, out childSession) ||
                !ProcessIdToSessionId((uint)Process.GetCurrentProcess().Id, out parentSession))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "ProcessIdToSessionId failed for disposable user");
            }
            if (childSession != parentSession || childSession == 0)
            {
                throw new InvalidOperationException(
                    "disposable standard-user harness is not in the current interactive session");
            }
        }

        // The completion port is attached before any process joins, so it
        // sees every member's exit (see WaitForJobMembersToExit).
        private static IntPtr CreateKillOnCloseJob(out IntPtr port)
        {
            port = IntPtr.Zero;
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW failed");
            }
            try
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION information =
                    new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                information.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "SetInformationJobObject failed");
                }
                IntPtr created = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
                if (created == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateIoCompletionPort failed");
                }
                port = created;
                JOBOBJECT_ASSOCIATE_COMPLETION_PORT association = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT();
                association.CompletionKey = job;
                association.CompletionPort = port;
                if (!SetInformationJobObject(
                    job,
                    JobObjectAssociateCompletionPortInformation,
                    ref association,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "SetInformationJobObject(completion port) failed");
                }
                IntPtr result = job;
                job = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (job != IntPtr.Zero)
                {
                    CloseHandle(job);
                    if (port != IntPtr.Zero) CloseHandle(port);
                    port = IntPtr.Zero;
                }
            }
        }

        private static uint GetActiveJobProcessCount(IntPtr job)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
            uint returned;
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                out information,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryInformationJobObject(active processes) failed");
            }
            if (returned < Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)))
            {
                throw new InvalidOperationException(
                    "QueryInformationJobObject(active processes) returned truncated data");
            }
            return information.ActiveProcesses;
        }

        // Returns once ActiveProcesses reaches zero. The completion port was
        // attached before the root resumed, so every member exit, including
        // the ACTIVE_PROCESS_ZERO packet for the last one, is queued there:
        // while the count is nonzero another packet is still to come, and
        // once it is zero no process can join the job again.
        private static void WaitForJobMembersToExit(IntPtr job, IntPtr port)
        {
            while (GetActiveJobProcessCount(job) != 0)
            {
                uint message;
                IntPtr key;
                IntPtr overlapped;
                if (!GetQueuedCompletionStatus(port, out message, out key, out overlapped, INFINITE))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetQueuedCompletionStatus failed for disposable standard-user job");
                }
            }
        }

        // The disposable user's processes grant the runner's administrator
        // token nothing in their default DACL, so opening one for its exit
        // event needs SeDebugPrivilege enabled, not merely present.
        private static void EnableDebugPrivilege()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken(adjust) failed");
            }
            try
            {
                TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES();
                privileges.PrivilegeCount = 1;
                privileges.Attributes = SE_PRIVILEGE_ENABLED;
                if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out privileges.Luid))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValueW failed");
                }
                bool adjusted = AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
                int error = Marshal.GetLastWin32Error();
                if (!adjusted || error == ERROR_NOT_ALL_ASSIGNED)
                {
                    throw new Win32Exception(error, "SeDebugPrivilege could not be enabled");
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }

        // Exit event for one exact process (PID plus creation time) that a
        // CIM sweep just terminated. A vanished or reused PID means the
        // original already exited.
        public static void WaitForExactProcessExit(int processId, DateTime creationUtc)
        {
            EnableDebugPrivilege();
            IntPtr process = OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                processId);
            if (process == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_INVALID_PARAMETER) return;
                throw new Win32Exception(
                    error,
                    "OpenProcess failed for exact-SID process " + processId);
            }
            try
            {
                long creation, exit, kernel, user;
                if (!GetProcessTimes(process, out creation, out exit, out kernel, out user))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetProcessTimes failed for exact-SID process " + processId);
                }
                long delta = DateTime.FromFileTimeUtc(creation).Ticks - creationUtc.ToUniversalTime().Ticks;
                if (Math.Abs(delta) >= TimeSpan.TicksPerMillisecond) return;
                if (WaitForSingleObject(process, INFINITE) != WAIT_OBJECT_0)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "WaitForSingleObject failed for exact-SID process " + processId);
                }
            }
            finally
            {
                CloseHandle(process);
            }
        }

        private static byte[] ReadUserObjectDacl(IntPtr userObject, string label)
        {
            uint information = DACL_SECURITY_INFORMATION;
            uint needed;
            GetUserObjectSecurity(userObject, ref information, null, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (needed == 0 || error != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new Win32Exception(error, "GetUserObjectSecurity size failed for " + label);
            }
            byte[] descriptor = new byte[needed];
            if (!GetUserObjectSecurity(
                userObject,
                ref information,
                descriptor,
                (uint)descriptor.Length,
                out needed))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetUserObjectSecurity failed for " + label);
            }
            return descriptor;
        }

        private static void WriteUserObjectDacl(
            IntPtr userObject,
            byte[] descriptor,
            string label)
        {
            uint information = DACL_SECURITY_INFORMATION;
            if (!SetUserObjectSecurity(userObject, ref information, descriptor))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetUserObjectSecurity failed for " + label);
            }
        }

        private static byte[] AddAllowAce(
            byte[] descriptor,
            SecurityIdentifier sid,
            int accessMask)
        {
            RawSecurityDescriptor security = new RawSecurityDescriptor(descriptor, 0);
            RawAcl dacl = security.DiscretionaryAcl ??
                new RawAcl(GenericAcl.AclRevision, 1);
            int insertion = dacl.Count;
            for (int index = 0; index < dacl.Count; index++)
            {
                if ((dacl[index].AceFlags & AceFlags.Inherited) != 0)
                {
                    insertion = index;
                    break;
                }
            }
            dacl.InsertAce(
                insertion,
                new CommonAce(
                    AceFlags.None,
                    AceQualifier.AccessAllowed,
                    accessMask,
                    sid,
                    false,
                    null));
            security.DiscretionaryAcl = dacl;
            byte[] result = new byte[security.BinaryLength];
            security.GetBinaryForm(result, 0);
            return result;
        }

        private static StringBuilder BuildCommandLine(string applicationPath, string[] arguments)
        {
            StringBuilder commandLine = new StringBuilder(QuoteWindowsArgument(applicationPath));
            foreach (string argument in arguments ?? new string[0])
            {
                commandLine.Append(' ');
                commandLine.Append(QuoteWindowsArgument(argument));
            }
            // CreateProcessWithLogonW has a 1,024-character lpCommandLine
            // ceiling, unlike CreateProcessW's much larger limit. Reject an
            // unsafe harness shape before Windows reports an opaque logon
            // failure that looks like bad disposable-user credentials.
            if (commandLine.Length > 1024)
            {
                throw new ArgumentException(
                    "disposable standard-user command line exceeds the " +
                    "CreateProcessWithLogonW 1024-character limit");
            }
            return commandLine;
        }

        private static string QuoteWindowsArgument(string argument)
        {
            if (argument == null) throw new ArgumentNullException("argument");
            if (argument.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("Windows process arguments cannot contain NUL", "argument");
            }
            if (argument.Length == 0) return "\"\"";
            bool needsQuotes = false;
            foreach (char character in argument)
            {
                if (Char.IsWhiteSpace(character) || character == '"')
                {
                    needsQuotes = true;
                    break;
                }
            }
            if (!needsQuotes) return argument;

            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in argument)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(character);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        // Change notification on the account's ProfileList entry. The User
        // Profile Service records the unload there once it has released the
        // hive, so a caller arms the watch, checks Win32_UserProfile, and
        // waits for the next change instead of polling against a clock.
        // Returns null when no ProfileList entry exists.
        public static ProfileListWatch WatchProfileList(string accountSid)
        {
            SecurityIdentifier sid = new SecurityIdentifier(accountSid);
            IntPtr key;
            int status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                ProfileListPath + "\\" + sid.Value,
                0,
                KEY_QUERY_VALUE | KEY_NOTIFY,
                out key);
            if (status == ERROR_FILE_NOT_FOUND) return null;
            if (status != 0)
            {
                throw new Win32Exception(status, "RegOpenKeyExW failed for the disposable profile entry");
            }
            return new ProfileListWatch(key);
        }

        public sealed class ProfileListWatch : IDisposable
        {
            private IntPtr key;
            private readonly System.Threading.AutoResetEvent changed =
                new System.Threading.AutoResetEvent(false);

            internal ProfileListWatch(IntPtr key) { this.key = key; }

            // Arm before reading the state the change would invalidate.
            public void Arm()
            {
                if (key == IntPtr.Zero) throw new ObjectDisposedException("ProfileListWatch");
                int status = RegNotifyChangeKeyValue(
                    key,
                    true,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                    changed.SafeWaitHandle.DangerousGetHandle(),
                    true);
                if (status != 0)
                {
                    throw new Win32Exception(status, "RegNotifyChangeKeyValue failed for the disposable profile entry");
                }
            }

            // No wall-clock bound: the enclosing step timeout reports a
            // profile that never unloads.
            public void WaitForChange()
            {
                if (key == IntPtr.Zero) throw new ObjectDisposedException("ProfileListWatch");
                uint result = WaitForSingleObject(changed.SafeWaitHandle.DangerousGetHandle(), INFINITE);
                if (result != WAIT_OBJECT_0)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "WaitForSingleObject failed for the disposable profile entry");
                }
            }

            public void Dispose()
            {
                if (key != IntPtr.Zero)
                {
                    RegCloseKey(key);
                    key = IntPtr.Zero;
                }
                changed.Dispose();
            }
        }

        public sealed class InteractiveDesktopGrant : IDisposable
        {
            private readonly IntPtr station;
            private readonly IntPtr desktop;
            private readonly byte[] stationDescriptor;
            private readonly byte[] desktopDescriptor;
            private bool restored;

            internal InteractiveDesktopGrant(
                IntPtr station,
                IntPtr desktop,
                byte[] stationDescriptor,
                byte[] desktopDescriptor)
            {
                this.station = station;
                this.desktop = desktop;
                this.stationDescriptor = stationDescriptor;
                this.desktopDescriptor = desktopDescriptor;
            }

            public void Restore()
            {
                if (restored) return;
                Exception failure = null;
                try
                {
                    WriteUserObjectDacl(desktop, desktopDescriptor, "desktop restore");
                }
                catch (Exception error)
                {
                    failure = error;
                }
                try
                {
                    WriteUserObjectDacl(station, stationDescriptor, "window station restore");
                }
                catch (Exception error)
                {
                    failure = failure == null ? error :
                        new AggregateException(failure, error);
                }
                if (failure != null) throw failure;
                restored = true;
            }

            public void Dispose()
            {
                Restore();
            }
        }

        public sealed class DisposableStandardUserProcess : IDisposable
        {
            private readonly Process process;
            private readonly uint initialSuspendCount;
            private IntPtr processHandle;
            private IntPtr job;
            private IntPtr port;
            private bool disposed;

            internal DisposableStandardUserProcess(
                Process process,
                IntPtr processHandle,
                IntPtr job,
                IntPtr port,
                uint initialSuspendCount)
            {
                this.process = process;
                this.processHandle = processHandle;
                this.job = job;
                this.port = port;
                this.initialSuspendCount = initialSuspendCount;
            }

            public int Id { get { return process.Id; } }
            public bool HasExited { get { return WaitForNativeExit(0); } }
            public int ExitCode
            {
                get
                {
                    if (!WaitForNativeExit(0))
                    {
                        throw new InvalidOperationException("process has not exited");
                    }
                    return ReadNativeExitCode();
                }
            }

            public bool WaitForExit(int milliseconds)
            {
                return WaitForNativeExit(milliseconds);
            }

            public bool WaitForExitAndGetExitCode(int milliseconds, out int exitCode)
            {
                exitCode = 0;
                if (!WaitForNativeExit(milliseconds))
                {
                    return false;
                }
                exitCode = ReadNativeExitCode();
                return true;
            }

            private bool WaitForNativeExit(int milliseconds)
            {
                if (disposed || processHandle == IntPtr.Zero)
                {
                    throw new ObjectDisposedException("DisposableStandardUserProcess");
                }
                if (milliseconds < -1)
                {
                    throw new ArgumentOutOfRangeException("milliseconds");
                }
                uint timeout = milliseconds == -1 ? UInt32.MaxValue : checked((uint)milliseconds);
                uint result = WaitForSingleObject(processHandle, timeout);
                if (result == WAIT_OBJECT_0) return true;
                if (result == WAIT_TIMEOUT) return false;
                if (result == WAIT_FAILED)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "WaitForSingleObject failed for disposable standard-user process");
                }
                throw new InvalidOperationException(
                    "WaitForSingleObject returned unexpected status " + result);
            }

            private int ReadNativeExitCode()
            {
                uint exitCode;
                if (!GetExitCodeProcess(processHandle, out exitCode))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetExitCodeProcess failed for disposable standard-user process");
                }
                return unchecked((int)exitCode);
            }

            public uint ActiveProcessCount
            {
                get { return job == IntPtr.Zero ? 0 : GetActiveJobProcessCount(job); }
            }

            public string GetStartupDiagnostics()
            {
                StringBuilder diagnostic = new StringBuilder();
                diagnostic.Append("pid=").Append(process.Id);
                diagnostic.Append(" resume_previous_count=").Append(initialSuspendCount);
                try
                {
                    bool hasExited = WaitForNativeExit(0);
                    diagnostic.Append(" has_exited=").Append(hasExited);
                    if (hasExited)
                    {
                        diagnostic.Append(" exit_code=").Append(ReadNativeExitCode());
                        return diagnostic.ToString();
                    }
                    process.Refresh();
                    diagnostic.Append(" cpu_ms=").Append(
                        (long)process.TotalProcessorTime.TotalMilliseconds);
                    int emitted = 0;
                    foreach (ProcessThread thread in process.Threads)
                    {
                        if (emitted++ == 16)
                        {
                            diagnostic.Append(" threads=truncated");
                            break;
                        }
                        diagnostic.Append(" thread[").Append(thread.Id).Append("]=");
                        try
                        {
                            diagnostic.Append(thread.ThreadState);
                            if (thread.ThreadState == ThreadState.Wait)
                            {
                                diagnostic.Append('/').Append(thread.WaitReason);
                            }
                        }
                        catch (Exception error)
                        {
                            diagnostic.Append("unavailable(").Append(error.Message).Append(')');
                        }
                    }
                }
                catch (Exception error)
                {
                    diagnostic.Append(" inspection_error=").Append(error.Message);
                }
                return diagnostic.ToString();
            }

            // Closing a kill-on-close handle is not enough evidence for a
            // privileged caller to begin traversing child-writable paths. CI
            // explicitly terminates the job, waits on the job's completion
            // port until ActiveProcesses is zero, and only then releases the
            // handle. The enclosing step timeout bounds a host that cannot
            // kill its own job.
            public void TerminateAndDrain()
            {
                if (disposed) return;
                if (job != IntPtr.Zero)
                {
                    if (!TerminateJobObject(job, 1603))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "TerminateJobObject failed for disposable standard-user harness");
                    }
                    WaitForJobMembersToExit(job, port);
                    CloseHandle(job);
                    job = IntPtr.Zero;
                    CloseHandle(port);
                    port = IntPtr.Zero;
                }
                if (!WaitForNativeExit(-1))
                {
                    throw new InvalidOperationException(
                        "disposable standard-user root process did not exit after job termination");
                }
            }

            public void Terminate()
            {
                TerminateAndDrain();
            }

            public void Dispose()
            {
                if (disposed) return;
                try
                {
                    Terminate();
                }
                finally
                {
                    if (job != IntPtr.Zero)
                    {
                        CloseHandle(job);
                        job = IntPtr.Zero;
                    }
                    if (port != IntPtr.Zero)
                    {
                        CloseHandle(port);
                        port = IntPtr.Zero;
                    }
                    try
                    {
                        process.Dispose();
                    }
                    finally
                    {
                        if (processHandle != IntPtr.Zero)
                        {
                            CloseHandle(processHandle);
                            processHandle = IntPtr.Zero;
                        }
                        disposed = true;
                    }
                }
            }
        }
    }
}
