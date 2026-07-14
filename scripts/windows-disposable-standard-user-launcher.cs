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
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int TokenTypeInformation = 8;
        private const int TokenElevation = 20;
        private const int TokenPrimary = 1;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

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

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

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
            Process process = null;
            bool resumed = false;
            try
            {
                passwordBuffer = Marshal.SecureStringToGlobalAllocUnicode(password);
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.lpDesktop = @"winsta0\default";
                if (!CreateProcessWithLogon(
                    username,
                    domain,
                    passwordBuffer,
                    LOGON_WITH_PROFILE,
                    applicationPath,
                    BuildCommandLine(applicationPath, arguments),
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero,
                    workingDirectory,
                    ref startupInfo,
                    out processInfo))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "CreateProcessWithLogonW failed for the disposable standard user");
                }

                token = OpenToken(processInfo.hProcess);
                ValidateChildToken(token, processInfo.dwProcessId, expectedSid);
                job = CreateKillOnCloseJob();
                if (!AssignProcessToJobObject(job, processInfo.hProcess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "AssignProcessToJobObject failed for the disposable standard-user harness");
                }
                process = Process.GetProcessById(checked((int)processInfo.dwProcessId));
                if (ResumeThread(processInfo.hThread) == UInt32.MaxValue)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                }
                resumed = true;
                DisposableStandardUserProcess result =
                    new DisposableStandardUserProcess(process, job);
                process = null;
                job = IntPtr.Zero;
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
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    throw new InvalidOperationException(
                        "disposable standard-user harness token is an administrator");
                }
                SecurityIdentifier interactive = new SecurityIdentifier("S-1-5-4");
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
                            break;
                        }
                    }
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

        private static IntPtr CreateKillOnCloseJob()
        {
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
                IntPtr result = job;
                job = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (job != IntPtr.Zero) CloseHandle(job);
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
            private IntPtr job;
            private bool disposed;

            internal DisposableStandardUserProcess(Process process, IntPtr job)
            {
                this.process = process;
                this.job = job;
            }

            public int Id { get { return process.Id; } }
            public bool HasExited { get { return process.HasExited; } }
            public int ExitCode { get { return process.ExitCode; } }

            public bool WaitForExit(int milliseconds)
            {
                return process.WaitForExit(milliseconds);
            }

            public uint ActiveProcessCount
            {
                get { return job == IntPtr.Zero ? 0 : GetActiveJobProcessCount(job); }
            }

            // Closing a kill-on-close handle is not enough evidence for a
            // privileged caller to begin traversing child-writable paths. CI
            // explicitly terminates the job, observes ActiveProcesses reach
            // zero, and only then releases the handle.
            public void TerminateAndDrain(int milliseconds)
            {
                if (disposed) return;
                if (milliseconds < 1)
                {
                    throw new ArgumentOutOfRangeException("milliseconds");
                }
                if (job != IntPtr.Zero)
                {
                    if (!TerminateJobObject(job, 1603))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "TerminateJobObject failed for disposable standard-user harness");
                    }
                    Stopwatch timer = Stopwatch.StartNew();
                    while (GetActiveJobProcessCount(job) != 0)
                    {
                        if (timer.ElapsedMilliseconds >= milliseconds)
                        {
                            throw new InvalidOperationException(
                                "disposable standard-user job retained active processes after termination");
                        }
                        System.Threading.Thread.Sleep(50);
                    }
                    CloseHandle(job);
                    job = IntPtr.Zero;
                }
                if (!process.HasExited && !process.WaitForExit(milliseconds))
                {
                    throw new InvalidOperationException(
                        "disposable standard-user root process did not exit after job termination");
                }
            }

            public void Terminate()
            {
                TerminateAndDrain(30000);
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
                    process.Dispose();
                    disposed = true;
                }
            }
        }
    }
}
