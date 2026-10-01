// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw
{
    // Runs one CI command inside its own job object.
    //
    // Standard output and standard error go to private delete-on-close
    // files, and the child inherits exactly three handles (an explicit
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST). A descendant that outlives the root
    // therefore cannot keep a pipe open, and output is complete as soon as
    // the root exits. Root exit (the process handle) and job empty (every
    // process handle in the job signaled after TerminateJobObject) are
    // separate events, so callers never infer either from a wall clock.
    //
    // The job mirrors the caller's breakaway allowance: product daemons
    // request CREATE_BREAKAWAY_FROM_JOB only when their current job allows
    // it, so they behave exactly as they would without this wrapper.
    public sealed class ContainedProcess : IDisposable
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const int STARTF_USESTDHANDLES = 0x00000100;
        private const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint DELETE = 0x00010000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint CREATE_NEW = 1;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
        private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
        private const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
        private const uint JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectBasicProcessIdList = 3;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
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
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
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

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value,
            IntPtr size, IntPtr previousValue, IntPtr returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName, uint desiredAccess, uint shareMode,
            ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job, int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, int informationClass,
            out JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint length, out uint returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, int informationClass,
            out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information, uint length, out uint returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, int informationClass, IntPtr information, uint length, out uint returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessInJob(
            IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process, out long creation, out long exit, out long kernel, out long user);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private IntPtr job;
        private IntPtr processHandle;
        private uint jobBreakawayFlags;
        private FileStream stdoutReader;
        private FileStream stderrReader;
        private Process process;
        private bool disposed;

        public int Id { get; private set; }
        public DateTime StartTimeUtc { get; private set; }

        // A Process view of the root for callbacks that poll HasExited. The
        // PID cannot be reused while this object holds its process handle.
        public Process Process { get { return process; } }

        private ContainedProcess() { }

        public static ContainedProcess Start(ProcessStartInfo startInfo, byte[] standardInput)
        {
            if (startInfo == null) throw new ArgumentNullException("startInfo");
            if (String.IsNullOrWhiteSpace(startInfo.FileName))
            {
                throw new ArgumentException("FileName is required", "startInfo");
            }
            StringBuilder commandLine = BuildCommandLine(startInfo);
            string workingDirectory = String.IsNullOrEmpty(startInfo.WorkingDirectory)
                ? null
                : startInfo.WorkingDirectory;

            ContainedProcess result = new ContainedProcess();
            string stdoutPath = NewOutputPath("out");
            string stderrPath = NewOutputPath("err");
            string stdinPath = null;
            SafeFileHandle stdin = null;
            SafeFileHandle stdout = null;
            SafeFileHandle stderr = null;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            bool started = false;
            try
            {
                SECURITY_ATTRIBUTES inheritable = new SECURITY_ATTRIBUTES();
                inheritable.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                inheritable.bInheritHandle = 1;

                if (standardInput == null)
                {
                    stdin = OpenOrThrow("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        ref inheritable, OPEN_EXISTING, 0, "standard input");
                }
                else
                {
                    stdinPath = NewOutputPath("in");
                    File.WriteAllBytes(stdinPath, standardInput);
                    stdin = OpenOrThrow(stdinPath, GENERIC_READ | DELETE,
                        FILE_SHARE_READ | FILE_SHARE_DELETE, ref inheritable, OPEN_EXISTING,
                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, "standard input");
                    stdinPath = null;
                }
                stdout = OpenOutput(stdoutPath, ref inheritable, "standard output");
                result.stdoutReader = OpenReader(stdoutPath);
                stderr = OpenOutput(stderrPath, ref inheritable, "standard error");
                result.stderrReader = OpenReader(stderrPath);

                result.jobBreakawayFlags = GetInheritedBreakawayFlags();
                result.job = CreateJobObject(IntPtr.Zero, null);
                if (result.job == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW failed");
                }
                SetJobLimits(result.job, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | result.jobBreakawayFlags);

                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                attributeList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
                {
                    Marshal.FreeHGlobal(attributeList);
                    attributeList = IntPtr.Zero;
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");
                }
                handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleList, 0, stdin.DangerousGetHandle());
                Marshal.WriteIntPtr(handleList, IntPtr.Size, stdout.DangerousGetHandle());
                Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, stderr.DangerousGetHandle());
                if (!UpdateProcThreadAttribute(attributeList, 0,
                    new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), handleList,
                    new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(handle list) failed");
                }

                STARTUPINFOEX startup = new STARTUPINFOEX();
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdin.DangerousGetHandle();
                startup.StartupInfo.hStdOutput = stdout.DangerousGetHandle();
                startup.StartupInfo.hStdError = stderr.DangerousGetHandle();
                startup.lpAttributeList = attributeList;

                PROCESS_INFORMATION information;
                if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero, workingDirectory, ref startup, out information))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "failed to start " + startInfo.FileName + ": " + new Win32Exception(error).Message);
                }
                result.processHandle = information.hProcess;
                result.Id = unchecked((int)information.dwProcessId);
                try
                {
                    // Assign before the first instruction runs, so no
                    // descendant can be created outside the job.
                    if (!AssignProcessToJobObject(result.job, information.hProcess))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed");
                    }
                    long creation, exit, kernel, user;
                    if (GetProcessTimes(information.hProcess, out creation, out exit, out kernel, out user))
                    {
                        result.StartTimeUtc = DateTime.FromFileTimeUtc(creation);
                    }
                    try { result.process = Process.GetProcessById(result.Id); }
                    catch (ArgumentException) { result.process = null; }
                    if (ResumeThread(information.hThread) == UInt32.MaxValue)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                    }
                    started = true;
                }
                finally
                {
                    if (!started) TerminateProcess(information.hProcess, 1);
                    CloseHandle(information.hThread);
                }
                return result;
            }
            finally
            {
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                // The child holds its own inherited copies. Closing ours now
                // keeps them out of any other process the caller starts.
                if (stdin != null) stdin.Dispose();
                if (stdout != null) stdout.Dispose();
                if (stderr != null) stderr.Dispose();
                if (stdinPath != null) TryDelete(stdinPath);
                if (!started) result.Dispose();
            }
        }

        public bool HasExited
        {
            get { return WaitForExit(0); }
        }

        // Root exit event. -1 waits without a bound; callers pass their own
        // step budget.
        public bool WaitForExit(int milliseconds)
        {
            ThrowIfDisposed();
            uint timeout = milliseconds < 0 ? INFINITE : (uint)milliseconds;
            uint wait = WaitForSingleObject(processHandle, timeout);
            if (wait == WAIT_OBJECT_0) return true;
            if (wait == WAIT_TIMEOUT) return false;
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed for contained process");
        }

        public int ExitCode
        {
            get
            {
                ThrowIfDisposed();
                if (!WaitForExit(0)) throw new InvalidOperationException("contained process has not exited");
                uint code;
                if (!GetExitCodeProcess(processHandle, out code))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
                }
                return unchecked((int)code);
            }
        }

        // PIDs of processes that are still members of the job: the root, if
        // alive, and every descendant that did not break away.
        public int[] GetActiveProcessIds()
        {
            ThrowIfDisposed();
            if (job == IntPtr.Zero) return new int[0];
            int capacity = 64;
            while (true)
            {
                int bytes = 8 + IntPtr.Size * capacity;
                IntPtr buffer = Marshal.AllocHGlobal(bytes);
                try
                {
                    uint returned;
                    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)bytes, out returned))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != ERROR_MORE_DATA)
                        {
                            throw new Win32Exception(error, "QueryInformationJobObject(process list) failed");
                        }
                    }
                    int assigned = Marshal.ReadInt32(buffer, 0);
                    int listed = Marshal.ReadInt32(buffer, 4);
                    if (listed < assigned)
                    {
                        capacity = Math.Max(capacity * 2, assigned + 16);
                        continue;
                    }
                    int[] ids = new int[listed];
                    for (int i = 0; i < listed; i++)
                    {
                        ids[i] = unchecked((int)Marshal.ReadIntPtr(buffer, 8 + IntPtr.Size * i).ToInt64());
                    }
                    return ids;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        public uint ActiveProcessCount
        {
            get
            {
                ThrowIfDisposed();
                if (job == IntPtr.Zero) return 0;
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out information,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), out returned))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject(accounting) failed");
                }
                return information.ActiveProcesses;
            }
        }

        // Kills every job member and returns only once each one has exited
        // (job-empty event). No wall-clock bound: an unkillable member is a
        // host fault the enclosing step timeout reports.
        public void TerminateTree()
        {
            ThrowIfDisposed();
            if (job == IntPtr.Zero) return;
            if (!TerminateJobObject(job, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject failed");
            }
            while (ActiveProcessCount != 0)
            {
                bool waited = false;
                foreach (int id in GetActiveProcessIds())
                {
                    IntPtr member = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, id);
                    if (member == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_INVALID_PARAMETER) continue;
                        throw new Win32Exception(error, "OpenProcess failed for job member " + id);
                    }
                    try
                    {
                        bool inJob;
                        if (IsProcessInJob(member, job, out inJob) && inJob)
                        {
                            WaitForSingleObject(member, INFINITE);
                            waited = true;
                        }
                    }
                    finally
                    {
                        CloseHandle(member);
                    }
                }
                // A member can be signaled a moment before the job's active
                // count drops; yield instead of spinning on that transition.
                if (!waited) System.Threading.Thread.Yield();
            }
            WaitForExit(-1);
        }

        // Leaves any surviving descendants running outside our control, the
        // same as a process started without a job.
        public void Release()
        {
            ThrowIfDisposed();
            if (job == IntPtr.Zero) return;
            SetJobLimits(job, jobBreakawayFlags);
            CloseHandle(job);
            job = IntPtr.Zero;
        }

        public string ReadStandardOutput() { return ReadAll(stdoutReader); }

        public string ReadStandardError() { return ReadAll(stderrReader); }

        public void Dispose()
        {
            if (disposed) return;
            try
            {
                if (job != IntPtr.Zero)
                {
                    // Closing a KILL_ON_JOB_CLOSE handle kills the remaining
                    // members if an exception skipped TerminateTree/Release.
                    CloseHandle(job);
                    job = IntPtr.Zero;
                }
            }
            finally
            {
                if (stdoutReader != null) stdoutReader.Dispose();
                if (stderrReader != null) stderrReader.Dispose();
                if (process != null) process.Dispose();
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                    processHandle = IntPtr.Zero;
                }
                disposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            if (disposed || processHandle == IntPtr.Zero) throw new ObjectDisposedException("ContainedProcess");
        }

        private static string ReadAll(FileStream stream)
        {
            if (stream == null) return String.Empty;
            stream.Seek(0, SeekOrigin.Begin);
            using (StreamReader reader = new StreamReader(stream, new UTF8Encoding(false), true, 65536, true))
            {
                return reader.ReadToEnd();
            }
        }

        private static string NewOutputPath(string suffix)
        {
            return Path.Combine(Path.GetTempPath(), "dc-contained-" + Guid.NewGuid().ToString("N") + "." + suffix);
        }

        private static SafeFileHandle OpenOrThrow(
            string path, uint access, uint share, ref SECURITY_ATTRIBUTES attributes,
            uint disposition, uint flags, string label)
        {
            SafeFileHandle handle = CreateFile(path, access, share, ref attributes, disposition, flags, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "could not open " + label + " for contained process");
            }
            return handle;
        }

        private static SafeFileHandle OpenOutput(string path, ref SECURITY_ATTRIBUTES attributes, string label)
        {
            return OpenOrThrow(path, GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, ref attributes, CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, label);
        }

        private static FileStream OpenReader(string path)
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.None);
        }

        private static void TryDelete(string path)
        {
            try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        private static uint GetInheritedBreakawayFlags()
        {
            bool inJob;
            if (!IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsProcessInJob failed");
            }
            if (!inJob) return JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION current;
            uint returned;
            if (!QueryInformationJobObject(IntPtr.Zero, JobObjectExtendedLimitInformation, out current,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)), out returned))
            {
                return 0;
            }
            uint flags = current.BasicLimitInformation.LimitFlags;
            return (flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) != 0
                ? JOB_OBJECT_LIMIT_BREAKAWAY_OK
                : 0;
        }

        private static void SetJobLimits(IntPtr target, uint limitFlags)
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            information.BasicLimitInformation.LimitFlags = limitFlags;
            if (!SetInformationJobObject(target, JobObjectExtendedLimitInformation, ref information,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed");
            }
        }

        // Same rules as System.Diagnostics.Process for ArgumentList, so the
        // argument vector a child observes is unchanged.
        private static StringBuilder BuildCommandLine(ProcessStartInfo startInfo)
        {
            StringBuilder line = new StringBuilder();
            string fileName = startInfo.FileName.Trim();
            bool quoted = fileName.Length > 1 && fileName.StartsWith("\"") && fileName.EndsWith("\"");
            if (!quoted) line.Append('"');
            line.Append(fileName);
            if (!quoted) line.Append('"');
            foreach (string argument in startInfo.ArgumentList)
            {
                AppendArgument(line, argument ?? String.Empty);
            }
            if (startInfo.ArgumentList.Count == 0 && !String.IsNullOrEmpty(startInfo.Arguments))
            {
                line.Append(' ').Append(startInfo.Arguments);
            }
            return line;
        }

        private static void AppendArgument(StringBuilder line, string argument)
        {
            line.Append(' ');
            bool plain = argument.Length != 0;
            foreach (char c in argument)
            {
                if (Char.IsWhiteSpace(c) || c == '"') { plain = false; break; }
            }
            if (plain)
            {
                line.Append(argument);
                return;
            }
            line.Append('"');
            int index = 0;
            while (index < argument.Length)
            {
                char c = argument[index++];
                if (c == '\\')
                {
                    int backslashes = 1;
                    while (index < argument.Length && argument[index] == '\\')
                    {
                        index++;
                        backslashes++;
                    }
                    if (index == argument.Length)
                    {
                        line.Append('\\', backslashes * 2);
                    }
                    else if (argument[index] == '"')
                    {
                        line.Append('\\', backslashes * 2 + 1);
                        line.Append('"');
                        index++;
                    }
                    else
                    {
                        line.Append('\\', backslashes);
                    }
                    continue;
                }
                if (c == '"')
                {
                    line.Append('\\');
                    line.Append('"');
                    continue;
                }
                line.Append(c);
            }
            line.Append('"');
        }
    }
}
