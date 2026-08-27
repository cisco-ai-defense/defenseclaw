// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DefenseClaw
{
    public sealed class RestrictedSetupProcess : IDisposable
    {
        public const int MaxCapturedBytesPerStream = 1048576;

        private sealed class CaptureResult
        {
            public string Text;
            public int CapturedBytes;
            public bool Truncated;
            public string Error;
        }

        private readonly Process process;
        private readonly Stream stdoutStream;
        private readonly Stream stderrStream;
        private readonly Task<CaptureResult> stdoutTask;
        private readonly Task<CaptureResult> stderrTask;
        private CaptureResult stdout;
        private CaptureResult stderr;
        private bool outputCompleted;
        private bool outputHealthy;
        private bool disposed;

        internal RestrictedSetupProcess(Process process, Stream stdoutStream, Stream stderrStream)
        {
            if (process == null)
            {
                throw new ArgumentNullException("process");
            }
            if (process.Handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("restricted Setup process handle is null");
            }
            this.process = process;
            this.stdoutStream = stdoutStream;
            this.stderrStream = stderrStream;
            stdoutTask = StartCapture(stdoutStream);
            stderrTask = StartCapture(stderrStream);
        }

        private static Task<CaptureResult> StartCapture(Stream stream)
        {
            return Task.Factory.StartNew(
                () => DrainBounded(stream),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        private static CaptureResult DrainBounded(Stream stream)
        {
            byte[] captured = new byte[MaxCapturedBytesPerStream];
            byte[] buffer = new byte[8192];
            int stored = 0;
            bool truncated = false;
            string error = "";
            try
            {
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    int available = MaxCapturedBytesPerStream - stored;
                    int keep = Math.Min(available, count);
                    if (keep > 0)
                    {
                        Buffer.BlockCopy(buffer, 0, captured, stored, keep);
                        stored += keep;
                    }
                    if (keep != count) truncated = true;
                }
            }
            catch (ObjectDisposedException)
            {
                error = "redirected output stream closed before drain completed";
            }
            catch (IOException exception)
            {
                error = exception.Message;
            }
            return new CaptureResult
            {
                Text = new UTF8Encoding(false, false).GetString(captured, 0, stored),
                CapturedBytes = stored,
                Truncated = truncated,
                Error = error
            };
        }

        public int Id { get { return process.Id; } }
        public bool HasExited { get { return process.HasExited; } }
        public int ExitCode { get { return process.ExitCode; } }

        public bool WaitForExit(int milliseconds)
        {
            return process.WaitForExit(milliseconds);
        }

        public void Kill(bool entireProcessTree)
        {
            var treeKill = typeof(Process).GetMethod("Kill", new Type[] { typeof(bool) });
            if (entireProcessTree && treeKill != null)
            {
                try
                {
                    treeKill.Invoke(process, new object[] { true });
                    return;
                }
                catch (TargetInvocationException exception)
                {
                    // Kill(bool) raises InvalidOperationException when the
                    // process has already exited. Treat that as success on
                    // this branch so the reflection path behaves like the
                    // ordinary Process.Kill() fallback below.
                    if (exception.InnerException is InvalidOperationException) return;
                    // Rethrow WITHOUT the reflection wrapper, but preserve
                    // the inner stack trace so triage sees where the kill
                    // actually failed.
                    if (exception.InnerException != null)
                    {
                        ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
                    }
                    throw;
                }
            }
            if (entireProcessTree)
            {
                string taskkill = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "taskkill.exe");
                // Process.Start can throw Win32Exception when taskkill.exe is
                // absent or blocked. Swallow it here so the ordinary Kill()
                // fallback below still runs — otherwise a missing taskkill
                // removes the last chance to terminate the child.
                try
                {
                    using (Process killer = Process.Start(new ProcessStartInfo
                    {
                        FileName = taskkill,
                        Arguments = "/PID " + process.Id.ToString(CultureInfo.InvariantCulture) + " /T /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }))
                    {
                        if (killer != null) killer.WaitForExit(30000);
                    }
                }
                catch (Win32Exception)
                {
                    // taskkill.exe missing/blocked; fall through to Kill().
                }
                if (process.HasExited) return;
            }
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException)
            {
                // The process exited between the state check and kill request.
            }
        }

        public bool CompleteOutput(int timeoutMilliseconds)
        {
            if (timeoutMilliseconds < 0) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            if (outputCompleted) return outputHealthy;

            bool drained = Task.WaitAll(
                new Task[] { stdoutTask, stderrTask },
                timeoutMilliseconds);
            if (!drained)
            {
                stdoutStream.Dispose();
                stderrStream.Dispose();
                Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 1000);
            }

            stdout = stdoutTask.IsCompleted
                ? stdoutTask.GetAwaiter().GetResult()
                : new CaptureResult { Text = "", Error = "stdout drain did not complete" };
            stderr = stderrTask.IsCompleted
                ? stderrTask.GetAwaiter().GetResult()
                : new CaptureResult { Text = "", Error = "stderr drain did not complete" };
            outputHealthy = drained && String.IsNullOrEmpty(stdout.Error) && String.IsNullOrEmpty(stderr.Error);
            outputCompleted = true;
            return outputHealthy;
        }

        private void RequireCompletedOutput()
        {
            if (!outputCompleted)
            {
                throw new InvalidOperationException("CompleteOutput must be called before reading redirected output");
            }
        }

        public string StdOut
        {
            get { RequireCompletedOutput(); return stdout.Text; }
        }

        public string StdErr
        {
            get { RequireCompletedOutput(); return stderr.Text; }
        }

        public bool StdOutTruncated
        {
            get { RequireCompletedOutput(); return stdout.Truncated; }
        }

        public bool StdErrTruncated
        {
            get { RequireCompletedOutput(); return stderr.Truncated; }
        }

        public int StdOutCapturedBytes
        {
            get { RequireCompletedOutput(); return stdout.CapturedBytes; }
        }

        public int StdErrCapturedBytes
        {
            get { RequireCompletedOutput(); return stderr.CapturedBytes; }
        }

        public string OutputCaptureError
        {
            get
            {
                RequireCompletedOutput();
                return String.Join("; ", new string[] { stdout.Error, stderr.Error })
                    .Trim(' ', ';');
            }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            stdoutStream.Dispose();
            stderrStream.Dispose();
            process.Dispose();
        }
    }

    // Native release jobs need administrator authority for machine policy, but
    // user-scope Setup deliberately rejects elevation. This helper prefers the
    // elevated user's linked limited primary token. A filtered LUA token is
    // available only when a caller explicitly opts into the UAC-disabled
    // default-token compatibility path; release certification prohibits it.
    // The helper verifies the suspended child before the exact image executes.
    public static class SetupStandardUserLauncher
    {
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint DISABLE_MAX_PRIVILEGE = 0x0001;
        private const uint LUA_TOKEN = 0x0004;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int STARTF_USESTDHANDLES = 0x00000100;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
        private const int TokenGroups = 2;
        private const int TokenTypeInformation = 8;
        private const int TokenElevationType = 18;
        private const int TokenLinkedToken = 19;
        private const int TokenElevation = 20;
        private const int TokenIntegrityLevel = 25;
        private const int TokenPrimary = 1;
        private const int TokenElevationTypeDefault = 1;
        private const int TokenElevationTypeFull = 2;
        private const int TokenElevationTypeLimited = 3;
        private const int SecurityImpersonation = 2;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const uint SE_GROUP_ENABLED = 0x00000004;
        private const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        private const uint SE_GROUP_INTEGRITY = 0x00000020;
        private const string MediumIntegritySid = "S-1-16-8192";

        private enum LaunchTokenKind
        {
            LinkedLimited,
            RestrictedLua
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_LINKED_TOKEN
        {
            public IntPtr LinkedToken;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_GROUPS_HEADER
        {
            public uint GroupCount;
            public SID_AND_ATTRIBUTES FirstGroup;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateRestrictedToken(
            IntPtr existingToken,
            uint flags,
            uint disableSidCount,
            IntPtr sidsToDisable,
            uint deletePrivilegeCount,
            IntPtr privilegesToDelete,
            uint restrictedSidCount,
            IntPtr sidsToRestrict,
            out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateTokenEx(
            IntPtr existingToken,
            uint desiredAccess,
            IntPtr tokenAttributes,
            int impersonationLevel,
            int tokenType,
            out IntPtr newToken);

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
            "advapi32.dll",
            EntryPoint = "GetTokenInformation",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformationBuffer(
            IntPtr token,
            int informationClass,
            IntPtr information,
            int informationLength,
            out int returnLength);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "GetTokenInformation",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformationLinkedToken(
            IntPtr token,
            int informationClass,
            out TOKEN_LINKED_TOKEN information,
            int informationLength,
            out int returnLength);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "SetTokenInformation",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetTokenInformationIntegrity(
            IntPtr token,
            int informationClass,
            ref TOKEN_MANDATORY_LABEL information,
            int informationLength);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CreateProcessAsUserW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessAsUser(
            IntPtr token,
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

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CreateProcessAsUserW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessAsUserExtended(
            IntPtr token,
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

        private static IntPtr OpenToken(IntPtr process, uint access)
        {
            IntPtr token;
            if (!OpenProcessToken(process, access, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }
            return token;
        }

        private static bool IsElevated(IntPtr token)
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
                    "GetTokenInformation(TokenElevation) failed");
            }
            return elevation.TokenIsElevated != 0;
        }

        private static int GetTokenInteger(IntPtr token, int informationClass, string label)
        {
            int value;
            int returned;
            if (!GetTokenInformationInteger(
                token,
                informationClass,
                out value,
                sizeof(int),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetTokenInformation(" + label + ") failed");
            }
            if (returned < sizeof(int))
            {
                throw new InvalidOperationException(
                    "GetTokenInformation(" + label + ") returned a truncated value");
            }
            return value;
        }

        private static void SetMediumIntegrity(IntPtr token)
        {
            SecurityIdentifier identifier = new SecurityIdentifier(MediumIntegritySid);
            byte[] sid = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(sid, 0);
            GCHandle pinned = GCHandle.Alloc(sid, GCHandleType.Pinned);
            try
            {
                TOKEN_MANDATORY_LABEL label = new TOKEN_MANDATORY_LABEL
                {
                    Label = new SID_AND_ATTRIBUTES
                    {
                        Sid = pinned.AddrOfPinnedObject(),
                        Attributes = SE_GROUP_INTEGRITY
                    }
                };
                int size = checked(
                    Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + sid.Length);
                if (!SetTokenInformationIntegrity(
                    token,
                    TokenIntegrityLevel,
                    ref label,
                    size))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "SetTokenInformation(TokenIntegrityLevel) failed");
                }
            }
            finally
            {
                pinned.Free();
            }
        }

        private static IntPtr GetLinkedToken(IntPtr sourceToken)
        {
            TOKEN_LINKED_TOKEN linked;
            int returned;
            if (!GetTokenInformationLinkedToken(
                sourceToken,
                TokenLinkedToken,
                out linked,
                Marshal.SizeOf(typeof(TOKEN_LINKED_TOKEN)),
                out returned))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetTokenInformation(TokenLinkedToken) failed for a full elevated token");
            }
            if (returned < Marshal.SizeOf(typeof(TOKEN_LINKED_TOKEN)) || linked.LinkedToken == IntPtr.Zero)
            {
                if (linked.LinkedToken != IntPtr.Zero) CloseHandle(linked.LinkedToken);
                throw new InvalidOperationException(
                    "GetTokenInformation(TokenLinkedToken) returned an invalid token handle");
            }
            return linked.LinkedToken;
        }

        private static IntPtr DuplicatePrimaryToken(IntPtr token, string label)
        {
            IntPtr primary;
            if (!DuplicateTokenEx(
                token,
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                IntPtr.Zero,
                SecurityImpersonation,
                TokenPrimary,
                out primary))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DuplicateTokenEx failed for " + label);
            }
            return primary;
        }

        private static bool IsAdministrator(IntPtr token)
        {
            int bufferLength;
            if (GetTokenInformationBuffer(
                token,
                TokenGroups,
                IntPtr.Zero,
                0,
                out bufferLength))
            {
                throw new InvalidOperationException(
                    "GetTokenInformation(TokenGroups) unexpectedly accepted an empty buffer");
            }
            int sizingError = Marshal.GetLastWin32Error();
            if (sizingError != ERROR_INSUFFICIENT_BUFFER || bufferLength <= 0)
            {
                throw new Win32Exception(
                    sizingError,
                    "GetTokenInformation(TokenGroups) sizing failed");
            }

            IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
            try
            {
                int returnedLength;
                if (!GetTokenInformationBuffer(
                    token,
                    TokenGroups,
                    buffer,
                    bufferLength,
                    out returnedLength))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetTokenInformation(TokenGroups) failed");
                }
                int groupOffset = Marshal.OffsetOf(
                    typeof(TOKEN_GROUPS_HEADER),
                    "FirstGroup").ToInt32();
                int groupSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                uint groupCount = unchecked((uint)Marshal.ReadInt32(buffer));
                long groupBytes = (long)groupCount * groupSize;
                if (returnedLength < groupOffset ||
                    groupBytes > returnedLength - groupOffset)
                {
                    throw new InvalidOperationException(
                        "GetTokenInformation(TokenGroups) returned an invalid group array");
                }

                SecurityIdentifier administrators = new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null);
                for (uint index = 0; index < groupCount; index++)
                {
                    IntPtr entry = IntPtr.Add(
                        buffer,
                        checked(groupOffset + checked((int)index * groupSize)));
                    SID_AND_ATTRIBUTES group = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        entry,
                        typeof(SID_AND_ATTRIBUTES));
                    if (group.Sid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException(
                            "GetTokenInformation(TokenGroups) returned a null group SID");
                    }
                    if (administrators.Equals(new SecurityIdentifier(group.Sid)))
                    {
                        return (group.Attributes & SE_GROUP_ENABLED) != 0 &&
                            (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0;
                    }
                }
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void ValidateStandardUserPrimaryToken(
            IntPtr token,
            LaunchTokenKind kind,
            string label)
        {
            if (token == IntPtr.Zero)
            {
                throw new InvalidOperationException(label + " token handle is null");
            }
            if (GetTokenInteger(token, TokenTypeInformation, "TokenType") != TokenPrimary)
            {
                throw new InvalidOperationException(label + " token is not a primary token");
            }
            if (IsElevated(token))
            {
                throw new InvalidOperationException(label + " token remains elevated");
            }
            if (IsAdministrator(token))
            {
                throw new InvalidOperationException(
                    label + " token retains enabled administrator membership");
            }

            int elevationType = GetTokenInteger(token, TokenElevationType, "TokenElevationType");
            if (kind == LaunchTokenKind.LinkedLimited)
            {
                if (elevationType != TokenElevationTypeLimited)
                {
                    throw new InvalidOperationException(
                        label + " linked token is not TokenElevationTypeLimited");
                }
                return;
            }
            // LUA_TOKEN can mark administrator groups deny-only without adding
            // a restricting-SID list, so IsTokenRestricted is not the right
            // proof. Effective membership above plus the default elevation
            // type is the standard-user contract for this UAC-disabled path.
            if (elevationType != TokenElevationTypeDefault)
            {
                throw new InvalidOperationException(
                    label + " fallback token is not TokenElevationTypeDefault");
            }
        }

        private static IntPtr OpenStandardUserPrimaryToken(
            IntPtr sourceToken,
            bool allowRestrictedLuaFallback,
            out LaunchTokenKind kind)
        {
            int sourceElevationType = GetTokenInteger(
                sourceToken,
                TokenElevationType,
                "TokenElevationType");
            IntPtr launchToken = IntPtr.Zero;
            try
            {
                if (sourceElevationType == TokenElevationTypeFull)
                {
                    IntPtr linkedToken = GetLinkedToken(sourceToken);
                    try
                    {
                        if (GetTokenInteger(linkedToken, TokenTypeInformation, "TokenType") == TokenPrimary)
                        {
                            launchToken = linkedToken;
                            linkedToken = IntPtr.Zero;
                        }
                        else
                        {
                            launchToken = DuplicatePrimaryToken(linkedToken, "linked limited Setup");
                        }
                        kind = LaunchTokenKind.LinkedLimited;
                        ValidateStandardUserPrimaryToken(launchToken, kind, "linked limited Setup");
                        IntPtr result = launchToken;
                        launchToken = IntPtr.Zero;
                        return result;
                    }
                    finally
                    {
                        if (linkedToken != IntPtr.Zero) CloseHandle(linkedToken);
                    }
                }
                else if (sourceElevationType != TokenElevationTypeDefault)
                {
                    throw new InvalidOperationException(
                        "elevated Setup launcher has an inconsistent token elevation type " +
                        sourceElevationType);
                }

                if (!allowRestrictedLuaFallback)
                {
                    throw new InvalidOperationException(
                        "restricted LUA default-token fallback is disabled for certification; " +
                        "use a real standard user or a UAC-linked limited token");
                }

                kind = LaunchTokenKind.RestrictedLua;
                if (!CreateRestrictedToken(
                    sourceToken,
                    DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
                    0,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    out launchToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken failed");
                }
                SetMediumIntegrity(launchToken);
                ValidateStandardUserPrimaryToken(launchToken, kind, "restricted LUA Setup");
                IntPtr fallback = launchToken;
                launchToken = IntPtr.Zero;
                return fallback;
            }
            finally
            {
                if (launchToken != IntPtr.Zero) CloseHandle(launchToken);
            }
        }

        public static bool IsCurrentProcessElevated()
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                token = OpenToken(GetCurrentProcess(), TOKEN_QUERY);
                return IsElevated(token);
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        // GitHub-hosted Windows disables UAC, so its administrator token has
        // no linked limited half. CI uses this probe to distinguish that host
        // limitation from a failure of the real UAC-linked launch path.
        public static bool CurrentElevatedTokenHasLinkedLimitedToken()
        {
            IntPtr sourceToken = IntPtr.Zero;
            IntPtr linkedToken = IntPtr.Zero;
            try
            {
                sourceToken = OpenToken(GetCurrentProcess(), TOKEN_QUERY);
                if (!IsElevated(sourceToken) ||
                    GetTokenInteger(sourceToken, TokenElevationType, "TokenElevationType") !=
                        TokenElevationTypeFull)
                {
                    return false;
                }
                linkedToken = GetLinkedToken(sourceToken);
                return !IsElevated(linkedToken) &&
                    GetTokenInteger(linkedToken, TokenElevationType, "TokenElevationType") ==
                        TokenElevationTypeLimited;
            }
            finally
            {
                if (linkedToken != IntPtr.Zero) CloseHandle(linkedToken);
                if (sourceToken != IntPtr.Zero) CloseHandle(sourceToken);
            }
        }

        // Exposed for the real launcher smoke child so CI can assert that an
        // elevated parent produced either a linked limited token or the
        // restricted fallback, rather than merely trusting process creation.
        public static bool IsCurrentProcessRestrictedOrLimited()
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                token = OpenToken(GetCurrentProcess(), TOKEN_QUERY);
                if (IsElevated(token) || IsAdministrator(token)) return false;
                int elevationType = GetTokenInteger(
                    token,
                    TokenElevationType,
                    "TokenElevationType");
                return elevationType == TokenElevationTypeLimited ||
                    elevationType == TokenElevationTypeDefault;
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        // Implements the CommandLineToArgvW-compatible quoting rules used by
        // ProcessStartInfo.ArgumentList, including trailing backslashes before
        // the closing quote. It is public so the PowerShell smoke test can
        // exercise exact Unicode/quote/backslash round trips.
        public static string QuoteWindowsArgument(string argument)
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
                if (char.IsWhiteSpace(character) || character == '"')
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

        private static IntPtr BuildEnvironment(string[] environmentEntries)
        {
            string[] entries = (string[])(environmentEntries ?? new string[0]).Clone();
            Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
            foreach (string entry in entries)
            {
                int separator = entry == null ? -1 : entry.IndexOf('=', entry.StartsWith("=") ? 1 : 0);
                if (entry == null || entry.IndexOf('\0') >= 0 || separator <= 0)
                {
                    throw new ArgumentException("invalid Windows environment entry");
                }
            }
            string block = String.Join("\0", entries) + "\0\0";
            return Marshal.StringToHGlobalUni(block);
        }

        private static IntPtr BuildInheritedHandleList(
            IntPtr stdinHandle,
            IntPtr stdoutHandle,
            IntPtr stderrHandle,
            out IntPtr handleListBuffer)
        {
            IntPtr attributeListSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize);
            if (attributeListSize == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList did not report a buffer size");
            }

            IntPtr attributeList = Marshal.AllocHGlobal(attributeListSize);
            handleListBuffer = IntPtr.Zero;
            bool initialized = false;
            try
            {
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "InitializeProcThreadAttributeList failed");
                }
                initialized = true;
                handleListBuffer = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleListBuffer, 0, stdinHandle);
                Marshal.WriteIntPtr(handleListBuffer, IntPtr.Size, stdoutHandle);
                Marshal.WriteIntPtr(handleListBuffer, IntPtr.Size * 2, stderrHandle);
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleListBuffer,
                    new IntPtr(IntPtr.Size * 3),
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "UpdateProcThreadAttribute(handle list) failed");
                }
                return attributeList;
            }
            catch
            {
                if (handleListBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(handleListBuffer);
                    handleListBuffer = IntPtr.Zero;
                }
                if (initialized) DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
                throw;
            }
        }

        public static Process StartRestricted(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string[] environmentEntries,
            bool allowRestrictedLuaFallback)
        {
            RestrictedSetupProcess ignored;
            return StartRestrictedInternal(
                applicationPath,
                arguments,
                workingDirectory,
                environmentEntries,
                allowRestrictedLuaFallback,
                false,
                out ignored);
        }

        public static RestrictedSetupProcess StartRestrictedWithCapture(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string[] environmentEntries,
            bool allowRestrictedLuaFallback)
        {
            RestrictedSetupProcess captured;
            StartRestrictedInternal(
                applicationPath,
                arguments,
                workingDirectory,
                environmentEntries,
                allowRestrictedLuaFallback,
                true,
                out captured);
            if (captured == null)
            {
                throw new InvalidOperationException("restricted Setup capture was not initialized");
            }
            return captured;
        }

        private static Process StartRestrictedInternal(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string[] environmentEntries,
            bool allowRestrictedLuaFallback,
            bool captureOutput,
            out RestrictedSetupProcess capturedProcess)
        {
            capturedProcess = null;
            if (String.IsNullOrWhiteSpace(applicationPath) || !Path.IsPathRooted(applicationPath))
            {
                throw new ArgumentException("restricted Setup application path must be absolute");
            }
            if (applicationPath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("restricted Setup application path contains NUL");
            }
            if (String.IsNullOrWhiteSpace(workingDirectory) || !Path.IsPathRooted(workingDirectory))
            {
                throw new ArgumentException("restricted Setup working directory must be absolute");
            }
            if (workingDirectory.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("restricted Setup working directory contains NUL");
            }

            IntPtr sourceToken = IntPtr.Zero;
            IntPtr launchToken = IntPtr.Zero;
            IntPtr childToken = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr handleListBuffer = IntPtr.Zero;
            AnonymousPipeServerStream stdinPipe = null;
            AnonymousPipeServerStream stdoutPipe = null;
            AnonymousPipeServerStream stderrPipe = null;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            Process process = null;
            bool resumed = false;
            try
            {
                // CreateRestrictedToken preserves the source handle's access;
                // TOKEN_ADJUST_DEFAULT is required to lower the fallback MIC.
                sourceToken = OpenToken(
                    GetCurrentProcess(),
                    TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                        TOKEN_ADJUST_DEFAULT);
                if (!IsElevated(sourceToken))
                {
                    throw new InvalidOperationException(
                        "restricted Setup launch was requested from an already non-elevated process");
                }
                LaunchTokenKind launchTokenKind;
                launchToken = OpenStandardUserPrimaryToken(
                    sourceToken,
                    allowRestrictedLuaFallback,
                    out launchTokenKind);

                environment = BuildEnvironment(environmentEntries);
                bool created;
                if (captureOutput)
                {
                    stdinPipe = new AnonymousPipeServerStream(
                        PipeDirection.Out,
                        HandleInheritability.Inheritable);
                    stdoutPipe = new AnonymousPipeServerStream(
                        PipeDirection.In,
                        HandleInheritability.Inheritable);
                    stderrPipe = new AnonymousPipeServerStream(
                        PipeDirection.In,
                        HandleInheritability.Inheritable);
                    IntPtr stdinHandle = stdinPipe.ClientSafePipeHandle.DangerousGetHandle();
                    IntPtr stdoutHandle = stdoutPipe.ClientSafePipeHandle.DangerousGetHandle();
                    IntPtr stderrHandle = stderrPipe.ClientSafePipeHandle.DangerousGetHandle();
                    attributeList = BuildInheritedHandleList(
                        stdinHandle,
                        stdoutHandle,
                        stderrHandle,
                        out handleListBuffer);
                    STARTUPINFOEX startupInfo = new STARTUPINFOEX();
                    startupInfo.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                    startupInfo.StartupInfo.lpDesktop = @"winsta0\default";
                    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                    startupInfo.StartupInfo.hStdInput = stdinHandle;
                    startupInfo.StartupInfo.hStdOutput = stdoutHandle;
                    startupInfo.StartupInfo.hStdError = stderrHandle;
                    startupInfo.lpAttributeList = attributeList;
                    created = CreateProcessAsUserExtended(
                        launchToken,
                        applicationPath,
                        BuildCommandLine(applicationPath, arguments),
                        IntPtr.Zero,
                        IntPtr.Zero,
                        true,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
                            EXTENDED_STARTUPINFO_PRESENT,
                        environment,
                        workingDirectory,
                        ref startupInfo,
                        out processInfo);
                }
                else
                {
                    STARTUPINFO startupInfo = new STARTUPINFO();
                    startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                    startupInfo.lpDesktop = @"winsta0\default";
                    created = CreateProcessAsUser(
                        launchToken,
                        applicationPath,
                        BuildCommandLine(applicationPath, arguments),
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                        environment,
                        workingDirectory,
                        ref startupInfo,
                        out processInfo);
                }
                if (!created)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUserW failed");
                }

                if (captureOutput)
                {
                    stdinPipe.DisposeLocalCopyOfClientHandle();
                    stdoutPipe.DisposeLocalCopyOfClientHandle();
                    stderrPipe.DisposeLocalCopyOfClientHandle();
                    stdinPipe.Dispose();
                    stdinPipe = null;
                }

                childToken = OpenToken(processInfo.hProcess, TOKEN_QUERY);
                ValidateStandardUserPrimaryToken(
                    childToken,
                    launchTokenKind,
                    "suspended Setup child");
                process = Process.GetProcessById(checked((int)processInfo.dwProcessId));
                if (captureOutput)
                {
                    capturedProcess = new RestrictedSetupProcess(process, stdoutPipe, stderrPipe);
                    stdoutPipe = null;
                    stderrPipe = null;
                }
                if (ResumeThread(processInfo.hThread) == UInt32.MaxValue)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
                }
                resumed = true;
                return process;
            }
            finally
            {
                if (!resumed && processInfo.hProcess != IntPtr.Zero)
                {
                    TerminateProcess(processInfo.hProcess, 1603);
                }
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
                if (childToken != IntPtr.Zero) CloseHandle(childToken);
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleListBuffer != IntPtr.Zero) Marshal.FreeHGlobal(handleListBuffer);
                if (stdinPipe != null) stdinPipe.Dispose();
                if (stdoutPipe != null) stdoutPipe.Dispose();
                if (stderrPipe != null) stderrPipe.Dispose();
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                if (launchToken != IntPtr.Zero) CloseHandle(launchToken);
                if (sourceToken != IntPtr.Zero) CloseHandle(sourceToken);
                if (!resumed)
                {
                    if (capturedProcess != null)
                    {
                        capturedProcess.Dispose();
                        capturedProcess = null;
                    }
                    else if (process != null)
                    {
                        process.Dispose();
                    }
                }
            }
        }
    }
}
