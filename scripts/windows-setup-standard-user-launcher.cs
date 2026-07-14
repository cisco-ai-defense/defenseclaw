// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DefenseClaw
{
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
        private const uint DISABLE_MAX_PRIVILEGE = 0x0001;
        private const uint LUA_TOKEN = 0x0004;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int TokenTypeInformation = 8;
        private const int TokenElevationType = 18;
        private const int TokenLinkedToken = 19;
        private const int TokenElevation = 20;
        private const int TokenPrimary = 1;
        private const int TokenElevationTypeDefault = 1;
        private const int TokenElevationTypeFull = 2;
        private const int TokenElevationTypeLimited = 3;
        private const int SecurityImpersonation = 2;

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
        private static extern bool GetTokenInformationLinkedToken(
            IntPtr token,
            int informationClass,
            out TOKEN_LINKED_TOKEN information,
            int informationLength,
            out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsTokenRestricted(IntPtr token);

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
            if (!IsTokenRestricted(token))
            {
                throw new InvalidOperationException(label + " fallback token is not restricted");
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
                if (IsElevated(token)) return false;
                return GetTokenInteger(token, TokenElevationType, "TokenElevationType") ==
                    TokenElevationTypeLimited || IsTokenRestricted(token);
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

        public static Process StartRestricted(
            string applicationPath,
            string[] arguments,
            string workingDirectory,
            string[] environmentEntries,
            bool allowRestrictedLuaFallback)
        {
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
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            Process process = null;
            bool resumed = false;
            try
            {
                sourceToken = OpenToken(
                    GetCurrentProcess(),
                    TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY);
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
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.lpDesktop = @"winsta0\default";
                if (!CreateProcessAsUser(
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
                    out processInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUserW failed");
                }

                childToken = OpenToken(processInfo.hProcess, TOKEN_QUERY);
                ValidateStandardUserPrimaryToken(
                    childToken,
                    launchTokenKind,
                    "suspended Setup child");
                process = Process.GetProcessById(checked((int)processInfo.dwProcessId));
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
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                if (launchToken != IntPtr.Zero) CloseHandle(launchToken);
                if (sourceToken != IntPtr.Zero) CloseHandle(sourceToken);
                if (!resumed && process != null) process.Dispose();
            }
        }
    }
}
